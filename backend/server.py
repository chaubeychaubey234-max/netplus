"""FastAPI backend for NetPulse."""

from contextlib import asynccontextmanager
import hmac
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Literal
from urllib.error import URLError
from urllib.request import Request, urlopen

from fastapi import Depends, FastAPI, Header, HTTPException, Request as APIRequest, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

if __package__:
    from .diagnosis import diagnose
else:
    from diagnosis import diagnose

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
logger = logging.getLogger("netpulse")
basic_auth = HTTPBasic(auto_error=False)


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    state: Literal["pass", "fail", "unknown"]
    detail: str = Field(default="", max_length=1000)
    loss: float | None = Field(default=None, ge=0, le=100)
    rtt: float | None = Field(default=None, ge=0)
    jitter: float | None = Field(default=None, ge=0)


class ServiceResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = Field(min_length=1, max_length=128)
    state: Literal["pass", "fail", "unknown"]
    detail: str = Field(default="", max_length=1000)


class TraceHop(BaseModel):
    ttl: int = Field(ge=1, le=255)
    address: str | None = None
    rtt_ms: float | None = Field(default=None, ge=0)


class TraceResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: str
    hops: list[TraceHop] = Field(default_factory=list)
    reached_destination: bool = False
    error: str | None = None


class Report(BaseModel):
    model_config = ConfigDict(extra="allow")

    report_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    network_id: str = Field(min_length=1, max_length=128)
    captured_at: float = Field(gt=0)
    checks: dict[str, CheckResult]
    services: list[ServiceResult] = Field(default_factory=list)
    traceroute: TraceResult | str | None = None

    def has_required_checks(self):
        return {"gateway", "internet", "system_dns", "reference_dns"} <= self.checks.keys()


class SnmpSample(BaseModel):
    model_config = ConfigDict(extra="allow")

    device_id: str = Field(min_length=1, max_length=128)
    network_id: str = Field(default="default", min_length=1, max_length=128)
    captured_at: float = Field(gt=0)
    counters: dict[str, int | None]
    throughput_bps: float | None = Field(default=None, ge=0)


class PostgresStore:
    def __init__(self, database_url):
        self.pool = ConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=10,
            kwargs={"row_factory": dict_row},
            open=False,
        )

    def open(self):
        self.pool.open(wait=True)
        with self.pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    network_id TEXT NOT NULL,
                    captured_at DOUBLE PRECISION NOT NULL,
                    received_at DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS reports_network_time ON reports(network_id, captured_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS reports_agent_time ON reports(agent_id, captured_at DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snmp_samples (
                    device_id TEXT NOT NULL,
                    network_id TEXT NOT NULL,
                    captured_at DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL,
                    PRIMARY KEY (device_id, captured_at)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_key TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    code TEXT NOT NULL,
                    title TEXT NOT NULL,
                    affected_agents JSONB NOT NULL,
                    started_at DOUBLE PRECISION NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL,
                    resolved_at DOUBLE PRECISION
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS diagnoses (
                    diagnosis_id BIGSERIAL PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    captured_at DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS diagnoses_network_time ON diagnoses(network_id, captured_at DESC)"
            )

    def close(self):
        self.pool.close()

    def health(self):
        with self.pool.connection() as conn:
            conn.execute("SELECT 1")

    def add_report(self, report):
        payload = report.model_dump(mode="json")
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO reports(report_id, agent_id, network_id, captured_at, received_at, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT(report_id) DO NOTHING
                """,
                (
                    report.report_id,
                    report.agent_id,
                    report.network_id,
                    report.captured_at,
                    time.time(),
                    Jsonb(payload),
                ),
            )

    def reports(self, minutes=60, network_id=None):
        filters = []
        parameters = []
        if minutes is not None:
            filters.append("captured_at >= %s")
            parameters.append(time.time() - minutes * 60)
        if network_id is not None:
            filters.append("network_id = %s")
            parameters.append(network_id)
        where = "WHERE " + " AND ".join(filters) if filters else ""
        query = f"""
            WITH ranked_reports AS (
                SELECT payload, network_id, agent_id, captured_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY network_id, agent_id ORDER BY captured_at DESC
                    ) AS sample_rank
                FROM reports
                {where}
            )
            SELECT payload FROM ranked_reports
            WHERE sample_rank <= 3 ORDER BY captured_at DESC
        """
        with self.pool.connection() as conn:
            rows = conn.execute(query, parameters).fetchall()
        return [row["payload"] for row in rows]

    def agent_history(self, agent_id, minutes=60, network_id=None):
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT payload FROM reports
                WHERE agent_id = %s AND captured_at >= %s
                  AND (%s::text IS NULL OR network_id = %s)
                ORDER BY captured_at ASC
                """,
                (agent_id, time.time() - minutes * 60, network_id, network_id),
            ).fetchall()
        return [row["payload"] for row in rows]

    def networks(self):
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT network_id FROM reports ORDER BY network_id
                """
            ).fetchall()
        return [row["network_id"] for row in rows]

    def add_snmp(self, sample):
        payload = sample.model_dump(mode="json")
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO snmp_samples(device_id, network_id, captured_at, payload)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(device_id, captured_at) DO UPDATE SET payload = EXCLUDED.payload
                """,
                (
                    sample.device_id,
                    sample.network_id,
                    sample.captured_at,
                    Jsonb(payload),
                ),
            )

    def add_diagnosis(self, diagnosis, network_id):
        with self.pool.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (network_id,))
            previous = conn.execute(
                """
                SELECT payload FROM diagnoses
                WHERE network_id = %s ORDER BY captured_at DESC LIMIT 1
                """,
                (network_id,),
            ).fetchone()
            if previous and previous["payload"] == diagnosis:
                return False
            conn.execute(
                """
                INSERT INTO diagnoses(network_id, captured_at, payload)
                VALUES (%s, %s, %s)
                """,
                (network_id, time.time(), Jsonb(diagnosis)),
            )
        return True

    def diagnosis_history(self, network_id=None, limit=100):
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT payload, captured_at FROM diagnoses
                WHERE (%s::text IS NULL OR network_id = %s)
                ORDER BY captured_at DESC LIMIT %s
                """,
                (network_id, network_id, limit),
            ).fetchall()
        return [
            {"captured_at": row["captured_at"], "diagnosis": row["payload"]}
            for row in rows
        ]

    def snmp(self, network_id=None):
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT payload FROM snmp_samples
                WHERE (%s::text IS NULL OR network_id = %s)
                ORDER BY captured_at DESC LIMIT 100
                """,
                (network_id, network_id),
            ).fetchall()
        return [row["payload"] for row in rows]

    def update_incident(self, diagnosis, network_id):
        if diagnosis["code"] in {"healthy", "pending"}:
            with self.pool.connection() as conn:
                conn.execute(
                    """
                    UPDATE incidents SET resolved_at = %s
                    WHERE network_id = %s AND resolved_at IS NULL
                    """,
                    (time.time(), network_id),
                )
            return False
        key = network_id + ":" + diagnosis["code"] + ":" + ",".join(
            diagnosis["affected_agents"]
        )
        now = time.time()
        with self.pool.connection() as conn:
            conn.execute(
                """
                UPDATE incidents SET resolved_at = %s
                WHERE network_id = %s AND resolved_at IS NULL AND incident_key <> %s
                """,
                (now, network_id, key),
            )
            existing = conn.execute(
                "SELECT resolved_at FROM incidents WHERE incident_key = %s",
                (key,),
            ).fetchone()
            if existing and existing["resolved_at"] is None:
                conn.execute(
                    "UPDATE incidents SET updated_at = %s WHERE incident_key = %s",
                    (now, key),
                )
                return False
            conn.execute(
                """
                INSERT INTO incidents(
                    incident_key, network_id, code, title, affected_agents,
                    started_at, updated_at, resolved_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NULL)
                ON CONFLICT(incident_key) DO UPDATE SET
                    title = EXCLUDED.title,
                    affected_agents = EXCLUDED.affected_agents,
                    started_at = EXCLUDED.started_at,
                    updated_at = EXCLUDED.updated_at,
                    resolved_at = NULL
                """,
                (
                    key,
                    network_id,
                    diagnosis["code"],
                    diagnosis["title"],
                    Jsonb(diagnosis["affected_agents"]),
                    now,
                    now,
                ),
            )
            return True

    def incidents(self, network_id=None):
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT code, title, affected_agents, started_at, updated_at, resolved_at
                FROM incidents WHERE (%s::text IS NULL OR network_id = %s)
                ORDER BY updated_at DESC LIMIT 50
                """,
                (network_id, network_id),
            ).fetchall()
        return [
            {
                "code": row["code"],
                "title": row["title"],
                "affected_agents": row["affected_agents"],
                "started_at": row["started_at"],
                "updated_at": row["updated_at"],
                "resolved_at": row["resolved_at"],
            }
            for row in rows
        ]


def load_config(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _dashboard_authorized(credentials, settings):
    username = settings.get("dashboard_username")
    password = settings.get("dashboard_password")
    if not username and not password:
        return
    valid = (
        credentials is not None
        and hmac.compare_digest(credentials.username, username or "")
        and hmac.compare_digest(credentials.password, password or "")
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Dashboard authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )


def require_token(provided: str | None, settings):
    valid_tokens = settings["agent_tokens"]
    if not provided or not any(hmac.compare_digest(provided, token) for token in valid_tokens):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")


def send_alert(webhook_url, diagnosis):
    if not webhook_url:
        return
    payload = json.dumps(
        {"text": f"NetPulse: {diagnosis['title']} - {diagnosis['evidence']}"}
    ).encode()
    request = Request(
        webhook_url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=5) as response:
            if response.status >= 400:
                logger.warning("Alert webhook returned HTTP %s", response.status)
    except (URLError, OSError) as error:
        logger.warning("Could not deliver alert webhook: %s", error)


def evaluate_network(store, settings, network_id):
    diagnosis = diagnose(
        store.reports(minutes=None, network_id=network_id),
        time.time(),
        snmp_samples=store.snmp(network_id=network_id),
        stale_after=settings["stale_after_seconds"],
        loss_threshold=settings["loss_threshold_percent"],
        jitter_threshold=settings["jitter_threshold_ms"],
        snmp_error_delta_threshold=settings["snmp_error_delta_threshold"],
    )
    store.add_diagnosis(diagnosis, network_id)
    if store.update_incident(diagnosis, network_id):
        send_alert(settings["alert_webhook_url"], diagnosis)
    return diagnosis


def monitor_networks(store, settings, stop_event):
    while not stop_event.is_set():
        for network_id in store.networks():
            evaluate_network(store, settings, network_id)
        if stop_event.wait(settings["diagnosis_interval_seconds"]):
            return


def create_app(repository=None, settings=None):
    settings = settings or {}
    settings.setdefault("agent_tokens", [])
    settings.setdefault("stale_after_seconds", 45)
    settings.setdefault("loss_threshold_percent", 10)
    settings.setdefault("jitter_threshold_ms", 40)
    settings.setdefault("snmp_error_delta_threshold", 10)
    settings.setdefault("diagnosis_interval_seconds", 5)
    settings.setdefault("alert_webhook_url", None)
    settings.setdefault(
        "database_url", os.environ.get("NETPULSE_DATABASE_URL", "")
    )

    @asynccontextmanager
    async def lifespan(app):
        if not settings["agent_tokens"]:
            raise RuntimeError("Configure at least one agent token before starting NetPulse.")
        if repository is None:
            if not settings["database_url"]:
                raise RuntimeError(
                    "Set NETPULSE_DATABASE_URL to a PostgreSQL connection string."
                )
            app.state.store = PostgresStore(settings["database_url"])
            app.state.store.open()
        else:
            app.state.store = repository
        stop_event = threading.Event()
        monitor = threading.Thread(
            target=monitor_networks,
            args=(app.state.store, settings, stop_event),
            name="netpulse-diagnosis",
            daemon=True,
        )
        monitor.start()
        yield
        stop_event.set()
        monitor.join()
        if repository is None:
            app.state.store.close()

    app = FastAPI(title="NetPulse API", version="1.0.0", lifespan=lifespan)
    app.state.settings = settings

    def dashboard_guard(
        credentials: HTTPBasicCredentials | None = Depends(basic_auth),
    ):
        _dashboard_authorized(credentials, settings)

    def token_guard(
        x_netpulse_token: str | None = Header(default=None, alias="X-NetPulse-Token"),
    ):
        require_token(x_netpulse_token, settings)

    @app.get("/healthz")
    def health(request: APIRequest):
        request.app.state.store.health()
        return {"status": "ok"}

    @app.post("/api/reports", status_code=status.HTTP_201_CREATED, dependencies=[Depends(token_guard)])
    def receive_report(report: Report, request: APIRequest):
        if not report.has_required_checks():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Report is missing required network checks.",
            )
        request.app.state.store.add_report(report)
        evaluate_network(request.app.state.store, settings, report.network_id)
        return {"accepted": True, "report_id": report.report_id}

    @app.post("/api/snmp", status_code=status.HTTP_201_CREATED, dependencies=[Depends(token_guard)])
    def receive_snmp(sample: SnmpSample, request: APIRequest):
        store = request.app.state.store
        store.add_snmp(sample)
        evaluate_network(store, settings, sample.network_id)
        return {"accepted": True}

    @app.get("/api/status", dependencies=[Depends(dashboard_guard)])
    def get_status(request: APIRequest, network_id: str | None = None):
        store = request.app.state.store
        all_reports = store.reports(minutes=None, network_id=network_id)
        if network_id is None and all_reports:
            network_id = max(all_reports, key=lambda item: item["captured_at"])["network_id"]
        reports = (
            [report for report in all_reports if report["network_id"] == network_id]
            if network_id
            else all_reports
        )
        samples = store.snmp(network_id=network_id)
        diagnosis = evaluate_network(store, settings, network_id) if network_id else diagnose(
            reports,
            time.time(),
            snmp_samples=samples,
            stale_after=settings["stale_after_seconds"],
            loss_threshold=settings["loss_threshold_percent"],
            jitter_threshold=settings["jitter_threshold_ms"],
            snmp_error_delta_threshold=settings["snmp_error_delta_threshold"],
        )
        thresholds = {
            "stale_after": settings["stale_after_seconds"],
            "loss_threshold": settings["loss_threshold_percent"],
            "jitter_threshold": settings["jitter_threshold_ms"],
            "snmp_error_delta_threshold": settings["snmp_error_delta_threshold"],
        }
        agents = {}
        for report in sorted(reports, key=lambda item: item["captured_at"], reverse=True):
            agents.setdefault(report["agent_id"], report)
        return {
            "diagnosis": diagnosis,
            "network_id": network_id,
            "networks": store.networks(),
            "agents": list(agents.values()),
            "snmp": samples[:30],
            "incidents": store.incidents(network_id=network_id),
            "settings": thresholds,
            "server_time": time.time(),
        }

    @app.get("/api/incidents", dependencies=[Depends(dashboard_guard)])
    def get_incidents(request: APIRequest, network_id: str | None = None):
        return request.app.state.store.incidents(network_id=network_id)

    @app.get("/api/diagnoses", dependencies=[Depends(dashboard_guard)])
    def get_diagnoses(request: APIRequest, network_id: str | None = None, limit: int = 100):
        if not 1 <= limit <= 1000:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="limit must be between 1 and 1000.",
            )
        return request.app.state.store.diagnosis_history(
            network_id=network_id, limit=limit
        )

    @app.get("/api/history/{agent_id}", dependencies=[Depends(dashboard_guard)])
    def get_history(agent_id: str, request: APIRequest, network_id: str | None = None):
        return request.app.state.store.agent_history(agent_id, network_id=network_id)

    @app.get("/", dependencies=[Depends(dashboard_guard)])
    def dashboard():
        index = FRONTEND_DIST / "index.html"
        if not index.is_file():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Build the React dashboard with npm run build in frontend/.",
            )
        return FileResponse(index)

    if (FRONTEND_DIST / "assets").is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount(
            "/assets",
            StaticFiles(directory=FRONTEND_DIST / "assets"),
            name="assets",
        )
    return app


def settings_from_config(config):
    tokens = os.environ.get("NETPULSE_AGENT_TOKENS")
    return {
        "agent_tokens": (
            [token.strip() for token in tokens.split(",") if token.strip()]
            if tokens
            else config.get("agent_tokens", [])
        ),
        "database_url": os.environ.get(
            "NETPULSE_DATABASE_URL", config.get("database_url", "")
        ),
        "dashboard_username": os.environ.get(
            "NETPULSE_DASHBOARD_USERNAME",
            config.get("dashboard_auth", {}).get("username"),
        ),
        "dashboard_password": os.environ.get(
            "NETPULSE_DASHBOARD_PASSWORD",
            config.get("dashboard_auth", {}).get("password"),
        ),
        "alert_webhook_url": os.environ.get(
            "NETPULSE_ALERT_WEBHOOK_URL", config.get("alert_webhook_url")
        ),
        "stale_after_seconds": config.get("stale_after_seconds", 45),
        "loss_threshold_percent": config.get("loss_threshold_percent", 10),
        "jitter_threshold_ms": config.get("jitter_threshold_ms", 40),
        "snmp_error_delta_threshold": config.get("snmp_error_delta_threshold", 10),
        "diagnosis_interval_seconds": config.get("diagnosis_interval_seconds", 5),
    }


def main():
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=PROJECT_ROOT / "config" / "server.json")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    config = load_config(args.config)
    settings = settings_from_config(config)
    if not settings["agent_tokens"]:
        raise SystemExit("Set at least one agent token in the config or NETPULSE_AGENT_TOKENS.")
    app = create_app(settings=settings)
    uvicorn.run(
        app,
        host=args.host or config.get("host", "127.0.0.1"),
        port=args.port or config.get("port", 8765),
    )


default_config_path = Path(os.environ.get("NETPULSE_CONFIG", PROJECT_ROOT / "config" / "server.json"))
default_config = load_config(default_config_path) if default_config_path.is_file() else {}
app = create_app(settings=settings_from_config(default_config))


if __name__ == "__main__":
    main()
