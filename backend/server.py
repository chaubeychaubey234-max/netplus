"""NetPulse backend and dashboard server. Uses only Python's standard library."""

import argparse
import base64
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import time
from urllib.request import Request, urlopen

try:
    from .diagnosis import diagnose
except ImportError:
    from diagnosis import diagnose

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEB = PROJECT_ROOT / "frontend"
ASSETS = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/style.css": ("style.css", "text/css")}


class Store:
    def __init__(self, path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, network_id TEXT NOT NULL,
                captured_at REAL NOT NULL, received_at REAL NOT NULL, payload TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS reports_agent_time ON reports(agent_id, captured_at DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS snmp_samples (
                device_id TEXT NOT NULL, captured_at REAL NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY (device_id, captured_at))""")
            db.execute("""CREATE TABLE IF NOT EXISTS incidents (
                incident_key TEXT PRIMARY KEY, code TEXT NOT NULL, title TEXT NOT NULL,
                affected_agents TEXT NOT NULL, started_at REAL NOT NULL, updated_at REAL NOT NULL,
                resolved_at REAL)""")

    def add_report(self, report):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT OR IGNORE INTO reports VALUES (?, ?, ?, ?, ?, ?)", (
                report["report_id"], report["agent_id"], report["network_id"], report["captured_at"],
                time.time(), json.dumps(report),
            ))

    def reports(self, minutes=15):
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("SELECT payload FROM reports WHERE captured_at >= ? ORDER BY captured_at DESC",
                              (time.time() - minutes * 60,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def agent_history(self, agent_id, minutes=60):
        return [report for report in self.reports(minutes) if report["agent_id"] == agent_id]

    def add_snmp(self, sample):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT OR REPLACE INTO snmp_samples VALUES (?, ?, ?)",
                       (sample["device_id"], sample["captured_at"], json.dumps(sample)))

    def snmp(self):
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("SELECT payload FROM snmp_samples ORDER BY captured_at DESC LIMIT 30").fetchall()
        return [json.loads(row[0]) for row in rows]

    def update_incident(self, diagnosis):
        if diagnosis["code"] in {"healthy", "pending"}:
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("UPDATE incidents SET resolved_at = ? WHERE resolved_at IS NULL", (time.time(),))
            return False
        key = diagnosis["code"] + ":" + ",".join(diagnosis["affected_agents"])
        now = time.time()
        with closing(sqlite3.connect(self.path)) as db, db:
            existing = db.execute("SELECT resolved_at FROM incidents WHERE incident_key = ?", (key,)).fetchone()
            if existing and existing[0] is None:
                db.execute("UPDATE incidents SET updated_at = ? WHERE incident_key = ?", (now, key))
                return False
            db.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, NULL)",
                       (key, diagnosis["code"], diagnosis["title"], json.dumps(diagnosis["affected_agents"]), now, now))
            return True

    def incidents(self):
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("SELECT code, title, affected_agents, started_at, updated_at, resolved_at FROM incidents ORDER BY updated_at DESC LIMIT 20").fetchall()
        return [{"code": row[0], "title": row[1], "affected_agents": json.loads(row[2]),
                 "started_at": row[3], "updated_at": row[4], "resolved_at": row[5]} for row in rows]


def read_json(request):
    length = int(request.headers.get("Content-Length", "0"))
    if not 0 < length <= 100_000:
        raise ValueError("Invalid request size")
    return json.loads(request.rfile.read(length))


def report_is_valid(report):
    required = {"report_id", "agent_id", "network_id", "captured_at", "checks"}
    checks = {"gateway", "internet", "system_dns", "reference_dns"}
    return required <= report.keys() and checks <= report["checks"].keys()


class Handler(BaseHTTPRequestHandler):
    def send_json(self, body, status=200):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def dashboard_authorized(self):
        auth = self.server.dashboard_auth
        if not auth:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, password = base64.b64decode(header[6:]).decode().split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False
        return user == auth["username"] and password == auth["password"]

    def require_dashboard_auth(self):
        if self.dashboard_authorized():
            return False
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="NetPulse"')
        self.end_headers()
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if self.require_dashboard_auth():
            return
        if path == "/api/status":
            reports = self.server.store.reports()
            agents = {}
            for report in reports:
                agents.setdefault(report["agent_id"], report)
            return self.send_json(status_payload(self.server, reports, agents))
        if path == "/api/incidents":
            return self.send_json(self.server.store.incidents())
        if path.startswith("/api/history/"):
            agent_id = path.rsplit("/", 1)[-1]
            return self.send_json(self.server.store.agent_history(agent_id))
        if path in ASSETS:
            filename, mime = ASSETS[path]
            payload = (WEB / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            return self.wfile.write(payload)
        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/snmp":
            if self.headers.get("X-NetPulse-Token") not in self.server.tokens:
                return self.send_error(401)
            try:
                sample = read_json(self)
                if not {"device_id", "captured_at", "counters"} <= sample.keys():
                    raise ValueError("Invalid SNMP payload")
            except (ValueError, json.JSONDecodeError):
                return self.send_error(422)
            self.server.store.add_snmp(sample)
            return self.send_json({"accepted": True}, 201)
        if self.path != "/api/reports":
            return self.send_error(404)
        token = self.headers.get("X-NetPulse-Token")
        if token not in self.server.tokens:
            return self.send_error(401)
        try:
            report = read_json(self)
        except (ValueError, json.JSONDecodeError):
            return self.send_error(400)
        if not report_is_valid(report):
            return self.send_error(422)
        self.server.store.add_report(report)
        reports = self.server.store.reports()
        diagnosis = diagnose(reports, time.time(), **self.server.thresholds)
        if self.server.store.update_incident(diagnosis):
            send_alert(self.server.alert_webhook_url, diagnosis)
        self.send_json({"accepted": True}, 201)

    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args), flush=True)


def load_config(path):
    with open(path) as stream:
        config = json.load(stream)
    if not config.get("agent_tokens"):
        raise ValueError("server.json must contain at least one agent token")
    return config


def status_payload(server, reports, agents):
    return {"diagnosis": diagnose(reports, time.time(), **server.thresholds), "agents": list(agents.values()),
            "snmp": server.store.snmp(), "incidents": server.store.incidents(),
            "settings": server.thresholds, "server_time": time.time()}


def send_alert(webhook_url, diagnosis):
    if not webhook_url:
        return
    payload = json.dumps({"text": f"NetPulse: {diagnosis['title']} - {diagnosis['evidence']}"}).encode()
    request = Request(webhook_url, data=payload, method="POST", headers={"Content-Type": "application/json"})
    try:
        urlopen(request, timeout=5).close()
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=PROJECT_ROOT / "config" / "server.json")
    parser.add_argument("--port", type=int, help="Override the port in server.json")
    args = parser.parse_args()
    config = load_config(args.config)
    host = config.get("host", "127.0.0.1")
    port = args.port or config.get("port", 8765)
    try:
        with ThreadingHTTPServer((host, port), Handler) as server:
            server.tokens = set(config["agent_tokens"])
            server.dashboard_auth = config.get("dashboard_auth")
            server.alert_webhook_url = config.get("alert_webhook_url")
            server.thresholds = {"stale_after": config.get("stale_after_seconds", 45),
                                 "loss_threshold": config.get("loss_threshold_percent", 10),
                                 "jitter_threshold": config.get("jitter_threshold_ms", 40)}
            server.store = Store(PROJECT_ROOT / config.get("database", "netpulse.sqlite3"))
            print(f"NetPulse dashboard: http://{host}:{server.server_port}", flush=True)
            server.serve_forever()
    except OSError as error:
        if error.errno == 48:
            raise SystemExit(f"Port {port} is already in use. Run: python3 backend/server.py --port 8766")
        raise


if __name__ == "__main__":
    main()
