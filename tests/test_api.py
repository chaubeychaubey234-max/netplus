import time
import unittest

from fastapi.testclient import TestClient

from backend.server import create_app


class MemoryStore:
    def __init__(self):
        self.report_data = []
        self.samples = []
        self.diagnoses = []
        self.diagnosis_data = []

    def add_report(self, report):
        self.report_data.append(report.model_dump(mode="json"))

    def reports(self, minutes=60, network_id=None):
        earliest = time.time() - minutes * 60 if minutes is not None else None
        return [
            item for item in self.report_data
            if earliest is None or item["captured_at"] >= earliest
            if network_id is None or item["network_id"] == network_id
        ]

    def agent_history(self, agent_id, minutes=60, network_id=None):
        earliest = time.time() - minutes * 60
        return [
            item for item in self.report_data
            if item["agent_id"] == agent_id
            and item["captured_at"] >= earliest
            and (network_id is None or item["network_id"] == network_id)
        ]

    def networks(self):
        return sorted({item["network_id"] for item in self.report_data})

    def add_snmp(self, sample):
        self.samples.append(sample.model_dump(mode="json"))

    def add_diagnosis(self, diagnosis, network_id):
        if self.diagnosis_data and self.diagnosis_data[0]["diagnosis"] == diagnosis:
            return False
        self.diagnosis_data.insert(
            0,
            {
                "network_id": network_id,
                "captured_at": time.time(),
                "diagnosis": diagnosis,
            },
        )
        return True

    def diagnosis_history(self, network_id=None, limit=100):
        return [
            item for item in self.diagnosis_data
            if network_id is None or item["network_id"] == network_id
        ][:limit]

    def snmp(self, network_id=None):
        return [
            item for item in self.samples
            if network_id is None or item["network_id"] == network_id
        ]

    def update_incident(self, diagnosis, network_id):
        self.diagnoses.append((diagnosis, network_id))
        return False

    def incidents(self, network_id=None):
        if network_id:
            return []
        return []

    def health(self):
        return None


def valid_report(**overrides):
    report = {
        "report_id": "test-report",
        "agent_id": "agent-a",
        "network_id": "lab",
        "captured_at": time.time(),
        "checks": {
            "gateway": {"state": "pass", "detail": "4/4 replies"},
            "internet": {"state": "pass", "detail": "upstream reachable", "loss": 0, "jitter": 0},
            "system_dns": {"state": "pass", "detail": "resolved"},
            "reference_dns": {"state": "pass", "detail": "resolved"},
        },
        "services": [],
        "inventory": {"hostname": "agent-a"},
    }
    report.update(overrides)
    return report


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.client = TestClient(
            create_app(
                repository=self.store,
                settings={"agent_tokens": ["test-token"]},
            )
        )
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def test_ingest_requires_agent_token(self):
        response = self.client.post("/api/reports", json=valid_report())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.store.report_data, [])

    def test_ingest_persists_report_and_runs_diagnosis(self):
        response = self.client.post(
            "/api/reports",
            json=valid_report(),
            headers={"X-NetPulse-Token": "test-token"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["report_id"], "test-report")
        self.assertEqual(len(self.store.report_data), 1)
        self.assertEqual(self.store.diagnoses[0][1], "lab")
        self.assertEqual(self.store.diagnosis_data[0]["diagnosis"]["code"], "pending")

    def test_ingest_rejects_missing_required_check(self):
        payload = valid_report(checks={"gateway": {"state": "pass"}})
        response = self.client.post(
            "/api/reports",
            json=payload,
            headers={"X-NetPulse-Token": "test-token"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.store.report_data, [])

    def test_status_is_scoped_to_network(self):
        self.store.report_data = [
            valid_report(report_id="a", agent_id="a", network_id="lab"),
            valid_report(report_id="b", agent_id="b", network_id="other"),
        ]
        response = self.client.get("/api/status?network_id=lab")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["network_id"], "lab")
        self.assertEqual([item["agent_id"] for item in response.json()["agents"]], ["a"])

    def test_status_detects_stale_agent_after_reports_stop(self):
        self.store.report_data = [
            valid_report(captured_at=time.time() - 60)
        ]
        response = self.client.get("/api/status?network_id=lab")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["diagnosis"]["code"], "agent_offline")

    def test_diagnosis_history_is_persisted(self):
        self.client.post(
            "/api/reports",
            json=valid_report(),
            headers={"X-NetPulse-Token": "test-token"},
        )
        response = self.client.get("/api/diagnoses?network_id=lab")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["diagnosis"]["code"], "pending")

    def test_configured_dashboard_requires_basic_auth(self):
        app = create_app(
            repository=self.store,
            settings={
                "agent_tokens": ["test-token"],
                "dashboard_username": "admin",
                "dashboard_password": "secret",
            },
        )
        with TestClient(app) as client:
            response = client.get("/api/status")
            self.assertEqual(response.status_code, 401)
            authenticated = client.get("/api/status", auth=("admin", "secret"))
            self.assertEqual(authenticated.status_code, 200)


if __name__ == "__main__":
    unittest.main()
