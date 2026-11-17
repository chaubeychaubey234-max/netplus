import unittest

from backend.diagnosis import diagnose


def report(agent, timestamp, gateway="pass", internet="pass", system_dns="pass", reference_dns="pass"):
    return {"agent_id": agent, "captured_at": timestamp, "checks": {
        "gateway": {"state": gateway}, "internet": {"state": internet, "loss": 0, "jitter": 0},
        "system_dns": {"state": system_dns}, "reference_dns": {"state": reference_dns},
    }}


class DiagnosisTests(unittest.TestCase):
    def test_dns_isolated_to_agent(self):
        reports = [report("a", 100, system_dns="fail"), report("a", 95, system_dns="fail"), report("b", 100), report("b", 95)]
        self.assertEqual(diagnose(reports, 102)["code"], "dns")

    def test_shared_gateway_failure(self):
        reports = [report(agent, timestamp, gateway="fail", internet="fail") for agent in ("a", "b") for timestamp in (100, 95)]
        self.assertEqual(diagnose(reports, 102)["code"], "shared_gateway")

    def test_local_gateway_failure(self):
        reports = [report("a", 100, gateway="fail", internet="fail"), report("a", 95, gateway="fail", internet="fail"), report("b", 100), report("b", 95)]
        self.assertEqual(diagnose(reports, 102)["code"], "local_link")


if __name__ == "__main__":
    unittest.main()
