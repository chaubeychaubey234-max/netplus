import unittest

from backend.diagnosis import diagnose
from backend.snmp_poller import counter_delta


def report(
    agent,
    timestamp,
    gateway="pass",
    internet="pass",
    system_dns="pass",
    reference_dns="pass",
    loss=0,
    jitter=0,
    traceroute=None,
    wifi="unknown",
    services=None,
):
    return {
        "agent_id": agent,
        "network_id": "lab",
        "captured_at": timestamp,
        "checks": {
            "gateway": {"state": gateway},
            "internet": {"state": internet, "loss": loss, "jitter": jitter},
            "wifi": {"state": wifi},
            "system_dns": {"state": system_dns},
            "reference_dns": {"state": reference_dns},
        },
        "traceroute": traceroute,
        "services": services or [],
    }


def repeated(agent, **kwargs):
    return [report(agent, timestamp, **kwargs) for timestamp in (100, 95, 90)]


class DiagnosisTests(unittest.TestCase):
    def test_dns_requires_system_failure_and_reference_success(self):
        reports = repeated("a", system_dns="fail") + repeated("b")
        result = diagnose(reports, 102)
        self.assertEqual(result["code"], "dns")
        self.assertGreaterEqual(result["confidence"], 80)

    def test_shared_gateway_failure_needs_multiple_agents(self):
        reports = repeated("a", gateway="fail", internet="fail") + repeated(
            "b", gateway="fail", internet="fail"
        )
        self.assertEqual(diagnose(reports, 102)["code"], "shared_gateway")
        single_agent = diagnose(
            repeated("a", gateway="fail", internet="fail"), 102
        )
        self.assertEqual(single_agent["code"], "unclear")
        self.assertIn("shared gateway", single_agent["candidate_causes"])

    def test_local_gateway_failure_uses_healthy_peer_as_control(self):
        reports = repeated("a", gateway="fail", internet="fail") + repeated("b")
        result = diagnose(reports, 102)
        self.assertEqual(result["code"], "local_link")
        self.assertEqual(result["affected_agents"], ["a"])

    def test_inconsistent_recent_results_are_unclear(self):
        reports = [
            report("a", 100, gateway="fail", internet="fail"),
            report("a", 95),
            report("a", 90),
        ]
        self.assertEqual(diagnose(reports, 102)["code"], "unclear")

    def test_route_silence_is_only_a_low_confidence_suspect(self):
        trace = {
            "target": "203.0.113.1",
            "reached_destination": False,
            "hops": [
                {"ttl": 1, "address": "192.0.2.1"},
                {"ttl": 2, "address": None},
                {"ttl": 3, "address": None},
            ],
        }
        result = diagnose(
            repeated("a", internet="fail", traceroute=trace), 102
        )
        self.assertEqual(result["code"], "route_interruption")
        self.assertLess(result["confidence"], 70)
        self.assertIn("ICMP filtering", result["candidate_causes"])

    def test_rising_snmp_errors_corroborate_shared_gateway_failure(self):
        reports = repeated("a", gateway="fail", internet="fail") + repeated(
            "b", gateway="fail", internet="fail"
        )
        samples = [
            {"device_id": "router", "captured_at": 100, "counters": {"in_errors": 25}},
            {"device_id": "router", "captured_at": 90, "counters": {"in_errors": 3}},
        ]
        result = diagnose(reports, 102, snmp_samples=samples)
        self.assertEqual(result["code"], "shared_gateway")
        self.assertIn("in_errors +22", result["evidence"])
        self.assertEqual(result["confidence"], 90)

    def test_degraded_link_uses_recent_average(self):
        reports = repeated("a", loss=12, jitter=45)
        self.assertEqual(diagnose(reports, 102)["code"], "degraded")

    def test_wifi_failure_compared_with_connected_peer(self):
        reports = repeated("a", wifi="fail") + repeated("b", wifi="pass")
        result = diagnose(reports, 102)
        self.assertEqual(result["code"], "local_link")
        self.assertEqual(result["affected_agents"], ["a"])

    def test_service_failure_is_separated_from_network_failure(self):
        reports = repeated(
            "a",
            services=[{"name": "portal", "state": "fail"}],
        )
        self.assertEqual(diagnose(reports, 102)["code"], "service")

    def test_stale_agent_is_not_reported_healthy(self):
        result = diagnose(repeated("a"), 200, stale_after=45)
        self.assertEqual(result["code"], "agent_offline")

    def test_counter_delta_handles_wraparound(self):
        self.assertEqual(counter_delta(2**32 - 5, 3, 32), 8)
        self.assertIsNone(counter_delta(100, 3, 32))


if __name__ == "__main__":
    unittest.main()
