import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent import agent


class AgentTests(unittest.TestCase):
    def test_ping_reports_loss_from_icmp_echo_replies(self):
        sent = SimpleNamespace(sent_time=1.0)
        reply = SimpleNamespace(time=1.012)
        with patch.object(agent, "sr", return_value=([(sent, reply)], [])) as send_receive:
            result = agent.ping("192.0.2.1")
        self.assertEqual(result["state"], "pass")
        self.assertEqual(result["loss"], 75)
        self.assertEqual(result["rtt"], 12)
        packets = send_receive.call_args.args[0]
        self.assertEqual(len(packets), agent.PING_COUNT)
        self.assertNotIn("count", send_receive.call_args.kwargs)

    def test_collect_reports_wifi_and_aggregates_upstream_probes(self):
        config = {
            "agent_id": "a",
            "network_id": "lab",
            "upstream_hosts": ["192.0.2.1", "192.0.2.2"],
            "test_domain": "example.test",
            "reference_dns": "192.0.2.53",
            "services": [],
        }
        successful = {
            "state": "pass",
            "detail": "4/4 replies",
            "loss": 0,
            "rtt": 10,
            "jitter": 1,
        }
        failed = {
            "state": "fail",
            "detail": "0/4 replies",
            "loss": 100,
            "rtt": None,
            "jitter": 0,
        }
        with (
            patch.object(agent, "default_gateway", return_value="192.0.2.254"),
            patch.object(agent, "ping", side_effect=[successful, successful, failed]),
            patch.object(agent, "system_dns", return_value={"state": "pass", "detail": "ok"}),
            patch.object(agent, "reference_dns", return_value={"state": "pass", "detail": "ok"}),
            patch.object(agent, "wifi_check", return_value={"state": "pass", "detail": "Connected"}),
            patch.object(agent, "device_inventory", return_value={"hostname": "a"}),
        ):
            report, failures = agent.collect(config, 0)
        self.assertEqual(report["checks"]["internet"]["state"], "pass")
        self.assertEqual(report["checks"]["internet"]["loss"], 0)
        self.assertEqual(report["checks"]["internet"]["targets"][1]["state"], "fail")
        self.assertEqual(report["checks"]["wifi"]["state"], "pass")
        self.assertEqual(failures, 0)

    def test_collect_captures_route_after_second_failed_cycle(self):
        config = {
            "agent_id": "a",
            "network_id": "lab",
            "upstream_hosts": ["192.0.2.1"],
            "test_domain": "example.test",
            "reference_dns": "192.0.2.53",
            "services": [],
        }
        failure = {
            "state": "fail",
            "detail": "0/4 replies",
            "loss": 100,
            "rtt": None,
            "jitter": 0,
        }
        with (
            patch.object(agent, "default_gateway", return_value="192.0.2.254"),
            patch.object(agent, "ping", return_value=failure),
            patch.object(agent, "system_dns", return_value={"state": "fail", "detail": "failed"}),
            patch.object(agent, "reference_dns", return_value={"state": "fail", "detail": "failed"}),
            patch.object(agent, "wifi_check", return_value={"state": "unknown", "detail": "unknown"}),
            patch.object(agent, "device_inventory", return_value={"hostname": "a"}),
            patch.object(agent, "traceroute", return_value={"hops": []}) as trace,
            patch.object(agent, "evidence_snapshot", return_value={}),
        ):
            report, failures = agent.collect(config, 1)
        self.assertEqual(failures, 2)
        self.assertEqual(report["traceroute"], {"hops": []})
        trace.assert_called_once_with("192.0.2.1")


if __name__ == "__main__":
    unittest.main()
