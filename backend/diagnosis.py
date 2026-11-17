"""Rule-based fault diagnosis shared by the NetPulse backend and tests."""

from collections import defaultdict


def latest_window(reports, samples=3):
    """Return the latest consecutive reports for each agent."""
    grouped = defaultdict(list)
    for report in sorted(reports, key=lambda item: item["captured_at"], reverse=True):
        if len(grouped[report["agent_id"]]) < samples:
            grouped[report["agent_id"]].append(report)
    return grouped


def consistently(window, field, state):
    return len(window) >= 2 and all(item["checks"][field]["state"] == state for item in window)


GUIDANCE = {
    "agent_offline": "Check that the NetPulse agent process is running and that this device can reach the backend.",
    "pending": "Start an agent and wait for two probe cycles before relying on a diagnosis.",
    "dns": "Try a known-good DNS resolver, then inspect the router DNS and the device DNS settings.",
    "shared_gateway": "Check router power, switch links, and the gateway interface. Compare router counters if SNMP is available.",
    "local_link": "Reconnect Wi-Fi or Ethernet, check signal and cable status, then restart the network adapter if needed.",
    "wan": "Check the router WAN status and ISP service. The local gateway remains reachable.",
    "upstream": "Check upstream routing and internet service from this device, then compare another monitored device.",
    "degraded": "Inspect Wi-Fi signal, interference, router interface errors, and bandwidth use before changing network settings.",
    "healthy": "No action is needed. Keep the agent running to retain network history.",
}


def diagnose(reports, now, stale_after=45, loss_threshold=10, jitter_threshold=40):
    """Return the strongest diagnosis justified by the last reports.

    Reports are dictionaries whose checks contain gateway, internet, system_dns,
    and reference_dns results. The backend calls this after every upload.
    """
    by_agent = latest_window(reports)
    fresh = {
        agent_id: window for agent_id, window in by_agent.items()
        if now - window[0]["captured_at"] <= stale_after
    }
    stale = sorted(set(by_agent) - set(fresh))
    if stale:
        return result("agent_offline", "Agent telemetry is stale", "medium", stale,
                      "No recent report arrived from " + ", ".join(stale) + ".")
    if not fresh:
        return result("pending", "Waiting for reports", "low", [], "No agent reports yet.")

    all_agents = sorted(fresh)
    gateway_failed = [agent for agent, window in fresh.items()
                      if consistently(window, "gateway", "fail")]
    internet_failed = [agent for agent, window in fresh.items()
                       if consistently(window, "internet", "fail")]

    dns_failed = [agent for agent, window in fresh.items()
                  if consistently(window, "internet", "pass")
                  and consistently(window, "system_dns", "fail")
                  and consistently(window, "reference_dns", "pass")]
    if dns_failed:
        return result("dns", "DNS resolver problem", "high", sorted(dns_failed),
                      "External IP reachability works while system DNS fails and reference DNS works.")

    if len(all_agents) > 1 and len(gateway_failed) == len(all_agents):
        return result("shared_gateway", "Router or shared LAN issue", "high", all_agents,
                      "Every fresh agent repeatedly failed to reach its default gateway.")
    if len(gateway_failed) and len(gateway_failed) < len(all_agents):
        return result("local_link", "Local link issue", "high", sorted(gateway_failed),
                      "Only the affected agent repeatedly failed to reach the shared gateway.")
    if len(all_agents) > 1 and len(internet_failed) == len(all_agents):
        return result("wan", "WAN or upstream issue", "high", all_agents,
                      "Agents can reach their gateway but repeatedly cannot reach upstream IPs.")
    if internet_failed:
        return result("upstream", "Upstream reachability issue", "medium", sorted(internet_failed),
                      "The affected agent repeatedly cannot reach either configured upstream IP.")

    degraded = []
    for agent, window in fresh.items():
        losses = [item["checks"]["internet"].get("loss") for item in window]
        jitters = [item["checks"]["internet"].get("jitter") for item in window]
        losses = [value for value in losses if isinstance(value, (int, float))]
        jitters = [value for value in jitters if isinstance(value, (int, float))]
        loss_high = bool(losses) and sum(losses) / len(losses) >= loss_threshold
        jitter_high = bool(jitters) and sum(jitters) / len(jitters) >= jitter_threshold
        if loss_high or jitter_high:
            degraded.append(agent)
    if degraded:
        return result("degraded", "Degraded connection", "medium", sorted(degraded),
                      "Loss or jitter exceeded the configured threshold in the recent window.")

    return result("healthy", "Connectivity looks healthy", "high", all_agents,
                  "Gateway, upstream reachability, and DNS checks passed in the latest window.")


def result(code, title, confidence, affected_agents, evidence):
    return {"code": code, "title": title, "confidence": confidence,
            "affected_agents": affected_agents, "evidence": evidence,
            "next_step": GUIDANCE[code]}
