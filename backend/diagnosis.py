"""Evidence-based, rule-based diagnosis for NetPulse reports."""

from collections import defaultdict


GUIDANCE = {
    "agent_offline": "Check that the affected agent is running and can reach the backend.",
    "pending": "Start an agent and wait for at least two probe cycles.",
    "unclear": "Collect another probe cycle and compare a second device or network vantage point.",
    "dns": "Compare the device resolver with the reference resolver, then inspect router DNS settings.",
    "shared_gateway": "Check router power, switch links, and gateway interfaces. Review SNMP counters if available.",
    "local_link": "Check the affected device's Wi-Fi, NIC, cable, and local routing configuration.",
    "wan": "Check router WAN status and ISP service; monitored devices can still reach their gateway.",
    "upstream": "Compare another device and inspect upstream routing beyond the local gateway.",
    "route_interruption": "Inspect the route beyond the last responding hop; traceroute silence alone is not proof of a failed router.",
    "degraded": "Inspect link quality, interference, interface errors, discards, and bandwidth use.",
    "service": "Check the affected application's health, server, and service-specific routing or firewall rules.",
    "healthy": "No action is needed. Keep agents running to retain useful network history.",
}

TITLES = {
    "agent_offline": "Agent telemetry is stale",
    "pending": "Waiting for reports",
    "unclear": "Cause unclear",
    "dns": "DNS resolver problem",
    "shared_gateway": "Router or shared LAN issue",
    "local_link": "Local link issue",
    "wan": "WAN or upstream issue",
    "upstream": "Upstream reachability issue",
    "route_interruption": "Possible route interruption",
    "degraded": "Degraded connection",
    "service": "Application service unavailable",
    "healthy": "Connectivity looks healthy",
}


def latest_window(reports, samples=3):
    """Return the newest reports per agent, ordered newest first."""
    grouped = defaultdict(list)
    for report in sorted(reports, key=lambda item: item["captured_at"], reverse=True):
        if len(grouped[report["agent_id"]]) < samples:
            grouped[report["agent_id"]].append(report)
    return grouped


def consistently(window, field, state, minimum=2):
    return len(window) >= minimum and all(
        item.get("checks", {}).get(field, {}).get("state") == state for item in window
    )


def _result(code, confidence, affected_agents, evidence, candidates=None):
    return {
        "code": code,
        "title": TITLES[code],
        "confidence": confidence,
        "affected_agents": sorted(affected_agents),
        "evidence": evidence,
        "next_step": GUIDANCE[code],
        "candidate_causes": candidates or [],
    }


def _snmp_error_evidence(samples, threshold):
    grouped = defaultdict(list)
    for sample in sorted(samples, key=lambda item: item.get("captured_at", 0), reverse=True):
        grouped[sample.get("device_id", "unknown")].append(sample)

    evidence = []
    for device_id, window in grouped.items():
        if len(window) < 2:
            continue
        current = window[0].get("counters", {})
        previous = window[1].get("counters", {})
        increments = []
        for field in ("in_errors", "out_errors", "in_discards", "out_discards"):
            new_value = current.get(field)
            old_value = previous.get(field)
            if isinstance(new_value, int) and isinstance(old_value, int):
                delta = new_value - old_value
                if delta < 0:
                    if old_value >= 2**32 * 0.9 and new_value <= 2**32 * 0.1:
                        delta += 2**32
                    else:
                        continue
                if delta >= threshold:
                    increments.append(f"{field} +{delta}")
        if increments:
            evidence.append(f"{device_id}: " + ", ".join(increments))
    return evidence


def _repeated_route_interruption(window):
    traces = []
    for report in window:
        trace = report.get("traceroute")
        if not isinstance(trace, dict) or trace.get("reached_destination"):
            continue
        hops = trace.get("hops", [])
        responding = [hop for hop in hops if hop.get("address")]
        if not responding:
            continue
        last_reply_ttl = max(hop["ttl"] for hop in responding)
        later_hops = [hop for hop in hops if hop.get("ttl", 0) > last_reply_ttl]
        if len(later_hops) >= 2 and all(not hop.get("address") for hop in later_hops):
            traces.append((trace.get("target", "destination"), last_reply_ttl))
    return traces


def _repeated_service_failures(window):
    if len(window) < 2:
        return []
    service_states = [
        {
            service.get("name"): service.get("state")
            for service in report.get("services", [])
            if service.get("name")
        }
        for report in window
    ]
    names = set.intersection(*(set(states) for states in service_states))
    return sorted(
        name
        for name in names
        if all(states.get(name) == "fail" for states in service_states)
    )


def diagnose(
    reports,
    now,
    snmp_samples=(),
    stale_after=45,
    loss_threshold=10,
    jitter_threshold=40,
    snmp_error_delta_threshold=10,
):
    """Diagnose the strongest supported cause, or explicitly return an unclear result."""
    by_agent = latest_window(reports)
    fresh = {
        agent_id: window
        for agent_id, window in by_agent.items()
        if now - window[0]["captured_at"] <= stale_after
    }
    stale = sorted(set(by_agent) - set(fresh))
    if stale:
        return _result(
            "agent_offline",
            75,
            stale,
            "No recent report arrived from " + ", ".join(stale) + ".",
        )
    if not fresh:
        return _result("pending", 0, [], "No agent reports are available.")

    all_agents = sorted(fresh)
    gateway_failed = [
        agent for agent, window in fresh.items()
        if consistently(window, "gateway", "fail")
    ]
    internet_failed = [
        agent for agent, window in fresh.items()
        if consistently(window, "internet", "fail")
    ]
    gateway_passed = [
        agent for agent, window in fresh.items()
        if consistently(window, "gateway", "pass")
    ]
    wifi_failed = [
        agent for agent, window in fresh.items()
        if consistently(window, "wifi", "fail")
    ]

    snmp_evidence = _snmp_error_evidence(snmp_samples, snmp_error_delta_threshold)
    if len(all_agents) > 1 and len(gateway_failed) == len(all_agents):
        confidence = 90 if snmp_evidence else 85
        detail = "Every fresh agent repeatedly failed to reach its default gateway."
        if snmp_evidence:
            detail += " Rising router or switch interface counters corroborate the local-network fault: " + "; ".join(snmp_evidence) + "."
        return _result("shared_gateway", confidence, all_agents, detail)

    if gateway_failed and len(gateway_failed) < len(all_agents):
        confidence = 90 if snmp_evidence else 85
        detail = "Only " + ", ".join(sorted(gateway_failed)) + " repeatedly failed to reach its gateway while another agent succeeded."
        if snmp_evidence:
            detail += " Interface counter increases were also observed: " + "; ".join(snmp_evidence) + "."
            confidence = min(95, confidence + 5)
        return _result("local_link", confidence, gateway_failed, detail)

    if gateway_failed:
        return _result(
            "unclear",
            35,
            gateway_failed,
            "The only available vantage point repeatedly failed to reach its gateway; the endpoint link and shared gateway cannot be distinguished.",
            ["local link", "shared gateway"],
        )

    if wifi_failed and len(wifi_failed) < len(all_agents):
        healthy_wifi_peers = [
            agent for agent, window in fresh.items()
            if agent not in wifi_failed and consistently(window, "wifi", "pass")
        ]
        if healthy_wifi_peers:
            return _result(
                "local_link",
                80,
                wifi_failed,
                "Wi-Fi association failed repeatedly on "
                + ", ".join(sorted(wifi_failed))
                + " while another monitored device reported Wi-Fi connected.",
            )

    dns_failed = [
        agent for agent, window in fresh.items()
        if consistently(window, "internet", "pass")
        and consistently(window, "system_dns", "fail")
        and consistently(window, "reference_dns", "pass")
    ]
    if dns_failed:
        return _result(
            "dns",
            90,
            dns_failed,
            "Repeated external IP checks pass, the system resolver fails, and the reference resolver succeeds.",
        )

    if len(all_agents) > 1 and len(internet_failed) == len(all_agents) and len(gateway_passed) == len(all_agents):
        return _result(
            "wan",
            85,
            all_agents,
            "Every fresh agent repeatedly reached its gateway but failed to reach either configured upstream IP.",
        )

    if internet_failed:
        affected = sorted(internet_failed)
        routes = []
        for agent in affected:
            routes.extend(_repeated_route_interruption(fresh[agent]))
        if routes:
            targets = ", ".join(f"{target} after hop {ttl}" for target, ttl in routes)
            return _result(
                "route_interruption",
                55,
                affected,
                "Repeated traces show an unreachable destination and only silent hops after the last reply (" + targets + "). This suggests a path issue but does not identify a failed router.",
                ["upstream routing", "ICMP filtering", "destination unavailable"],
            )
        return _result(
            "upstream",
            65 if len(all_agents) == 1 else 75,
            affected,
            "The affected agent repeatedly failed to reach both configured upstream IPs.",
        )

    degraded = []
    for agent, window in fresh.items():
        if len(window) < 2:
            continue
        losses = [
            item.get("checks", {}).get("internet", {}).get("loss")
            for item in window
        ]
        jitters = [
            item.get("checks", {}).get("internet", {}).get("jitter")
            for item in window
        ]
        losses = [value for value in losses if isinstance(value, (int, float))]
        jitters = [value for value in jitters if isinstance(value, (int, float))]
        if (
            (losses and sum(losses) / len(losses) >= loss_threshold)
            or (jitters and sum(jitters) / len(jitters) >= jitter_threshold)
        ):
            degraded.append(agent)
    if degraded:
        detail = "Recent average loss or jitter exceeded the configured threshold."
        if snmp_evidence:
            detail += " Rising interface counters provide additional evidence: " + "; ".join(snmp_evidence) + "."
        return _result("degraded", 80 if snmp_evidence else 70, degraded, detail)

    service_failures = {}
    unresolved_services = False
    for agent, window in fresh.items():
        service_names = {
            service.get("name")
            for report in window
            for service in report.get("services", [])
            if service.get("name")
        }
        unresolved_services = unresolved_services or any(
            len(window) < 2
            or any(
                not any(
                    service.get("name") == name and service.get("state") == "pass"
                    for service in report.get("services", [])
                )
                for report in window
            )
            for name in service_names
        )
        if (
            consistently(window, "internet", "pass")
            and consistently(window, "system_dns", "pass")
        ):
            failures = _repeated_service_failures(window)
            if failures:
                service_failures[agent] = failures
    if service_failures:
        details = [
            f"{agent}: {', '.join(names)}"
            for agent, names in sorted(service_failures.items())
        ]
        return _result(
            "service",
            80,
            service_failures,
            "Internet and system DNS checks pass, but configured application checks repeatedly fail ("
            + "; ".join(details)
            + ").",
        )

    required_checks = ("gateway", "internet", "system_dns", "reference_dns")
    all_pass = all(
        consistently(window, field, "pass")
        for window in fresh.values()
        for field in required_checks
    ) and not wifi_failed and not unresolved_services
    if all_pass:
        return _result(
            "healthy",
            95,
            all_agents,
            "Gateway, upstream reachability, and both DNS checks passed in every agent's recent window.",
        )

    if any(len(window) < 2 for window in fresh.values()):
        return _result(
            "pending",
            0,
            all_agents,
            "Waiting for at least two reports per agent before diagnosing recent failures.",
        )

    candidates = []
    if gateway_failed:
        candidates.extend(("local link", "shared gateway"))
    if internet_failed:
        candidates.extend(("WAN or ISP", "upstream route"))
    if any(not consistently(window, "system_dns", "pass") for window in fresh.values()):
        candidates.append("DNS resolver")
    if wifi_failed:
        candidates.append("Wi-Fi association or access point")
    if unresolved_services:
        candidates.append("application service")
    if not candidates:
        candidates.append("transient probe failure")
    return _result(
        "unclear",
        25,
        all_agents,
        "Recent checks are inconsistent or incomplete; current evidence does not justify a specific cause.",
        list(dict.fromkeys(candidates)),
    )
