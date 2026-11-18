"""NetPulse agent. Run with administrator privileges on each monitored computer."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import dns.exception
import dns.resolver
import json
from pathlib import Path
import platform
import re
import socket
import sqlite3
import subprocess
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scapy.all import DNS, DNSQR, ICMP, IP, UDP, conf, sr, sr1
from scapy.error import Scapy_Exception

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PING_COUNT = 4
PING_TIMEOUT_SECONDS = 1.5
TRACE_MAX_TTL = 12


def _failure(detail):
    return {
        "state": "unknown",
        "detail": detail,
        "loss": None,
        "rtt": None,
        "jitter": None,
    }


def default_gateway():
    try:
        gateway = conf.route.route("0.0.0.0")[2]
        return gateway if gateway and gateway != "0.0.0.0" else None
    except (OSError, Scapy_Exception):
        return None


def ping(address):
    samples = []
    try:
        answered = sr(
            [
                IP(dst=address) / ICMP(seq=sequence)
                for sequence in range(PING_COUNT)
            ],
            inter=0.1,
            timeout=PING_TIMEOUT_SECONDS,
            verbose=0,
        )[0]
        for sent, reply in answered:
            if sent.sent_time is not None:
                samples.append((reply.time - sent.sent_time) * 1000)
    except (OSError, Scapy_Exception) as error:
        return _failure(f"ICMP probe could not run: {error}")

    received = len(answered)
    differences = [abs(right - left) for left, right in zip(samples, samples[1:])]
    return {
        "state": "pass" if received else "fail",
        "detail": f"{received}/{PING_COUNT} replies",
        "loss": round((PING_COUNT - received) * 100 / PING_COUNT, 1),
        "rtt": round(sum(samples) / received, 1) if received else None,
        "jitter": round(sum(differences) / len(differences), 1) if differences else 0,
    }


def system_dns(domain):
    started = time.monotonic()
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = 3
        answers = resolver.resolve(domain, "A")
        addresses = sorted({answer.address for answer in answers})
        return {
            "state": "pass",
            "detail": (
                f"{domain} resolved via system resolver "
                f"{', '.join(resolver.nameservers)} to {', '.join(addresses)}"
            ),
            "rtt": round((time.monotonic() - started) * 1000, 1),
        }
    except (dns.exception.DNSException, OSError) as error:
        return {"state": "fail", "detail": f"System DNS lookup failed: {error}"}


def wifi_check():
    if platform.system() == "Darwin":
        args = ["networksetup", "-getairportnetwork", "en0"]
    elif platform.system() == "Windows":
        args = ["netsh", "wlan", "show", "interfaces"]
    else:
        args = ["iw", "dev"]
    try:
        result = subprocess.run(
            args, text=True, capture_output=True, timeout=3, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"state": "unknown", "detail": f"Wi-Fi status unavailable: {error}"}
    output = (result.stdout + result.stderr).strip()
    if platform.system() == "Darwin":
        match = re.search(r"Current Wi-Fi Network:\s*(.+)", output)
        if match:
            return {"state": "pass", "detail": f"Connected to {match.group(1).strip()}"}
        if "not associated" in output.lower():
            return {"state": "fail", "detail": "Not associated with a Wi-Fi network"}
    elif platform.system() == "Windows":
        connected = re.search(r"^\s*State\s*:\s*connected\s*$", output, re.I | re.M)
        ssid = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", output, re.I | re.M)
        if connected and ssid:
            return {"state": "pass", "detail": f"Connected to {ssid.group(1)}"}
        if "state" in output.lower() and "disconnected" in output.lower():
            return {"state": "fail", "detail": "Not connected to a Wi-Fi network"}
    else:
        interfaces = re.findall(r"^\s*Interface\s+(\S+)", output, re.M)
        ssid = re.search(r"^\s*ssid\s+(.+?)\s*$", output, re.I | re.M)
        if ssid:
            return {"state": "pass", "detail": f"Connected to {ssid.group(1)}"}
        if interfaces:
            return {"state": "fail", "detail": "Wi-Fi interface is not associated"}
    return {"state": "unknown", "detail": "Wi-Fi status could not be determined"}


def reference_dns(domain, resolver):
    try:
        packet = IP(dst=resolver) / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype="A")
        )
        response = sr1(packet, timeout=2, verbose=0)
    except (OSError, Scapy_Exception) as error:
        return {"state": "unknown", "detail": f"Reference DNS probe could not run: {error}"}
    if response is None or not response.haslayer(DNS):
        return {"state": "fail", "detail": f"No DNS response from {resolver}"}
    answer = response[DNS]
    if answer.rcode == 0 and answer.ancount:
        values = []
        record = answer.an
        for _ in range(answer.ancount):
            if getattr(record, "type", None) == 1:
                values.append(str(record.rdata))
            record = getattr(record, "payload", None)
            if record is None:
                break
        detail = f"{domain} resolved via {resolver}"
        if values:
            detail += " to " + ", ".join(values)
        return {"state": "pass", "detail": detail}
    return {
        "state": "fail",
        "detail": f"Reference resolver {resolver} returned DNS rcode {answer.rcode}",
    }


def traceroute(target):
    hops = []
    reached_destination = False
    try:
        for ttl in range(1, TRACE_MAX_TTL + 1):
            started = time.monotonic()
            response = sr1(
                IP(dst=target, ttl=ttl) / UDP(dport=33434 + ttl),
                timeout=1,
                verbose=0,
            )
            address = response[IP].src if response is not None and response.haslayer(IP) else None
            rtt = round((time.monotonic() - started) * 1000, 1) if response is not None else None
            hops.append({"ttl": ttl, "address": address, "rtt_ms": rtt})
            if address == target:
                reached_destination = True
                break
            if response is not None and response.haslayer(ICMP):
                icmp = response[ICMP]
                if icmp.type == 3 and icmp.code == 3:
                    reached_destination = True
                    break
    except (OSError, Scapy_Exception) as error:
        return {
            "target": target,
            "hops": hops,
            "reached_destination": False,
            "error": f"Traceroute could not run: {error}",
        }
    return {
        "target": target,
        "hops": hops,
        "reached_destination": reached_destination,
        "error": None,
    }


def device_inventory(wifi=None):
    hostname = socket.gethostname()
    try:
        addresses = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(hostname, None)
                if not item[4][0].startswith(("127.", "::1"))
            }
        )
    except socket.gaierror:
        addresses = []
    inventory = {
        "hostname": hostname,
        "platform": platform.platform(),
        "local_ips": addresses,
    }
    if wifi:
        inventory["wifi"] = wifi["detail"]
    return inventory


def http_service_check(service):
    request = Request(
        service["url"],
        method="HEAD",
        headers={"User-Agent": "NetPulse/1.0"},
    )
    started = time.monotonic()
    try:
        with urlopen(request, timeout=service.get("timeout_seconds", 5)) as response:
            return {
                "name": service["name"],
                "state": "pass",
                "detail": f"HTTP {response.status}",
                "rtt_ms": round((time.monotonic() - started) * 1000, 1),
            }
    except HTTPError as error:
        return {
            "name": service["name"],
            "state": "pass" if error.code < 500 else "fail",
            "detail": f"HTTP {error.code}",
            "rtt_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except (URLError, OSError) as error:
        reason = error.reason if isinstance(error, URLError) else error
        return {
            "name": service["name"],
            "state": "fail",
            "detail": str(reason),
            "rtt_ms": None,
        }


def evidence_snapshot():
    if platform.system() == "Windows":
        commands = {
            "routes": ["route", "print"],
            "dns": ["ipconfig", "/all"],
            "wifi": ["netsh", "wlan", "show", "interfaces"],
        }
    elif platform.system() == "Darwin":
        commands = {
            "routes": ["/sbin/route", "-n", "get", "default"],
            "dns": ["/usr/sbin/scutil", "--dns"],
            "wifi": ["networksetup", "-getairportnetwork", "en0"],
        }
    else:
        commands = {
            "routes": ["ip", "route"],
            "dns": ["cat", "/etc/resolv.conf"],
        }
    evidence = {}
    for name, args in commands.items():
        try:
            result = subprocess.run(
                args, text=True, capture_output=True, timeout=5, check=False
            )
            evidence[name] = (result.stdout + result.stderr)[:4000]
        except (OSError, subprocess.TimeoutExpired) as error:
            evidence[name] = f"Could not capture {name}: {error}"
    return evidence


def _aggregate_internet(probes, hosts):
    passing = [probe for probe in probes if probe["state"] == "pass"]
    failing = [probe for probe in probes if probe["state"] == "fail"]
    unknown = [probe for probe in probes if probe["state"] == "unknown"]
    state = (
        "pass"
        if passing
        else "fail"
        if len(failing) == len(probes)
        else "unknown"
    )
    measured = passing
    loss_values = [probe["loss"] for probe in measured if probe.get("loss") is not None]
    rtt_values = [probe["rtt"] for probe in measured if probe.get("rtt") is not None]
    jitter_values = [probe["jitter"] for probe in measured if probe.get("jitter") is not None]
    return {
        "state": state,
        "detail": " | ".join(
            f"{host}: {probe['detail']}" for host, probe in zip(hosts, probes)
        ),
        "targets": [
            {"host": host, **probe} for host, probe in zip(hosts, probes)
        ],
        "loss": round(sum(loss_values) / len(loss_values), 1) if loss_values else None,
        "rtt": round(sum(rtt_values) / len(rtt_values), 1) if rtt_values else None,
        "jitter": (
            round(sum(jitter_values) / len(jitter_values), 1)
            if jitter_values
            else None
        ),
        "unknown_targets": len(unknown),
    }


def collect(config, failure_count):
    gateway = default_gateway()
    gateway_check = (
        ping(gateway)
        if gateway
        else _failure("Default gateway could not be determined")
    )
    hosts = config["upstream_hosts"]
    upstream_probes = [ping(host) for host in hosts]
    internet = _aggregate_internet(upstream_probes, hosts)
    wifi = wifi_check()

    failed_path = (
        gateway_check["state"] == "fail" or internet["state"] == "fail"
    )
    consecutive = failure_count + 1 if failed_path else 0
    report = {
        "report_id": str(uuid.uuid4()),
        "agent_id": config["agent_id"],
        "network_id": config["network_id"],
        "captured_at": time.time(),
        "checks": {
            "gateway": gateway_check,
            "internet": internet,
            "wifi": wifi,
            "system_dns": system_dns(config["test_domain"]),
            "reference_dns": reference_dns(
                config["test_domain"], config["reference_dns"]
            ),
        },
        "services": [],
        "inventory": device_inventory(wifi),
        "traceroute": (
            traceroute(hosts[0]) if consecutive >= 2 else None
        ),
        "evidence": evidence_snapshot() if consecutive >= 2 else None,
    }
    services = config.get("services", [])
    if services:
        with ThreadPoolExecutor(max_workers=min(8, len(services))) as executor:
            report["services"] = list(executor.map(http_service_check, services))
    return report, consecutive


def queue_report(path, report):
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS queue (report_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        db.execute(
            "INSERT OR IGNORE INTO queue VALUES (?, ?)",
            (report["report_id"], json.dumps(report)),
        )


def upload(path, config):
    with sqlite3.connect(path) as db:
        rows = db.execute(
            "SELECT report_id, payload FROM queue ORDER BY rowid LIMIT 50"
        ).fetchall()
    for report_id, payload in rows:
        request = Request(
            config["server_url"].rstrip("/") + "/api/reports",
            data=payload.encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-NetPulse-Token": config["token"],
            },
        )
        try:
            with urlopen(request, timeout=8) as response:
                if response.status not in (200, 201):
                    raise RuntimeError(
                        f"Backend rejected report with HTTP {response.status}"
                    )
        except (URLError, OSError) as error:
            print(f"Report upload deferred: {error}", flush=True)
            return
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM queue WHERE report_id = ?", (report_id,))


def load_config(path):
    with open(path, encoding="utf-8") as stream:
        config = json.load(stream)
    required = {
        "agent_id",
        "network_id",
        "server_url",
        "token",
        "upstream_hosts",
        "reference_dns",
        "test_domain",
    }
    missing = required - config.keys()
    if missing:
        raise ValueError("Missing agent configuration: " + ", ".join(sorted(missing)))
    if not config["upstream_hosts"] or not all(
        isinstance(host, str) and host for host in config["upstream_hosts"]
    ):
        raise ValueError("upstream_hosts must contain at least one host.")
    if config.get("interval_seconds", 15) < 5:
        raise ValueError("interval_seconds must be at least 5 seconds.")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=PROJECT_ROOT / "config" / "agent.json")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    queue_path = Path(args.config).with_name("agent-queue.sqlite3")
    failures = 0
    interval = config.get("interval_seconds", 15)
    next_probe = time.monotonic()
    while True:
        report, failures = collect(config, failures)
        queue_report(queue_path, report)
        upload(queue_path, config)
        print(
            f"{config['agent_id']}: {report['checks']['internet']['detail']}",
            flush=True,
        )
        if args.once:
            return
        next_probe += interval
        delay = next_probe - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_probe = time.monotonic()


if __name__ == "__main__":
    main()
