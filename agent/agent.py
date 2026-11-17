"""NetPulse agent. Run this on every Mac or Linux device you want to monitor."""

import argparse
import json
from pathlib import Path
import platform
import re
import socket
import sqlite3
import subprocess
import time
import uuid
from urllib.error import URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def command(args, timeout):
    try:
        process = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return process.stdout + process.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error)


def default_gateway():
    if platform.system() == "Darwin":
        text = command(["/sbin/route", "-n", "get", "default"], 3)
        match = re.search(r"^\s*gateway:\s+(\S+)", text, re.M)
    else:
        text = command(["ip", "route", "show", "default"], 3)
        match = re.search(r"default via (\S+)", text)
    return match.group(1) if match else None


def ping(address):
    args = ["ping", "-n", "-c", "4", address]
    text = command(args, 8)
    counts = re.search(r"(\d+) packets transmitted, (\d+) packets received", text)
    if not counts:
        return {"state": "unknown", "detail": "Ping command did not return statistics", "loss": None,
                "rtt": None, "jitter": None}
    sent, received = map(int, counts.groups())
    samples = [float(value) for value in re.findall(r"time[=<]([\d.]+)\s*ms", text)]
    differences = [abs(b - a) for a, b in zip(samples, samples[1:])]
    return {
        "state": "pass" if received else "fail",
        "detail": f"{received}/{sent} replies",
        "loss": round((sent - received) * 100 / sent, 1),
        "rtt": round(sum(samples) / len(samples), 1) if samples else None,
        "jitter": round(sum(differences) / len(differences), 1) if differences else 0,
    }


def system_dns(domain):
    try:
        addresses = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        return {"state": "pass", "detail": f"{domain} resolved to {addresses[0][4][0]}"}
    except socket.gaierror as error:
        return {"state": "fail", "detail": f"{domain} lookup failed: {error.strerror}"}


def reference_dns(domain, resolver):
    text = command(["dig", f"@{resolver}", "+time=2", "+tries=1", domain, "A", "+short"], 4)
    answer = re.search(r"^\d+\.\d+\.\d+\.\d+$", text, re.M)
    if answer:
        return {"state": "pass", "detail": f"{domain} resolved via {resolver}"}
    return {"state": "fail", "detail": f"No DNS answer from {resolver}"}


def traceroute(target):
    binary = "/usr/sbin/traceroute" if platform.system() == "Darwin" else "traceroute"
    return command([binary, "-n", "-q", "1", "-w", "1", "-m", "12", target], 16)


def device_inventory():
    hostname = socket.gethostname()
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None) if "." in item[4][0]})
    inventory = {"hostname": hostname, "platform": platform.platform(), "local_ips": addresses}
    if platform.system() == "Darwin":
        network = command(["networksetup", "-getairportnetwork", "en0"], 3).strip()
        info = command(["networksetup", "-getinfo", "Wi-Fi"], 3).strip()
        inventory["wifi"] = {"network": network, "details": info}
    return inventory


def http_service_check(service):
    try:
        request = Request(service["url"], method="HEAD", headers={"User-Agent": "NetPulse/1.0"})
        with urlopen(request, timeout=service.get("timeout_seconds", 5)) as response:
            return {"name": service["name"], "state": "pass", "detail": f"HTTP {response.status}"}
    except (URLError, OSError) as error:
        return {"name": service["name"], "state": "fail", "detail": str(error.reason if hasattr(error, "reason") else error)}


def evidence_snapshot():
    commands = {
        "route": ["/sbin/route", "-n", "get", "default"] if platform.system() == "Darwin" else ["ip", "route"],
        "dns": ["scutil", "--dns"] if platform.system() == "Darwin" else ["cat", "/etc/resolv.conf"],
    }
    if platform.system() == "Darwin":
        commands["wifi"] = ["networksetup", "-getinfo", "Wi-Fi"]
    return {name: command(args, 5)[:4000] for name, args in commands.items()}


def collect(config, failure_count):
    gateway = default_gateway()
    gateway_check = ping(gateway) if gateway else {
        "state": "unknown", "detail": "Default gateway could not be determined", "loss": None,
        "rtt": None, "jitter": None,
    }
    probes = [ping(host) for host in config["upstream_hosts"]]
    passed = [probe for probe in probes if probe["state"] == "pass"]
    failed = [probe for probe in probes if probe["state"] == "fail"]
    internet = probes[0].copy()
    internet["state"] = "pass" if passed else "fail" if len(failed) == len(probes) else "unknown"
    internet["detail"] = " · ".join(
        f"{host}: {probe['detail']}" for host, probe in zip(config["upstream_hosts"], probes)
    )
    failed_path = gateway_check["state"] == "fail" or internet["state"] == "fail"
    consecutive = failure_count + 1 if failed_path else 0
    report = {
        "report_id": str(uuid.uuid4()), "agent_id": config["agent_id"],
        "network_id": config["network_id"], "captured_at": time.time(),
        "checks": {
            "gateway": gateway_check,
            "internet": internet,
            "system_dns": system_dns(config["test_domain"]),
            "reference_dns": reference_dns(config["test_domain"], config["reference_dns"]),
        },
        "services": [http_service_check(service) for service in config.get("services", [])],
        "inventory": device_inventory(),
        "traceroute": traceroute(config["upstream_hosts"][0]) if consecutive >= 2 else None,
        "evidence": evidence_snapshot() if consecutive >= 2 else None,
    }
    return report, consecutive


def queue_report(path, report):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS queue (report_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO queue VALUES (?, ?)", (report["report_id"], json.dumps(report)))


def upload(path, config):
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT report_id, payload FROM queue ORDER BY rowid LIMIT 50").fetchall()
    for report_id, payload in rows:
        request = Request(
            config["server_url"].rstrip("/") + "/api/reports", data=payload.encode(), method="POST",
            headers={"Content-Type": "application/json", "X-NetPulse-Token": config["token"]},
        )
        try:
            with urlopen(request, timeout=8) as response:
                if response.status not in (200, 201):
                    return
        except (URLError, OSError):
            return
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM queue WHERE report_id = ?", (report_id,))


def load_config(path):
    with open(path) as stream:
        config = json.load(stream)
    required = {"agent_id", "network_id", "server_url", "token", "upstream_hosts", "reference_dns", "test_domain"}
    missing = required - config.keys()
    if missing:
        raise ValueError("Missing agent configuration: " + ", ".join(sorted(missing)))
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=PROJECT_ROOT / "config" / "agent.json")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    queue_path = Path(args.config).with_name("agent-queue.sqlite3")
    failures = 0
    while True:
        report, failures = collect(config, failures)
        queue_report(queue_path, report)
        upload(queue_path, config)
        print(f"{config['agent_id']}: {report['checks']['internet']['detail']}", flush=True)
        if args.once:
            return
        time.sleep(config.get("interval_seconds", 15))


if __name__ == "__main__":
    main()
