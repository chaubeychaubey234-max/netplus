"""Optional SNMP interface collector. Requires the `snmpget` command from net-snmp."""

import argparse
import json
from pathlib import Path
import subprocess
import time
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent


OIDS = {"in_octets": "1.3.6.1.2.1.31.1.1.1.6", "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
        "in_errors": "1.3.6.1.2.1.2.2.1.14", "in_discards": "1.3.6.1.2.1.2.2.1.13"}


def get_value(device, oid):
    command = ["snmpget", "-v2c", "-c", device["community"], "-Ovq", device["host"], f"{oid}.{device['interface_index']}"]
    output = subprocess.run(command, text=True, capture_output=True, timeout=8).stdout.strip()
    return int(output) if output.isdigit() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=PROJECT_ROOT / "config" / "snmp.json")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    previous = {}
    while True:
        captured_at = time.time()
        for device in config["devices"]:
            counters = {name: get_value(device, oid) for name, oid in OIDS.items()}
            key = device["device_id"]
            previous_sample = previous.get(key)
            throughput_bps = None
            if previous_sample and counters["in_octets"] is not None:
                elapsed = captured_at - previous_sample["captured_at"]
                delta = counters["in_octets"] - previous_sample["counters"]["in_octets"]
                throughput_bps = round(max(0, delta) * 8 / elapsed, 1)
            previous[key] = {"captured_at": captured_at, "counters": counters}
            sample = {"device_id": key, "captured_at": captured_at, "counters": counters,
                      "throughput_bps": throughput_bps}
            payload = json.dumps(sample).encode()
            request = Request(config["server_url"].rstrip("/") + "/api/snmp", data=payload, method="POST",
                              headers={"Content-Type": "application/json", "X-NetPulse-Token": config["token"]})
            try:
                urlopen(request, timeout=8).close()
            except OSError:
                pass
        time.sleep(config.get("interval_seconds", 30))


if __name__ == "__main__":
    main()
