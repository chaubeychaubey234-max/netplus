"""Poll router or switch interface counters with Net-SNMP's snmpget command."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OIDS = {
    "in_octets": ("1.3.6.1.2.1.31.1.1.1.6", 64),
    "out_octets": ("1.3.6.1.2.1.31.1.1.1.10", 64),
    "in_errors": ("1.3.6.1.2.1.2.2.1.14", 32),
    "in_discards": ("1.3.6.1.2.1.2.2.1.13", 32),
    "out_errors": ("1.3.6.1.2.1.2.2.1.20", 32),
    "out_discards": ("1.3.6.1.2.1.2.2.1.19", 32),
}


def get_value(device, oid):
    command = [
        "snmpget",
        "-v2c",
        "-c",
        device["community"],
        "-Oqv",
        device["host"],
        f"{oid}.{device['interface_index']}",
    ]
    try:
        result = subprocess.run(
            command, text=True, capture_output=True, timeout=8, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"SNMP query failed for {device['device_id']}: {error}", flush=True)
        return None
    if result.returncode:
        detail = result.stderr.strip() or f"snmpget exited with {result.returncode}"
        print(f"SNMP query failed for {device['device_id']}: {detail}", flush=True)
        return None
    output = result.stdout.strip()
    try:
        value = int(output)
    except ValueError:
        print(
            f"SNMP returned a non-integer counter for {device['device_id']}: {output!r}",
            flush=True,
        )
        return None
    return value if value >= 0 else None


def counter_delta(previous, current, bits):
    delta = current - previous
    if delta >= 0:
        return delta
    modulus = 2**bits
    if previous >= modulus * 0.9 and current <= modulus * 0.1:
        return modulus - previous + current
    return None


def poll_device(device, network_id, previous_sample, captured_at):
    counters = {name: get_value(device, OIDS[name][0]) for name in OIDS}
    throughput_bps = None
    if previous_sample and counters["in_octets"] is not None:
        old_octets = previous_sample["counters"].get("in_octets")
        elapsed = captured_at - previous_sample["captured_at"]
        if old_octets is not None and elapsed > 0:
            octet_delta = counter_delta(
                old_octets, counters["in_octets"], OIDS["in_octets"][1]
            )
            if octet_delta is not None:
                throughput_bps = round(octet_delta * 8 / elapsed, 1)
    return {
        "device_id": device["device_id"],
        "network_id": network_id,
        "captured_at": captured_at,
        "interface_index": device["interface_index"],
        "counters": counters,
        "throughput_bps": throughput_bps,
    }


def upload_sample(config, sample):
    payload = json.dumps(sample).encode()
    request = Request(
        config["server_url"].rstrip("/") + "/api/snmp",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-NetPulse-Token": config["token"],
        },
    )
    try:
        with urlopen(request, timeout=8) as response:
            if response.status not in (200, 201):
                raise RuntimeError(f"Backend rejected SNMP sample: HTTP {response.status}")
    except (URLError, OSError) as error:
        print(f"SNMP sample upload failed: {error}", flush=True)


def load_config(path):
    with open(path, encoding="utf-8") as stream:
        config = json.load(stream)
    for key in ("server_url", "token", "network_id", "devices"):
        if key not in config:
            raise ValueError(f"Missing SNMP configuration: {key}")
    for device in config["devices"]:
        for key in ("device_id", "host", "community", "interface_index"):
            if key not in device:
                raise ValueError(f"SNMP device is missing {key}")
    config["server_url"] = os.environ.get(
        "NETPULSE_SERVER_URL", config["server_url"]
    )
    config["token"] = os.environ.get("NETPULSE_AGENT_TOKEN", config["token"])
    if config.get("interval_seconds", 30) < 5:
        raise ValueError("interval_seconds must be at least 5 seconds.")
    return config


def run(config, once=False):
    previous = {}
    interval = config.get("interval_seconds", 30)
    next_poll = time.monotonic()
    while True:
        captured_at = time.time()
        for device in config["devices"]:
            key = device["device_id"]
            sample = poll_device(
                device, config["network_id"], previous.get(key), captured_at
            )
            upload_sample(config, sample)
            previous[key] = sample
            print(
                f"{key}: inbound {sample['throughput_bps'] if sample['throughput_bps'] is not None else 'N/A'} bps",
                flush=True,
            )
        if once:
            return
        next_poll += interval
        delay = next_poll - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_poll = time.monotonic()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=PROJECT_ROOT / "config" / "snmp.json")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    run(load_config(args.config), once=args.once)


if __name__ == "__main__":
    main()
