# NetPulse

NetPulse diagnoses network faults by collecting active probes from every monitored computer. Each agent checks its gateway, two external IP addresses, system DNS, and a reference DNS resolver. The backend compares recent reports and identifies local-link, shared gateway, WAN, DNS, degraded-link, and stale-agent conditions.

## Components

| Component | Files | Purpose |
|---|---|---|
| Backend | `backend/server.py`, `backend/diagnosis.py` | Receives reports, stores SQLite history, and runs diagnosis. |
| Frontend | `frontend/` | Dashboard for live status, charts, traceroute, and SNMP. |
| Agent | `agent/agent.py` | Runs on each Mac or Linux host. It buffers reports locally during backend outages. |
| SNMP poller | `backend/snmp_poller.py` | Optional router or switch counter polling through `snmpget`. |

This implementation uses Python's built-in web server and SQLite, so it runs immediately on your Mac. The agent sends real ICMP, DNS, and traceroute probes. It does not include simulated results.

## Start on your Mac

For a fresh clone, copy the example configuration files and use the same new token in both local files.

```sh
cp config/server.example.json config/server.json
cp config/agent.example.json config/agent.json
```

The local `server.json` and `agent.json` files are excluded from Git because they contain your agent token and machine settings.

Start the backend in Terminal window one:

```sh
python3 backend/server.py
```

Open http://127.0.0.1:8765 in your browser. Keep this Terminal window open. If 8765 is occupied, run `python3 backend/server.py --port 8766` and set `server_url` in `config/agent.json` to `http://127.0.0.1:8766`.

Start the agent in Terminal window two:

```sh
python3 agent/agent.py
```

The dashboard shows actual network measurements from your Mac after the first probe cycle. Use Ctrl+C in either Terminal to stop that component.

## Add another computer

1. Copy the NetPulse folder to the second computer.
2. Change `agent_id` in its `config/agent.json`.
3. Change `server_url` to your Mac's LAN address, for example `http://192.168.1.20:8000`.
4. Replace the included local token with a new shared token in the Mac backend config and every agent config.
5. Change `host` in the Mac `config/server.json` to `0.0.0.0`, restart `backend/server.py`, and allow incoming connections if macOS Firewall asks.
6. Run `python3 agent/agent.py` on the second computer.

The dashboard now has independent viewpoints. This comparison identifies one device's Wi-Fi or cable issue versus a shared gateway or WAN outage.

## Diagnosis rules

- One agent repeatedly fails to reach its gateway while a peer succeeds. Local link, Wi-Fi, NIC, or cable issue.
- Every agent repeatedly fails to reach the gateway. Shared LAN, router, or switch issue.
- Every agent reaches the gateway and repeatedly fails to reach both upstream IPs. WAN or ISP issue.
- Upstream IP reachability passes, system DNS fails, and reference DNS passes. DNS resolver issue.
- Recent loss is at least 10% or jitter is at least 40 ms. Degraded connection.
- No report arrives for 45 seconds. Agent telemetry is stale.

The agent collects traceroute only after two consecutive gateway or upstream failures. Silent traceroute hops are evidence and are not treated as a failure on their own.

## Extended features

- Service checks verify configured websites or internal portals separately from generic internet reachability.
- Device inventory reports hostname, operating system, local IP addresses, and available Wi-Fi information.
- Automatic evidence capture saves routing, DNS, Wi-Fi, and traceroute output after repeated failures.
- Incident history records when a diagnosis starts, remains active, and recovers.
- The dashboard includes a repair suggestion for every diagnosis.
- Configure `alert_webhook_url` in `server.json` to send outage alerts to a compatible webhook. It stays disabled until you provide a URL.
- Set `dashboard_auth` in `server.json` to require a browser username and password.
- Thresholds for stale telemetry, loss, and jitter are configurable in `server.json`.

## Deployment

`deploy/Dockerfile` and `deploy/docker-compose.yml` package the backend for repeatable deployment. Before running Docker Compose, replace both placeholder values in `deploy/server.json` and put that same agent token in every agent configuration. The included Caddyfile example provides HTTPS when you have a public domain pointed at the deployment machine. Set a real dashboard password and replace the local agent token before exposing the backend outside your private network.

## Optional SNMP

Install the `snmpget` command from Net-SNMP on the backend machine. Copy `config/snmp.example.json` to `config/snmp.json`, set the router address and interface index, then run:

```sh
python3 backend/snmp_poller.py
```

It records interface octets, errors, discards, and calculated inbound throughput. The dashboard shows `N/A` when SNMP is unavailable.

## Evaluation workflow

For each trial, record injection time, expected diagnosis, actual diagnosis, and recovery time.

1. Give one agent a wrong DNS resolver. Expect DNS resolver problem on that agent.
2. Disable one agent's Wi-Fi or disconnect Ethernet. Expect local link issue when a peer stays healthy.
3. Disconnect the router's WAN connection. Expect WAN or upstream issue when every agent reaches the gateway.
4. Add packet loss in an isolated lab path. Expect degraded connection.
5. Stop an agent process. Expect stale-agent telemetry after 45 seconds.

`netpulse.sqlite3` stores backend history. `agent-queue.sqlite3` stores unuploaded agent reports. Delete either only while its corresponding process is stopped if you want to reset its data.
