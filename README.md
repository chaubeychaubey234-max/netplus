# NetPulse

NetPulse is a distributed network-monitoring and fault-localization system. Agents measure connectivity from multiple computers; a FastAPI backend stores probe and SNMP history in PostgreSQL; an evidence-based rule engine returns the most likely fault, supporting observations, confidence, and candidate causes when the evidence is inconclusive. The React dashboard displays device status chains, incidents, traceroute hops, and latency/loss history.

Network probes can narrow down a failure, but cannot always identify the exact physical component. NetPulse reports a likely cause and explicitly reports **Cause unclear** when the current measurements do not support a specific diagnosis. In particular, a traceroute timeout alone does not prove that a router is faulty.

## Architecture

| Component | Implementation |
|---|---|
| Agent | Python and Scapy ICMP/DNS probes, system DNS lookup, traceroute, inventory, and a local SQLite upload queue |
| Backend | FastAPI JSON API, token-protected ingestion, optional dashboard Basic authentication |
| Storage | PostgreSQL tables for reports, SNMP samples, diagnosis changes, and incidents; JSONB preserves probe evidence |
| Diagnosis | Periodic temporal, multi-agent rules using gateway, upstream, DNS, traceroute, and SNMP counter evidence |
| Dashboard | React, Vite, and Chart.js |
| Router polling | Optional Net-SNMP `snmpget` poller; counter wrap-around is accounted for |

Agents and the server use JSON over HTTP in a private lab. Use HTTPS (for example, the included Caddy configuration) when traffic crosses an untrusted network. Scapy uses raw sockets: run the agent with the required privileges and install Npcap when using Windows. Linux VMs are recommended for repeatable lab experiments with `tc netem`.

## Local setup

### 1. Install dependencies

Requirements: Python 3.11+, Node.js 20+, PostgreSQL 15+, and (for SNMP polling) Net-SNMP.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd frontend
npm ci
npm run build
cd ..
```

Create a PostgreSQL database and user, then copy and edit the example configuration:

```powershell
Copy-Item config\server.example.json config\server.json
Copy-Item config\agent.example.json config\agent.json
```

Set a long random token in both configurations and set `database_url` to your PostgreSQL connection string. Replace the dashboard password as well. If the database password contains URL-reserved characters, percent-encode them in the connection string.

Start the backend:

```powershell
python backend\server.py --config config\server.json
```

Open <http://127.0.0.1:8765>. Start the agent in a second **elevated** terminal:

```powershell
python agent\agent.py --config config\agent.json
```

For agents on other computers, set `server_url` to the backend's reachable LAN address and use a unique `agent_id`. Keep the same `network_id` for computers whose measurements should be compared. Permit only the required lab traffic through the host firewall.

### 2. Run the optional SNMP poller

Copy `config\snmp.example.json` to `config\snmp.json`. Set the same `network_id` as the agents, the router address, interface index, and a read-only SNMP community. Then run:

```powershell
python backend\snmp_poller.py --config config\snmp.json
```

SNMPv2c communities are sent without encryption. Use a restricted, read-only community on a trusted lab network; do not expose it to the public internet. Devices without SNMP support can still be monitored with agent probes.

## Docker deployment

Copy `deploy/.env.example` to `deploy/.env` and replace every placeholder. Do not commit `.env`. Start PostgreSQL and the backend with:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build
```

The database has a persistent Docker volume. The backend listens on port 8765. Configure agents to use the host's reachable address. To include the optional SNMP poller, also create `config/snmp.json` and start the `snmp` profile:

```sh
docker compose --profile snmp --env-file deploy/.env -f deploy/docker-compose.yml up --build
```

For HTTPS, configure a DNS name in `deploy/Caddyfile.example` and proxy to the backend. Restrict direct access to port 8765 if Caddy is the public entry point.

## Diagnosis and evidence

The engine examines up to three recent reports per agent and separates networks by `network_id`. It requires repeated observations for fault rules:

| Repeated observations | Diagnosis |
|---|---|
| Every agent fails to reach its gateway | Shared gateway or LAN issue |
| One agent fails its gateway while another reaches it | Likely local link/device issue |
| Agents reach the gateway but fail both configured upstream IPs | Likely WAN/upstream issue |
| Upstream reachability works, system DNS fails, and reference DNS succeeds | DNS resolver issue |
| Average loss or jitter exceeds configured thresholds | Degraded connection |
| Traceroute destination is unreachable and multiple hops after the last reply are silent | Possible route interruption, with low confidence |
| Recent results are inconsistent or incomplete | Cause unclear, with candidate causes |

Rising interface error/discard counters support a local-network or degradation diagnosis; SNMP counters are evidence, not proof of causation. The current score is a rule-based evidence score, not a statistically calibrated probability.

Configure `stale_after_seconds`, `loss_threshold_percent`, `jitter_threshold_ms`, and `snmp_error_delta_threshold` in the server configuration. Dashboard credentials can be set with `NETPULSE_DASHBOARD_USERNAME` and `NETPULSE_DASHBOARD_PASSWORD`; agent tokens can be supplied as a comma-separated `NETPULSE_AGENT_TOKENS` value. Prefer environment variables for deployed secrets.

## Fault-injection evaluation

Use an isolated lab with at least two monitored endpoints and record the known injected fault before examining NetPulse's diagnosis. Include at least ten trials across cases such as:

1. A wrong resolver on one endpoint while a peer uses a working resolver.
2. One endpoint disconnected from Wi-Fi or Ethernet while a peer remains connected.
3. Gateway unavailable to all endpoints.
4. WAN disconnected while the local gateway remains reachable.
5. Packet loss and added delay on a controlled Linux lab interface using `tc netem`.
6. DNS reference resolver unreachable while the system resolver works.
7. Agent stopped to verify stale telemetry.
8. A route with nonresponsive intermediate hops but a reachable destination.
9. A route interruption in a controlled virtual network.
10. A normal/no-fault baseline.

Report diagnosis accuracy, false positives, unclear-result rate, time from fault injection to diagnosis, recovery time, and agent CPU/network overhead. Capture packet traces with Wireshark during selected trials to verify that the generated probes and observed outcomes match the reported evidence. Do not treat a silent traceroute hop as conclusive in isolation.

## Tests and build

```sh
python -m unittest discover -s tests -v
cd frontend
npm ci
npm run build
```

PostgreSQL integration tests require a running database; the diagnosis and API unit tests use an in-memory repository where appropriate.
