import { useEffect, useMemo, useState } from "react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend
} from "chart.js";
import { Line } from "react-chartjs-2";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

const checkLabels = [
  ["wifi", "Wi-Fi"],
  ["gateway", "Gateway"],
  ["internet", "Internet"],
  ["system_dns", "System DNS"],
  ["reference_dns", "Reference DNS"]
];

function formatTime(value) {
  return value ? new Date(value * 1000).toLocaleTimeString() : "—";
}

function stateLabel(state) {
  return state === "pass" ? "Passing" : state === "fail" ? "Failing" : "Unknown";
}

function AgentCard({ report, serverTime, staleAfter }) {
  const checks = report.checks || {};
  const failed = Object.values(checks).some((check) => check.state === "fail");
  const stale = serverTime - report.captured_at > staleAfter;
  const inventory = report.inventory || {};
  const services = report.services || [];
  return (
    <article className={`agent-card ${failed ? "has-failure" : ""} ${stale ? "is-stale" : ""}`}>
      <header className="agent-header">
        <div>
          <h3>{report.agent_id}</h3>
          <small>{report.network_id} · {formatTime(report.captured_at)}</small>
        </div>
        <span className={`pill ${stale || failed ? "pill-fail" : "pill-pass"}`}>
          {stale ? "Telemetry stale" : failed ? "Needs attention" : "No probe failures"}
        </span>
      </header>
      <div className="status-chain" aria-label="Network status chain">
        {checkLabels.map(([key, label]) => {
          const check = checks[key] || { state: "unknown", detail: "No result" };
          return (
            <div className={`chain-step state-${check.state}`} key={key}>
              <span className="step-name">{label}</span>
              <strong>{stateLabel(check.state)}</strong>
              <small>{check.detail}</small>
            </div>
          );
        })}
      </div>
      <div className="device-meta">
        <strong>{inventory.hostname || "Device details unavailable"}</strong>
        <span>{inventory.platform || ""}</span>
        <span>{(inventory.local_ips || []).join(", ")}</span>
        <span>
          Services: {services.length
            ? services.map((service) => `${service.name} ${stateLabel(service.state)}`).join(" · ")
            : "none configured"}
        </span>
      </div>
    </article>
  );
}

function MetricChart({ title, reports, field, color, suffix, max }) {
  const values = reports.map((report) => report.checks?.internet?.[field] ?? null);
  const chartData = {
    labels: reports.map((report) => formatTime(report.captured_at)),
    datasets: [{
      label: title,
      data: values,
      borderColor: color,
      backgroundColor: color,
      pointRadius: 2,
      borderWidth: 2,
      spanGaps: false
    }]
  };
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      y: {
        beginAtZero: true,
        ...(max ? { max } : {}),
        ticks: { callback: (value) => `${value}${suffix}` }
      },
      x: { ticks: { maxTicksLimit: 6 } }
    }
  };
  return (
    <article className="chart-card">
      <p>{title}</p>
      <strong>{values.length && values.at(-1) != null ? `${values.at(-1)}${suffix}` : "—"}</strong>
      <div className="chart-area"><Line data={chartData} options={options} /></div>
    </article>
  );
}

function ThroughputChart({ samples }) {
  const ordered = [...samples].sort((left, right) => left.captured_at - right.captured_at);
  const values = ordered.map((sample) => sample.throughput_bps ?? null);
  const chartData = {
    labels: ordered.map((sample) => formatTime(sample.captured_at)),
    datasets: [{
      label: "Inbound throughput",
      data: values,
      borderColor: "#5473b8",
      backgroundColor: "#5473b8",
      pointRadius: 2,
      borderWidth: 2,
      spanGaps: false
    }]
  };
  return (
    <article className="chart-card">
      <p>SNMP inbound throughput</p>
      <strong>{values.length && values.at(-1) != null ? `${values.at(-1)} bps` : "N/A"}</strong>
      <div className="chart-area">
        <Line
          data={chartData}
          options={{
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true }, x: { ticks: { maxTicksLimit: 6 } } }
          }}
        />
      </div>
    </article>
  );
}

function Traceroute({ trace }) {
  if (!trace) return <p className="muted">A traceroute is captured after repeated reachability failures.</p>;
  if (typeof trace === "string") return <pre>{trace}</pre>;
  return (
    <div>
      <p className="muted">
        Target {trace.target || "unknown"} · {trace.reached_destination ? "destination reached" : "destination not reached"}
      </p>
      {trace.error && <p className="error-text">{trace.error}</p>}
      <ol className="hop-list">
        {(trace.hops || []).map((hop) => (
          <li key={hop.ttl}>
            <span>Hop {hop.ttl}</span>
            <strong>{hop.address || "No response"}</strong>
            <small>{hop.rtt_ms == null ? "—" : `${hop.rtt_ms} ms`}</small>
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function App() {
  const [networkId, setNetworkId] = useState("");
  const [agentId, setAgentId] = useState("");
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);

  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const query = networkId ? `?network_id=${encodeURIComponent(networkId)}` : "";
        const response = await fetch(`/api/status${query}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`Backend returned HTTP ${response.status}`);
        const payload = await response.json();
        if (!active) return;
        setData(payload);
        setError("");
        setUpdatedAt(payload.server_time);
        if (!networkId && payload.network_id) setNetworkId(payload.network_id);
      } catch (requestError) {
        if (active) setError(`Backend unavailable: ${requestError.message}`);
      }
    }
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [networkId]);

  useEffect(() => {
    const ids = (data?.agents || []).map((report) => report.agent_id);
    if (!ids.includes(agentId)) setAgentId(ids[0] || "");
  }, [data, agentId]);

  useEffect(() => {
    if (!agentId) {
      setHistory([]);
      return undefined;
    }
    let active = true;
    async function loadHistory() {
      try {
        const params = new URLSearchParams();
        if (networkId) params.set("network_id", networkId);
        const response = await fetch(`/api/history/${encodeURIComponent(agentId)}?${params}`);
        if (!response.ok) throw new Error(`History returned HTTP ${response.status}`);
        const reports = await response.json();
        if (active) setHistory(reports);
      } catch (requestError) {
        if (active) setError(requestError.message);
      }
    }
    loadHistory();
    return () => { active = false; };
  }, [agentId, networkId, updatedAt]);

  const latest = useMemo(() => history.at(-1) || null, [history]);
  const diagnosis = data?.diagnosis;
  const snmp = data?.snmp?.[0];
  const snmpHistory = (data?.snmp || []).filter(
    (sample) => !snmp || sample.device_id === snmp.device_id
  );
  const networks = data?.networks || [];

  return (
    <>
      <header className="topbar">
        <a className="brand" href="/"> <span className="brand-mark">∿</span> NetPulse</a>
        <p>{error || (updatedAt ? `Dashboard updated ${formatTime(updatedAt)}` : "Connecting…")}</p>
      </header>
      <main>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">NETWORK MONITORING · EVIDENCE-BASED DIAGNOSIS</p>
            <h1>Know where the connection fails.</h1>
            <p className="intro">Compare measurements from multiple devices to narrow down the likely fault—and see the evidence behind it.</p>
          </div>
          <div className={`diagnosis-card diagnosis-${diagnosis?.code || "pending"}`}>
            <p className="eyebrow">CURRENT ASSESSMENT</p>
            <h2>{diagnosis?.title || "Waiting for agent reports"}</h2>
            <div className="confidence">
              <strong>{diagnosis?.confidence ?? 0}%</strong>
              <span>evidence confidence · {diagnosis?.affected_agents?.length || 0} affected</span>
            </div>
            <p className="evidence">{diagnosis?.evidence || "Start an agent to send the first network probe."}</p>
            {diagnosis?.candidate_causes?.length > 0 && (
              <p className="candidates"><strong>Possible causes:</strong> {diagnosis.candidate_causes.join(" · ")}</p>
            )}
            <p className="next-step"><strong>Suggested next step:</strong> {diagnosis?.next_step || "Start an agent and wait for probe results."}</p>
            <small className="caveat">Diagnosis is an evidence-based estimate; probe results cannot always identify the exact failed component.</small>
          </div>
        </section>

        <section>
          <div className="section-heading">
            <div>
              <h2>Monitored computers</h2>
              <p>Each agent measures connectivity from its own vantage point.</p>
            </div>
            <label className="network-picker">
              Network
              <select value={networkId} onChange={(event) => setNetworkId(event.target.value)}>
                {!networkId && <option value="">Select a network</option>}
                {networks.map((network) => <option value={network} key={network}>{network}</option>)}
                {networkId && !networks.includes(networkId) && <option value={networkId}>{networkId}</option>}
              </select>
            </label>
          </div>
          <div className="agent-grid">
            {data?.agents?.length
              ? data.agents.map((report) => (
                <AgentCard
                  key={report.agent_id}
                  report={report}
                  serverTime={data.server_time}
                  staleAfter={data.settings.stale_after}
                />
              ))
              : <p className="empty-state">No reports yet. Start an agent to begin monitoring.</p>}
          </div>
        </section>

        <section>
          <div className="section-heading">
            <div>
              <h2>Connection history</h2>
              <p>Recent latency and packet-loss measurements.</p>
            </div>
            <label className="network-picker">
              Agent
              <select value={agentId} disabled={!agentId} onChange={(event) => setAgentId(event.target.value)}>
                {(data?.agents || []).map((report) => (
                  <option value={report.agent_id} key={report.agent_id}>{report.agent_id}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="chart-grid">
            <MetricChart title="Average upstream latency" reports={history} field="rtt" color="#117354" suffix=" ms" />
            <MetricChart title="Packet loss" reports={history} field="loss" color="#bd473e" suffix="%" max={100} />
            <ThroughputChart samples={snmpHistory} />
          </div>
        </section>

        <section>
          <div className="section-heading">
            <div><h2>Incident timeline</h2><p>Open and recovered network events.</p></div>
          </div>
          <div className="timeline">
            {(data?.incidents || []).length
              ? data.incidents.map((incident, index) => (
                <article className="incident" key={`${incident.code}-${incident.started_at}-${index}`}>
                  <span className={`incident-dot ${incident.resolved_at ? "resolved" : ""}`} />
                  <div>
                    <strong>{incident.title}</strong>
                    <p>{incident.affected_agents.join(", ")} · started {formatTime(incident.started_at)} · {incident.resolved_at ? `recovered ${formatTime(incident.resolved_at)}` : "active"}</p>
                  </div>
                </article>
              ))
              : <p className="empty-state">No incidents recorded.</p>}
          </div>
        </section>

        <section className="detail-grid">
          <article className="detail-card">
            <h2>Latest traceroute</h2>
            <Traceroute trace={latest?.traceroute} />
          </article>
          <article className="detail-card">
            <h2>Router or switch SNMP</h2>
            {snmp ? (
              <div className="snmp-summary">
                <strong>{snmp.device_id}</strong>
                <p>Inbound throughput: {snmp.throughput_bps == null ? "N/A" : `${snmp.throughput_bps} bps`}</p>
                <p>Interface errors: in {snmp.counters?.in_errors ?? "N/A"} · out {snmp.counters?.out_errors ?? "N/A"}</p>
                <p>Discards: in {snmp.counters?.in_discards ?? "N/A"} · out {snmp.counters?.out_discards ?? "N/A"}</p>
                <small>Polled {formatTime(snmp.captured_at)} · these counters are also used as corroborating diagnosis evidence.</small>
              </div>
            ) : <p className="muted">No SNMP sample. Configure the optional SNMP poller for a supported device.</p>}
          </article>
        </section>
      </main>
      <footer>NetPulse reports likely causes from network evidence; it does not guarantee identification of a specific failed device.</footer>
    </>
  );
}
