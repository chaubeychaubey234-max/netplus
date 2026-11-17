const element = (id) => document.getElementById(id);
const labels = { gateway: "Gateway", internet: "Internet", system_dns: "System DNS", reference_dns: "Reference DNS" };
let currentAgent = null;

function time(value) { return new Date(value * 1000).toLocaleTimeString(); }
function title(state) { return state === "pass" ? "Passing" : state === "fail" ? "Failing" : "Unknown"; }

function renderAgent(report) {
  const checks = Object.entries(report.checks).map(([key, value]) => `
    <div class="check"><strong>${labels[key]} · ${title(value.state)}</strong><p>${value.detail}</p></div>`).join("");
  const failed = Object.values(report.checks).some((check) => check.state === "fail");
  const inventory = report.inventory || {};
  const services = (report.services || []).map((service) => `${service.name}: ${title(service.state)}`).join(" · ") || "No service checks configured";
  return `<article class="agent ${failed ? "fail" : "pass"}"><header><div><h3>${report.agent_id}</h3><small>${report.network_id} · ${time(report.captured_at)}</small></div><span class="pill">${failed ? "Needs attention" : "Healthy"}</span></header><div class="checks">${checks}</div><div class="inventory"><strong>${inventory.hostname || "Device details unavailable"}</strong><p>${inventory.platform || ""}</p><p>${inventory.wifi?.network || ""}</p><p>Services · ${services}</p></div></article>`;
}

function renderStatus(data) {
  const diagnosis = data.diagnosis;
  element("diagnosis").innerHTML = `<p>Diagnosis</p><h2>${diagnosis.title}</h2><span>${diagnosis.confidence} confidence · ${diagnosis.affected_agents.length} affected</span><p class="evidence">${diagnosis.evidence}</p><p class="next-step"><strong>Suggested action</strong> · ${diagnosis.next_step}</p>`;
  element("agents").innerHTML = data.agents.length ? data.agents.map(renderAgent).join("") : "<p>No reports yet. Start the local agent and refresh this page.</p>";
  element("last-update").textContent = `Dashboard updated ${time(data.server_time)}`;
  const selector = element("agent-selector");
  const ids = data.agents.map((report) => report.agent_id);
  if (!ids.includes(currentAgent)) currentAgent = ids[0] || null;
  selector.innerHTML = ids.map((id) => `<option value="${id}" ${id === currentAgent ? "selected" : ""}>${id}</option>`).join("");
  selector.disabled = !currentAgent;
  const snmp = data.snmp[0];
  element("snmp").textContent = snmp ? `${snmp.device_id} · ${snmp.throughput_bps ?? "N/A"} bps · errors ${snmp.counters.in_errors ?? "N/A"} · discards ${snmp.counters.in_discards ?? "N/A"}` : "No SNMP sample. Configure the optional SNMP poller for supported devices.";
  element("incidents").innerHTML = data.incidents.length ? data.incidents.map((incident) => `<article><strong>${incident.title}</strong><p>${incident.affected_agents.join(", ")} · started ${time(incident.started_at)} · ${incident.resolved_at ? "recovered" : "active"}</p></article>`).join("") : "<p>No incidents recorded.</p>";
  if (currentAgent) loadHistory(currentAgent);
}

function chart(canvasId, values, color, maxValue) {
  const canvas = element(canvasId), rect = canvas.getBoundingClientRect(), dpr = devicePixelRatio || 1;
  canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
  const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
  const width = rect.width, height = rect.height, left = 38, top = 10, bottom = height - 17;
  const valid = values.filter(Number.isFinite); const max = maxValue || Math.max(10, ...valid) * 1.15;
  ctx.strokeStyle = "#e1e9e3"; ctx.fillStyle = "#65776d"; ctx.font = "11px system-ui";
  [0, .5, 1].forEach((ratio) => { const y = bottom - (bottom - top) * ratio; ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width, y); ctx.stroke(); ctx.fillText(`${Math.round(max * ratio)}`, 0, y + 4); });
  let previous = null; ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = 2;
  values.forEach((value, index) => { if (!Number.isFinite(value)) { previous = null; return; } const x = left + (width - left - 4) * index / Math.max(1, values.length - 1); const y = bottom - (bottom - top) * value / max; if (previous) { ctx.beginPath(); ctx.moveTo(...previous); ctx.lineTo(x, y); ctx.stroke(); } ctx.beginPath(); ctx.arc(x, y, 2, 0, Math.PI * 2); ctx.fill(); previous = [x, y]; });
}

async function loadHistory(agentId) {
  const response = await fetch(`/api/history/${encodeURIComponent(agentId)}`);
  if (!response.ok) return;
  const reports = await response.json(); const latest = reports.at(-1);
  element("history-title").textContent = `Connection history · ${agentId}`;
  element("latency").textContent = latest?.checks.internet.rtt == null ? "—" : `${latest.checks.internet.rtt} ms`;
  element("loss").textContent = latest?.checks.internet.loss == null ? "—" : `${latest.checks.internet.loss}%`;
  chart("latency-chart", reports.map((report) => report.checks.internet.rtt), "#147552");
  chart("loss-chart", reports.map((report) => report.checks.internet.loss), "#bd473e", 100);
  element("trace").textContent = latest?.traceroute || "A traceroute is captured after repeated reachability failures.";
}

async function refresh() {
  try { const response = await fetch("/api/status"); if (!response.ok) throw Error(); renderStatus(await response.json()); }
  catch { element("last-update").textContent = "Backend unavailable. Check that NetPulse server is running."; }
}
element("agent-selector").addEventListener("change", (event) => { currentAgent = event.target.value; loadHistory(currentAgent); });
addEventListener("resize", () => currentAgent && loadHistory(currentAgent));
refresh(); setInterval(refresh, 5000);
