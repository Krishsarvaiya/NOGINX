renderAppShell("live", "Live Monitor", "Traffic stream, anomaly triage, and watcher telemetry");

let liveAfterId = 0;
let liveEvents = [];
let selectedEventId = null;
let pollDelay = 1200;

pageMount(`
  <div id="liveAlert" class="alert"></div>
  <section class="live-hero">
    <div class="live-radar" aria-hidden="true">
      <span></span><span></span><span></span>
      <div class="radar-core"></div>
    </div>
    <div class="live-metrics">
      <article class="metric-tile">
        <span>Stream</span>
        <strong id="metricStream">ONLINE</strong>
      </article>
      <article class="metric-tile">
        <span>Requests</span>
        <strong id="metricRequests">0</strong>
      </article>
      <article class="metric-tile">
        <span>Threats</span>
        <strong id="metricThreats">0</strong>
      </article>
      <article class="metric-tile">
        <span>Critical</span>
        <strong id="metricCritical">0</strong>
      </article>
    </div>
  </section>

  <section class="live-grid">
    <article class="signal-panel">
      <div class="panel-head">
        <div>
          <h3>Traffic Feed</h3>
          <p class="muted" id="lastSeen">Waiting for watcher telemetry</p>
        </div>
        <span class="live-chip"><span class="status-dot"></span> LIVE</span>
      </div>
      <div id="trafficFeed" class="traffic-feed"></div>
    </article>

    <article class="signal-panel detail-panel">
      <div class="panel-head">
        <div>
          <h3>Anomaly Intel</h3>
          <p class="muted">Cause, impact, and response guidance</p>
        </div>
      </div>
      <div id="intelPanel" class="intel-empty">
        <div class="intel-icon">N</div>
        <strong>No selected event</strong>
        <span>Select a live request or wait for the next anomaly.</span>
      </div>
    </article>
  </section>

  <section class="coverage-strip">
    <div>
      <strong>Visibility boundary</strong>
      <span>Direct browser HTTPS traffic appears here only when it is routed through NGINX, a local proxy, or another log-producing capture agent.</span>
    </div>
    <div>
      <strong>Current source</strong>
      <span>Watcher telemetry from <code>NGINX_ACCESS_LOG</code></span>
    </div>
  </section>
`);

function eventTone(event) {
  if (event.threat_type === "Benign") return "benign";
  return (event.severity || "medium").toLowerCase();
}

function eventIcon(event) {
  if (event.threat_type === "Benign") return "OK";
  if ((event.severity || "").toLowerCase() === "critical") return "!!";
  if ((event.severity || "").toLowerCase() === "high") return "HI";
  return "AN";
}

function shortPath(event) {
  const value = event.path || event.url || "/";
  return value.length > 72 ? `${value.slice(0, 69)}...` : value;
}

function renderMetrics() {
  const threats = liveEvents.filter((event) => event.threat_type !== "Benign");
  document.getElementById("metricRequests").textContent = liveEvents.length;
  document.getElementById("metricThreats").textContent = threats.length;
  document.getElementById("metricCritical").textContent = threats.filter((event) => event.severity === "critical").length;
  document.getElementById("metricStream").textContent = "ONLINE";
}

function renderFeed() {
  const feed = document.getElementById("trafficFeed");
  if (!feed) return;
  if (!liveEvents.length) {
    feed.innerHTML = `<div class="empty-state">Start the watcher and generate traffic through the monitored log source.</div>`;
    return;
  }

  feed.innerHTML = liveEvents
    .slice(0, 80)
    .map((event) => {
      const active = selectedEventId === event.id ? "active" : "";
      return `
        <button class="traffic-row ${eventTone(event)} ${active}" data-event-id="${event.id}" type="button">
          <span class="event-glyph">${eventIcon(event)}</span>
          <span class="event-main">
            <span class="event-title">
              <strong>${event.threat_type}</strong>
              <em>${event.method || "-"} ${shortPath(event)}</em>
            </span>
            <span class="event-meta">
              <span>${event.ip || "0.0.0.0"}</span>
              <span>HTTP ${event.status || "-"}</span>
              <span>${formatDate(event.received_at)}</span>
            </span>
          </span>
          <span class="event-score">${formatPercent(event.confidence)}</span>
        </button>`;
    })
    .join("");

  feed.querySelectorAll(".traffic-row").forEach((row) => {
    row.addEventListener("click", () => {
      selectedEventId = Number(row.dataset.eventId);
      renderFeed();
      renderIntel();
    });
  });
}

function renderIntel() {
  const panel = document.getElementById("intelPanel");
  if (!panel) return;

  const selected =
    liveEvents.find((event) => event.id === selectedEventId) ||
    liveEvents.find((event) => event.threat_type !== "Benign") ||
    liveEvents[0];

  if (!selected) {
    panel.className = "intel-empty";
    panel.innerHTML = `
      <div class="intel-icon">N</div>
      <strong>No selected event</strong>
      <span>Select a live request or wait for the next anomaly.</span>`;
    return;
  }

  selectedEventId = selected.id;
  const explanation = selected.explanation || {};
  panel.className = `intel-card ${eventTone(selected)}`;
  panel.innerHTML = `
    <div class="intel-topline">
      ${severityBadge(selected.severity)}
      <span>${selected.threat_type}</span>
    </div>
    <h2>${explanation.summary || selected.message || "Security signal detected"}</h2>
    <div class="intel-kv">
      <span>Source</span><strong>${selected.ip || "-"}</strong>
      <span>Request</span><strong>${selected.method || "-"} ${shortPath(selected)}</strong>
      <span>Status</span><strong>HTTP ${selected.status || "-"}</strong>
      <span>Confidence</span><strong>${formatPercent(selected.confidence)}</strong>
    </div>
    <div class="intel-block">
      <span>Likely Cause</span>
      <p>${explanation.cause || selected.message || "The request matched a suspicious behavior profile."}</p>
    </div>
    <div class="intel-block">
      <span>Next Action</span>
      <p>${explanation.action || "Inspect the source IP and surrounding requests."}</p>
    </div>
    <pre class="raw-line">${selected.user_agent || "No user agent"}</pre>`;
}

async function pullLiveEvents() {
  try {
    const data = await apiRequest(`/api/live/events?after=${liveAfterId}&limit=100`);
    if (data.events?.length) {
      liveAfterId = data.latest_id || data.events[data.events.length - 1].id;
      liveEvents = [...data.events.reverse(), ...liveEvents]
        .filter((event, index, all) => all.findIndex((item) => item.id === event.id) === index)
        .sort((a, b) => b.id - a.id)
        .slice(0, 150);

      document.getElementById("lastSeen").textContent = `Last event ${formatDate(liveEvents[0].received_at)}`;
      selectedEventId = selectedEventId || liveEvents.find((event) => event.threat_type !== "Benign")?.id || liveEvents[0].id;
      renderMetrics();
      renderFeed();
      renderIntel();
    }
    hideAlert("liveAlert");
    pollDelay = 1200;
  } catch (error) {
    document.getElementById("metricStream").textContent = "OFFLINE";
    showAlert("liveAlert", error.message);
    pollDelay = 3000;
  } finally {
    setTimeout(pullLiveEvents, pollDelay);
  }
}

renderMetrics();
renderFeed();
renderIntel();
pullLiveEvents();
