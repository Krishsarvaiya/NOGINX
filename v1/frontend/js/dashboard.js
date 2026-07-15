renderAppShell("dashboard", "Security Overview", "Real-time snapshot of threats, scans, and ML detections");

pageMount(`
  <div id="dashboardAlert" class="alert"></div>
  <section class="stats-grid">
    <article class="card"><div class="stat-label">Total Scans</div><div id="statScans" class="stat-value">0</div></article>
    <article class="card"><div class="stat-label">Incidents</div><div id="statIncidents" class="stat-value">0</div></article>
    <article class="card"><div class="stat-label">Critical</div><div id="statCritical" class="stat-value">0</div></article>
    <article class="card"><div class="stat-label">Watcher Alerts</div><div id="statWatcher" class="stat-value">0</div></article>
  </section>
  <section class="grid-2">
    <article class="card highlight-card">
      <h3>Highest Confidence Threat</h3>
      <div id="bestThreatCard"></div>
    </article>
    <article class="card">
      <h3>Quick Actions</h3>
      <div style="display:grid;gap:0.65rem;">
        <a class="btn btn-primary" href="/ui/scan.html">Upload & Scan Log File</a>
        <a class="btn btn-secondary" href="/ui/incidents.html">View All Incidents</a>
        <a class="btn btn-secondary" href="/ui/live.html">Live Monitor Setup</a>
      </div>
    </article>
  </section>
  <section class="grid-2">
    <article class="card"><h3>Severity Breakdown</h3><div id="severityChart" class="chart-bars"></div></article>
    <article class="card"><h3>Threat Types</h3><div id="threatChart" class="chart-bars"></div></article>
  </section>
`);

function renderBars(containerId, data) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const entries = Object.entries(data || {});
  if (!entries.length) {
    container.innerHTML = '<div class="empty-state">No data yet.</div>';
    return;
  }
  const max = Math.max(...entries.map(([, value]) => value), 1);
  container.innerHTML = entries
    .map(
      ([label, value]) => `
      <div class="bar-row">
        <span>${label}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(value / max) * 100}%"></div></div>
        <strong>${value}</strong>
      </div>`
    )
    .join("");
}

function renderBestThreat(best) {
  const card = document.getElementById("bestThreatCard");
  if (!best) {
    card.innerHTML = '<div class="empty-state">No threats recorded yet. Run a scan or start the watcher.</div>';
    return;
  }
  card.innerHTML = `
    <div style="display:grid;gap:0.55rem;">
      <div>${severityBadge(best.severity)} <strong>${best.threat_type}</strong></div>
      <div>Confidence: <strong>${formatPercent(best.confidence)}</strong></div>
      <div class="mono">IP: ${best.ip || "-"} · Path: ${best.path || "-"}</div>
      <div class="muted">${formatDate(best.created_at)}</div>
    </div>`;
}

async function loadDashboard() {
  try {
    const [stats, profile] = await Promise.all([
      apiRequest("/api/dashboard/stats"),
      apiRequest("/api/profile"),
    ]);
    document.getElementById("statScans").textContent = stats.total_scans;
    document.getElementById("statIncidents").textContent = stats.total_incidents;
    document.getElementById("statCritical").textContent = stats.severity_breakdown?.critical || 0;
    document.getElementById("statWatcher").textContent = profile.stats?.watcher_alerts || 0;
    renderBars("severityChart", stats.severity_breakdown);
    renderBars("threatChart", stats.threat_type_breakdown);
    renderBestThreat(stats.highest_confidence_threat);
  } catch (error) {
    showAlert("dashboardAlert", error.message);
  }
}

loadDashboard();
