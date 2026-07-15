renderAppShell("incidents", "Security Incidents", "All detected threats from scans and live watcher");

pageMount(`
  <div id="incidentsAlert" class="alert"></div>
  <section class="card">
    <div style="display:flex;gap:0.75rem;margin-bottom:1rem;flex-wrap:wrap;">
      <button class="btn btn-secondary filter-btn active" data-filter="all" type="button">All</button>
      <button class="btn btn-secondary filter-btn" data-filter="watcher" type="button">Live Watcher</button>
      <button class="btn btn-secondary filter-btn" data-filter="scan" type="button">Log Scans</button>
      <button class="btn btn-secondary filter-btn" data-filter="dashboard" type="button">Manual</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Threat</th>
            <th>Confidence</th>
            <th>Source</th>
            <th>IP</th>
            <th>Path</th>
            <th>Details</th>
            <th>Detected</th>
          </tr>
        </thead>
        <tbody id="incidentsBody"></tbody>
      </table>
    </div>
  </section>
`);

let allIncidents = [];
let activeFilter = "all";

function renderIncidents() {
  const rows = activeFilter === "all"
    ? allIncidents
    : allIncidents.filter((row) => (row.source || "dashboard") === activeFilter);
  const tbody = document.getElementById("incidentsBody");
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No incidents for this filter.</td></tr>';
    return;
  }
  tbody.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td>${severityBadge(row.severity)}</td>
        <td>${row.threat_type}</td>
        <td>${formatPercent(row.confidence)}</td>
        <td><span class="badge badge-low">${row.source || "dashboard"}</span></td>
        <td class="mono">${row.ip || "-"}</td>
        <td class="mono">${row.path || "-"}</td>
        <td>${row.message || "-"}</td>
        <td>${formatDate(row.created_at)}</td>
      </tr>`
    )
    .join("");
}

async function loadIncidents() {
  try {
    allIncidents = await apiRequest("/api/dashboard/incidents?limit=200");
    renderIncidents();
  } catch (error) {
    showAlert("incidentsAlert", error.message);
  }
}

document.querySelectorAll(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.filter;
    renderIncidents();
  });
});

loadIncidents();
setInterval(loadIncidents, 15000);
