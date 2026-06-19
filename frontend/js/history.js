renderAppShell("history", "Scan History", "All uploaded log scans stored in your account");

pageMount(`
  <div id="historyAlert" class="alert"></div>
  <section class="card">
    <h3>Past Scans</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>File</th>
            <th>Lines</th>
            <th>Threats</th>
            <th>Top Prediction</th>
            <th>Confidence</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody id="historyBody"></tbody>
      </table>
    </div>
  </section>
  <section class="card" id="scanDetailPanel" style="display:none;">
    <h3>Scan Detail</h3>
    <div id="scanDetail"></div>
  </section>
`);

async function loadHistory() {
  try {
    const scans = await apiRequest("/api/dashboard/scans?limit=100");
    const tbody = document.getElementById("historyBody");
    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No scans yet. <a href="/ui/scan.html">Upload a log file</a></td></tr>';
      return;
    }
    tbody.innerHTML = scans
      .map(
        (scan) => `
        <tr style="cursor:pointer" data-scan-id="${scan.id}">
          <td>#${scan.id}</td>
          <td>${scan.filename}</td>
          <td>${scan.total_lines}</td>
          <td>${scan.threats_found}</td>
          <td>${scan.best_threat || "-"}</td>
          <td>${formatPercent(scan.best_confidence || 0)}</td>
          <td>${formatDate(scan.created_at)}</td>
        </tr>`
      )
      .join("");

    tbody.querySelectorAll("tr[data-scan-id]").forEach((row) => {
      row.addEventListener("click", () => loadScanDetail(row.dataset.scanId));
    });
  } catch (error) {
    showAlert("historyAlert", error.message);
  }
}

async function loadScanDetail(scanId) {
  try {
    const data = await apiRequest(`/api/dashboard/scans/${scanId}`);
    document.getElementById("scanDetailPanel").style.display = "block";
    const scan = data.scan;
    document.getElementById("scanDetail").innerHTML = `
      <div class="info-list">
        <div class="info-row"><span>File</span><strong>${scan.filename}</strong></div>
        <div class="info-row"><span>Lines parsed</span><strong>${scan.total_lines}</strong></div>
        <div class="info-row"><span>Threats found</span><strong>${scan.threats_found}</strong></div>
        <div class="info-row"><span>Best threat</span><strong>${scan.best_threat || "-"}</strong></div>
        <div class="info-row"><span>Confidence</span><strong>${formatPercent(scan.best_confidence || 0)}</strong></div>
        <div class="info-row"><span>Scanned at</span><strong>${formatDate(scan.created_at)}</strong></div>
      </div>
      <h4 style="margin:1rem 0 0.5rem;">Related incidents</h4>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Threat</th><th>Severity</th><th>Confidence</th><th>IP</th><th>Path</th></tr></thead>
          <tbody>
            ${(data.incidents || [])
              .map(
                (item) => `
                <tr>
                  <td>${item.threat_type}</td>
                  <td>${severityBadge(item.severity)}</td>
                  <td>${formatPercent(item.confidence)}</td>
                  <td class="mono">${item.ip}</td>
                  <td class="mono">${item.path || "-"}</td>
                </tr>`
              )
              .join("") || '<tr><td colspan="5" class="empty-state">No related incidents</td></tr>'}
          </tbody>
        </table>
      </div>`;
  } catch (error) {
    showAlert("historyAlert", error.message);
  }
}

loadHistory();
