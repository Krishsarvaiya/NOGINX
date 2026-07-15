renderAppShell("scan", "Log Scanner", "Upload any NGINX access log for AI + rule-based threat analysis");

pageMount(`
  <div id="scanAlert" class="alert"></div>
  <section class="grid-2">
    <article class="card">
      <h3>Upload Log File</h3>
      <form id="uploadForm" class="upload-zone">
        <p class="muted">Supports .log, .txt files. Detects HTTP insecurity, SQLi, XSS, scanners, ML anomalies, and more.</p>
        <input id="logFile" type="file" accept=".log,.txt,.csv" required />
        <button id="scanBtn" class="btn btn-primary" type="submit">Run AI Threat Scan</button>
      </form>
    </article>
    <article class="card">
      <h3>What we detect</h3>
      <ul class="feature-list">
        <li>Insecure HTTP requests & referers</li>
        <li>Login pages over unencrypted HTTP</li>
        <li>Credentials in URL parameters</li>
        <li>SQL injection, XSS, path traversal</li>
        <li>Scanner probes & unknown endpoints</li>
        <li>Isolation Forest traffic anomalies</li>
      </ul>
    </article>
  </section>
  <section class="card">
    <h3>Scan Results</h3>
    <div id="scanSummary" class="scan-result"><div class="empty-state">Results will appear here after scanning.</div></div>
    <div id="topThreats" style="margin-top:1rem;"></div>
  </section>
`);

function renderThreatCard(item, rank) {
  return `
    <div class="threat-card">
      <div style="display:flex;justify-content:space-between;gap:1rem;align-items:start;">
        <div>
          <strong>#${rank} ${item.threat_type}</strong>
          <div style="margin-top:0.35rem;">${severityBadge(item.severity)} ${formatPercent(item.confidence)}</div>
        </div>
        <span class="mono">${item.ip}</span>
      </div>
      <p class="muted" style="margin-top:0.65rem;">${item.message || "No details"}</p>
      <div class="mono" style="margin-top:0.45rem;">${item.method} ${item.path} → ${item.status}</div>
    </div>`;
}

document.getElementById("uploadForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = document.getElementById("logFile").files?.[0];
  if (!file) return;

  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning...";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${window.location.origin}/api/analyze-log?top_n=15`, {
      method: "POST",
      headers: { Authorization: `Bearer ${getToken()}` },
      body: formData,
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan failed");

    const best = data.best_prediction;
    document.getElementById("scanSummary").innerHTML = `
      <div class="highlight-card card">
        <h3>${file.name}</h3>
        <p>Parsed <strong>${data.total_lines_parsed}</strong> lines ·
           <strong>${data.total_threats}</strong> threats ·
           Anomaly rate <strong>${formatPercent(data.anomaly_rate)}</strong></p>
        ${best ? `<p>Top prediction: <strong>${best.threat_type}</strong> at <strong>${formatPercent(best.confidence)}</strong></p><p class="muted">${best.message || ""}</p>` : ""}
        <p style="margin-top:0.5rem;"><a href="/ui/history.html">View in scan history →</a></p>
      </div>`;

    const threats = data.top_predictions || [];
    document.getElementById("topThreats").innerHTML = threats.length
      ? `<h3 style="margin-bottom:0.75rem;">Top ${threats.length} Predictions</h3>${threats.map((item, i) => renderThreatCard(item, i + 1)).join("")}`
      : '<div class="empty-state">No threats above threshold in this file.</div>';

    showAlert("scanAlert", "Scan completed and saved to history.", "success");
  } catch (error) {
    showAlert("scanAlert", error.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run AI Threat Scan";
  }
});
