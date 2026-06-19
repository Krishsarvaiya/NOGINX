renderAppShell("live", "Live Monitor", "Real-time NGINX log watcher configuration and recent alerts");

pageMount(`
  <section class="grid-2">
    <article class="card">
      <h3>How Live Monitoring Works</h3>
      <p class="muted" style="margin-bottom:0.75rem;">
        The watcher tails your NGINX <code>access.log</code> and analyzes every new request.
        <strong>Only traffic that passes through your NGINX server is logged.</strong>
        Browsing insecure HTTP sites in Chrome/Firefox directly will NOT appear unless NGINX proxies that traffic.
      </p>
      <ul class="feature-list">
        <li>Insecure HTTP requests & referers</li>
        <li>Brute force / rate abuse (10+ req/10s)</li>
        <li>ML anomalies + cybersecurity rules</li>
        <li>Desktop notifications (enabled by default)</li>
        <li>Auto-report to dashboard via service token</li>
      </ul>
    </article>
    <article class="card highlight-card">
      <h3>Start the Watcher</h3>
      <pre class="mono" style="background:var(--bg-elevated);padding:1rem;border-radius:10px;overflow:auto;font-size:0.8rem;">cd watcher
python watcher.py</pre>
      <p class="muted" style="margin-top:0.75rem;">Required .env settings:</p>
      <pre class="mono" style="background:var(--bg-elevated);padding:1rem;border-radius:10px;overflow:auto;font-size:0.8rem;">NGINX_ACCESS_LOG=C:\\nginx-1.29.8\\logs\\access.log
NOGINX_SERVICE_TOKEN=your-secret-token
NOGINX_SERVICE_USER=watcher
WATCHER_ALERT_THRESHOLD=0.45
ENABLE_DESKTOP_ALERTS=true
ENABLE_EMAIL_ALERTS=false</pre>
    </article>
  </section>
  <section class="card">
    <h3>Recent Watcher Alerts</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Severity</th><th>Threat</th><th>Confidence</th><th>IP</th><th>Path</th><th>Message</th><th>Time</th></tr>
        </thead>
        <tbody id="liveBody"></tbody>
      </table>
    </div>
  </section>
`);

async function loadLiveIncidents() {
  try {
    const incidents = await apiRequest("/api/dashboard/incidents?limit=100");
    const watcherOnly = incidents.filter((row) => row.source === "watcher");
    const tbody = document.getElementById("liveBody");
    if (!watcherOnly.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No watcher alerts yet. Start watcher.py and generate traffic through NGINX.</td></tr>';
      return;
    }
    tbody.innerHTML = watcherOnly
      .map(
        (row) => `
        <tr>
          <td>${severityBadge(row.severity)}</td>
          <td>${row.threat_type}</td>
          <td>${formatPercent(row.confidence)}</td>
          <td class="mono">${row.ip}</td>
          <td class="mono">${row.path || "-"}</td>
          <td>${row.message || "-"}</td>
          <td>${formatDate(row.created_at)}</td>
        </tr>`
      )
      .join("");
  } catch (error) {
    /* ignore */
  }
}

loadLiveIncidents();
setInterval(loadLiveIncidents, 10000);
