renderAppShell("profile", "My Profile", "Account details and activity summary");

pageMount(`
  <div id="profileAlert" class="alert"></div>
  <section class="grid-2">
    <article class="card">
      <h3>Account Information</h3>
      <div id="profileInfo" class="info-list"></div>
    </article>
    <article class="card">
      <h3>Activity Summary</h3>
      <div id="profileStats" class="stats-grid" style="grid-template-columns:1fr 1fr;"></div>
    </article>
  </section>
  <section class="card">
    <h3>Security Tips</h3>
    <ul class="feature-list">
      <li>Rotate NOGINX_SERVICE_TOKEN if shared with watcher</li>
      <li>Retrain model on your own logs: python parse_logs.py && python train_model.py</li>
      <li>Set WATCHER_ALERT_THRESHOLD lower (e.g. 0.40) for more sensitive detection</li>
      <li>Route browser traffic through NGINX proxy to monitor HTTP site visits</li>
    </ul>
  </section>
`);

async function loadProfile() {
  try {
    const profile = await apiRequest("/api/profile");
    document.getElementById("profileInfo").innerHTML = `
      <div class="info-row"><span>Username</span><strong>${profile.username}</strong></div>
      <div class="info-row"><span>Email</span><strong>${profile.email}</strong></div>
      <div class="info-row"><span>Member since</span><strong>${formatDate(profile.created_at)}</strong></div>
      <div class="info-row"><span>User ID</span><strong>#${profile.id}</strong></div>`;

    const stats = profile.stats || {};
    document.getElementById("profileStats").innerHTML = `
      <article class="card"><div class="stat-label">Total Incidents</div><div class="stat-value">${stats.total_incidents || 0}</div></article>
      <article class="card"><div class="stat-label">Log Scans</div><div class="stat-value">${stats.total_scans || 0}</div></article>
      <article class="card"><div class="stat-label">Watcher Alerts</div><div class="stat-value">${stats.watcher_alerts || 0}</div></article>
      <article class="card"><div class="stat-label">Account Status</div><div class="stat-value" style="font-size:1.2rem;color:var(--success);">Active</div></article>`;
  } catch (error) {
    showAlert("profileAlert", error.message);
  }
}

loadProfile();
