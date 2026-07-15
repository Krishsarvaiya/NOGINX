const NAV_ITEMS = [
  { href: "/ui/dashboard.html", label: "Overview", page: "dashboard" },
  { href: "/ui/scan.html", label: "Log Scanner", page: "scan" },
  { href: "/ui/history.html", label: "Scan History", page: "history" },
  { href: "/ui/incidents.html", label: "Incidents", page: "incidents" },
  { href: "/ui/live.html", label: "Live Monitor", page: "live" },
];

function renderAppShell(activePage, pageTitle, pageSubtitle) {
  requireAuth();
  const username = localStorage.getItem("noginx_username") || "User";
  const initial = username.charAt(0).toUpperCase();

  const mount = document.getElementById("app-shell");
  if (!mount) return;

  mount.innerHTML = `
    <aside class="app-sidebar">
      <div class="logo"><span class="logo-icon">🛡</span> NOGINX</div>
      <nav>
        ${NAV_ITEMS.map(
          (item) =>
            `<a class="nav-link ${item.page === activePage ? "active" : ""}" href="${item.href}">${item.label}</a>`
        ).join("")}
      </nav>
    </aside>
    <div class="app-main">
      <div class="app-topbar">
        <div>
          <h1>${pageTitle}</h1>
          ${pageSubtitle ? `<p class="muted">${pageSubtitle}</p>` : ""}
        </div>
        <div style="display:flex;align-items:center;gap:0.75rem;">
          <div class="status-pill"><span class="status-dot"></span> ML Engine Online</div>
          <div class="profile-menu">
            <button class="profile-btn" id="profileBtn" type="button">
              <span class="avatar">${initial}</span>
              <span>${username}</span>
            </button>
            <div class="profile-dropdown" id="profileDropdown">
              <a href="/ui/profile.html">My Profile</a>
              <a href="/docs" target="_blank">API Docs</a>
              <button type="button" id="logoutBtn">Sign Out</button>
            </div>
          </div>
        </div>
      </div>
      <div id="page-content"></div>
    </div>`;

  document.getElementById("profileBtn")?.addEventListener("click", () => {
    document.getElementById("profileDropdown")?.classList.toggle("show");
  });

  document.getElementById("logoutBtn")?.addEventListener("click", () => {
    clearAuth();
    window.location.href = "/ui/login.html";
  });

  document.addEventListener("click", (event) => {
    const menu = document.querySelector(".profile-menu");
    if (menu && !menu.contains(event.target)) {
      document.getElementById("profileDropdown")?.classList.remove("show");
    }
  });
}

function pageMount(html) {
  const content = document.getElementById("page-content");
  if (content) content.innerHTML = html;
}
