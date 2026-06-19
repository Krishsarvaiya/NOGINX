const API_BASE = window.location.origin;

function getToken() {
  return localStorage.getItem("noginx_token");
}

function setToken(token) {
  localStorage.setItem("noginx_token", token);
}

function clearAuth() {
  localStorage.removeItem("noginx_token");
  localStorage.removeItem("noginx_username");
}

function requireAuth() {
  if (!getToken()) {
    window.location.href = "/ui/login.html";
  }
}

async function apiRequest(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg || item).join(", ")
      : detail || data.message || "Request failed";
    throw new Error(message);
  }
  return data;
}

function showAlert(elementId, message, type = "error") {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `alert alert-${type} show`;
}

function hideAlert(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = "alert";
  el.textContent = "";
}

function severityBadge(severity) {
  const safe = (severity || "low").toLowerCase();
  return `<span class="badge badge-${safe}">${safe}</span>`;
}

function formatPercent(value) {
  return `${(Number(value || 0) * 100).toFixed(1)}%`;
}

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}
