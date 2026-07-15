document.getElementById("loginForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAlert("alert");

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  try {
    const data = await apiRequest("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    setToken(data.access_token);
    localStorage.setItem("noginx_username", data.username);
    window.location.href = "/ui/dashboard.html";
  } catch (error) {
    showAlert("alert", error.message);
  }
});

document.getElementById("signupForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAlert("alert");

  const username = document.getElementById("username").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  try {
    const data = await apiRequest("/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password }),
    });
    setToken(data.access_token);
    localStorage.setItem("noginx_username", data.username);
    window.location.href = "/ui/dashboard.html";
  } catch (error) {
    showAlert("alert", error.message);
  }
});
