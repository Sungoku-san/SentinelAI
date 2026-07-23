const API_BASE = "http://localhost:8000/api";

const getHeaders = () => {
  const token = localStorage.getItem("token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
};

export const api = {
  async login(username, password) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Authentication failed");
    }
    const data = await res.json();
    localStorage.setItem("token", data.access_token);
    return data;
  },

  logout() {
    localStorage.removeItem("token");
  },

  isLoggedIn() {
    return !!localStorage.getItem("token");
  },

  async getStats() {
    const res = await fetch(`${API_BASE}/dashboard/stats`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch dashboard metrics");
    return res.json();
  },

  async getStatus() {
    const res = await fetch(`${API_BASE}/dashboard/status`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch service status");
    return res.json();
  },

  async getSessions(limit = 20, offset = 0, protocol = "", level = "") {
    let url = `${API_BASE}/sessions?limit=${limit}&offset=${offset}`;
    if (protocol) url += `&protocol=${protocol}`;
    if (level) url += `&threat_level=${level}`;
    
    const res = await fetch(url, { headers: getHeaders() });
    if (!res.ok) throw new Error("Failed to fetch sessions list");
    return res.json();
  },

  async getSessionDetails(sessionId) {
    const res = await fetch(`${API_BASE}/sessions/${sessionId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch session details");
    return res.json();
  },

  getPdfReportUrl() {
    const token = localStorage.getItem("token");
    return `${API_BASE}/reports/pdf?token=${token}`; // Token can be passed in query or headers, but for direct download in a link we can fetch it, or backend handles auth. Wait, in routers we checked get_current_user from standard oauth2 header, so we will use dynamic fetch blob and URL.createObjectURL to support authentication header download!
  },

  async downloadPdfReport() {
    const res = await fetch(`${API_BASE}/reports/pdf`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to compile PDF report");
    const blob = await res.blob();
    return URL.createObjectURL(blob);
  },

  async downloadCsvReport() {
    const res = await fetch(`${API_BASE}/reports/csv`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to compile CSV report");
    const blob = await res.blob();
    return URL.createObjectURL(blob);
  }
};
