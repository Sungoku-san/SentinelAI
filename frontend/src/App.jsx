import React, { useState, useEffect } from "react";
import { api } from "./services/api";
import { 
  ShieldAlert, 
  Terminal, 
  Activity, 
  Settings as SettingsIcon, 
  Download, 
  User, 
  LogOut, 
  Clock, 
  MapPin, 
  FileCode, 
  Key, 
  Lock,
  Cpu,
  RefreshCw,
  Server,
  Globe
} from "lucide-react";

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(api.isLoggedIn());
  const [username, setUsername] = useState("mujeeb");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  
  // Navigation tabs
  const [activeTab, setActiveTab] = useState("dashboard"); // dashboard, sessions, config
  
  // Dashboard states
  const [stats, setStats] = useState({
    total_sessions: 0,
    total_attacks: 0,
    critical_alerts: 0,
    unique_ips: 0,
    protocol_distribution: { SSH: 0, HTTP: 0, FTP: 0, Telnet: 0 },
    threat_level_distribution: { Low: 0, Medium: 0, High: 0, Critical: 0 },
    top_ips: []
  });
  
  const [sysStatus, setSysStatus] = useState({
    ssh_port: 2222,
    http_port: 8080,
    ftp_port: 2121,
    telnet_port: 2323,
    ssh_running: false,
    http_running: false,
    ftp_running: false,
    telnet_running: false,
    packet_stats: { total_packets: 0, tcp_packets: 0, udp_packets: 0 }
  });

  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetailTab, setSessionDetailTab] = useState("details"); // details, terminal, credentials, files
  const [refreshInterval, setRefreshInterval] = useState(5); // in seconds
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // Settings/Configuration
  const [config, setConfig] = useState({
    bruteForceThreshold: 5,
    tarpitLatencyMax: 5.0,
    fsRealismLevel: 2
  });

  // Login handler
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoginError("");
    try {
      await api.login(username, password);
      setIsLoggedIn(true);
      fetchDashboardData();
    } catch (err) {
      setLoginError(err.message || "Invalid credentials");
    }
  };

  // Logout handler
  const handleLogout = () => {
    api.logout();
    setIsLoggedIn(false);
  };

  // Fetch all dashboard stats and system statuses
  const fetchDashboardData = async () => {
    if (!api.isLoggedIn()) return;
    setIsRefreshing(true);
    try {
      const statsData = await api.getStats();
      const statusData = await api.getStatus();
      const recentSessions = await api.getSessions(10, 0);
      
      setStats(statsData);
      setSysStatus(statusData);
      setSessions(recentSessions);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Fetch full sessions list for sessions view
  const fetchSessionsList = async () => {
    try {
      const allSessions = await api.getSessions(50, 0);
      setSessions(allSessions);
    } catch (err) {
      console.error("Sessions fetch error:", err);
    }
  };

  // Fetch single session details
  const viewSessionDetails = async (sessionId) => {
    try {
      const details = await api.getSessionDetails(sessionId);
      setSelectedSession(details);
      setSessionDetailTab("details");
    } catch (err) {
      console.error("Session details fetch error:", err);
    }
  };

  // Dynamic config handler (simulated backend updates)
  const handleSaveConfig = (e) => {
    e.preventDefault();
    alert("Configuration parameters updated in system runtime.");
  };

  // PDF Report downloader
  const downloadPDF = async () => {
    try {
      const url = await api.downloadPdfReport();
      const a = document.createElement("a");
      a.href = url;
      a.download = "SentinelAI_Threat_Report.pdf";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      alert("Error compiling PDF report: " + err.message);
    }
  };

  // CSV Report downloader
  const downloadCSV = async () => {
    try {
      const url = await api.downloadCsvReport();
      const a = document.createElement("a");
      a.href = url;
      a.download = "SentinelAI_Session_Logs.csv";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      alert("Error compiling CSV report: " + err.message);
    }
  };

  // Polling setup
  useEffect(() => {
    if (!isLoggedIn) return;
    
    fetchDashboardData();
    const interval = setInterval(() => {
      fetchDashboardData();
    }, refreshInterval * 1000);
    
    return () => clearInterval(interval);
  }, [isLoggedIn, refreshInterval]);

  // Handle active tab changes
  useEffect(() => {
    if (activeTab === "sessions") {
      fetchSessionsList();
    }
  }, [activeTab]);

  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-cyber-bg text-cyber-text flex items-center justify-center relative overflow-hidden font-sans">
        {/* Subtle grid elements */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1E2D4A_1px,transparent_1px),linear-gradient(to_bottom,#1E2D4A_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-20 pointer-events-none"></div>
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyber-primary opacity-10 rounded-full blur-3xl"></div>
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-cyber-secondary opacity-10 rounded-full blur-3xl"></div>
        
        <div className="w-full max-w-md bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-8 relative z-10 backdrop-blur-md">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center p-3 bg-cyber-primary/10 rounded-full border border-cyber-primary/20 mb-3">
              <ShieldAlert className="w-8 h-8 text-cyber-primary animate-pulse" />
            </div>
            <h1 className="text-2xl font-bold tracking-wider uppercase text-cyber-text">SentinelAI</h1>
            <p className="text-cyber-muted text-sm mt-1">AI-Driven Adaptive Honeypot Administration</p>
          </div>
          
          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-cyber-muted mb-2">Username</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                  <User className="w-4 h-4" />
                </span>
                <input 
                  type="text" 
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full bg-cyber-bg/50 border border-cyber-border rounded-lg pl-10 pr-4 py-3 focus:outline-none focus:border-cyber-primary text-cyber-text placeholder-cyber-muted"
                  placeholder="Enter administrator user"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-cyber-muted mb-2">Password</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                  <Lock className="w-4 h-4" />
                </span>
                <input 
                  type="password" 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-cyber-bg/50 border border-cyber-border rounded-lg pl-10 pr-4 py-3 focus:outline-none focus:border-cyber-primary text-cyber-text placeholder-cyber-muted"
                  placeholder="Enter secure password"
                  required
                />
              </div>
            </div>

            {loginError && (
              <div className="p-3 bg-cyber-accent/10 border border-cyber-accent/20 rounded-lg text-cyber-accent text-sm text-center">
                {loginError}
              </div>
            )}

            <button 
              type="submit" 
              className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary rounded-lg font-semibold tracking-wider text-cyber-bg uppercase hover:brightness-110 transition duration-200"
            >
              Access System
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-text font-sans flex flex-col">
      {/* Dynamic Header */}
      <header className="bg-cyber-card/85 backdrop-blur-md border-b border-cyber-border px-6 py-4 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-3">
          <ShieldAlert className="w-6 h-6 text-cyber-primary" />
          <div>
            <h1 className="text-lg font-bold tracking-widest uppercase text-cyber-text">SentinelAI</h1>
            <p className="text-xs text-cyber-muted">AI Threat Intel Control Panel</p>
          </div>
        </div>

        {/* Emulators Quick State Lights */}
        <div className="hidden lg:flex items-center space-x-6">
          <div className="flex items-center space-x-2 bg-cyber-bg/50 border border-cyber-border rounded-lg px-3 py-1.5 text-xs">
            <Server className="w-3.5 h-3.5 text-cyber-primary" />
            <span className="text-cyber-muted uppercase tracking-wider">SSH:</span>
            <span className={`w-2 h-2 rounded-full ${sysStatus.ssh_running ? 'bg-cyber-success animate-pulse' : 'bg-cyber-muted'}`}></span>
          </div>
          <div className="flex items-center space-x-2 bg-cyber-bg/50 border border-cyber-border rounded-lg px-3 py-1.5 text-xs">
            <Globe className="w-3.5 h-3.5 text-cyber-primary" />
            <span className="text-cyber-muted uppercase tracking-wider">HTTP:</span>
            <span className={`w-2 h-2 rounded-full ${sysStatus.http_running ? 'bg-cyber-success animate-pulse' : 'bg-cyber-muted'}`}></span>
          </div>
          <div className="flex items-center space-x-2 bg-cyber-bg/50 border border-cyber-border rounded-lg px-3 py-1.5 text-xs">
            <FileCode className="w-3.5 h-3.5 text-cyber-primary" />
            <span className="text-cyber-muted uppercase tracking-wider">FTP:</span>
            <span className={`w-2 h-2 rounded-full ${sysStatus.ftp_running ? 'bg-cyber-success animate-pulse' : 'bg-cyber-muted'}`}></span>
          </div>
          <div className="flex items-center space-x-2 bg-cyber-bg/50 border border-cyber-border rounded-lg px-3 py-1.5 text-xs">
            <Terminal className="w-3.5 h-3.5 text-cyber-primary" />
            <span className="text-cyber-muted uppercase tracking-wider">Telnet:</span>
            <span className={`w-2 h-2 rounded-full ${sysStatus.telnet_running ? 'bg-cyber-success animate-pulse' : 'bg-cyber-muted'}`}></span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <button 
            onClick={fetchDashboardData}
            className="p-2 bg-cyber-card border border-cyber-border hover:border-cyber-primary rounded-lg text-cyber-muted hover:text-cyber-primary transition"
            title="Refresh logs"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyber-primary' : ''}`} />
          </button>
          
          <button 
            onClick={handleLogout}
            className="flex items-center space-x-2 bg-cyber-accent/15 border border-cyber-accent/30 text-cyber-accent px-4 py-2 rounded-lg hover:bg-cyber-accent/25 transition text-sm font-medium"
          >
            <LogOut className="w-4 h-4" />
            <span>Lock</span>
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <aside className="w-64 bg-cyber-card border-r border-cyber-border p-6 flex flex-col space-y-2 justify-between">
          <nav className="space-y-2">
            <button 
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium tracking-wider uppercase transition ${activeTab === "dashboard" ? 'bg-cyber-primary/10 border border-cyber-primary/20 text-cyber-primary' : 'text-cyber-muted hover:bg-cyber-bg hover:text-cyber-text'}`}
            >
              <Activity className="w-4 h-4" />
              <span>Metrics Overview</span>
            </button>
            
            <button 
              onClick={() => setActiveTab("sessions")}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium tracking-wider uppercase transition ${activeTab === "sessions" ? 'bg-cyber-primary/10 border border-cyber-primary/20 text-cyber-primary' : 'text-cyber-muted hover:bg-cyber-bg hover:text-cyber-text'}`}
            >
              <Terminal className="w-4 h-4" />
              <span>Attacker Sessions</span>
            </button>
            
            <button 
              onClick={() => setActiveTab("config")}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium tracking-wider uppercase transition ${activeTab === "config" ? 'bg-cyber-primary/10 border border-cyber-primary/20 text-cyber-primary' : 'text-cyber-muted hover:bg-cyber-bg hover:text-cyber-text'}`}
            >
              <SettingsIcon className="w-4 h-4" />
              <span>Adaptation Settings</span>
            </button>
          </nav>

          {/* Quick downloads block */}
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-lg space-y-3">
            <p className="text-xs font-semibold tracking-wider text-cyber-muted uppercase">Threat Reports</p>
            <button 
              onClick={downloadPDF}
              className="w-full flex items-center justify-between px-3 py-2 bg-cyber-card border border-cyber-border hover:border-cyber-primary text-xs rounded hover:text-cyber-primary transition"
            >
              <span>Download PDF</span>
              <Download className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={downloadCSV}
              className="w-full flex items-center justify-between px-3 py-2 bg-cyber-card border border-cyber-border hover:border-cyber-primary text-xs rounded hover:text-cyber-primary transition"
            >
              <span>Export CSV</span>
              <Download className="w-3.5 h-3.5" />
            </button>
          </div>
        </aside>

        {/* View Port */}
        <main className="flex-1 overflow-y-auto p-8 relative">
          
          {/* TAB 1: DASHBOARD METRICS */}
          {activeTab === "dashboard" && (
            <div className="space-y-8 animate-fadeIn">
              
              {/* Overview Metric Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl relative overflow-hidden">
                  <div className="flex justify-between items-center">
                    <p className="text-sm text-cyber-muted uppercase tracking-wider">Total Probe Sessions</p>
                    <Activity className="w-5 h-5 text-cyber-primary" />
                  </div>
                  <h3 className="text-3xl font-extrabold mt-4 tracking-wider">{stats.total_sessions}</h3>
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyber-primary to-transparent"></div>
                </div>

                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl relative overflow-hidden">
                  <div className="flex justify-between items-center">
                    <p className="text-sm text-cyber-muted uppercase tracking-wider">Aggregated Attacks</p>
                    <ShieldAlert className="w-5 h-5 text-cyber-secondary" />
                  </div>
                  <h3 className="text-3xl font-extrabold mt-4 tracking-wider text-cyber-secondary">{stats.total_attacks}</h3>
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyber-secondary to-transparent"></div>
                </div>

                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl relative overflow-hidden">
                  <div className="flex justify-between items-center">
                    <p className="text-sm text-cyber-muted uppercase tracking-wider">Critical Alerts</p>
                    <ShieldAlert className="w-5 h-5 text-cyber-accent" />
                  </div>
                  <h3 className="text-3xl font-extrabold mt-4 tracking-wider text-cyber-accent">{stats.critical_alerts}</h3>
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyber-accent to-transparent"></div>
                </div>

                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl relative overflow-hidden">
                  <div className="flex justify-between items-center">
                    <p className="text-sm text-cyber-muted uppercase tracking-wider">Unique Attacking Hosts</p>
                    <Globe className="w-5 h-5 text-cyber-success" />
                  </div>
                  <h3 className="text-3xl font-extrabold mt-4 tracking-wider text-cyber-success">{stats.unique_ips}</h3>
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyber-success to-transparent"></div>
                </div>
              </div>

              {/* Graphical Analysis grid */}
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
                
                {/* Protocol Target Distribution */}
                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl">
                  <h3 className="text-base font-bold tracking-wider uppercase mb-6 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-cyber-primary" />
                    <span>Protocol Vector Distribution</span>
                  </h3>
                  
                  {/* Clean Visual fallback charts if Recharts isn't built yet */}
                  <div className="space-y-4">
                    {Object.entries(stats.protocol_distribution).map(([protocol, count]) => {
                      const total = Object.values(stats.protocol_distribution).reduce((a,b) => a+b, 0) || 1;
                      const percentage = Math.round((count / total) * 100);
                      
                      return (
                        <div key={protocol}>
                          <div className="flex justify-between text-sm mb-1">
                            <span className="font-medium">{protocol} Simulator</span>
                            <span className="text-cyber-muted">{count} sessions ({percentage}%)</span>
                          </div>
                          <div className="w-full bg-cyber-bg h-2.5 rounded-full overflow-hidden border border-cyber-border">
                            <div 
                              className={`h-full rounded-full ${
                                protocol === "SSH" ? "bg-cyber-primary" : 
                                protocol === "HTTP" ? "bg-cyber-secondary" : 
                                protocol === "FTP" ? "bg-cyber-success" : "bg-cyber-accent"
                              }`}
                              style={{ width: `${percentage}%` }}
                            ></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Threat Levels Severity */}
                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl">
                  <h3 className="text-base font-bold tracking-wider uppercase mb-6 flex items-center space-x-2">
                    <Cpu className="w-4 h-4 text-cyber-secondary" />
                    <span>Severity Classification Overview</span>
                  </h3>
                  
                  <div className="space-y-4">
                    {Object.entries(stats.threat_level_distribution).map(([level, count]) => {
                      const total = Object.values(stats.threat_level_distribution).reduce((a,b) => a+b, 0) || 1;
                      const percentage = Math.round((count / total) * 100);
                      
                      return (
                        <div key={level}>
                          <div className="flex justify-between text-sm mb-1">
                            <span className="font-medium">{level} Threat</span>
                            <span className="text-cyber-muted">{count} sessions ({percentage}%)</span>
                          </div>
                          <div className="w-full bg-cyber-bg h-2.5 rounded-full overflow-hidden border border-cyber-border">
                            <div 
                              className={`h-full rounded-full ${
                                level === "Critical" ? "bg-cyber-accent" : 
                                level === "High" ? "bg-orange-500" : 
                                level === "Medium" ? "bg-yellow-500" : "bg-cyan-500"
                              }`}
                              style={{ width: `${percentage}%` }}
                            ></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

              </div>

              {/* Top Attacking Hosts & Recent connections lists */}
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
                
                {/* Top IPs */}
                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl xl:col-span-1">
                  <h3 className="text-base font-bold tracking-wider uppercase mb-4 flex items-center space-x-2">
                    <Globe className="w-4 h-4 text-cyber-success" />
                    <span>Top Attacking Hosts (IPs)</span>
                  </h3>
                  
                  <div className="divide-y divide-cyber-border">
                    {stats.top_ips.length > 0 ? (
                      stats.top_ips.map((ipData, i) => (
                        <div key={i} className="py-3 flex justify-between items-center text-sm">
                          <div>
                            <p className="font-semibold text-cyber-text">{ipData.ip_address}</p>
                            <div className="flex items-center space-x-1.5 mt-0.5 text-xs text-cyber-muted">
                              <MapPin className="w-3 h-3" />
                              <span>{ipData.country || "Local"}</span>
                              <span className="border-l border-cyber-border pl-1.5 uppercase font-medium">{ipData.protocols.join(", ")}</span>
                            </div>
                          </div>
                          <div className="text-right">
                            <span className="px-2 py-0.5 bg-cyber-accent/10 border border-cyber-accent/20 rounded text-xs text-cyber-accent font-mono font-bold">
                              Score: {ipData.max_score.toFixed(0)}
                            </span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="py-4 text-cyber-muted text-sm text-center">No attacking host logs available yet.</p>
                    )}
                  </div>
                </div>

                {/* Recent Connection Activities */}
                <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl xl:col-span-2">
                  <h3 className="text-base font-bold tracking-wider uppercase mb-4 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-cyber-primary" />
                    <span>Live Attacker Connection Stream</span>
                  </h3>
                  
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-cyber-border text-xs text-cyber-muted uppercase tracking-wider">
                          <th className="py-3 px-4">Timestamp</th>
                          <th className="py-3 px-4">Attacker IP</th>
                          <th className="py-3 px-4">Protocol</th>
                          <th className="py-3 px-4">Threat Level</th>
                          <th className="py-3 px-4">AI Class</th>
                          <th className="py-3 px-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-cyber-border text-sm">
                        {sessions.length > 0 ? (
                          sessions.map((sess, idx) => (
                            <tr key={idx} className="hover:bg-cyber-bg/35 transition">
                              <td className="py-3 px-4 text-xs font-mono text-cyber-muted">
                                {new Date(sess.start_time).toLocaleTimeString()}
                              </td>
                              <td className="py-3 px-4 font-semibold text-cyber-text">{sess.ip_address}</td>
                              <td className="py-3 px-4 text-xs font-mono">
                                <span className={`px-2 py-0.5 rounded ${
                                  sess.protocol === "SSH" ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20" :
                                  sess.protocol === "HTTP" ? "bg-purple-500/10 text-purple-400 border border-purple-500/20" :
                                  "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                }`}>
                                  {sess.protocol}
                                </span>
                              </td>
                              <td className="py-3 px-4">
                                <span className={`text-xs font-bold ${
                                  sess.threat_level === "Critical" ? "text-cyber-accent" :
                                  sess.threat_level === "High" ? "text-orange-500" :
                                  sess.threat_level === "Medium" ? "text-yellow-500" : "text-cyan-500"
                                }`}>
                                  {sess.threat_level}
                                </span>
                              </td>
                              <td className="py-3 px-4 text-cyber-muted">{sess.ai_classification}</td>
                              <td className="py-3 px-4 text-right">
                                <button 
                                  onClick={() => viewSessionDetails(sess.session_id)}
                                  className="px-3 py-1 bg-cyber-primary/10 border border-cyber-primary/20 rounded hover:bg-cyber-primary/25 text-xs text-cyber-primary font-medium"
                                >
                                  Inspect
                                </button>
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="6" className="py-8 text-cyber-muted text-center">No active honeypot connection sessions recorded.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>

            </div>
          )}

          {/* TAB 2: SESSIONS HISTORY & REPLAY */}
          {activeTab === "sessions" && (
            <div className="space-y-6 animate-fadeIn">
              <div className="flex justify-between items-center mb-4">
                <div>
                  <h2 className="text-xl font-bold tracking-wider text-cyber-text uppercase">Security Session Analysis</h2>
                  <p className="text-cyber-muted text-sm mt-0.5">Explore command execution transcripts, payloads, and AI explanation models.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* Active/History connection list */}
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 lg:col-span-1 space-y-4">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-cyber-muted">Recorded Sessions</h3>
                  
                  <div className="space-y-3 max-h-[600px] overflow-y-auto pr-2">
                    {sessions.map((sess, idx) => (
                      <div 
                        key={idx}
                        onClick={() => viewSessionDetails(sess.session_id)}
                        className={`p-4 border rounded-xl cursor-pointer transition ${
                          selectedSession?.session_id === sess.session_id 
                            ? 'bg-cyber-primary/10 border-cyber-primary' 
                            : 'bg-cyber-bg/40 border-cyber-border hover:border-cyber-primary/50'
                        }`}
                      >
                        <div className="flex justify-between items-start">
                          <span className="font-mono text-xs text-cyber-muted">
                            {new Date(sess.start_time).toLocaleString()}
                          </span>
                          <span className={`text-xs font-bold ${
                            sess.threat_level === "Critical" ? "text-cyber-accent" :
                            sess.threat_level === "High" ? "text-orange-500" :
                            sess.threat_level === "Medium" ? "text-yellow-500" : "text-cyan-500"
                          }`}>
                            {sess.threat_level}
                          </span>
                        </div>
                        <h4 className="font-bold text-cyber-text mt-2">{sess.ip_address}</h4>
                        <div className="flex justify-between items-center mt-3 text-xs">
                          <span className="text-cyber-primary uppercase tracking-widest">{sess.protocol}</span>
                          <span className="text-cyber-muted font-mono">{sess.ai_classification}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Session Inspector details */}
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 lg:col-span-2 flex flex-col min-h-[500px]">
                  {selectedSession ? (
                    <div className="flex-1 flex flex-col">
                      
                      {/* Top Header info */}
                      <div className="border-b border-cyber-border pb-4 mb-4 flex justify-between items-start">
                        <div>
                          <span className="px-2 py-0.5 bg-cyber-primary/10 border border-cyber-primary/20 rounded text-xs text-cyber-primary font-mono uppercase">
                            Session: {selectedSession.session_id.substring(0, 8)}...
                          </span>
                          <h3 className="text-2xl font-extrabold text-cyber-text mt-2">{selectedSession.ip_address}</h3>
                          <div className="flex space-x-4 mt-2 text-xs text-cyber-muted">
                            <span className="flex items-center space-x-1">
                              <Globe className="w-3.5 h-3.5" />
                              <span>{selectedSession.geo_location.country} ({selectedSession.geo_location.city})</span>
                            </span>
                            <span className="flex items-center space-x-1">
                              <Clock className="w-3.5 h-3.5" />
                              <span>Duration: {selectedSession.features.session_duration.toFixed(1)}s</span>
                            </span>
                          </div>
                        </div>

                        <div className="text-right">
                          <p className="text-xs text-cyber-muted uppercase font-bold">Threat Score</p>
                          <p className="text-3xl font-extrabold text-cyber-accent font-mono mt-0.5">{selectedSession.threat_score.toFixed(0)}</p>
                        </div>
                      </div>

                      {/* Detail Sub Tabs navigation */}
                      <div className="flex border-b border-cyber-border mb-6">
                        {["details", "terminal", "credentials", "files"].map((tab) => (
                          <button
                            key={tab}
                            onClick={() => setSessionDetailTab(tab)}
                            className={`px-4 py-2 border-b-2 font-medium text-sm uppercase tracking-wider transition ${
                              sessionDetailTab === tab 
                                ? 'border-cyber-primary text-cyber-primary' 
                                : 'border-transparent text-cyber-muted hover:text-cyber-text'
                            }`}
                          >
                            {tab}
                          </button>
                        ))}
                      </div>

                      {/* Tab content displays */}
                      <div className="flex-1">
                        
                        {/* Tab 1: AI Details */}
                        {sessionDetailTab === "details" && (
                          <div className="space-y-6">
                            <div className="p-5 bg-cyber-bg border border-cyber-border rounded-xl">
                              <h4 className="text-sm font-bold uppercase tracking-wider text-cyber-primary mb-2 flex items-center space-x-2">
                                <ShieldAlert className="w-4 h-4" />
                                <span>AI Behavior Classification & Explanation</span>
                              </h4>
                              <p className="text-sm font-semibold text-cyber-text mb-4">
                                Dynamic Class: {selectedSession.ai_classification} (Confidence: {(selectedSession.threat_score / 100 * 100).toFixed(0)}%)
                              </p>
                              <p className="text-cyber-muted text-sm leading-relaxed font-mono">
                                {selectedSession.ai_explanation}
                              </p>
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                              <div className="bg-cyber-bg/50 border border-cyber-border p-4 rounded-xl text-center">
                                <p className="text-xs text-cyber-muted uppercase">Login Attempts</p>
                                <p className="text-2xl font-bold mt-1 text-cyber-text">{selectedSession.features.login_attempts}</p>
                              </div>
                              <div className="bg-cyber-bg/50 border border-cyber-border p-4 rounded-xl text-center">
                                <p className="text-xs text-cyber-muted uppercase">Unique Passwords</p>
                                <p className="text-2xl font-bold mt-1 text-cyber-text">{selectedSession.features.distinct_passwords}</p>
                              </div>
                              <div className="bg-cyber-bg/50 border border-cyber-border p-4 rounded-xl text-center">
                                <p className="text-xs text-cyber-muted uppercase">Commands Executed</p>
                                <p className="text-2xl font-bold mt-1 text-cyber-text">{selectedSession.features.commands_count}</p>
                              </div>
                              <div className="bg-cyber-bg/50 border border-cyber-border p-4 rounded-xl text-center">
                                <p className="text-xs text-cyber-muted uppercase">Malware Uploads</p>
                                <p className="text-2xl font-bold mt-1 text-cyber-accent">{selectedSession.features.malware_uploaded}</p>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Tab 2: Terminal replay console */}
                        {sessionDetailTab === "terminal" && (
                          <div className="bg-[#080B15] border border-cyber-border rounded-xl p-5 font-mono text-xs text-green-400 relative overflow-hidden h-[400px] flex flex-col justify-between">
                            {/* CRT Screen Scanlines */}
                            <div className="absolute inset-0 scanline pointer-events-none"></div>
                            
                            <div className="flex-1 overflow-y-auto space-y-3 pr-2 select-text relative z-10">
                              <p className="text-cyber-muted"># Replaying terminal interactive console transcript...</p>
                              
                              {selectedSession.commands.length > 0 ? (
                                selectedSession.commands.map((cmd, i) => (
                                  <div key={i} className="space-y-1">
                                    <p className="text-cyan-400 font-bold">$ {cmd.command}</p>
                                    {cmd.response && (
                                      <p className="text-slate-300 whitespace-pre-wrap pl-3 border-l border-cyber-border py-1">
                                        {cmd.response}
                                      </p>
                                    )}
                                  </div>
                                ))
                              ) : (
                                <p className="text-cyber-muted">No commands executed during this connection session.</p>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Tab 3: Credentials tried */}
                        {sessionDetailTab === "credentials" && (
                          <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                              <thead>
                                <tr className="border-b border-cyber-border text-xs text-cyber-muted uppercase tracking-wider">
                                  <th className="py-2.5 px-4">Timestamp</th>
                                  <th className="py-2.5 px-4">Username</th>
                                  <th className="py-2.5 px-4">Password</th>
                                  <th className="py-2.5 px-4 text-right">Result</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-cyber-border text-sm">
                                {selectedSession.credentials_attempts.length > 0 ? (
                                  selectedSession.credentials_attempts.map((cred, i) => (
                                    <tr key={i} className="hover:bg-cyber-bg/25">
                                      <td className="py-2 px-4 text-xs font-mono text-cyber-muted">
                                        {new Date(cred.timestamp).toLocaleTimeString()}
                                      </td>
                                      <td className="py-2 px-4 font-bold text-cyber-text">{cred.username}</td>
                                      <td className="py-2 px-4 font-mono text-cyan-400">{cred.password}</td>
                                      <td className="py-2 px-4 text-right">
                                        <span className={`px-2 py-0.5 rounded text-xs ${cred.success ? 'bg-cyber-success/10 text-cyber-success' : 'bg-cyber-accent/10 text-cyber-accent'}`}>
                                          {cred.success ? 'ACCEPTED' : 'DENIED'}
                                        </span>
                                      </td>
                                    </tr>
                                  ))
                                ) : (
                                  <tr>
                                    <td colSpan="4" className="py-4 text-cyber-muted text-center">No credential verification login logs.</td>
                                  </tr>
                                )}
                              </tbody>
                            </table>
                          </div>
                        )}

                        {/* Tab 4: Quarantined Files list */}
                        {sessionDetailTab === "files" && (
                          <div className="space-y-4">
                            {selectedSession.uploaded_files.length > 0 ? (
                              selectedSession.uploaded_files.map((file, i) => (
                                <div key={i} className="p-4 bg-cyber-bg border border-cyber-border rounded-xl space-y-2">
                                  <div className="flex justify-between items-center border-b border-cyber-border/40 pb-2">
                                    <h4 className="font-bold text-cyber-accent">{file.filename}</h4>
                                    <span className="text-xs text-cyber-muted">Size: {(file.size / 1024).toFixed(2)} KB</span>
                                  </div>
                                  <div className="space-y-1 text-xs font-mono text-cyber-muted">
                                    <p><span className="text-cyber-text">MD5:</span> {file.md5}</p>
                                    <p><span className="text-cyber-text">SHA-256:</span> {file.sha256}</p>
                                    <p><span className="text-cyber-text">Quarantine Path:</span> {file.quarantine_path || "Logs directory"}</p>
                                  </div>
                                </div>
                              ))
                            ) : (
                              <p className="py-8 text-cyber-muted text-center">No malware files or payloads uploaded in this session.</p>
                            )}
                          </div>
                        )}

                      </div>
                    </div>
                  ) : (
                    <div className="flex-1 flex flex-col justify-center items-center text-cyber-muted">
                      <Terminal className="w-12 h-12 mb-3 text-cyber-muted opacity-40 animate-pulse" />
                      <p className="text-sm">Select an attacker connection from the left panel to begin forensic analysis.</p>
                    </div>
                  )}
                </div>

              </div>
            </div>
          )}

          {/* TAB 3: SYSTEM CONFIG & TARPIT RULES */}
          {activeTab === "config" && (
            <div className="space-y-8 animate-fadeIn max-w-4xl">
              <div>
                <h2 className="text-xl font-bold tracking-wider text-cyber-text uppercase">Adaptive Honeypot Configuration</h2>
                <p className="text-cyber-muted text-sm mt-0.5">Control live honeypot behavior, artificial tarpit network latency, and notification limits.</p>
              </div>

              <form onSubmit={handleSaveConfig} className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-6">
                
                {/* Brute Force slider */}
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <label className="text-sm font-semibold text-cyber-text">Brute Force Tarpit Trigger Limit</label>
                    <span className="text-sm font-mono text-cyber-primary">{config.bruteForceThreshold} failures</span>
                  </div>
                  <p className="text-xs text-cyber-muted leading-relaxed">
                    Specifies how many authentication attempts a host can perform before the system triggers the network tarpit delay.
                  </p>
                  <input 
                    type="range" 
                    min="3" 
                    max="15" 
                    value={config.bruteForceThreshold}
                    onChange={(e) => setConfig({ ...config, bruteForceThreshold: parseInt(e.target.value) })}
                    className="w-full h-2 bg-cyber-bg rounded-lg border border-cyber-border cursor-pointer accent-cyber-primary" 
                  />
                </div>

                {/* Tarpit Max Latency */}
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <label className="text-sm font-semibold text-cyber-text">Maximum Tarpit Latency Delay</label>
                    <span className="text-sm font-mono text-cyber-primary">{config.tarpitLatencyMax.toFixed(1)} seconds</span>
                  </div>
                  <p className="text-xs text-cyber-muted leading-relaxed">
                    Configures the maximum delay sleep parameter SentinelAI will dynamically inject into socket responses for abusive connections.
                  </p>
                  <input 
                    type="range" 
                    min="1.0" 
                    max="10.0" 
                    step="0.5"
                    value={config.tarpitLatencyMax}
                    onChange={(e) => setConfig({ ...config, tarpitLatencyMax: parseFloat(e.target.value) })}
                    className="w-full h-2 bg-cyber-bg rounded-lg border border-cyber-border cursor-pointer accent-cyber-primary" 
                  />
                </div>

                {/* Realism settings */}
                <div className="space-y-3">
                  <label className="text-sm font-semibold text-cyber-text block">Filesystem Decoy Depth</label>
                  <p className="text-xs text-cyber-muted leading-relaxed">
                    Specifies the depth levels of virtualized decoy environments dynamically generated on HTTP scanning and SSH navigation.
                  </p>
                  <div className="grid grid-cols-3 gap-4">
                    {[1, 2, 3].map((level) => (
                      <button
                        type="button"
                        key={level}
                        onClick={() => setConfig({ ...config, fsRealismLevel: level })}
                        className={`p-3 border rounded-xl text-center text-xs font-semibold uppercase transition ${
                          config.fsRealismLevel === level 
                            ? 'bg-cyber-primary/10 border-cyber-primary text-cyber-primary' 
                            : 'bg-cyber-bg/50 border-cyber-border text-cyber-muted hover:border-cyber-primary/30'
                        }`}
                      >
                        {level === 1 ? 'Low (Quick Probes)' : level === 2 ? 'Medium (Standard)' : 'High (Deep Sandbox)'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="border-t border-cyber-border pt-6 flex justify-end">
                  <button 
                    type="submit"
                    className="px-6 py-2.5 bg-gradient-to-r from-cyber-primary to-cyber-secondary text-cyber-bg font-semibold rounded-lg text-sm tracking-wider uppercase hover:brightness-110 transition"
                  >
                    Commit Parameters
                  </button>
                </div>

              </form>
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
