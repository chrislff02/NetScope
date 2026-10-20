import { useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  ChartNoAxesCombined,
  CircleAlert,
  Database,
  LayoutDashboard,
  Network,
  Radio,
  Settings,
  ShieldCheck,
} from "lucide-react";

import "./App.css";

const navigation = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "Live Packets", icon: Activity },
  { label: "Traffic History", icon: Database },
  { label: "Security Alerts", icon: CircleAlert },
  { label: "Settings", icon: Settings },
];

const statistics = [
  {
    label: "Total Packets",
    value: "24,891",
    detail: "Packets analyzed",
    icon: Network,
  },
  {
    label: "Download",
    value: "2.4 MB/s",
    detail: "Sample traffic rate",
    icon: ArrowDownRight,
  },
  {
    label: "Upload",
    value: "842 KB/s",
    detail: "Sample traffic rate",
    icon: ArrowUpRight,
  },
  {
    label: "Security Alerts",
    value: "3",
    detail: "Sample alerts",
    icon: ShieldCheck,
  },
];

const samplePackets = [
  {
    time: "09:31:42",
    source: "192.168.1.10",
    destination: "8.8.8.8",
    protocol: "UDP",
    size: 128,
  },
  {
    time: "09:31:41",
    source: "192.168.1.10",
    destination: "142.250.80.46",
    protocol: "TCP",
    size: 1472,
  },
  {
    time: "09:31:40",
    source: "104.18.21.21",
    destination: "192.168.1.10",
    protocol: "TCP",
    size: 1284,
  },
  {
    time: "09:31:39",
    source: "192.168.1.10",
    destination: "1.1.1.1",
    protocol: "ICMP",
    size: 84,
  },
];

function App() {
  // Track which sidebar page is selected.
  const [activePage, setActivePage] = useState("Dashboard");

  return (
    <div className="app-container">
      {/* Sidebar navigation */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Network size={28} />
          <span>NetScope</span>
        </div>

        <div className="sidebar-section-title">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.label}
                className={`nav-item ${
                  activePage === item.label ? "active" : ""
                }`}
                onClick={() => setActivePage(item.label)}
              >
                <Icon size={19} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="system-status">
            <span className="status-dot" />
            Demo Mode
          </div>
          <p>NetScope v0.1.0</p>
        </div>
      </aside>

      {/* Main dashboard */}
      <main className="main-content">
        <header className="dashboard-header">
          <div>
            <p className="eyebrow">NETWORK MONITORING</p>
            <h1>{activePage}</h1>
            <p className="subtitle">Monitor and analyze network activity.</p>
          </div>

          <div className="header-actions">
            <span className="demo-indicator">
              <Radio size={15} />
              Demo Data
            </span>
          </div>
        </header>

        {activePage === "Dashboard" ? (
          <>
            {/* Network statistics */}
            <section className="stats-grid">
              {statistics.map((stat) => {
                const Icon = stat.icon;

                return (
                  <div className="stat-card" key={stat.label}>
                    <div className="stat-header">
                      <span>{stat.label}</span>
                      <Icon size={20} />
                    </div>

                    <h2>{stat.value}</h2>
                    <p>{stat.detail}</p>
                  </div>
                );
              })}
            </section>

            {/* Chart placeholders */}
            <section className="charts-grid">
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h3>Network Traffic</h3>
                    <p>Traffic activity over time</p>
                  </div>
                  <ChartNoAxesCombined size={20} />
                </div>

                <div className="chart-placeholder">
                  <Activity size={35} />
                  <p>Network traffic chart</p>
                  <span>Coming in Phase 5.4</span>
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h3>Protocol Distribution</h3>
                    <p>Traffic by protocol</p>
                  </div>
                </div>

                <div className="chart-placeholder">
                  <Network size={35} />
                  <p>Protocol distribution chart</p>
                  <span>Coming in Phase 5.4</span>
                </div>
              </div>
            </section>

            {/* Recent packet table */}
            <section className="panel packet-panel">
              <div className="panel-header">
                <div>
                  <h3>Recent Packets</h3>
                  <p>Sample network packet records</p>
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Protocol</th>
                      <th>Size</th>
                    </tr>
                  </thead>

                  <tbody>
                    {samplePackets.map((packet, index) => (
                      <tr key={index}>
                        <td>{packet.time}</td>
                        <td>{packet.source}</td>
                        <td>{packet.destination}</td>
                        <td>
                          <span
                            className={`protocol-badge ${packet.protocol.toLowerCase()}`}
                          >
                            {packet.protocol}
                          </span>
                        </td>
                        <td>{packet.size} B</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        ) : (
          <section className="panel empty-page">
            <Database size={42} />
            <h2>{activePage}</h2>
            <p>This section will be implemented in a future phase.</p>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
