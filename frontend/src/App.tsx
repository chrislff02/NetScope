import { useEffect, useState } from "react";

import {
  Activity,
  ChartNoAxesCombined,
  CircleAlert,
  Database,
  HardDriveDownload,
  LayoutDashboard,
  Network,
  Radio,
  Settings,
  Users,
  Globe,
} from "lucide-react";

import {
  getTrafficSummary,
  getPackets,
  type Packet,
  type TrafficSummary,
} from "./services/api";

import "./App.css";

const navigation = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "Live Packets", icon: Activity },
  { label: "Traffic History", icon: Database },
  { label: "Security Alerts", icon: CircleAlert },
  { label: "Settings", icon: Settings },
];

function App() {
  // Track the selected sidebar page.
  const [activePage, setActivePage] = useState("Dashboard");

  // Store network information returned by FastAPI.
  const [summary, setSummary] = useState<TrafficSummary | null>(null);

  const [packets, setPackets] = useState<Packet[]>([]);

  // Track loading and error states.
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Retrieve data when the dashboard first loads.
  useEffect(() => {
    const controller = new AbortController();

    async function loadDashboardData() {
      try {
        setLoading(true);
        setError(null);

        const [summaryData, packetData] = await Promise.all([
          getTrafficSummary(controller.signal),
          getPackets(controller.signal),
        ]);

        if (!controller.signal.aborted) {
          setSummary(summaryData);
          setPackets(packetData.packets);
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load network traffic.",
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    loadDashboardData();

    return () => {
      controller.abort();
    };
  }, []);

  // Build statistic cards using API data.
  const statistics = [
    {
      label: "Total Packets",
      value: summary?.total_packets.toLocaleString() ?? "—",
      detail: "IPv4 packets analyzed",
      icon: Network,
    },
    {
      label: "Total Bytes",
      value: summary?.total_bytes.toLocaleString() ?? "—",
      detail: "Bytes analyzed",
      icon: HardDriveDownload,
    },
    {
      label: "Unique Source IPs",
      value: summary?.unique_source_ips.toString() ?? "—",
      detail: "Distinct source addresses",
      icon: Users,
    },
    {
      label: "Unique Destination IPs",
      value: summary?.unique_destination_ips.toString() ?? "—",
      detail: "Distinct destination addresses",
      icon: Globe,
    },
  ];

  // Show the newest five packet records first.
  const recentPackets = packets.slice(-5).reverse();

  return (
    <div className="app-container">
      {/* Sidebar */}
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
            Saved Capture Mode
          </div>

          <p>NetScope v0.1.0</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        <header className="dashboard-header">
          <div>
            <p className="eyebrow">NETWORK MONITORING</p>

            <h1>{activePage}</h1>

            <p className="subtitle">
              Analyze network traffic and protocol activity.
            </p>
          </div>

          <div className="header-actions">
            <span className="demo-indicator">
              <Radio size={15} />
              Saved PCAP Data
            </span>
          </div>
        </header>

        {/* API status */}
        {loading && <p role="status">Loading network traffic...</p>}

        {error && (
          <p role="alert" style={{ color: "#fca5a5" }}>
            Unable to load data: {error}
          </p>
        )}

        {activePage === "Dashboard" ? (
          <>
            {/* Statistics cards */}
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

            {/* Recent packets */}
            <section className="panel packet-panel">
              <div className="panel-header">
                <div>
                  <h3>Recent Packets</h3>
                  <p>Packet records from the saved capture</p>
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
                    {recentPackets.map((packet, index) => (
                      <tr key={index}>
                        <td>{packet.timestamp.slice(11, 19)}</td>

                        <td>{packet.source_ip}</td>

                        <td>{packet.destination_ip}</td>

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

                {!loading && !error && recentPackets.length === 0 && (
                  <p>No packets available.</p>
                )}
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
