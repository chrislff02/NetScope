import { useEffect, useState } from "react";
import LiveTrafficStream from "./components/LiveTrafficStream";
import TrafficHistory from "./components/TrafficHistory";
import SecurityAlerts from "./components/SecurityAlerts";

import {
  Activity,
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

import TrafficChart from "./components/TrafficChart";
import ProtocolChart from "./components/ProtocolChart";

import PacketExplorer from "./components/PacketExplorer";

import LiveCapture from "./components/LiveCapture";

const navigation = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "Packet Explorer", icon: Activity },
  { label: "Live Capture", icon: Radio },
  { label: "Live Stream", icon: Activity },
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

  // Incrementing this value triggers another API request.
  const [retryCount, setRetryCount] = useState(0);

  // Load saved capture data on startup and after retry.
  useEffect(() => {
    const controller = new AbortController();

    // Retrieve both resources from FastAPI.
    Promise.all([
      getTrafficSummary(controller.signal),
      getPackets(controller.signal),
    ])
      .then(([summaryData, packetData]) => {
        if (controller.signal.aborted) {
          return;
        }

        setSummary(summaryData);
        setPackets(packetData.packets);
        setError(null);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        setError(
          err instanceof Error
            ? err.message
            : "Unable to load network traffic.",
        );

        // Clear stale saved-capture data on failure.
        setSummary(null);
        setPackets([]);
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    // Cancel the request when the effect is cleaned up.
    return () => {
      controller.abort();
    };
  }, [retryCount]);

  // Retry is triggered by a user interaction.
  function retryDashboardData() {
    setLoading(true);
    setError(null);
    setRetryCount((previous) => previous + 1);
  }

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

  // Distinguish successful empty responses
  // from loading and API failures.

  const hasProtocolData =
    summary !== null &&
    Object.values(summary.protocol_counts).some((count) => count > 0);

  const hasTimelineData =
    summary !== null && Object.values(summary.traffic_over_time).length > 0;

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
                type="button"
                className={`nav-item ${
                  activePage === item.label ? "active" : ""
                }`}
                aria-current={activePage === item.label ? "page" : undefined}
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

        {/* Saved capture API status */}
        {activePage !== "Live Stream" &&
          activePage !== "Live Capture" &&
          loading && (
            <div className="dashboard-notice" role="status">
              Loading saved network traffic...
            </div>
          )}

        {activePage !== "Live Stream" &&
          activePage !== "Live Capture" &&
          error && (
            <div
              className="dashboard-notice dashboard-notice-error"
              role="alert"
            >
              <div>
                <strong>Unable to load saved traffic data.</strong>
                <p>{error}</p>
              </div>

              <button
                type="button"
                className="capture-refresh-button"
                onClick={retryDashboardData}
              >
                Retry
              </button>
            </div>
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

            {/* Network traffic charts */}
            <section className="charts-grid">
              {/* Traffic over time */}
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h3>Network Traffic</h3>
                    <p>Bytes analyzed per second</p>
                  </div>
                </div>

                {hasTimelineData && summary ? (
                  <TrafficChart traffic={summary.traffic_over_time} />
                ) : (
                  <div className="chart-placeholder" role="status">
                    <p>
                      {loading
                        ? "Loading network traffic..."
                        : error
                          ? "Traffic data unavailable."
                          : "No network traffic available."}
                    </p>

                    <span>
                      {loading
                        ? "Retrieving saved capture statistics."
                        : error
                          ? "Check the backend connection and retry."
                          : "Capture network packets to populate this chart."}
                    </span>
                  </div>
                )}
              </div>

              {/* Protocol distribution */}
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h3>Protocol Distribution</h3>
                    <p>Packets grouped by protocol</p>
                  </div>
                </div>

                {hasProtocolData && summary ? (
                  <ProtocolChart protocols={summary.protocol_counts} />
                ) : (
                  <div className="chart-placeholder" role="status">
                    <p>
                      {loading
                        ? "Loading protocol statistics..."
                        : error
                          ? "Protocol data unavailable."
                          : "No protocol data available."}
                    </p>

                    <span>
                      {loading
                        ? "Retrieving protocol distribution."
                        : error
                          ? "Check the backend connection and retry."
                          : "Protocol statistics will appear after packets are captured."}
                    </span>
                  </div>
                )}
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

                {recentPackets.length === 0 && (
                  <div className="explorer-empty" role="status">
                    <p>
                      {loading
                        ? "Loading recent packets..."
                        : error
                          ? "Recent packets unavailable."
                          : "No recent packets available."}
                    </p>

                    <span>
                      {loading
                        ? "Retrieving packet records."
                        : error
                          ? "Check the backend connection and retry."
                          : "Capture or load packet data to display recent activity."}
                    </span>
                  </div>
                )}
              </div>
            </section>
          </>
        ) : activePage === "Packet Explorer" ? (
          <PacketExplorer packets={packets} />
        ) : activePage === "Live Capture" ? (
          <LiveCapture />
        ) : activePage === "Live Stream" ? (
          <LiveTrafficStream />
        ) : activePage === "Traffic History" ? (
          <TrafficHistory packets={packets} loading={loading} error={error} />
        ) : activePage === "Security Alerts" ? (
          <SecurityAlerts packets={packets} loading={loading} error={error} />
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
