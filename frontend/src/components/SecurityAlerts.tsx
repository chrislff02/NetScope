import { useMemo } from "react";
import {
  Activity,
  CircleCheck,
  Database,
  Network,
  ShieldAlert,
} from "lucide-react";

import type { Packet } from "../services/api";

interface SecurityAlertsProps {
  packets: Packet[];
  loading?: boolean;
  error?: string | null;
}

interface SecurityObservation {
  id: string;
  title: string;
  description: string;
  detail: string;
  count: number;
  threshold: number;
}

// Initial detection thresholds.
const SYN_THRESHOLD = 10;
const PORT_THRESHOLD = 20;
const ICMP_THRESHOLD = 20;

function SecurityAlerts({
  packets,
  loading = false,
  error = null,
}: SecurityAlertsProps) {
  // Analyze packet metadata from the saved capture.
  const observations = useMemo(() => {
    const results: SecurityObservation[] = [];

    const synBySource = new Map<string, number>();
    const packetsByPort = new Map<number, number>();

    let icmpCount = 0;

    for (const packet of packets) {
      // Count SYN-only packets by source address.
      if (packet.protocol === "TCP" && packet.tcp_flags === "S") {
        synBySource.set(
          packet.source_ip,
          (synBySource.get(packet.source_ip) ?? 0) + 1,
        );
      }

      // Count TCP/UDP traffic by destination port.
      if (
        (packet.protocol === "TCP" || packet.protocol === "UDP") &&
        packet.destination_port !== null
      ) {
        const port = packet.destination_port;

        packetsByPort.set(port, (packetsByPort.get(port) ?? 0) + 1);
      }

      if (packet.protocol === "ICMP") {
        icmpCount += 1;
      }
    }

    // Identify sources with repeated SYN-only packets.
    for (const [source, count] of synBySource) {
      if (count >= SYN_THRESHOLD) {
        results.push({
          id: `syn-${source}`,
          title: "Repeated TCP SYN Activity",
          description:
            "A source address generated repeated SYN-only " +
            "packets. This may reflect normal connection " +
            "attempts or activity worth investigating.",
          detail: `Source IP: ${source}`,
          count,
          threshold: SYN_THRESHOLD,
        });
      }
    }

    // Identify destination ports receiving frequent traffic.
    for (const [port, count] of packetsByPort) {
      if (count >= PORT_THRESHOLD) {
        results.push({
          id: `port-${port}`,
          title: "High Destination Port Activity",
          description:
            "A destination port appeared frequently in " +
            "the capture. Popular application ports may " +
            "normally receive substantial traffic.",
          detail: `Destination port: ${port}`,
          count,
          threshold: PORT_THRESHOLD,
        });
      }
    }

    // Identify captures containing substantial ICMP traffic.
    if (icmpCount >= ICMP_THRESHOLD) {
      results.push({
        id: "icmp-volume",
        title: "Elevated ICMP Activity",
        description:
          "The capture contains repeated ICMP packets. " +
          "This can occur during ordinary ping tests " +
          "and other network diagnostics.",
        detail: "Protocol: ICMP",
        count: icmpCount,
        threshold: ICMP_THRESHOLD,
      });
    }

    // Present the most frequent observations first.
    return results.sort((a, b) => b.count - a.count);
  }, [packets]);

  const synObservations = observations.filter((observation) =>
    observation.id.startsWith("syn-"),
  ).length;

  const portObservations = observations.filter((observation) =>
    observation.id.startsWith("port-"),
  ).length;

  const visibleObservations = observations.slice(0, 12);

  return (
    <section className="security-alerts-page">
      <div className="capture-toolbar">
        <div>
          <h2>Security Alerts</h2>
          <p>
            Review rule-based observations from saved network packet metadata.
          </p>
        </div>
      </div>

      {/* Analysis summary */}
      <div className="security-stats-grid">
        <div className="stat-card">
          <div className="stat-header">
            <span>Traffic Observations</span>
            <ShieldAlert size={20} />
          </div>

          <h2>{loading || error ? "—" : observations.length}</h2>

          <p>Rules meeting their thresholds</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>SYN Sources</span>
            <Activity size={20} />
          </div>

          <h2>{loading || error ? "—" : synObservations}</h2>

          <p>Sources meeting the SYN threshold</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>Active Destination Ports</span>
            <Network size={20} />
          </div>

          <h2>{loading || error ? "—" : portObservations}</h2>

          <p>Ports meeting the activity threshold</p>
        </div>
      </div>

      {/* Explain limitations of the analysis. */}
      <div className="panel security-info-panel">
        <div className="security-info-heading">
          <Database size={20} />
          <h3>How Detection Works</h3>
        </div>

        <p>
          NetScope evaluates packet counts, TCP flags, source addresses, and
          destination ports within the loaded saved capture.
        </p>

        <p>
          Observations are informational. They do not establish malicious intent
          or confirm a security incident. Counts apply to the entire loaded
          capture, regardless of its duration.
        </p>
      </div>

      {/* Observation results */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Detected Traffic Patterns</h3>
            <p>
              Observations appear when packet counts meet the defined
              thresholds.
            </p>
          </div>

          <ShieldAlert size={20} />
        </div>

        {loading ? (
          <div className="explorer-empty" role="status">
            <p>Analyzing saved packet metadata...</p>
          </div>
        ) : error ? (
          <div className="explorer-empty" role="status">
            <p>Security observations are unavailable.</p>
            <span>Check the backend connection and retry.</span>
          </div>
        ) : packets.length === 0 ? (
          <div className="explorer-empty" role="status">
            <p>No packet data available for analysis.</p>
            <span>
              Capture or load network traffic to evaluate the detection rules.
            </span>
          </div>
        ) : observations.length === 0 ? (
          <div className="security-clear-state" role="status">
            <CircleCheck size={32} />

            <h3>No detection thresholds reached</h3>

            <p>
              NetScope analyzed {packets.length.toLocaleString()} packet records
              without finding any patterns meeting the configured thresholds.
            </p>

            <span>
              This does not guarantee that the traffic is free of security
              threats.
            </span>
          </div>
        ) : (
          <>
            <div className="security-observation-list">
              {visibleObservations.map((observation) => (
                <article className="security-observation" key={observation.id}>
                  <div className="security-observation-heading">
                    <div>
                      <span className="security-review-label">Review</span>

                      <h4>{observation.title}</h4>
                    </div>

                    <ShieldAlert size={20} />
                  </div>

                  <p>{observation.description}</p>

                  <div className="security-observation-meta">
                    <span>{observation.detail}</span>

                    <span>Observed: {observation.count}</span>

                    <span>Threshold: {observation.threshold}</span>
                  </div>
                </article>
              ))}
            </div>

            {observations.length > visibleObservations.length && (
              <p className="security-overflow-note">
                Showing the 12 highest-count observations out of{" "}
                {observations.length}.
              </p>
            )}
          </>
        )}
      </div>
    </section>
  );
}

export default SecurityAlerts;
