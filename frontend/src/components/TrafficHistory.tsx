import { useMemo } from "react";
import { Activity, Clock3, Database, HardDrive } from "lucide-react";

import type { Packet } from "../services/api";

interface TrafficHistoryProps {
  packets: Packet[];
  loading?: boolean;
  error?: string | null;
}

interface HistoryInterval {
  minute: string;
  packets: number;
  bytes: number;
  tcp: number;
  udp: number;
  icmp: number;
  other: number;
}

function TrafficHistory({
  packets,
  loading = false,
  error = null,
}: TrafficHistoryProps) {
  // Analyze only the loaded saved-capture records.
  const history = useMemo(() => {
    const intervals = new Map<string, HistoryInterval>();

    for (const packet of packets) {
      // ISO timestamps can be grouped by minute.
      const minute = packet.timestamp.slice(0, 16);

      let interval = intervals.get(minute);

      if (!interval) {
        interval = {
          minute,
          packets: 0,
          bytes: 0,
          tcp: 0,
          udp: 0,
          icmp: 0,
          other: 0,
        };

        intervals.set(minute, interval);
      }

      interval.packets += 1;
      interval.bytes += packet.size;

      switch (packet.protocol) {
        case "TCP":
          interval.tcp += 1;
          break;
        case "UDP":
          interval.udp += 1;
          break;
        case "ICMP":
          interval.icmp += 1;
          break;
        default:
          interval.other += 1;
      }
    }

    return Array.from(intervals.values()).sort((a, b) =>
      b.minute.localeCompare(a.minute),
    );
  }, [packets]);

  const totalBytes = useMemo(
    () => packets.reduce((total, packet) => total + packet.size, 0),
    [packets],
  );

  const timestamps = useMemo(
    () => packets.map((packet) => packet.timestamp).sort(),
    [packets],
  );

  const firstPacket = timestamps[0] ?? null;
  const lastPacket = timestamps[timestamps.length - 1] ?? null;

  return (
    <section className="traffic-history-page">
      <div className="capture-toolbar">
        <div>
          <h2>Traffic History</h2>
          <p>
            Review packet activity over time within the loaded saved capture.
          </p>
        </div>
      </div>

      {/* Capture statistics */}
      <div className="history-stats-grid">
        <div className="stat-card">
          <div className="stat-header">
            <span>Recorded Packets</span>
            <Activity size={20} />
          </div>

          <h2>{packets.length.toLocaleString()}</h2>
          <p>Packet records in this capture</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>Recorded Bytes</span>
            <HardDrive size={20} />
          </div>

          <h2>{totalBytes.toLocaleString()}</h2>
          <p>Total bytes in packet records</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>Active Minutes</span>
            <Clock3 size={20} />
          </div>

          <h2>{history.length.toLocaleString()}</h2>
          <p>Minutes containing captured packets</p>
        </div>
      </div>

      {/* Time range */}
      <div className="panel history-range-panel">
        <h3>Capture Time Range</h3>

        <div className="history-time-grid">
          <div>
            <span>First Recorded Packet</span>
            <strong>
              {firstPacket ? firstPacket.replace("T", " ") : "N/A"}
            </strong>
          </div>

          <div>
            <span>Last Recorded Packet</span>
            <strong>{lastPacket ? lastPacket.replace("T", " ") : "N/A"}</strong>
          </div>
        </div>
      </div>

      {/* Minute-by-minute traffic history */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Traffic Activity by Minute</h3>
            <p>
              Packet and byte counts grouped by recorded timestamp. Newest
              intervals appear first.
            </p>
          </div>

          <Database size={20} />
        </div>

        {loading ? (
          <div className="explorer-empty" role="status">
            <p>Loading traffic history...</p>
          </div>
        ) : error ? (
          <div className="explorer-empty" role="status">
            <p>Traffic history is unavailable.</p>
            <span>Check your backend connection and retry.</span>
          </div>
        ) : history.length === 0 ? (
          <div className="explorer-empty" role="status">
            <p>No saved traffic history available.</p>
            <span>Capture or load packet data to see activity over time.</span>
          </div>
        ) : (
          <div className="table-container">
            <table aria-label="Saved capture traffic by minute">
              <thead>
                <tr>
                  <th>Minute</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>TCP</th>
                  <th>UDP</th>
                  <th>ICMP</th>
                  <th>Other</th>
                </tr>
              </thead>

              <tbody>
                {history.map((interval) => (
                  <tr key={interval.minute}>
                    <td>{interval.minute.replace("T", " ")}</td>
                    <td>{interval.packets.toLocaleString()}</td>
                    <td>{interval.bytes.toLocaleString()} B</td>
                    <td>{interval.tcp}</td>
                    <td>{interval.udp}</td>
                    <td>{interval.icmp}</td>
                    <td>{interval.other}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

export default TrafficHistory;
