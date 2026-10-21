import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Database,
  HardDriveDownload,
  Network,
  RefreshCw,
} from "lucide-react";

import {
  getLatestCapture,
  type LiveCapture as LiveCaptureData,
} from "../services/api";

import TrafficChart from "./TrafficChart";
import ProtocolChart from "./ProtocolChart";
import PacketExplorer from "./PacketExplorer";

export default function LiveCapture() {
  // Store the most recently completed capture.
  const [capture, setCapture] = useState<LiveCaptureData | null>(null);

  // Track loading and error states.
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Retrieve the latest completed recording from FastAPI.
  const loadCapture = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);

    try {
      const data = await getLatestCapture(signal);

      if (!signal?.aborted) {
        setCapture(data);
      }
    } catch (err) {
      if (!signal?.aborted) {
        setError(
          err instanceof Error ? err.message : "Unable to load capture data.",
        );
      }
    } finally {
      if (!signal?.aborted) {
        setLoading(false);
      }
    }
  }, []);

  // Load once when the page is opened.

  useEffect(() => {
    // Allow us to cancel the request when the page unmounts.
    const controller = new AbortController();

    // Load the most recently completed network capture.
    async function fetchInitialCapture() {
      try {
        const data = await getLatestCapture(controller.signal);

        // Only update state if the request was not cancelled.
        if (!controller.signal.aborted) {
          setCapture(data);
          setError(null);
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(
            err instanceof Error ? err.message : "Unable to load capture data.",
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    void fetchInitialCapture();

    // Cancel the request if the component unmounts.
    return () => controller.abort();
  }, []);

  const statistics = capture?.statistics;

  return (
    <div className="live-capture-page">
      {/* Page controls */}
      <div className="capture-toolbar">
        <div>
          <h2>Latest Completed Capture</h2>
          <p>Inspect network traffic recorded from your Mac.</p>
        </div>

        <button
          className="capture-refresh-button"
          onClick={() => void loadCapture()}
          disabled={loading}
        >
          <RefreshCw size={16} />
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {/* Loading and error messages */}
      {loading && <p role="status">Loading capture data...</p>}

      {error && (
        <p role="alert" className="capture-error">
          {error}
        </p>
      )}

      {/* Display the latest capture when available */}
      {capture && statistics && (
        <>
          <div className="capture-info">
            <span>Interface: {capture.interface}</span>
            <span>Source: Completed live capture</span>
          </div>

          {/* Capture statistics */}
          <section className="stats-grid">
            <div className="stat-card">
              <div className="stat-header">
                <span>Raw Packets</span>
                <Network size={20} />
              </div>

              <h2>{capture.raw_packets_captured}</h2>
              <p>Observed during capture</p>
            </div>

            <div className="stat-card">
              <div className="stat-header">
                <span>IPv4 Packets</span>
                <Activity size={20} />
              </div>

              <h2>{statistics.total_packets}</h2>
              <p>Packets analyzed</p>
            </div>

            <div className="stat-card">
              <div className="stat-header">
                <span>Total Bytes</span>
                <HardDriveDownload size={20} />
              </div>

              <h2>{statistics.total_bytes.toLocaleString()}</h2>
              <p>Bytes analyzed</p>
            </div>

            <div className="stat-card">
              <div className="stat-header">
                <span>Unique Source IPs</span>
                <Database size={20} />
              </div>

              <h2>{statistics.unique_source_ips}</h2>
              <p>Distinct source addresses</p>
            </div>
          </section>

          {/* Traffic charts */}
          <section className="charts-grid">
            <div className="panel">
              <div className="panel-header">
                <div>
                  <h3>Captured Traffic</h3>
                  <p>Bytes analyzed per second</p>
                </div>
              </div>

              <TrafficChart traffic={statistics.traffic_over_time} />
            </div>

            <div className="panel">
              <div className="panel-header">
                <div>
                  <h3>Protocol Distribution</h3>
                  <p>Captured packets by protocol</p>
                </div>
              </div>

              <ProtocolChart protocols={statistics.protocol_counts} />
            </div>
          </section>

          {/* Reuse our existing Packet Explorer */}
          <div className="capture-packets-heading">
            <h3>Captured Packets</h3>
            <p>Inspect the individual packets from this recording.</p>
          </div>

          <PacketExplorer packets={capture.packets} />
        </>
      )}
    </div>
  );
}
