import { useEffect, useMemo, useRef, useState } from "react";
import { Play, Square, Radio } from "lucide-react";

import type { Packet } from "../services/api";
import PacketExplorer from "./PacketExplorer";

import TrafficChart from "./TrafficChart";
import ProtocolChart from "./ProtocolChart";

// Available streaming modes.
type StreamMode = "demo" | "live";

type StreamStatus =
  | "Disconnected"
  | "Connecting"
  | "Connected"
  | "Completed"
  | "Error";

// Both endpoints send packet events.
interface PacketEvent {
  event: "packet";
  sequence?: number;
  data: Packet;
}

// The demo endpoint sends this after five packets.
interface CompleteEvent {
  event: "complete";
  packets_sent: number;
}

// The live endpoint sends this after subscribing.
interface ConnectedEvent {
  event: "connected";
  message: string;
}

type StreamMessage = PacketEvent | CompleteEvent | ConnectedEvent;

function LiveTrafficStream() {
  // Keep a reference to the current WebSocket.
  const socketRef = useRef<WebSocket | null>(null);

  // Choose between simulated and live traffic.
  const [mode, setMode] = useState<StreamMode>("demo");

  // Track the connection status.
  const [status, setStatus] = useState<StreamStatus>("Disconnected");

  // Store received packet metadata.
  const [packets, setPackets] = useState<Packet[]>([]);

  // Number of packets reported by the demo endpoint.
  const [packetsSent, setPacketsSent] = useState(0);

  // Track whether we intentionally stopped the stream.
  const manuallyStoppedRef = useRef(false);

  // Open the selected WebSocket connection.
  function startStream() {
    // Prevent duplicate connections.
    if (socketRef.current !== null) {
      return;
    }

    // Reset previous session data.
    manuallyStoppedRef.current = false;
    setPackets([]);
    setPacketsSent(0);
    setStatus("Connecting");

    // Use wss when the page is served over HTTPS.
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";

    // Select the appropriate FastAPI endpoint.
    const endpoint = mode === "demo" ? "/ws/traffic" : "/ws/traffic/live";

    const url = `${protocol}://${window.location.hostname}:8000${endpoint}`;

    let socket: WebSocket;

    try {
      socket = new WebSocket(url);
    } catch {
      setStatus("Error");
      return;
    }

    socketRef.current = socket;

    socket.onopen = () => {
      if (socketRef.current !== socket) {
        return;
      }

      // The live endpoint will send its own connected event.
      if (mode === "demo") {
        setStatus("Connected");
      }
    };

    socket.onmessage = (event: MessageEvent<string>) => {
      if (socketRef.current !== socket) {
        return;
      }

      let message: StreamMessage;

      try {
        message = JSON.parse(event.data) as StreamMessage;
      } catch {
        setStatus("Error");
        socket.close();
        return;
      }

      // Live mode confirms the subscription is ready.
      if (message.event === "connected") {
        setStatus("Connected");
        return;
      }

      // Both modes receive packet events.
      if (message.event === "packet") {
        setPackets((previous) => [...previous, message.data]);
        return;
      }

      // Only demo mode sends a completion event.
      if (message.event === "complete") {
        setPacketsSent(message.packets_sent);
        setStatus("Completed");
      }
    };

    socket.onerror = () => {
      if (socketRef.current === socket) {
        setStatus("Error");
      }
    };

    socket.onclose = () => {
      // Ignore events from an outdated connection.
      if (socketRef.current !== socket) {
        return;
      }

      socketRef.current = null;

      if (manuallyStoppedRef.current) {
        setStatus("Disconnected");
        return;
      }

      // Preserve completed demo sessions and errors.
      setStatus((previous) => {
        if (previous === "Completed" || previous === "Error") {
          return previous;
        }

        return "Disconnected";
      });
    };
  }

  // Stop the active stream manually.
  function stopStream() {
    manuallyStoppedRef.current = true;

    const socket = socketRef.current;

    if (socket !== null) {
      // Clear the reference before closing.
      socketRef.current = null;
      socket.close();
    }

    setStatus("Disconnected");
  }

  // Disconnect when leaving the Live Stream page.
  useEffect(() => {
    return () => {
      const socket = socketRef.current;

      if (socket !== null) {
        socketRef.current = null;

        socket.onopen = null;
        socket.onmessage = null;
        socket.onerror = null;
        socket.onclose = null;

        socket.close();
      }
    };
  }, []);

  // Prevent mode changes while a stream is active.
  const streaming = status === "Connecting" || status === "Connected";

  // Calculate total received bytes.
  const totalBytes = useMemo(() => {
    return packets.reduce((total, packet) => total + packet.size, 0);
  }, [packets]);

  // Count packets by protocol.
  const protocolCounts = useMemo(() => {
    const counts: Record<string, number> = {};

    for (const packet of packets) {
      const protocol = packet.protocol;

      if (!(protocol in counts)) {
        counts[protocol] = 0;
      }

      counts[protocol] += 1;
    }

    return counts;
  }, [packets]);

  // Group received packets into one-second intervals.
  const trafficOverTime = useMemo(() => {
    const timeline: Record<string, { packets: number; bytes: number }> = {};

    for (const packet of packets) {
      const second = packet.timestamp.slice(0, 19);

      if (!timeline[second]) {
        timeline[second] = {
          packets: 0,
          bytes: 0,
        };
      }

      timeline[second].packets += 1;
      timeline[second].bytes += packet.size;
    }

    return Object.fromEntries(
      Object.entries(timeline).sort(([first], [second]) =>
        first.localeCompare(second),
      ),
    );
  }, [packets]);

  // Display mode-specific messages.
  const modeDescription =
    mode === "demo"
      ? "Receive simulated packet events through FastAPI WebSockets."
      : "Monitor packet metadata received through NetScope's Unix socket.";

  const modeLabel =
    mode === "demo" ? "Synthetic WebSocket data" : "Live Unix socket metadata";

  return (
    <div className="live-stream-page">
      <div className="capture-toolbar">
        <div>
          <h2>Live Traffic Stream</h2>
          <p>{modeDescription}</p>
        </div>

        <div className="stream-controls">
          <button
            type="button"
            className="capture-refresh-button"
            disabled={streaming}
            onClick={startStream}
          >
            <Play size={16} />
            {mode === "demo" ? "Start Demo Stream" : "Start Live Stream"}
          </button>

          <button
            type="button"
            className="stream-stop-button"
            disabled={!streaming}
            onClick={stopStream}
          >
            <Square size={16} />
            Stop
          </button>
        </div>
      </div>

      {/* Select Demo Mode or Live Mode. */}
      <div className="stream-mode-selector">
        <button
          type="button"
          className={
            mode === "demo" ? "stream-mode-button active" : "stream-mode-button"
          }
          aria-pressed={mode === "demo"}
          disabled={streaming}
          onClick={() => {
            setMode("demo");
            setStatus("Disconnected");
            setPackets([]);
            setPacketsSent(0);
          }}
        >
          <Play size={16} />
          Demo Mode
        </button>

        <button
          type="button"
          className={
            mode === "live" ? "stream-mode-button active" : "stream-mode-button"
          }
          aria-pressed={mode === "live"}
          disabled={streaming}
          onClick={() => {
            setMode("live");
            setStatus("Disconnected");
            setPackets([]);
            setPacketsSent(0);
          }}
        >
          <Radio size={16} />
          Live Mode
        </button>
      </div>

      {/* Connection information. */}
      <div className="capture-info">
        <Radio size={16} />
        <span>Connection: {status}</span>
        <span>Mode: {modeLabel}</span>
      </div>

      {/* Stream statistics. */}
      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-header">
            <span>Packets Received</span>
          </div>

          <h2>{packets.length}</h2>
          <p>Events received from FastAPI</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>Total Bytes</span>
          </div>

          <h2>{totalBytes.toLocaleString()}</h2>
          <p>Bytes in received packet records</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>{mode === "demo" ? "Packets Sent" : "Stream Status"}</span>
          </div>

          <h2>
            {mode === "demo" ? packetsSent : streaming ? "Active" : status}
          </h2>

          <p>
            {mode === "demo"
              ? "Reported after demo completion"
              : "Live receiver connection"}
          </p>
        </div>
      </section>

      {/* Charts update as packets arrive. */}
      <section className="charts-grid">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3>Streaming Network Traffic</h3>
              <p>Received bytes per second</p>
            </div>
          </div>

          {packets.length > 0 ? (
            <TrafficChart traffic={trafficOverTime} />
          ) : (
            <div className="chart-placeholder">
              <p>No streaming traffic yet.</p>
              <span>
                {mode === "demo"
                  ? "Start the demo stream to see network activity."
                  : "Start Live Mode and send packet metadata to see traffic."}
              </span>
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <h3>Live Protocol Distribution</h3>
              <p>Packets received by protocol</p>
            </div>
          </div>

          {packets.length > 0 ? (
            <ProtocolChart protocols={protocolCounts} />
          ) : (
            <div className="chart-placeholder">
              <p>No protocol data yet.</p>
              <span>Protocol statistics will appear during streaming.</span>
            </div>
          )}
        </div>
      </section>

      {/* WebSocket connection errors. */}
      {status === "Error" && (
        <p role="alert" className="capture-error">
          WebSocket connection failed. Check that FastAPI is running on port
          8000.
        </p>
      )}

      {/* Reuse the existing Packet Explorer. */}
      <div className="capture-packets-heading">
        <h3>Incoming Packets</h3>
        <p>
          {mode === "demo"
            ? "Packet records received during this demo session."
            : "Packet metadata received during this live session."}
        </p>
      </div>

      <PacketExplorer packets={packets} />
    </div>
  );
}

export default LiveTrafficStream;
