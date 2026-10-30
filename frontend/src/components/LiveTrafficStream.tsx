import { useEffect, useMemo, useRef, useState } from "react";
import { Play, Square, Radio } from "lucide-react";

import type { Packet } from "../services/api";
import PacketExplorer from "./PacketExplorer";

import TrafficChart from "./TrafficChart";
import ProtocolChart from "./ProtocolChart";

// Maximum number of packet records retained in memory.
const MAX_STREAM_PACKETS = 500;

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

  // Display useful information about connection failures.
  const [connectionMessage, setConnectionMessage] = useState<string | null>(
    null,
  );

  // Track whether a WebSocket connection succeeded.
  const [hasConnectedBefore, setHasConnectedBefore] = useState(false);

  // Store received packet metadata.
  const [packets, setPackets] = useState<Packet[]>([]);

  // Cumulative statistics for the current streaming session.
  const [totalPacketsReceived, setTotalPacketsReceived] = useState(0);
  const [totalSessionBytes, setTotalSessionBytes] = useState(0);

  // Number of packets reported by the demo endpoint.
  const [packetsSent, setPacketsSent] = useState(0);

  // Track whether we intentionally stopped the stream.
  const manuallyStoppedRef = useRef(false);

  // Start a new stream or reconnect to an existing session.
  function startStream(preserveSession = false) {
    // Prevent duplicate WebSocket connections.
    if (socketRef.current !== null) {
      return;
    }

    manuallyStoppedRef.current = false;

    // New sessions reset statistics.
    // Reconnecting preserves existing session data.
    if (!preserveSession) {
      setPackets([]);
      setPacketsSent(0);
      setTotalPacketsReceived(0);
      setTotalSessionBytes(0);
    }

    setConnectionMessage(null);
    setStatus("Connecting");

    const protocol = window.location.protocol === "https:" ? "wss" : "ws";

    const endpoint = mode === "demo" ? "/ws/traffic" : "/ws/traffic/live";

    const url = `${protocol}://${window.location.hostname}:8000${endpoint}`;

    let socket: WebSocket;

    try {
      socket = new WebSocket(url);
    } catch {
      setStatus("Error");
      setConnectionMessage(
        "Unable to create a WebSocket connection. Check the backend address.",
      );
      return;
    }

    socketRef.current = socket;

    socket.onopen = () => {
      if (socketRef.current !== socket) {
        return;
      }

      // Demo Mode connects immediately when the socket opens.
      // Live Mode waits for the backend's connected event.
      if (mode === "demo") {
        setHasConnectedBefore(true);
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
        setConnectionMessage("The server sent an invalid WebSocket message.");
        socket.close();
        return;
      }

      if (message.event === "connected") {
        setHasConnectedBefore(true);
        setStatus("Connected");
        setConnectionMessage(null);
        return;
      }

      if (message.event === "packet") {
        const packet = message.data;

        // Maintain cumulative statistics for this session.
        setTotalPacketsReceived((previous) => previous + 1);
        setTotalSessionBytes((previous) => previous + packet.size);

        // Keep only the most recent 500 packet records.
        setPackets((previous) => {
          const updatedPackets = [...previous, packet];

          if (updatedPackets.length > MAX_STREAM_PACKETS) {
            return updatedPackets.slice(-MAX_STREAM_PACKETS);
          }

          return updatedPackets;
        });

        return;
      }

      if (message.event === "complete") {
        setPacketsSent(message.packets_sent);
        setStatus("Completed");
        setConnectionMessage(null);
      }
    };

    socket.onerror = () => {
      if (socketRef.current !== socket) {
        return;
      }

      setStatus("Error");
      setConnectionMessage(
        "WebSocket connection failed. Check that FastAPI is running on port 8000.",
      );
    };

    socket.onclose = () => {
      // Ignore closure events from outdated connections.
      if (socketRef.current !== socket) {
        return;
      }

      socketRef.current = null;

      if (manuallyStoppedRef.current) {
        setStatus("Disconnected");
        setConnectionMessage(null);
        return;
      }

      // Preserve completed demo sessions and error states.
      setStatus((previous) => {
        if (previous === "Completed" || previous === "Error") {
          return previous;
        }

        return "Disconnected";
      });

      // Explain unexpected disconnections.
      setConnectionMessage((previous) => {
        if (previous !== null) {
          return previous;
        }

        // Normal demo completion doesn't need an error message.
        if (mode === "demo") {
          return null;
        }

        return (
          "The live connection was closed. " +
          "You can reconnect without losing your session data."
        );
      });
    };
  }

  function stopStream() {
    manuallyStoppedRef.current = true;

    const socket = socketRef.current;

    if (socket !== null) {
      socketRef.current = null;
      socket.close();
    }

    setStatus("Disconnected");
    setConnectionMessage(null);
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
            onClick={() => startStream(false)}
          >
            <Play size={16} />
            {mode === "demo" ? "Start Demo Stream" : "Start New Stream"}
          </button>

          <button
            type="button"
            className="capture-refresh-button"
            disabled={
              streaming || !hasConnectedBefore || status === "Completed"
            }
            onClick={() => startStream(true)}
          >
            <Radio size={16} />
            Reconnect
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
            setTotalPacketsReceived(0);
            setTotalSessionBytes(0);
            setConnectionMessage(null);
            setHasConnectedBefore(false);
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
            setTotalPacketsReceived(0);
            setTotalSessionBytes(0);
            setConnectionMessage(null);
            setHasConnectedBefore(false);
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

          <h2>{totalPacketsReceived.toLocaleString()}</h2>
          <p>Events received from FastAPI</p>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span>Total Bytes</span>
          </div>

          <h2>{totalSessionBytes.toLocaleString()}</h2>
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

      {/* Connection errors and unexpected disconnections. */}
      {connectionMessage && (
        <p role="alert" className="capture-error">
          {connectionMessage}
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

      <PacketExplorer
        packets={packets}
        sourceLabel={mode === "demo" ? "Demo stream" : "Live stream"}
      />
    </div>
  );
}

export default LiveTrafficStream;
