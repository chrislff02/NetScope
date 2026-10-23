import { useEffect, useRef, useState } from "react";
import { Play, Square, Radio } from "lucide-react";

import type { Packet } from "../services/api";
import PacketExplorer from "./PacketExplorer";

type StreamStatus =
  | "Disconnected"
  | "Connecting"
  | "Connected"
  | "Completed"
  | "Error";

interface PacketEvent {
  event: "packet";
  sequence: number;
  data: Packet;
}

interface CompleteEvent {
  event: "complete";
  packets_sent: number;
}

type StreamMessage = PacketEvent | CompleteEvent;

function LiveTrafficStream() {
  // Track the WebSocket connection.
  const socketRef = useRef<WebSocket | null>(null);

  // Track the current stream status.
  const [status, setStatus] = useState<StreamStatus>("Disconnected");

  // Store received packets.
  const [packets, setPackets] = useState<Packet[]>([]);

  // Store the completion count.
  const [packetsSent, setPacketsSent] = useState(0);

  // Open a new WebSocket connection.
  function startStream() {
    // Prevent multiple active connections.
    if (socketRef.current !== null) {
      return;
    }

    setPackets([]);
    setPacketsSent(0);
    setStatus("Connecting");

    // Use the same host as the current browser page.
    // Port 8000 is our local FastAPI backend.
    const socket = new WebSocket(
      `ws://${window.location.hostname}:8000/ws/traffic`,
    );

    socketRef.current = socket;

    socket.onopen = () => {
      setStatus("Connected");
    };

    socket.onmessage = (event: MessageEvent<string>) => {
      let message: StreamMessage;

      try {
        message = JSON.parse(event.data) as StreamMessage;
      } catch {
        setStatus("Error");
        socket.close();
        return;
      }

      if (message.event === "packet") {
        // Add each received packet to React state.
        setPackets((previous) => [...previous, message.data]);
      }

      if (message.event === "complete") {
        setPacketsSent(message.packets_sent);
        setStatus("Completed");
      }
    };

    socket.onerror = () => {
      setStatus("Error");
    };

    socket.onclose = () => {
      if (socketRef.current === socket) {
        socketRef.current = null;
      }

      // Avoid replacing Completed or Error status.
      setStatus((previous) =>
        previous === "Completed" || previous === "Error"
          ? previous
          : "Disconnected",
      );
    };
  }

  // Manually close the connection.
  function stopStream() {
    const socket = socketRef.current;

    if (socket) {
      socket.close();
      socketRef.current = null;
    }

    setStatus("Disconnected");
  }

  // Clean up when navigating away from this page.
  useEffect(() => {
    return () => {
      const socket = socketRef.current;

      if (socket) {
        socket.onopen = null;
        socket.onmessage = null;
        socket.onerror = null;
        socket.onclose = null;
        socket.close();
        socketRef.current = null;
      }
    };
  }, []);

  const streaming = status === "Connecting" || status === "Connected";

  const totalBytes = packets.reduce((total, packet) => total + packet.size, 0);

  return (
    <div className="live-stream-page">
      <div className="capture-toolbar">
        <div>
          <h2>Live Traffic Stream</h2>
          <p>Receive simulated packet events through FastAPI WebSockets.</p>
        </div>

        <div className="stream-controls">
          <button
            className="capture-refresh-button"
            disabled={streaming}
            onClick={startStream}
          >
            <Play size={16} />
            Start Demo Stream
          </button>

          <button
            className="stream-stop-button"
            disabled={!streaming}
            onClick={stopStream}
          >
            <Square size={16} />
            Stop
          </button>
        </div>
      </div>

      {/* Connection status */}
      <div className="capture-info">
        <Radio size={16} />
        <span>Connection: {status}</span>
        <span>Mode: Synthetic WebSocket data</span>
      </div>

      {/* Stream statistics */}
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
            <span>Packets Sent</span>
          </div>
          <h2>{packetsSent}</h2>
          <p>Reported after demo completion</p>
        </div>
      </section>

      {status === "Error" && (
        <p role="alert" className="capture-error">
          WebSocket connection failed. Check that FastAPI is running on port
          8000.
        </p>
      )}

      {/* Reuse our existing Packet Explorer */}
      <div className="capture-packets-heading">
        <h3>Incoming Packets</h3>
        <p>Packet records received during this demo session.</p>
      </div>

      <PacketExplorer packets={packets} />
    </div>
  );
}

export default LiveTrafficStream;
