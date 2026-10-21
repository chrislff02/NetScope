export interface Packet {
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port: number | null;
  destination_port: number | null;
  tcp_flags: string | null;
  size: number;
}

export interface TrafficSummary {
  total_packets: number;
  total_bytes: number;
  protocol_counts: Record<string, number>;
  protocol_bytes: Record<string, number>;
  unique_source_ips: number;
  unique_destination_ips: number;
  top_source_ips: [string, number][];
  top_destination_ports: [number, number][];
  traffic_over_time: Record<string, { packets: number; bytes: number }>;
}

export interface PacketResponse {
  total: number;
  packets: Packet[];
}

// Retrieve JSON data and handle unsuccessful responses.
async function fetchJSON<T>(
  endpoint: string,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(endpoint, { signal });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return (await response.json()) as T;
}

// Retrieve network traffic statistics.
export function getTrafficSummary(signal?: AbortSignal) {
  return fetchJSON<TrafficSummary>("/api/traffic/summary", signal);
}

// Retrieve individual packet records.
export function getPackets(signal?: AbortSignal) {
  return fetchJSON<PacketResponse>("/api/traffic/packets", signal);
}

export interface LiveCapture {
  source: string;
  interface: string;
  raw_packets_captured: number;
  packets: Packet[];
  statistics: TrafficSummary;
}

// Retrieve the most recently completed live capture.
export function getLatestCapture(signal?: AbortSignal) {
  return fetchJSON<LiveCapture>("/api/capture/latest", signal);
}
