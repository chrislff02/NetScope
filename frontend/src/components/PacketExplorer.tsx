import { useMemo, useState } from "react";
import { Search, X, ChevronLeft, ChevronRight } from "lucide-react";

import type { Packet } from "../services/api";

interface PacketExplorerProps {
  packets: Packet[];
  sourceLabel?: string;
}

const PAGE_SIZE = 10;

function PacketExplorer({
  packets,
  sourceLabel = "Saved capture",
}: PacketExplorerProps) {
  // Search text entered by the user.
  const [search, setSearch] = useState("");

  // Currently selected protocol filter.
  const [protocol, setProtocol] = useState("All");

  // Current table page.
  const [page, setPage] = useState(1);

  // Packet selected for detailed inspection.
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);

  // Filter packets by search text and protocol.
  const filteredPackets = useMemo(() => {
    const query = search.trim().toLowerCase();

    return packets.filter((packet) => {
      const matchesProtocol =
        protocol === "All" || packet.protocol === protocol;

      const searchableValues = [
        packet.source_ip,
        packet.destination_ip,
        packet.protocol,
        packet.source_port?.toString() ?? "",
        packet.destination_port?.toString() ?? "",
        packet.timestamp,
      ]
        .join(" ")
        .toLowerCase();

      return matchesProtocol && searchableValues.includes(query);
    });
  }, [packets, search, protocol]);

  // Distinguish an empty capture from filters
  // that return no matching packets.
  const hasPackets = packets.length > 0;
  const hasActiveFilters = search.trim() !== "" || protocol !== "All";

  // Calculate how many pages we need.
  const totalPages = Math.max(1, Math.ceil(filteredPackets.length / PAGE_SIZE));

  // Display only the packets on the current page.
  const currentPage = Math.min(page, totalPages);

  const visiblePackets = filteredPackets.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE,
  );

  function updateSearch(value: string) {
    setSearch(value);
    setPage(1);
    setSelectedPacket(null);
  }

  function updateProtocol(value: string) {
    setProtocol(value);
    setPage(1);
    setSelectedPacket(null);
  }

  return (
    <section className="packet-explorer">
      <div className="panel explorer-panel">
        {/* Search and filter controls */}
        <div className="explorer-toolbar">
          <div className="search-box">
            <Search size={17} />

            <input
              type="text"
              aria-label="Search packet records"
              placeholder="Search IP addresses, ports, timestamps..."
              value={search}
              onChange={(event) => updateSearch(event.target.value)}
            />
          </div>

          <div className="protocol-filters">
            {["All", "TCP", "UDP", "ICMP"].map((item) => (
              <button
                key={item}
                type="button"
                className={`filter-button ${
                  protocol === item ? "selected" : ""
                }`}
                aria-pressed={protocol === item}
                onClick={() => updateProtocol(item)}
              >
                {item}
              </button>
            ))}
          </div>
        </div>

        {/* Results summary */}
        <div className="explorer-summary">
          <span>
            Showing {filteredPackets.length} of {packets.length} packets
          </span>

          <span>{sourceLabel}</span>
        </div>

        {/* Packet table */}
        <div className="table-container">
          <table aria-label={`${sourceLabel} packet records`}>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Source Port</th>
                <th>Destination Port</th>
                <th>Size</th>
              </tr>
            </thead>

            <tbody>
              {visiblePackets.map((packet, index) => (
                <tr
                  key={`${packet.timestamp}-${index}`}
                  className="clickable-row"
                  tabIndex={0}
                  onClick={() => setSelectedPacket(packet)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setSelectedPacket(packet);
                    }
                  }}
                >
                  <td>{packet.timestamp.slice(11, 23)}</td>

                  <td>{packet.source_ip}</td>

                  <td>{packet.destination_ip}</td>

                  <td>
                    <span
                      className={`protocol-badge ${packet.protocol.toLowerCase()}`}
                    >
                      {packet.protocol}
                    </span>
                  </td>

                  <td>{packet.source_port ?? "—"}</td>

                  <td>{packet.destination_port ?? "—"}</td>

                  <td>{packet.size} B</td>
                </tr>
              ))}
            </tbody>
          </table>

          {visiblePackets.length === 0 && (
            <div className="explorer-empty" role="status">
              {!hasPackets ? (
                <div>
                  <p>No packet data available.</p>
                  <span>
                    {sourceLabel === "Live stream"
                      ? "Start a live stream and capture network traffic to see packets here."
                      : sourceLabel === "Demo stream"
                        ? "Start the demo stream to receive simulated packets."
                        : "Capture or load packet data to explore network traffic."}
                  </span>
                </div>
              ) : hasActiveFilters ? (
                <div>
                  <p>No packets match your filters.</p>
                  <span>Try a different search term or protocol filter.</span>
                </div>
              ) : (
                <p>No packets to display.</p>
              )}
            </div>
          )}
        </div>

        {/* Pagination */}
        <div className="pagination">
          <span>
            Page {currentPage} of {totalPages}
          </span>

          <div className="pagination-buttons">
            <button
              disabled={currentPage === 1}
              onClick={() => setPage(currentPage - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft size={18} />
            </button>

            <button
              disabled={currentPage === totalPages}
              onClick={() => setPage(currentPage + 1)}
              aria-label="Next page"
            >
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      </div>

      {/* Selected packet details */}
      {selectedPacket && (
        <div className="panel packet-details">
          <div className="details-header">
            <h3>Packet Details</h3>

            <button
              onClick={() => setSelectedPacket(null)}
              aria-label="Close packet details"
            >
              <X size={18} />
            </button>
          </div>

          <div className="details-grid">
            <div>
              <span>Timestamp</span>
              <strong>{selectedPacket.timestamp}</strong>
            </div>

            <div>
              <span>Protocol</span>
              <strong>{selectedPacket.protocol}</strong>
            </div>

            <div>
              <span>Source IP</span>
              <strong>{selectedPacket.source_ip}</strong>
            </div>

            <div>
              <span>Destination IP</span>
              <strong>{selectedPacket.destination_ip}</strong>
            </div>

            <div>
              <span>Source Port</span>
              <strong>{selectedPacket.source_port ?? "N/A"}</strong>
            </div>

            <div>
              <span>Destination Port</span>
              <strong>{selectedPacket.destination_port ?? "N/A"}</strong>
            </div>

            <div>
              <span>TCP Flags</span>
              <strong>{selectedPacket.tcp_flags ?? "N/A"}</strong>
            </div>

            <div>
              <span>Packet Size</span>
              <strong>{selectedPacket.size} bytes</strong>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default PacketExplorer;
