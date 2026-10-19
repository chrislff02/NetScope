
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from scapy.all import rdpcap

from traffic_analysis import (
    packet_to_dict,
    calculate_statistics,
)


# Create our FastAPI application.
app = FastAPI(
    title="NetScope API",
    description="Network Traffic Analysis API",
    version="1.0.0",
)


# Locate the sample PCAP file.
BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_FILE = BASE_DIR / "samples" / "sample_traffic.pcap"


@lru_cache(maxsize=1)
def load_packet_records():
    # Load sample traffic and cache the results.
    if not PCAP_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="Sample PCAP file not found."
        )

    packets = rdpcap(str(PCAP_FILE))
    records = []

    # Convert Scapy packets into dictionaries.
    for packet in packets:
        record = packet_to_dict(packet)

        if record is not None:
            records.append(record)

    return records


@app.get("/api/health")
def health_check():
    # Confirm that our API is running.
    return {
        "status": "healthy",
        "application": "NetScope",
    }


@app.get("/api/traffic/summary")
def get_traffic_summary():
    # Return our calculated network statistics.
    records = load_packet_records()
    return calculate_statistics(records)


@app.get("/api/traffic/packets")
def get_packets():
    # Return individual packet records.
    records = load_packet_records()

    return {
        "total": len(records),
        "packets": records,
    }


@app.get("/api/traffic/timeline")
def get_traffic_timeline():
    # Return traffic grouped by second.
    records = load_packet_records()
    statistics = calculate_statistics(records)

    return statistics["traffic_over_time"]
