
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

# Allow our tests to import main.py.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

import main


# Create a test client for our FastAPI application.
client = TestClient(main.app)


@pytest.fixture(autouse=True)
def clear_packet_cache():
    # Clear cached packets before and after each test.
    main.load_packet_records.cache_clear()
    yield
    main.load_packet_records.cache_clear()


@pytest.fixture
def sample_records(monkeypatch):
    # Create predictable packet data for API testing.
    records = [
        {
            "timestamp": "2026-10-15T12:00:00.100",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "TCP",
            "source_port": 50000,
            "destination_port": 443,
            "tcp_flags": "S",
            "size": 100,
        },
        {
            "timestamp": "2026-10-15T12:00:01.200",
            "source_ip": "192.168.1.20",
            "destination_ip": "1.1.1.1",
            "protocol": "UDP",
            "source_port": 53000,
            "destination_port": 53,
            "tcp_flags": None,
            "size": 200,
        },
    ]

    # Replace the real PCAP loader with synthetic data.
    monkeypatch.setattr(
        main,
        "load_packet_records",
        lambda: records,
    )

    return records


def test_health_check():
    # Verify the API is running.
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "application": "NetScope",
    }


def test_traffic_summary(sample_records):
    # Verify our API calculates traffic statistics.
    response = client.get("/api/traffic/summary")

    assert response.status_code == 200

    data = response.json()

    assert data["total_packets"] == 2
    assert data["total_bytes"] == 300

    assert data["protocol_counts"] == {
        "TCP": 1,
        "UDP": 1,
    }

    assert data["unique_source_ips"] == 2
    assert data["unique_destination_ips"] == 2


def test_packet_endpoint(sample_records):
    # Verify individual packet records are returned.
    response = client.get("/api/traffic/packets")

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert len(data["packets"]) == 2

    assert data["packets"][0]["protocol"] == "TCP"
    assert data["packets"][1]["protocol"] == "UDP"


def test_traffic_timeline(sample_records):
    # Verify packets are grouped into time intervals.
    response = client.get("/api/traffic/timeline")

    assert response.status_code == 200

    data = response.json()

    assert data["2026-10-15T12:00:00"] == {
        "packets": 1,
        "bytes": 100,
    }

    assert data["2026-10-15T12:00:01"] == {
        "packets": 1,
        "bytes": 200,
    }


def test_missing_pcap_file(monkeypatch, tmp_path):
    # Simulate a missing PCAP file.
    missing_file = tmp_path / "missing.pcap"

    monkeypatch.setattr(
        main,
        "PCAP_FILE",
        missing_file,
    )

    # Verify the API returns a proper 404 response.
    response = client.get("/api/traffic/summary")

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Sample PCAP file not found."
    )
