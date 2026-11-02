
import json
import os
import stat
import sys
from pathlib import Path

import pytest

# Allow tests to import our backend modules.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

import live_capture


@pytest.fixture
def capture_path(tmp_path, monkeypatch):
    # Use a temporary directory instead of real capture data.
    output_file = tmp_path / "data" / "live_capture.json"

    # Redirect the capture output to our test location.
    monkeypatch.setattr(
        live_capture,
        "CAPTURE_OUTPUT",
        output_file,
    )

    return output_file


@pytest.fixture
def sample_capture():
    # Simulated capture metadata.
    return {
        "source": "live_capture",
        "interface": "en0",
        "raw_packets_captured": 2,
        "packets": [
            {
                "timestamp": "2026-10-23T12:00:00.100",
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "protocol": "ICMP",
                "source_port": None,
                "destination_port": None,
                "tcp_flags": None,
                "size": 98,
            },
        ],
        "statistics": {
            "total_packets": 1,
            "total_bytes": 98,
        },
    }


def test_save_capture_creates_json(capture_path, sample_capture):
    # Save the synthetic capture.
    live_capture.save_capture_data(sample_capture)

    # Verify the file was created.
    assert capture_path.is_file()

    # Verify the saved content matches the original.
    with capture_path.open(encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data == sample_capture


def test_capture_file_permissions(capture_path, sample_capture):
    # Save the test capture.
    live_capture.save_capture_data(sample_capture)

    # Check file permission bits.
    file_mode = stat.S_IMODE(os.stat(capture_path).st_mode)

    # Only the owner should have read/write permissions.
    assert file_mode == 0o600


def test_capture_replaces_previous_file(
    capture_path,
    sample_capture,
):
    # Save the first recording.
    live_capture.save_capture_data(sample_capture)

    # Modify the recording.
    updated_capture = {
        **sample_capture,
        "raw_packets_captured": 10,
    }

    # Save the updated recording.
    live_capture.save_capture_data(updated_capture)

    # Verify the newest recording replaced the original.
    with capture_path.open(encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data["raw_packets_captured"] == 10

    # Confirm no temporary files remain.
    assert list(capture_path.parent.glob(".capture-*.tmp")) == []


def test_failed_save_preserves_previous_capture(
    capture_path,
    sample_capture,
):
    # First, save valid metadata.
    live_capture.save_capture_data(sample_capture)

    # Sets cannot be serialized directly to JSON.
    invalid_capture = {
        "packets": {"invalid", "data"},
    }

    # Saving should raise a serialization error.
    with pytest.raises(TypeError):
        live_capture.save_capture_data(invalid_capture)

    # The existing valid recording should be unchanged.
    with capture_path.open(encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data == sample_capture

    # Failed temporary files should be removed.
    assert list(capture_path.parent.glob(".capture-*.tmp")) == []

def test_live_capture_streams_packet_metadata(monkeypatch):
    """
    Verify that live capture forwards packet metadata
    and preserves the completed capture data.
    """

    sample_record = {
        "timestamp": "2026-10-29T13:00:00.000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size": 120,
    }

    forwarded = []
    saved = []

    class FakeForwarder:
        def start(self):
            pass

        def enqueue(self, packet):
            forwarded.append(packet)
            return True

        def stop(self, timeout=5):
            return True

        
        def get_statistics(self):
            return {
                "queued": len(forwarded),
                "sent": len(forwarded),
                "failed": 0,
                "dropped": 0,
                "shutdown_dropped": 0,
                "pending": 0,
                "in_flight": 0,
            }


    # Simulate capturing one packet.
    def fake_sniff(**kwargs):
        kwargs["prn"](object())

    # Replace real components with test doubles.
    monkeypatch.setattr(
        live_capture,
        "PacketForwarder",
        FakeForwarder,
    )

    monkeypatch.setattr(
        live_capture,
        "packet_to_dict",
        lambda packet: sample_record.copy(),
    )

    monkeypatch.setattr(
        live_capture,
        "sniff",
        fake_sniff,
    )

    # Prevent overwriting your real capture file.
    monkeypatch.setattr(
        live_capture,
        "save_capture_data",
        lambda data: saved.append(data),
    )

    # Run the capture with streaming enabled.
    live_capture.start_live_capture(
        interface="en0",
        max_packets=1,
        timeout=1,
        protocol="tcp",
        stream=True,
    )

    # Verify forwarding.
    assert forwarded == [sample_record]

    # Verify the completed capture was preserved.
    assert len(saved) == 1
    assert saved[0]["packets"] == [sample_record]

    assert saved[0]["statistics"]["total_packets"] == 1
    assert saved[0]["statistics"]["total_bytes"] == 120