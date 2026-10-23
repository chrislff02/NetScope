
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
