
import asyncio
import json
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from packet_receiver import (
    validate_packet,
    handle_connection,
)


@pytest.fixture
def sample_packet():
    return {
        "timestamp": "2026-10-26T19:00:00.000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size": 120,
    }


def test_valid_packet(sample_packet):
    assert validate_packet(sample_packet) == sample_packet


@pytest.mark.parametrize(
    "field,value",
    [
        ("protocol", "INVALID"),
        ("source_ip", "not-an-ip"),
        ("destination_ip", "::1"),
        ("source_port", 70000),
        ("destination_port", -1),
        ("size", 0),
        ("size", True),
        ("timestamp", "invalid-date"),
        ("tcp_flags", "X" * 20),
    ],
)
def test_invalid_packet_fields(sample_packet, field, value):
    packet = {**sample_packet, field: value}

    with pytest.raises(ValueError):
        validate_packet(packet)


def test_missing_packet_field(sample_packet):
    packet = sample_packet.copy()
    del packet["source_ip"]

    with pytest.raises(ValueError):
        validate_packet(packet)


def test_extra_packet_field(sample_packet):
    packet = {**sample_packet, "payload": "private data"}

    with pytest.raises(ValueError):
        validate_packet(packet)


def test_valid_socket_message(sample_packet):
    async def run_test():
        received = []

        async def callback(reader, writer):
            await handle_connection(reader, writer)
            received.append(True)

        server = await asyncio.start_server(
            callback,
            host="127.0.0.1",
            port=0,
        )

        try:
            port = server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
            )

            writer.write(
                (json.dumps(sample_packet) + "\n").encode()
            )
            await writer.drain()

            response = await reader.readline()

            assert json.loads(response) == {
                "status": "accepted"
            }

            writer.close()
            await writer.wait_closed()

            assert received == [True]

        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_test())
