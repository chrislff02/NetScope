
import asyncio
import json
import socket
import stat
import sys
import tempfile
from pathlib import Path

import pytest

# Allow tests to import the backend modules.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))


from packet_receiver import (
    validate_packet,
    handle_connection,
    read_packet_message,
    remove_owned_socket,
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


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b'{"protocol":"TCP"}',
        b"not valid json\n",
        b"\n",
        b"x" * 5000 + b"\n",
    ],
)
def test_invalid_message_framing(message):
    async def run_test():
        # Simulate an incoming message.
        reader = asyncio.StreamReader(limit=4097)

        reader.feed_data(message)
        reader.feed_eof()

        # Invalid messages must be rejected.
        with pytest.raises(ValueError):
            await read_packet_message(reader)

    asyncio.run(run_test())


def test_valid_message_reader(sample_packet):
    async def run_test():
        reader = asyncio.StreamReader(limit=4097)

        # Create a complete newline-delimited JSON message.
        message = (
            json.dumps(sample_packet) + "\n"
        ).encode("utf-8")

        reader.feed_data(message)

        packet = await read_packet_message(reader)

        assert packet == sample_packet

    asyncio.run(run_test())


def test_socket_cleanup_preserves_replacement():
    # Create a short temporary directory for the Unix socket.
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        # Create a real Unix domain socket.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(str(socket_path))

            original_inode = socket_path.lstat().st_ino

            # Simulate the original socket being replaced.
            socket_path.unlink()
            socket_path.write_text("replacement")

            # Cleanup should not delete the replacement file.
            remove_owned_socket(
                socket_path,
                original_inode,
            )

            assert socket_path.read_text() == "replacement"


def test_socket_cleanup_removes_original():
    # Use a short path to avoid macOS socket path limits.
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        # Create a real Unix domain socket.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(str(socket_path))

            original_inode = socket_path.lstat().st_ino

            # Remove the original socket.
            remove_owned_socket(
                socket_path,
                original_inode,
            )

            assert not socket_path.exists()


def test_unix_socket_connection(sample_packet):
    # Create a short temporary socket path.
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        async def run_test():
            # Start a real Unix domain socket server.
            server = await asyncio.start_unix_server(
                handle_connection,
                path=str(socket_path),
                limit=4097,
            )

            try:
                # Connect a client through the local socket.
                reader, writer = await asyncio.open_unix_connection(
                    str(socket_path)
                )

                try:
                    # Convert the sample packet to JSON.
                    message = json.dumps(sample_packet) + "\n"

                    # Send the packet to the receiver.
                    writer.write(message.encode("utf-8"))
                    await writer.drain()

                    # Read the receiver's acknowledgment.
                    response = await asyncio.wait_for(
                        reader.readline(),
                        timeout=5,
                    )

                    assert json.loads(response) == {
                        "status": "accepted"
                    }

                finally:
                    # Close the client connection.
                    writer.close()
                    await writer.wait_closed()

            finally:
                # Stop the Unix socket server.
                server.close()
                await server.wait_closed()

                # Remove any remaining socket file.
                socket_path.unlink(missing_ok=True)

        asyncio.run(run_test())
