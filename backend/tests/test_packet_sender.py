
import asyncio
import socket
import sys
import tempfile
import threading

from pathlib import Path

import pytest


# Allow importing modules from backend/.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from packet_receiver import handle_connection
from packet_sender import send_packet_metadata


@pytest.fixture
def sample_packet():
    return {
        "timestamp": "2026-10-29T09:00:00.000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size": 120,
    }


def test_sender_rejects_oversized_message():
    packet = {
        "payload": "X" * 5000,
    }

    assert send_packet_metadata(packet) is False


def test_sender_handles_missing_socket(tmp_path, sample_packet):
    socket_path = tmp_path / "missing.sock"

    assert send_packet_metadata(
        sample_packet,
        socket_path=socket_path,
    ) is False


def test_sender_handles_invalid_packet():
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"
        ready = threading.Event()
        errors = []

        def run_server():
            async def serve():
                server = await asyncio.start_unix_server(
                    handle_connection,
                    path=str(socket_path),
                    limit=4097,
                )

                ready.set()

                try:
                    async with server:
                        await server.serve_forever()
                finally:
                    server.close()
                    await server.wait_closed()

            try:
                asyncio.run(serve())
            except Exception as error:
                errors.append(error)
                ready.set()

        # Instead of running an infinite server in this test,
        # use a single-connection synchronous receiver.
        def receive_once():
            try:
                with socket.socket(
                    socket.AF_UNIX,
                    socket.SOCK_STREAM,
                ) as listener:
                    listener.bind(str(socket_path))
                    listener.listen(1)
                    ready.set()

                    connection, _ = listener.accept()

                    with connection:
                        connection.settimeout(3)
                        data = bytearray()

                        while not data.endswith(b"\n"):
                            chunk = connection.recv(4096)

                            if not chunk:
                                break

                            data.extend(chunk)

                        # Simulate the receiver rejecting a packet.
                        connection.sendall(
                            b'{"status":"rejected"}\n'
                        )

            except Exception as error:
                errors.append(error)
                ready.set()

        thread = threading.Thread(
            target=receive_once,
            daemon=True,
        )
        thread.start()

        assert ready.wait(timeout=3)

        invalid_packet = {
            **{
                "timestamp": "2026-10-29T09:00:00.000",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.10",
                "protocol": "INVALID",
                "source_port": 50000,
                "destination_port": 443,
                "tcp_flags": "S",
                "size": 120,
            },
        }

        assert send_packet_metadata(
            invalid_packet,
            socket_path=socket_path,
        ) is False

        thread.join(timeout=3)

        assert not thread.is_alive()
        assert not errors
