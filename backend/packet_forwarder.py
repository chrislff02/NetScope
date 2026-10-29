
import queue
import threading
import time

from packet_sender import send_packet_metadata


class PacketForwarder:
    """
    Forward packet metadata in a background thread.

    Scapy can enqueue packet records without waiting
    for Unix socket communication to complete.
    """

    def __init__(
        self,
        max_queue_size=500,
        send_function=None,
    ):
        if (
            type(max_queue_size) is not int
            or max_queue_size < 1
        ):
            raise ValueError(
                "Queue size must be a positive integer."
            )

        self.packet_queue = queue.Queue(
            maxsize=max_queue_size
        )

        self.send_function = (
            send_function
            if send_function is not None
            else send_packet_metadata
        )

        self.stop_event = threading.Event()
        self.worker = None

        self._lock = threading.Lock()
        self._running = False

        # Forwarding statistics.
        self.queued_packets = 0
        self.sent_packets = 0
        self.failed_packets = 0
        self.dropped_packets = 0

    def start(self):
        """
        Start the background sender thread.
        """

        with self._lock:
            if self._running or self.worker is not None:
                raise RuntimeError(
                    "Packet forwarder has already started."
                )

            self._running = True
            self.stop_event.clear()

            self.worker = threading.Thread(
                target=self._run,
                name="NetScopePacketForwarder",
                daemon=True,
            )

            self.worker.start()

    def enqueue(self, packet):
        """
        Add packet metadata without blocking Scapy.

        Returns False if the queue is full or the
        forwarder is not accepting new packets.
        """

        with self._lock:
            if not self._running:
                return False

            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                self.dropped_packets += 1
                return False

            self.queued_packets += 1
            return True

    def _run(self):
        """
        Send queued packets in the background.
        """

        while True:
            if (
                self.stop_event.is_set()
                and self.packet_queue.empty()
            ):
                break

            try:
                packet = self.packet_queue.get(
                    timeout=0.1
                )
            except queue.Empty:
                continue

            try:
                success = self.send_function(packet)

                with self._lock:
                    if success:
                        self.sent_packets += 1
                    else:
                        self.failed_packets += 1

            except Exception:
                # A failed send must not kill the worker.
                with self._lock:
                    self.failed_packets += 1

            finally:
                self.packet_queue.task_done()

    def stop(self, timeout=5):
        """
        Stop accepting new packets and attempt to
        finish sending queued packets.

        Returns True if the worker stops within the
        timeout, otherwise False.
        """

        if timeout < 0:
            raise ValueError(
                "Timeout must not be negative."
            )

        with self._lock:
            if self.worker is None:
                return True

            self._running = False
            self.stop_event.set()
            worker = self.worker

        if threading.current_thread() is worker:
            raise RuntimeError(
                "Forwarder cannot join its own thread."
            )

        worker.join(timeout=timeout)

        return not worker.is_alive()

    def get_statistics(self):
        """
        Return a snapshot of forwarding statistics.
        """

        with self._lock:
            return {
                "queued": self.queued_packets,
                "sent": self.sent_packets,
                "failed": self.failed_packets,
                "dropped": self.dropped_packets,
                "pending": self.packet_queue.qsize(),
                "running": self._running,
                "worker_alive": (
                    self.worker is not None
                    and self.worker.is_alive()
                ),
            }
