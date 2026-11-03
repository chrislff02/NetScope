
import queue
import threading
import time

from packet_sender import send_packet_metadata

import logging

from logging_config import configure_logging

configure_logging()
logger = logging.getLogger("netscope.forwarder")

class PacketForwarder:
    """
    Forward packet metadata through a background worker.

    Packets are queued without blocking Scapy.
    Shutdown waits for delivery up to a specified deadline.
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

        # Packet accounting.
        self.queued_packets = 0
        self.sent_packets = 0
        self.failed_packets = 0
        self.dropped_packets = 0

        # Records explicitly discarded during shutdown.
        self.shutdown_dropped_packets = 0

        # Packets currently being sent by the worker.
        self.in_flight_packets = 0

        # Tracks whether the worker should abandon
        # remaining queued records after the deadline.
        self._abort_pending = False

    def start(self):
        """
        Start the background sender exactly once.
        """

        with self._lock:
            if self._running or self.worker is not None:
                raise RuntimeError(
                    "Packet forwarder has already started."
                )

            self._running = True
            self.stop_event.clear()
            self._abort_pending = False

            self.worker = threading.Thread(
                target=self._run,
                name="NetScopePacketForwarder",
                daemon=True,
            )

            self.worker.start()

    def enqueue(self, packet):
        """
        Queue packet metadata without blocking capture.

        Return False when stopped or when the queue is full.
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
        Deliver queued records in the background.
        """

        while True:
            with self._lock:
                should_abort = self._abort_pending

            if should_abort:
                break

            if (
                self.stop_event.is_set()
                and self.packet_queue.empty()
            ):
                break

            try:
                packet = self.packet_queue.get(timeout=0.1)

            except queue.Empty:
                continue

            with self._lock:
                self.in_flight_packets += 1

            try:
                success = self.send_function(packet)

                with self._lock:
                    if success:
                        self.sent_packets += 1
                    else:
                        self.failed_packets += 1

            except Exception:
                # Record unexpected sender errors without
                # terminating the background worker.
                logger.exception(
                    "Unexpected error forwarding packet metadata."
                )

                with self._lock:
                    self.failed_packets += 1

            finally:
                with self._lock:
                    self.in_flight_packets -= 1

                self.packet_queue.task_done()

    def _discard_pending(self):
        """
        Remove records still waiting in the queue.

        This does not interrupt a send already in progress.
        """

        discarded = 0

        while True:
            try:
                self.packet_queue.get_nowait()

            except queue.Empty:
                break

            else:
                discarded += 1
                self.packet_queue.task_done()

        with self._lock:
            self.shutdown_dropped_packets += discarded

        return discarded

    def stop(self, timeout=5):
        """
        Attempt graceful shutdown within a deadline.

        Returns True only when the worker has stopped and
        all accepted records were processed.

        Returns False when the deadline expires or when
        delivery cannot complete within that time.
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

        # Allow the worker to drain the queue.
        worker.join(timeout=timeout)

       
        if worker.is_alive():
            # Tell the worker not to process further records.
            with self._lock:
                self._abort_pending = True

            # Account for records not yet sent.
            discarded = self._discard_pending()

            logger.warning(
                "Forwarder shutdown deadline reached. "
                "Discarded queued packets: %s. "
                "An in-progress send may still be active.",
                discarded,
            )

            # Do not block beyond the requested deadline.
            return False

        logger.debug(
            "Packet forwarding worker stopped successfully."
        )

        return True

    def get_statistics(self):
        """
        Return a thread-safe snapshot of packet accounting.
        """

        with self._lock:
            return {
                "queued": self.queued_packets,
                "sent": self.sent_packets,
                "failed": self.failed_packets,
                "dropped": self.dropped_packets,
                "shutdown_dropped": self.shutdown_dropped_packets,
                "pending": self.packet_queue.qsize(),
                "running": self._running,
                "worker_alive": (
                    self.worker is not None
                    and self.worker.is_alive()
                ),
                "in_flight": self.in_flight_packets,
            }
