
import logging
import sys
from pathlib import Path

import pytest


BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from logging_config import configure_logging


@pytest.fixture(autouse=True)
def restore_logging_state():
    """
    Restore the shared logger after each test.
    """

    logger = logging.getLogger("netscope")

    original_level = logger.level
    original_handlers = logger.handlers[:]
    original_propagate = logger.propagate

    yield

    for handler in logger.handlers[:]:
        if handler not in original_handlers:
            logger.removeHandler(handler)
            handler.close()

    logger.handlers = original_handlers
    logger.setLevel(original_level)
    logger.propagate = original_propagate


def test_logging_defaults_to_info(monkeypatch):
    monkeypatch.delenv(
        "NETSCOPE_LOG_LEVEL",
        raising=False,
    )

    logger = configure_logging()

    assert logger.level == logging.INFO
    assert logger.propagate is False


def test_logging_supports_debug(monkeypatch):
    monkeypatch.setenv(
        "NETSCOPE_LOG_LEVEL",
        "DEBUG",
    )

    logger = configure_logging()

    assert logger.level == logging.DEBUG


def test_invalid_log_level_defaults_to_info(monkeypatch):
    monkeypatch.setenv(
        "NETSCOPE_LOG_LEVEL",
        "INVALID",
    )

    logger = configure_logging()

    assert logger.level == logging.INFO


def test_logging_does_not_duplicate_handlers(monkeypatch):
    monkeypatch.delenv(
        "NETSCOPE_LOG_LEVEL",
        raising=False,
    )

    configure_logging()

    logger = logging.getLogger("netscope")

    before = len(logger.handlers)

    configure_logging()

    after = len(logger.handlers)

    assert after == before
