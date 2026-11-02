
import logging
import os
import sys


LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | "
    "%(name)s | %(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

VALID_LEVELS = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}


def configure_logging():
    """
    Configure consistent logging for NetScope.

    Use the NETSCOPE_LOG_LEVEL environment variable
    to control logging verbosity.
    """

    level_name = os.environ.get(
        "NETSCOPE_LOG_LEVEL",
        "INFO",
    ).upper()

    if level_name not in VALID_LEVELS:
        level_name = "INFO"

    logger = logging.getLogger("netscope")

    logger.setLevel(
        getattr(logging, level_name)
    )

    # Avoid attaching duplicate handlers when called
    # more than once during application startup.
    if not any(
        getattr(handler, "_netscope_managed", False)
        for handler in logger.handlers
    ):
        handler = logging.StreamHandler(sys.stderr)

        handler.setFormatter(
            logging.Formatter(
                fmt=LOG_FORMAT,
                datefmt=DATE_FORMAT,
            )
        )

        handler._netscope_managed = True
        logger.addHandler(handler)

    # Prevent duplicate messages from propagating
    # to the root logger.
    logger.propagate = False

    return logger
