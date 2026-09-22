"""Logging setup shared by the CLI entry points."""

from __future__ import annotations

import logging
import sys
from typing import Optional

LOGGER_NAME = "dockersec"
DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def configure_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure the ``dockersec`` logger and return it.

    Logs go to stderr so that stdout stays reserved for the report, which keeps
    ``docker-security-scanner ... > report.txt`` usable.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(DEFAULT_FORMAT)

    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the scanner logger."""
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
