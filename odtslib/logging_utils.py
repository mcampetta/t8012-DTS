from __future__ import annotations

import logging
import sys
from pathlib import Path


def configure_logging(level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    logger = logging.getLogger("odts")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter("%(levelname)s %(message)s")

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(Path(log_file), encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(file_handler)

    return logger
