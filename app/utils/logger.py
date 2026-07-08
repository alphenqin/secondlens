from __future__ import annotations

import sys
from pathlib import Path


def setup_logger(log_dir: str | Path = "logs"):
    try:
        from loguru import logger
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Missing loguru. Install dependencies with: python3 -m pip install -r requirements.txt") from exc

    path = Path(log_dir)
    path.mkdir(parents=True, exist_ok=True)
    logger.remove()
    logger.add(
        sys.stdout,
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {message}",
    )
    logger.add(
        path / "secondlens.log",
        level="INFO",
        rotation="20 MB",
        retention="14 days",
        encoding="utf-8",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {name}:{function}:{line} | {message}",
    )
    return logger
