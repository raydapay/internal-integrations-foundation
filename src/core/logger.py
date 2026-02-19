import json
import logging
import sys

import httpx
from loguru import logger

from src.config.settings import settings


class InterceptHandler(logging.Handler):
    """Intercepts standard logging messages and routes them to Loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )

class SeqSink:
    """Synchronous sink for sending logs to Seq via HTTP."""

    def __init__(self, server_url: str, api_key: str | None = None):
        self.server_url = f"{server_url.rstrip('/')}/api/events/raw"
        self.api_key = api_key
        # Timeout increased slightly to prevent flakiness
        self.client = httpx.Client(timeout=4.0)

    def write(self, message: str) -> None:
        """Writes a log record to Seq."""
        try:
            data = json.loads(message)
            record = data["record"]

            payload = {
                "Timestamp": record["time"]["repr"],
                "Level": record["level"]["name"],
                "MessageTemplate": record["message"],
                "Properties": {
                    **record["extra"],
                    "Function": record["function"],
                    "Module": record["module"],
                    "Line": record["line"],
                    "Process": record["process"].get("name"),
                }
            }

            if record.get("exception"):
                payload["Exception"] = record["exception"]["text"]

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-Seq-ApiKey"] = self.api_key

            resp = self.client.post(self.server_url, json={"Events": [payload]}, headers=headers)

            if resp.status_code >= 400:
                sys.stderr.write(f"Seq API Error {resp.status_code}: {resp.text}\n")

        except Exception as e:
            sys.stderr.write(f"Failed to send log to Seq: {e}\nPayload: {message}\n")

def configure_logging() -> None:
    """Configures Loguru to capture system logs and output to Seq and Console."""
    logger.remove()

    # 1. Console Sink
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )

    # 2. Seq Sink
    api_key = getattr(settings, "SEQ_API_KEY", None)

    if settings.SEQ_URL:
        logger.add(
            SeqSink(settings.SEQ_URL, api_key=api_key),
            level="INFO",
            format="{message}",
            serialize=True,     # Loguru serializes to JSON string
            enqueue=True,       # Runs in background thread
            backtrace=True,
            diagnose=True,
        )

    # 3. Intercept Standard Library Logs
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)

    # 4. Aggressive Suppression of Infinite Recursion
    # httpx/httpcore log at INFO by default. We must disable propagation to root
    # to ensure InterceptHandler never sees these logs.
    for _lib in ["httpx", "httpcore"]:
        _log = logging.getLogger(_lib)
        _log.setLevel(logging.WARNING) # Only allow warnings/errors
        _log.propagate = False         # Stop log bubbling to root
        _log.handlers = []             # Remove any attached handlers

    for _log in ["uvicorn", "uvicorn.error", "fastapi"]:
        _logger = logging.getLogger(_log)
        _logger.handlers = [InterceptHandler()]
        _logger.propagate = False

    logger.info("Logging configured. Forwarding to Seq: {}", settings.SEQ_URL)