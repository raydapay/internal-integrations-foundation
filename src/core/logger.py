import inspect
import json
import logging
import sys
from typing import Any

import httpx
from fastapi import status
from loguru import logger

from src.config.settings import settings


def _sanitize_value(val: Any) -> Any:
    """Recursively sanitizes objects to remove raw memory addresses and ugly reprs."""
    if isinstance(val, dict):
        return {k: _sanitize_value(v) for k, v in val.items()}
    if isinstance(val, list | tuple | set):
        return type(val)(_sanitize_value(v) for v in val)

    # 1. Sanitize Callables and Coroutines (e.g., bound methods)
    if callable(val) or inspect.iscoroutinefunction(val):
        module = getattr(val, "__module__", "")
        qualname = getattr(val, "__qualname__", type(val).__name__)
        return f"{module}.{qualname}()" if module else f"{qualname}()"

    # 2. Sanitize Raw Memory Addresses (e.g., <sqlite3.Connection object at 0x...>)
    # We target objects that fall back to the default object.__repr__
    val_repr = repr(val)
    if "<" in val_repr and " at 0x" in val_repr:
        clean_name = val.__class__.__name__
        module = val.__class__.__module__
        return f"[{module}.{clean_name}]"

    return val


def log_patcher(record: dict[str, Any]) -> None:
    """Intercepts the Loguru record before it hits sinks to beautify payloads."""
    if "extra" in record:
        record["extra"] = _sanitize_value(record["extra"])

    if "args" in record:
        record["args"] = tuple(_sanitize_value(arg) for arg in record["args"])


class InterceptHandler(logging.Handler):
    """Intercepts standard logging messages and routes them to Loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


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
                },
            }

            if record.get("exception"):
                payload["Exception"] = record["exception"]["text"]

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-Seq-ApiKey"] = self.api_key

            resp = self.client.post(self.server_url, json={"Events": [payload]}, headers=headers)

            if resp.status_code >= status.HTTP_400_BAD_REQUEST:
                sys.stderr.write(f"Seq API Error {resp.status_code}: {resp.text}\n")

        except Exception as e:
            sys.stderr.write(f"Failed to send log to Seq: {e}\nPayload: {message}\n")


def configure_logging() -> None:
    """Configures Loguru to capture system logs and output to Seq and Console."""
    logger.remove()

    # Apply the global patcher for beautification
    logger.configure(patcher=log_patcher)

    # 1. Console Sink
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>"
        "{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )

    # 2. Seq Sink
    api_key = getattr(settings, "SEQ_API_KEY", None)

    if settings.SEQ_URL:
        logger.add(
            SeqSink(settings.SEQ_URL, api_key=api_key),
            level="INFO",
            format="{message}",
            serialize=True,  # Loguru serializes to JSON string (now using sanitized dicts)
            enqueue=True,  # Runs in background thread
            backtrace=True,
            diagnose=True,
        )

    # 3. Intercept Standard Library Logs at the root
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)

    # 4. Aggressive Interception of 3rd Party Loggers (Fixes missing worker logs)
    loggers_to_intercept = [
        "uvicorn",
        "uvicorn.error",
        "fastapi",
        "arq",  # Catches ARQ Worker internal logs
        "arq.worker",  # Catches ARQ Worker job execution telemetry
    ]

    for _log in loggers_to_intercept:
        _logger = logging.getLogger(_log)
        _logger.handlers = [InterceptHandler()]
        _logger.propagate = False

    # 5. Aggressive Suppression of Noisy HTTP Libraries
    for _lib in ["httpx", "httpcore"]:
        _log = logging.getLogger(_lib)
        _log.setLevel(logging.WARNING)
        _log.propagate = False
        _log.handlers = []

    logger.info("Logging configured. Forwarding to Seq: {}", settings.SEQ_URL)
