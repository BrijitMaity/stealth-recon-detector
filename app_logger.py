"""
app_logger.py — Centralized Structured Logging for the Stealth Reconnaissance Detection System.

Provides a unified logging interface with:
  - Rotating file handler (auto-rotate at configurable size, keep N backups)
  - Console handler with ANSI color formatting
  - JSON-structured log entries for SIEM integration
  - Module-level logger names for traceability
  - Thread-safe operation

Usage:
    from app_logger import get_logger
    log = get_logger(__name__)
    log.info("System started", extra={"component": "monitor"})
"""

import logging
import logging.handlers
import json
import os
import sys
import threading
import datetime
from rich.logging import RichHandler


# (Removed custom ColoredConsoleFormatter as RichHandler natively handles beautiful output)


class JSONFormatter(logging.Formatter):
    """JSON-structured formatter for file output and SIEM ingestion.

    Each line is a valid JSON object containing:
      - timestamp (ISO 8601)
      - level
      - logger (module name)
      - message
      - thread
      - Any extra fields passed via ``extra={}``
    """

    # Fields from LogRecord that we always include
    _BASE_FIELDS = {
        "name", "msg", "args", "created", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs", "pathname",
        "process", "processName", "relativeCreated", "stack_info",
        "thread", "threadName", "exc_info", "exc_text", "message",
        "taskName",
    }

    def format(self, record):
        log_entry = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "thread": record.threadName,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        # Include any extra fields the caller passed
        for key, value in record.__dict__.items():
            if key not in self._BASE_FIELDS and not key.startswith("_"):
                try:
                    json.dumps(value)  # Ensure serializable
                    log_entry[key] = value
                except (TypeError, ValueError):
                    log_entry[key] = str(value)

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


# ── Logger factory ───────────────────────────────────────────────────
_logger_lock = threading.Lock()
_initialized = False


def _configure_root_logger():
    """One-time setup of the root logger with console + file handlers."""
    global _initialized
    if _initialized:
        return

    with _logger_lock:
        if _initialized:
            return

        # Import config lazily to avoid circular imports
        try:
            from config import cfg
            log_level = getattr(logging, cfg.LOG_LEVEL.upper(), logging.INFO)
            log_file = cfg.LOG_FILE
            max_bytes = cfg.LOG_MAX_BYTES
            backup_count = cfg.LOG_BACKUP_COUNT
        except Exception:
            log_level = logging.INFO
            log_file = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "app.log"
            )
            max_bytes = 10 * 1024 * 1024
            backup_count = 5

        root = logging.getLogger("stealth")
        root.setLevel(log_level)

        # Prevent duplicate handlers on reimport
        if root.handlers:
            _initialized = True
            return

        # ── Console handler (Rich UI) ────────────────────────────────
        console_handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_time=True,
            show_path=False,
            omit_repeated_times=False
        )
        console_handler.setLevel(log_level)
        root.addHandler(console_handler)

        # ── File handler (JSON, rotating) ────────────────────────────
        env_log_file = os.environ.get("STEALTH_LOG_FILE_NAME")
        if env_log_file:
            log_file = os.path.join(os.path.dirname(log_file), env_log_file)
        elif sys.argv and sys.argv[0]:
            script_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
            if script_name and script_name not in ('python', 'pythonw', '-c'):
                name, ext = os.path.splitext(log_file)
                log_file = f"{name}_{script_name}{ext}"

        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
        except (OSError, ValueError):
            pass

        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(JSONFormatter())
            root.addHandler(file_handler)
        except Exception as e:
            # If file logging fails, continue with console only
            root.warning(f"File logging unavailable: {e}")

        _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Get a named logger under the ``stealth`` namespace.

    Parameters
    ----------
    name : str
        Typically ``__name__`` from the calling module.

    Returns
    -------
    logging.Logger
        A configured child logger of the root ``stealth`` logger.
    """
    _configure_root_logger()
    # Prefix all loggers under 'stealth.' namespace
    if not name.startswith("stealth."):
        name = f"stealth.{name}"
    return logging.getLogger(name)
