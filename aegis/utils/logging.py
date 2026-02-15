"""
Aegis logging utilities.

Print-based logging with severity levels, timestamps, and module tags.
Designed to be easily swapped for Python's `logging` module later.

Usage:
    from aegis.utils.logging import log

    log.info("server", "Proxy started on port 8080")
    log.warn("shield", "Canary leak detected!")
    log.error("vault", "Encryption key not set")
    log.debug("lens", f"Normalized {count} characters")
"""

import sys
from datetime import datetime, timezone
from enum import IntEnum


class LogLevel(IntEnum):
    """Log severity levels."""
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3


# Mapping from string names to enum values
_LEVEL_MAP: dict[str, LogLevel] = {
    "DEBUG": LogLevel.DEBUG,
    "INFO": LogLevel.INFO,
    "WARN": LogLevel.WARN,
    "WARNING": LogLevel.WARN,
    "ERROR": LogLevel.ERROR,
}

# ANSI color codes for terminal output
_COLORS: dict[LogLevel, str] = {
    LogLevel.DEBUG: "\033[36m",   # Cyan
    LogLevel.INFO: "\033[32m",    # Green
    LogLevel.WARN: "\033[33m",    # Yellow
    LogLevel.ERROR: "\033[31m",   # Red
}
_RESET = "\033[0m"


class AegisLogger:
    """Simple print-based logger with severity filtering and module tags."""

    def __init__(self, min_level: str = "INFO", use_color: bool = True):
        self._min_level: LogLevel = _LEVEL_MAP.get(min_level.upper(), LogLevel.INFO)
        self._use_color = use_color

    def set_level(self, level: str) -> None:
        """Update the minimum log level."""
        self._min_level = _LEVEL_MAP.get(level.upper(), LogLevel.INFO)

    def _emit(self, level: LogLevel, module: str, message: str) -> None:
        """Format and print a log line if it meets the severity threshold."""
        if level < self._min_level:
            return

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        level_name = level.name.ljust(5)

        if self._use_color:
            color = _COLORS.get(level, "")
            line = f"{color}[{timestamp}] [{level_name}] [{module}]{_RESET} {message}"
        else:
            line = f"[{timestamp}] [{level_name}] [{module}] {message}"

        # Errors go to stderr, everything else to stdout
        stream = sys.stderr if level >= LogLevel.ERROR else sys.stdout
        print(line, file=stream)

    def debug(self, module: str, message: str) -> None:
        """Log a debug-level message."""
        self._emit(LogLevel.DEBUG, module, message)

    def info(self, module: str, message: str) -> None:
        """Log an info-level message."""
        self._emit(LogLevel.INFO, module, message)

    def warn(self, module: str, message: str) -> None:
        """Log a warning-level message."""
        self._emit(LogLevel.WARN, module, message)

    def error(self, module: str, message: str) -> None:
        """Log an error-level message."""
        self._emit(LogLevel.ERROR, module, message)


# Global logger instance
log = AegisLogger()
