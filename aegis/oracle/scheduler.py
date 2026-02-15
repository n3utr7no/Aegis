"""
Oracle Scheduler — Stub for scheduling periodic security scans.

In the full implementation, this would run the scanner and briefer
on a configurable schedule (e.g., every 24 hours).
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.oracle.briefer import OracleBriefer, SecurityBrief
from aegis.oracle.scanner import OracleScanner
from aegis.utils.logging import log


@dataclass
class ScheduleConfig:
    """Configuration for the Oracle scheduler.

    Attributes:
        interval_hours: How often to scan (in hours).
        auto_apply: Whether to auto-apply safe recommendations.
        notify_on_high: Send alerts for high-severity threats.
    """
    interval_hours: int = 24
    auto_apply: bool = False
    notify_on_high: bool = True


class OracleScheduler:
    """Schedules periodic threat scans and briefing generation.

    STUB: Provides a `run_now()` method for manual execution.
    Full implementation would use asyncio scheduling or a task queue.

    Usage:
        scheduler = OracleScheduler()
        brief = scheduler.run_now()
    """

    def __init__(
        self,
        scanner: OracleScanner | None = None,
        briefer: OracleBriefer | None = None,
        config: ScheduleConfig | None = None,
    ):
        self._scanner = scanner or OracleScanner()
        self._briefer = briefer or OracleBriefer()
        self._config = config or ScheduleConfig()

        log.info(
            "oracle.scheduler",
            f"OracleScheduler initialized "
            f"(interval={self._config.interval_hours}h, stub mode)",
        )

    def run_now(self) -> SecurityBrief:
        """Run a scan and generate a briefing immediately.

        Returns:
            SecurityBrief with current threat intelligence.
        """
        log.info("oracle.scheduler", "Running manual scan cycle...")

        threats = self._scanner.scan()
        brief = self._briefer.generate(threats)

        if self._config.notify_on_high:
            high_threats = [
                t for t in threats
                if t.severity in ("high", "critical")
            ]
            if high_threats:
                log.warn(
                    "oracle.scheduler",
                    f"⚠ {len(high_threats)} high-severity threats found!",
                )

        log.info("oracle.scheduler", "Scan cycle complete")
        return brief

    @property
    def config(self) -> ScheduleConfig:
        """Return the current schedule configuration."""
        return self._config
