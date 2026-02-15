"""
Oracle Scanner — Stub for scanning threat intelligence feeds.

In the full implementation, this would scrape security blogs,
CVE databases, and research papers for new attack techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aegis.utils.logging import log


@dataclass(frozen=True)
class ThreatIntel:
    """A piece of threat intelligence.

    Attributes:
        title: Brief title of the threat.
        description: Detailed description.
        severity: Severity level (low, medium, high, critical).
        source: Where the intel came from.
        discovered_at: When it was discovered.
    """
    title: str
    description: str
    severity: str = "medium"
    source: str = "stub"
    discovered_at: str = ""


class OracleScanner:
    """Scans for new LLM security threats.

    STUB: Returns pre-built threat intelligence samples.
    Full implementation would scrape real threat feeds.

    Usage:
        scanner = OracleScanner()
        threats = scanner.scan()
    """

    _SAMPLE_THREATS: list[dict] = [
        {
            "title": "Multi-turn Prompt Injection via Context Window",
            "description": "Attacker uses multiple conversation turns "
                          "to gradually shift context and inject instructions.",
            "severity": "high",
        },
        {
            "title": "Unicode Homoglyph Bypass in Safety Filters",
            "description": "Using Cyrillic/Greek lookalike characters "
                          "to bypass keyword-based safety filters.",
            "severity": "medium",
        },
        {
            "title": "Image-based Prompt Injection",
            "description": "Hiding adversarial text in images passed "
                          "to multimodal LLMs.",
            "severity": "high",
        },
    ]

    def __init__(self) -> None:
        log.info("oracle.scanner", "OracleScanner initialized (stub mode)")

    def scan(self) -> list[ThreatIntel]:
        """Scan for new threats.

        STUB: Returns sample threat intelligence.

        Returns:
            List of ThreatIntel items.
        """
        threats = [
            ThreatIntel(
                title=t["title"],
                description=t["description"],
                severity=t["severity"],
                source="stub",
                discovered_at=datetime.utcnow().isoformat(),
            )
            for t in self._SAMPLE_THREATS
        ]

        log.info("oracle.scanner", f"Found {len(threats)} threats (stub)")
        return threats
