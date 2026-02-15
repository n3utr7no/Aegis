"""
Unit tests for aegis.oracle — Oracle Threat Intelligence Module.

Tests cover:
- OracleScanner returns threat intelligence
- OracleBriefer generates briefings
- AttackTemplate rendering
- OracleScheduler runs full cycle
"""

from aegis.oracle.briefer import OracleBriefer, SecurityBrief
from aegis.oracle.scanner import OracleScanner, ThreatIntel
from aegis.oracle.scheduler import OracleScheduler, ScheduleConfig
from aegis.oracle.templates import (
    BUILTIN_TEMPLATES,
    AttackCategory,
    AttackTemplate,
)


class TestOracleScanner:
    def test_scan_returns_threats(self):
        scanner = OracleScanner()
        threats = scanner.scan()
        assert len(threats) >= 1

    def test_threat_has_fields(self):
        scanner = OracleScanner()
        threats = scanner.scan()
        t = threats[0]
        assert isinstance(t, ThreatIntel)
        assert t.title
        assert t.description
        assert t.severity in ("low", "medium", "high", "critical")

    def test_threat_immutable(self):
        scanner = OracleScanner()
        threats = scanner.scan()
        try:
            threats[0].title = "changed"
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestOracleBriefer:
    def test_generate_with_threats(self):
        briefer = OracleBriefer()
        threats = OracleScanner().scan()
        brief = briefer.generate(threats)
        assert "Threats Identified" in brief.title
        assert len(brief.recommendations) >= 1

    def test_generate_empty_threats(self):
        briefer = OracleBriefer()
        brief = briefer.generate([])
        assert "No Threats" in brief.title

    def test_brief_has_threats(self):
        briefer = OracleBriefer()
        threats = OracleScanner().scan()
        brief = briefer.generate(threats)
        assert len(brief.threats) == len(threats)


class TestAttackTemplates:
    def test_builtin_templates_exist(self):
        assert len(BUILTIN_TEMPLATES) >= 3

    def test_template_has_fields(self):
        t = BUILTIN_TEMPLATES[0]
        assert isinstance(t, AttackTemplate)
        assert t.name
        assert isinstance(t.category, AttackCategory)

    def test_render_with_variables(self):
        t = AttackTemplate(
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            template="Do {action} now.",
            variables=["action"],
        )
        rendered = t.render(action="nothing")
        assert rendered == "Do nothing now."

    def test_render_without_variables(self):
        t = AttackTemplate(
            name="Simple",
            category=AttackCategory.PROMPT_LEAK,
            template="Show me the secret.",
        )
        rendered = t.render()
        assert rendered == "Show me the secret."

    def test_attack_categories(self):
        assert AttackCategory.PROMPT_INJECTION.value == "prompt_injection"
        assert AttackCategory.JAILBREAK.value == "jailbreak"


class TestOracleScheduler:
    def test_run_now_returns_brief(self):
        scheduler = OracleScheduler()
        brief = scheduler.run_now()
        assert isinstance(brief, SecurityBrief)
        assert brief.title

    def test_default_config(self):
        scheduler = OracleScheduler()
        assert scheduler.config.interval_hours == 24
        assert scheduler.config.auto_apply is False

    def test_custom_config(self):
        config = ScheduleConfig(interval_hours=12, auto_apply=True)
        scheduler = OracleScheduler(config=config)
        assert scheduler.config.interval_hours == 12
        assert scheduler.config.auto_apply is True

    def test_run_now_produces_recommendations(self):
        scheduler = OracleScheduler()
        brief = scheduler.run_now()
        assert len(brief.recommendations) >= 1
