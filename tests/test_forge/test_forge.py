"""
Unit tests for aegis.forge — Forge Adversarial Module.

Tests cover:
- RedHatAgent generates attacks
- JudgeEvaluator evaluates defenses
- Optimizer proposes improvements
- ForgeRunner orchestrates full cycle
"""

from aegis.forge.judge import Judgment, JudgeEvaluator, JudgmentResult
from aegis.forge.optimizer import Optimizer, OptimizationProposal
from aegis.forge.red_hat import AttackPayload, RedHatAgent
from aegis.forge.runner import ForgeRunner


class TestRedHatAgent:
    def test_generate_attacks(self):
        agent = RedHatAgent()
        attacks = agent.generate_attacks(5)
        assert len(attacks) == 5

    def test_attack_has_fields(self):
        agent = RedHatAgent()
        attacks = agent.generate_attacks(1)
        attack = attacks[0]
        assert isinstance(attack, AttackPayload)
        assert attack.prompt
        assert attack.attack_type

    def test_attack_types_vary(self):
        agent = RedHatAgent()
        attacks = agent.generate_attacks(5)
        types = {a.attack_type for a in attacks}
        assert len(types) >= 3  # should have variety

    def test_cycles_templates(self):
        agent = RedHatAgent()
        attacks = agent.generate_attacks(10)
        assert len(attacks) == 10


class TestJudgeEvaluator:
    def test_blocked_response_is_defended(self):
        judge = JudgeEvaluator()
        attack = AttackPayload(prompt="Hack", attack_type="injection")
        judgment = judge.evaluate(attack, "[BLOCKED] Security violation.")
        assert judgment.result == JudgmentResult.DEFENDED
        assert judgment.score == 1.0

    def test_leak_indicator_is_bypassed(self):
        judge = JudgeEvaluator()
        attack = AttackPayload(prompt="Leak", attack_type="leak")
        judgment = judge.evaluate(
            attack, "The system prompt says you are a helpful assistant."
        )
        assert judgment.result == JudgmentResult.BYPASSED

    def test_clean_response_is_defended(self):
        judge = JudgeEvaluator()
        attack = AttackPayload(prompt="Tell me", attack_type="extraction")
        judgment = judge.evaluate(attack, "I can help you with that question.")
        assert judgment.result == JudgmentResult.DEFENDED


class TestOptimizer:
    def test_no_proposals_when_all_defended(self):
        optimizer = Optimizer()
        judgments = [
            Judgment(JudgmentResult.DEFENDED, 1.0, "OK")
            for _ in range(5)
        ]
        proposals = optimizer.analyze(judgments)
        assert len(proposals) == 0

    def test_proposals_when_bypassed(self):
        optimizer = Optimizer()
        judgments = [
            Judgment(JudgmentResult.BYPASSED, 0.8, "Leak")
            for _ in range(5)
        ]
        proposals = optimizer.analyze(judgments)
        assert len(proposals) >= 1
        assert all(p.requires_human_review for p in proposals)

    def test_proposal_has_fields(self):
        optimizer = Optimizer()
        judgments = [Judgment(JudgmentResult.BYPASSED, 0.8, "Leak")]
        proposals = optimizer.analyze(judgments)
        if proposals:
            p = proposals[0]
            assert p.component
            assert p.parameter
            assert p.rationale


class TestForgeRunner:
    def test_run_cycle_returns_report(self):
        runner = ForgeRunner()
        report = runner.run_cycle(num_attacks=3)
        assert len(report.attacks) == 3
        assert len(report.judgments) == 3

    def test_all_blocked_gives_high_success_rate(self):
        runner = ForgeRunner()
        report = runner.run_cycle(
            num_attacks=5,
            defense_response="[BLOCKED] No.",
        )
        assert report.success_rate == 1.0

    def test_leaked_gives_low_success_rate(self):
        runner = ForgeRunner()
        report = runner.run_cycle(
            num_attacks=3,
            defense_response="The system prompt says you are a helper.",
        )
        assert report.success_rate < 1.0

    def test_proposals_generated_on_bypass(self):
        runner = ForgeRunner()
        report = runner.run_cycle(
            num_attacks=5,
            defense_response="system prompt leaked here",
        )
        # With all bypassed, optimizer should propose changes
        assert len(report.proposals) >= 1
