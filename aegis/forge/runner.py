"""
Forge Runner — Stub for orchestrating adversarial red-teaming cycles.

Runs the full Forge loop: generate attacks → test defenses → judge → optimize.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.forge.judge import Judgment, JudgeEvaluator, JudgmentResult
from aegis.forge.optimizer import Optimizer, OptimizationProposal
from aegis.forge.red_hat import AttackPayload, RedHatAgent
from aegis.utils.logging import log


@dataclass
class ForgeReport:
    """Summary of one Forge adversarial cycle.

    Attributes:
        attacks: Attacks that were generated.
        judgments: How each attack was judged.
        proposals: Defense improvements proposed.
        success_rate: Percent of attacks that were defended.
    """
    attacks: list[AttackPayload] = field(default_factory=list)
    judgments: list[Judgment] = field(default_factory=list)
    proposals: list[OptimizationProposal] = field(default_factory=list)
    success_rate: float = 0.0


class ForgeRunner:
    """Orchestrates adversarial red-teaming cycles.

    STUB: Generates attacks, simulates defense responses, judges results,
    and proposes optimizations. No real LLM calls are made.

    Usage:
        runner = ForgeRunner()
        report = runner.run_cycle(num_attacks=5)
    """

    def __init__(
        self,
        red_hat: RedHatAgent | None = None,
        judge: JudgeEvaluator | None = None,
        optimizer: Optimizer | None = None,
    ):
        self._red_hat = red_hat or RedHatAgent()
        self._judge = judge or JudgeEvaluator()
        self._optimizer = optimizer or Optimizer()

        log.info("forge.runner", "ForgeRunner initialized (stub mode)")

    def run_cycle(
        self,
        num_attacks: int = 5,
        defense_response: str = "[BLOCKED] Security violation detected.",
    ) -> ForgeReport:
        """Run one adversarial red-teaming cycle.

        STUB: Uses a static defense response for all attacks.

        Args:
            num_attacks: Number of attacks to generate.
            defense_response: Simulated defense response for stub mode.

        Returns:
            ForgeReport with cycle results.
        """
        log.info("forge.runner", f"Starting Forge cycle with {num_attacks} attacks")

        # 1. Generate attacks
        attacks = self._red_hat.generate_attacks(num_attacks)

        # 2. Judge each attack
        judgments: list[Judgment] = []
        for attack in attacks:
            judgment = self._judge.evaluate(attack, defense_response)
            judgments.append(judgment)

        # 3. Analyze and propose optimizations
        proposals = self._optimizer.analyze(judgments)

        # 4. Calculate success rate
        defended = sum(
            1 for j in judgments
            if j.result == JudgmentResult.DEFENDED
        )
        success_rate = defended / len(judgments) if judgments else 0

        report = ForgeReport(
            attacks=attacks,
            judgments=judgments,
            proposals=proposals,
            success_rate=success_rate,
        )

        log.info(
            "forge.runner",
            f"Forge cycle complete: "
            f"{defended}/{len(attacks)} defended "
            f"({success_rate:.0%} success rate), "
            f"{len(proposals)} proposals",
        )

        return report
