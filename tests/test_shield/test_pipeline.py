"""
Unit tests for aegis.shield.pipeline — Shield Pipeline Orchestrator.

Tests cover:
- Full ingress chain (PII swap + tag + canary)
- Full egress chain (canary check + PII restore)
- Canary leak blocks response
- Clean response passes through
- Round-trip ingress → egress preserves meaning
"""

from aegis.shield.canary.detector import CanaryDetector
from aegis.shield.canary.generator import CanaryGenerator
from aegis.shield.canary.injector import CanaryInjector
from aegis.shield.pii.detector import PIIDetector
from aegis.shield.pii.generators import SyntheticGenerator
from aegis.shield.pii.swapper import SemanticSwapper
from aegis.shield.pipeline import ShieldPipeline
from aegis.shield.tagger.structural import StructuralTagger


def _make_pipeline(seed: int = 42) -> ShieldPipeline:
    """Create a deterministic pipeline for testing."""
    return ShieldPipeline(
        swapper=SemanticSwapper(
            detector=PIIDetector(enabled_types={"EMAIL", "SSN"}),
            generator=SyntheticGenerator(seed=seed),
        ),
        tagger=StructuralTagger(),
        canary_generator=CanaryGenerator(),
        canary_injector=CanaryInjector(),
        canary_detector=CanaryDetector(),
    )


class TestIngressProcessing:
    """Test the ingress pipeline."""

    def test_pii_is_swapped(self):
        pipeline = _make_pipeline()
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "My email is test@real.com"},
        ]

        result, context = pipeline.process_ingress(messages, "session-1")

        # The user message should not contain the real email
        user_msgs = [m for m in result if m["role"] == "user"]
        for msg in user_msgs:
            assert "test@real.com" not in msg["content"]

        # Swap map should have the mapping
        assert len(context.swap_map) >= 1

    def test_structural_tags_applied(self):
        pipeline = _make_pipeline()
        messages = [
            {"role": "user", "content": "Hello"},
        ]

        result, _ = pipeline.process_ingress(messages, "session-1")

        user_msgs = [m for m in result if m["role"] == "user"]
        assert any("<user_data>" in m["content"] for m in user_msgs)

    def test_canary_injected(self):
        pipeline = _make_pipeline()
        messages = [
            {"role": "system", "content": "Base"},
            {"role": "user", "content": "Hello"},
        ]

        result, context = pipeline.process_ingress(messages, "session-1")

        # Canary should be in the context
        assert len(context.canary) > 0
        assert context.canary.startswith("AEGIS-CANARY-")

        # Canary should be in the system message
        system_msgs = [m for m in result if m["role"] == "system"]
        assert any(context.canary in m["content"] for m in system_msgs)

    def test_session_id_preserved(self):
        pipeline = _make_pipeline()
        messages = [{"role": "user", "content": "Hi"}]
        _, context = pipeline.process_ingress(messages, "my-session")
        assert context.session_id == "my-session"


class TestEgressProcessing:
    """Test the egress pipeline."""

    def test_clean_response_passes(self):
        pipeline = _make_pipeline()
        messages = [
            {"role": "user", "content": "My SSN is 123-45-6789"},
        ]

        _, context = pipeline.process_ingress(messages, "session-1")

        # Simulate a clean LLM response using the synthetic SSN
        synthetic_ssn = context.swap_map.real_to_synthetic.get("123-45-6789", "")
        response = f"I see you provided SSN {synthetic_ssn}."

        result = pipeline.process_egress(response, context)

        assert result.blocked is False
        assert "123-45-6789" in result.response_text  # restored
        assert len(result.alerts) == 0

    def test_canary_leak_blocks_response(self):
        pipeline = _make_pipeline()
        messages = [{"role": "user", "content": "Hello"}]

        _, context = pipeline.process_ingress(messages, "session-1")

        # Simulate a response that leaks the canary
        response = f"Here is the secret: {context.canary}"

        result = pipeline.process_egress(response, context)

        assert result.blocked is True
        assert "[BLOCKED]" in result.response_text
        assert len(result.alerts) > 0
        assert "CANARY LEAK" in result.alerts[0]

    def test_no_pii_no_changes(self):
        pipeline = _make_pipeline()
        messages = [{"role": "user", "content": "What is AI?"}]

        _, context = pipeline.process_ingress(messages, "session-1")

        response = "AI is artificial intelligence."
        result = pipeline.process_egress(response, context)

        assert result.blocked is False
        assert result.response_text == response


class TestFullRoundTrip:
    """Test complete ingress → egress flow."""

    def test_round_trip_with_pii(self):
        pipeline = _make_pipeline()
        messages = [
            {"role": "system", "content": "You are a data analyst."},
            {"role": "user", "content": "Analyze data for test@company.org"},
        ]

        hardened, context = pipeline.process_ingress(messages, "rt-session")

        # Verify PII was removed from hardened messages
        user_content = [m["content"] for m in hardened if m["role"] == "user"]
        for content in user_content:
            assert "test@company.org" not in content

        # Simulate LLM response with synthetic email
        synthetic_email = context.swap_map.real_to_synthetic["test@company.org"]
        llm_response = f"Analysis for {synthetic_email} shows positive trends."

        result = pipeline.process_egress(llm_response, context)

        # The real email should be restored
        assert "test@company.org" in result.response_text
        assert result.blocked is False
