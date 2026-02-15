"""
Unit tests for aegis.shield.canary.injector — Canary Injection.

Tests cover:
- Injection into existing system message
- Creation of system message when none exists
- Original messages not mutated
- Empty canary handling
- Multiple user messages preserved
"""

from aegis.shield.canary.injector import CanaryInjector


class TestCanaryInjection:
    """Test canary injection into message lists."""

    def test_inject_with_existing_system_message(self):
        injector = CanaryInjector()
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello"},
        ]
        canary = "AEGIS-CANARY-test-123"
        result = injector.inject(messages, canary)

        # System message should contain the canary
        system_msg = result[0]
        assert canary in system_msg["content"]
        assert "You are a helpful assistant." in system_msg["content"]

    def test_inject_without_system_message(self):
        injector = CanaryInjector()
        messages = [
            {"role": "user", "content": "Hello"},
        ]
        canary = "AEGIS-CANARY-test-456"
        result = injector.inject(messages, canary)

        # A system message should be created at index 0
        assert result[0]["role"] == "system"
        assert canary in result[0]["content"]
        # The user message should still be there
        assert result[1]["role"] == "user"
        assert result[1]["content"] == "Hello"

    def test_original_messages_not_mutated(self):
        injector = CanaryInjector()
        original = [
            {"role": "system", "content": "Original system prompt."},
            {"role": "user", "content": "Hi"},
        ]
        original_content = original[0]["content"]

        injector.inject(original, "AEGIS-CANARY-test")

        # The original should NOT be modified
        assert original[0]["content"] == original_content

    def test_inject_empty_canary_skips(self):
        injector = CanaryInjector()
        messages = [{"role": "user", "content": "Hello"}]
        result = injector.inject(messages, "")

        # Should return the same messages unchanged
        assert len(result) == 1
        assert result[0]["content"] == "Hello"

    def test_inject_preserves_all_messages(self):
        injector = CanaryInjector()
        messages = [
            {"role": "system", "content": "System"},
            {"role": "user", "content": "User 1"},
            {"role": "assistant", "content": "Response 1"},
            {"role": "user", "content": "User 2"},
        ]
        result = injector.inject(messages, "CANARY-XYZ")
        assert len(result) == 4
        assert result[2]["content"] == "Response 1"
        assert result[3]["content"] == "User 2"


class TestCustomTemplate:
    """Test custom instruction templates."""

    def test_custom_template(self):
        injector = CanaryInjector(
            instruction_template="\n[SECRET: {canary}]\n"
        )
        messages = [{"role": "system", "content": "Base prompt."}]
        result = injector.inject(messages, "MY-TOKEN")
        assert "[SECRET: MY-TOKEN]" in result[0]["content"]
