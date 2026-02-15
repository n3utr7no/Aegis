"""
Unit tests for aegis.proxy.models — Data Models.

Tests cover:
- ChatMessage creation and roles
- ChatCompletionRequest validation
- SecurityReport defaults and verdict
- ChatCompletionResponse factory methods
- HealthResponse structure
"""

from aegis.proxy.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    Choice,
    HealthResponse,
    Role,
    SecurityReport,
    SecurityVerdict,
)


class TestChatMessage:
    def test_create_user_message(self):
        msg = ChatMessage(role=Role.USER, content="Hello")
        assert msg.role == Role.USER
        assert msg.content == "Hello"

    def test_create_system_message(self):
        msg = ChatMessage(role=Role.SYSTEM, content="You are helpful.")
        assert msg.role == Role.SYSTEM

    def test_role_values(self):
        assert Role.USER.value == "user"
        assert Role.SYSTEM.value == "system"
        assert Role.ASSISTANT.value == "assistant"


class TestChatCompletionRequest:
    def test_basic_request(self):
        req = ChatCompletionRequest(
            messages=[ChatMessage(role=Role.USER, content="Hi")],
        )
        assert len(req.messages) == 1
        assert req.model == "default"
        assert req.temperature == 0.7

    def test_to_dict_messages(self):
        req = ChatCompletionRequest(
            messages=[
                ChatMessage(role=Role.SYSTEM, content="Be helpful"),
                ChatMessage(role=Role.USER, content="Hello"),
            ],
        )
        dicts = req.to_dict_messages()
        assert dicts[0] == {"role": "system", "content": "Be helpful"}
        assert dicts[1] == {"role": "user", "content": "Hello"}

    def test_custom_model_and_temp(self):
        req = ChatCompletionRequest(
            model="gpt-4",
            messages=[ChatMessage(role=Role.USER, content="Hi")],
            temperature=0.3,
            max_tokens=100,
        )
        assert req.model == "gpt-4"
        assert req.temperature == 0.3
        assert req.max_tokens == 100


class TestSecurityReport:
    def test_defaults(self):
        report = SecurityReport()
        assert report.verdict == SecurityVerdict.PASS
        assert report.pii_entities_swapped == 0
        assert report.canary_injected is False

    def test_with_alerts(self):
        report = SecurityReport(
            verdict=SecurityVerdict.WARN,
            alerts=["Test alert"],
        )
        assert len(report.alerts) == 1
        assert report.verdict == SecurityVerdict.WARN


class TestChatCompletionResponse:
    def test_from_text(self):
        resp = ChatCompletionResponse.from_text("Hello back!")
        assert len(resp.choices) == 1
        assert resp.choices[0].message.content == "Hello back!"
        assert resp.choices[0].message.role == Role.ASSISTANT

    def test_blocked_response(self):
        resp = ChatCompletionResponse.blocked(reason="Canary leak")
        assert "[BLOCKED]" in resp.choices[0].message.content
        assert resp.security.verdict == SecurityVerdict.BLOCK
        assert resp.choices[0].finish_reason == "content_filter"

    def test_from_text_with_security(self):
        report = SecurityReport(pii_entities_swapped=3)
        resp = ChatCompletionResponse.from_text("OK", security=report)
        assert resp.security.pii_entities_swapped == 3

    def test_response_id(self):
        resp = ChatCompletionResponse.from_text("Hi", response_id="test-123")
        assert resp.id == "test-123"


class TestHealthResponse:
    def test_defaults(self):
        health = HealthResponse()
        assert health.status == "healthy"
        assert health.version == "0.1.0"

    def test_with_components(self):
        health = HealthResponse(
            components={"shield": "active", "lens": "active"},
        )
        assert health.components["shield"] == "active"
