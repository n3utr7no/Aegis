"""
Unit tests for aegis.proxy.middleware — Security Middleware.

Tests cover:
- Ingress processes PII and applies lens
- Egress restores PII and checks canary
- Blocked response on canary leak
- Clean response passes through
- Security report populated correctly
"""

from aegis.proxy.middleware import SecurityMiddleware
from aegis.proxy.models import (
    ChatCompletionRequest,
    ChatMessage,
    Role,
    SecurityVerdict,
)


def _make_request(content: str, system: str | None = None) -> ChatCompletionRequest:
    messages = []
    if system:
        messages.append(ChatMessage(role=Role.SYSTEM, content=system))
    messages.append(ChatMessage(role=Role.USER, content=content))
    return ChatCompletionRequest(messages=messages)


class TestIngressMiddleware:
    def test_ingress_returns_messages_and_context(self):
        mw = SecurityMiddleware()
        req = _make_request("My email is test@example.com")
        messages, ctx = mw.process_ingress(req)

        assert isinstance(messages, list)
        assert len(messages) >= 1
        assert ctx.session_id

    def test_pii_removed_from_messages(self):
        mw = SecurityMiddleware()
        req = _make_request("Contact me at secret@corp.com")
        messages, ctx = mw.process_ingress(req)

        # The hardened messages should not contain the real email
        all_content = " ".join(m.get("content", "") for m in messages)
        assert "secret@corp.com" not in all_content

    def test_lens_stats_tracked(self):
        mw = SecurityMiddleware()
        req = _make_request("Normal text")
        _, ctx = mw.process_ingress(req)
        assert isinstance(ctx.lens_stats, dict)


class TestEgressMiddleware:
    def test_clean_response_passes(self):
        mw = SecurityMiddleware()
        req = _make_request("My SSN is 123-45-6789")
        _, ctx = mw.process_ingress(req)

        # Simulate clean LLM response
        resp = mw.process_egress("Here is your analysis.", ctx, req)

        assert resp.security.verdict != SecurityVerdict.BLOCK
        assert resp.choices[0].message.content

    def test_canary_leak_blocks(self):
        mw = SecurityMiddleware()
        req = _make_request("Hello")
        _, ctx = mw.process_ingress(req)

        # Simulate response that leaks the canary
        canary = ctx.shield_context.canary
        resp = mw.process_egress(f"Secret: {canary}", ctx, req)

        assert resp.security.verdict == SecurityVerdict.BLOCK
        assert "[BLOCKED]" in resp.choices[0].message.content
        assert resp.security.canary_leaked is True

    def test_security_report_populated(self):
        mw = SecurityMiddleware()
        req = _make_request("Email: test@test.com")
        _, ctx = mw.process_ingress(req)

        resp = mw.process_egress("Done.", ctx, req)

        assert resp.security.canary_injected is True
        assert resp.security.pii_entities_swapped >= 1


class TestMiddlewareRoundTrip:
    def test_pii_restored_in_response(self):
        mw = SecurityMiddleware()
        req = _make_request("Data for user@domain.org")
        _, ctx = mw.process_ingress(req)

        # Simulate LLM echoing the synthetic email
        synthetic = ctx.shield_context.swap_map.real_to_synthetic.get(
            "user@domain.org", ""
        )
        if synthetic:
            resp = mw.process_egress(f"Found {synthetic}", ctx, req)
            assert "user@domain.org" in resp.choices[0].message.content
