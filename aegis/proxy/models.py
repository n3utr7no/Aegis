"""
Proxy Data Models — Pydantic models for request/response schemas.

Defines the structured data flowing through the Aegis proxy,
including chat completion requests, responses, and security metadata.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────


class Role(str, Enum):
    """Chat message roles."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class SecurityVerdict(str, Enum):
    """Result of security processing."""
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


# ── Request Models ────────────────────────────────────────────────────────


class ChatMessage(BaseModel):
    """Single chat message."""
    role: Role
    content: str


class ChatCompletionRequest(BaseModel):
    """Incoming chat completion request.

    Mirrors the OpenAI-compatible API format.
    """
    model: str = "default"
    messages: list[ChatMessage]
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, gt=0)
    stream: bool = False

    def to_dict_messages(self) -> list[dict[str, str]]:
        """Convert messages to plain dict format for internal processing."""
        return [{"role": m.role.value, "content": m.content} for m in self.messages]


# ── Response Models ───────────────────────────────────────────────────────


class SecurityReport(BaseModel):
    """Security processing report attached to each response."""
    verdict: SecurityVerdict = SecurityVerdict.PASS
    pii_entities_swapped: int = 0
    canary_injected: bool = False
    canary_leaked: bool = False
    lens_invisible_chars: int = 0
    lens_code_constructs: int = 0
    input_guardrail_label: str = "benign"
    input_guardrail_score: float = 0.0
    output_moderation_score: int = 1
    output_moderation_flagged: bool = False
    alerts: list[str] = Field(default_factory=list)


class Choice(BaseModel):
    """A single completion choice."""
    index: int = 0
    message: ChatMessage
    finish_reason: str = "stop"


class ChatCompletionResponse(BaseModel):
    """Outgoing chat completion response.

    Extends the standard OpenAI format with security metadata.
    """
    id: str = ""
    object: str = "chat.completion"
    model: str = "default"
    choices: list[Choice] = Field(default_factory=list)
    security: SecurityReport = Field(default_factory=SecurityReport)

    @classmethod
    def from_text(
        cls,
        text: str,
        model: str = "default",
        response_id: str = "",
        security: SecurityReport | None = None,
    ) -> ChatCompletionResponse:
        """Create a response from plain text."""
        return cls(
            id=response_id,
            model=model,
            choices=[
                Choice(
                    message=ChatMessage(role=Role.ASSISTANT, content=text),
                )
            ],
            security=security or SecurityReport(),
        )

    @classmethod
    def blocked(
        cls,
        reason: str = "Security violation detected.",
        security: SecurityReport | None = None,
    ) -> ChatCompletionResponse:
        """Create a blocked response."""
        report = security or SecurityReport(verdict=SecurityVerdict.BLOCK)
        report.verdict = SecurityVerdict.BLOCK
        return cls(
            choices=[
                Choice(
                    message=ChatMessage(
                        role=Role.ASSISTANT,
                        content=f"[BLOCKED] {reason}",
                    ),
                    finish_reason="content_filter",
                )
            ],
            security=report,
        )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "0.1.0"
    components: dict[str, str] = Field(default_factory=dict)
