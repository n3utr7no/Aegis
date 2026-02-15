"""
Proxy Routes — FastAPI route handlers for the Aegis proxy.

Provides:
- POST /v1/chat/completions — Main chat completion proxy endpoint
- GET  /health              — Health check endpoint

The chat completions endpoint uses the OpenAI async-parallel pattern:
the ML guardrail runs alongside the LLM call, so guardrail classification
adds zero latency on the happy path.
"""

from __future__ import annotations

import asyncio

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from aegis.config import get_config
from aegis.proxy.middleware import SecurityMiddleware
from aegis.proxy.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    HealthResponse,
)
from aegis.shield.guardrail.classifier import PromptInjectionClassifier
from aegis.shield.guardrail.output_safety import OutputSafetyClassifier
from aegis.utils.logging import log


def create_routes(
    app: FastAPI,
    middleware: SecurityMiddleware,
    guardrail: PromptInjectionClassifier | None = None,
    output_safety: OutputSafetyClassifier | None = None,
) -> None:
    """Register route handlers on the FastAPI app.

    Args:
        app: The FastAPI application instance.
        middleware: The SecurityMiddleware to use for processing.
        guardrail: Optional ML guardrail classifier. If None, one is
                   created with default settings.
        output_safety: Optional ML output safety classifier. If None,
                       one is created with default settings.
    """
    _guardrail = guardrail or PromptInjectionClassifier()
    _output_safety = output_safety or OutputSafetyClassifier()

    @app.get("/health", response_model=HealthResponse)
    async def health_check() -> HealthResponse:
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            version="0.1.0",
            components={
                "shield": "active",
                "lens": "active",
                "proxy": "active",
                "guardrail": (
                    f"active ({_guardrail.backend_name})"
                    if _guardrail.is_available
                    else "disabled (no backend)"
                ),
                "output_safety": (
                    "active (LLaMA Guard 4)"
                    if _output_safety.is_available
                    else "disabled (no Groq key)"
                ),
            },
        )

    @app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
    async def chat_completions(request: ChatCompletionRequest) -> ChatCompletionResponse:
        """Main chat completion proxy endpoint.

        Uses the OpenAI async-parallel guardrail pattern:
            1. Apply ingress security (Lens + Shield PII/tag/canary)
            2. Launch guardrail + LLM call in parallel
            3. If guardrail blocks → cancel LLM call, return blocked
            4. If LLM returns → wait for guardrail, proceed if clear
            5. Apply egress security (canary check + output moderation + PII restore)
        """
        config = get_config()

        log.info("proxy.routes", f"Chat completion request: model={request.model}")

        try:
            # 1. Ingress processing (PII swap, structural tag, canary)
            hardened_messages, context = middleware.process_ingress(request)

            # 2. Async parallel: guardrail + LLM
            upstream_url = config.upstream_url.rstrip("/")
            if not upstream_url:
                raise HTTPException(
                    status_code=502,
                    detail="No upstream LLM URL configured (AEGIS_UPSTREAM_URL)",
                )

            # Extract the latest user message for guardrail classification
            user_messages = [
                m for m in request.to_dict_messages()
                if m.get("role") == "user"
            ]
            guardrail_text = (
                user_messages[-1]["content"] if user_messages else ""
            )

            # Launch both tasks in parallel
            guardrail_task = asyncio.create_task(
                _guardrail.classify_async(guardrail_text),
            )
            llm_task = asyncio.create_task(
                _forward_to_upstream(
                    upstream_url=upstream_url,
                    api_key=config.upstream_api_key,
                    messages=hardened_messages,
                    model=request.model,
                    temperature=request.temperature,
                    max_tokens=request.max_tokens,
                ),
            )

            # Wait for guardrail first (it's faster)
            done, pending = await asyncio.wait(
                [guardrail_task, llm_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Check guardrail result
            if guardrail_task in done:
                guardrail_result = guardrail_task.result()

                if guardrail_result.threshold_exceeded:
                    # Block — cancel the LLM call to save compute
                    llm_task.cancel()
                    try:
                        await llm_task
                    except asyncio.CancelledError:
                        pass

                    log.warn(
                        "proxy.routes",
                        f"Request BLOCKED by guardrail: "
                        f"{guardrail_result.label.value} "
                        f"(score={guardrail_result.score:.3f})",
                    )

                    # Attach guardrail result to context for reporting
                    context.shield_context.guardrail_result = guardrail_result
                    return middleware.build_blocked_response(context, request)

                # Guardrail passed — wait for LLM if still running
                if llm_task not in done:
                    await llm_task

            else:
                # LLM finished first — wait for guardrail
                await guardrail_task
                guardrail_result = guardrail_task.result()

                if guardrail_result.threshold_exceeded:
                    log.warn(
                        "proxy.routes",
                        f"Request BLOCKED by guardrail (post-LLM): "
                        f"{guardrail_result.label.value}",
                    )
                    context.shield_context.guardrail_result = guardrail_result
                    return middleware.build_blocked_response(context, request)

            # Attach guardrail result for reporting
            context.shield_context.guardrail_result = guardrail_result
            llm_response_text = llm_task.result()

            # 3. ML Output Safety — run LLaMA Guard on the LLM output
            if _output_safety.is_available:
                # Extract the user prompt for context
                user_msgs = [
                    m for m in request.to_dict_messages()
                    if m.get("role") == "user"
                ]
                user_prompt = user_msgs[-1]["content"] if user_msgs else ""

                safety_result = await _output_safety.classify_async(
                    llm_response_text,
                    user_prompt=user_prompt,
                )

                if not safety_result.safe:
                    log.warn(
                        "proxy.routes",
                        f"OUTPUT BLOCKED by LLaMA Guard: "
                        f"categories={safety_result.categories} "
                        f"({', '.join(safety_result.category_names)})",
                    )
                    from aegis.proxy.models import SecurityReport, SecurityVerdict
                    report = SecurityReport(
                        verdict=SecurityVerdict.BLOCK,
                        input_guardrail_label=(
                            guardrail_result.label.value
                            if guardrail_result else "benign"
                        ),
                        input_guardrail_score=(
                            guardrail_result.score
                            if guardrail_result else 0.0
                        ),
                        output_moderation_flagged=True,
                        alerts=[
                            f"Output safety violation: "
                            f"{', '.join(safety_result.category_names)}",
                        ],
                    )
                    return ChatCompletionResponse.blocked(
                        reason=(
                            f"Response blocked — unsafe content detected: "
                            f"{', '.join(safety_result.category_names)}"
                        ),
                        security=report,
                    )

            # 4. Egress processing (canary check, rules moderation, PII restore)
            response = middleware.process_egress(
                llm_response_text,
                context,
                request,
            )

            log.info(
                "proxy.routes",
                f"Response: verdict={response.security.verdict.value}",
            )
            return response

        except HTTPException:
            raise
        except Exception as exc:
            log.error("proxy.routes", f"Request processing failed: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))


async def _forward_to_upstream(
    upstream_url: str,
    api_key: str,
    messages: list[dict],
    model: str,
    temperature: float,
    max_tokens: int | None,
) -> str:
    """Forward a hardened request to the upstream LLM provider.

    Args:
        upstream_url: The LLM provider's API URL.
        api_key: Bearer token for authentication.
        messages: Hardened chat messages.
        model: Model name.
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.

    Returns:
        The LLM's response text.

    Raises:
        HTTPException: If the upstream request fails.
    """
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                upstream_url,
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()

            data = resp.json()

            # Extract text from standard OpenAI response format
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")

            log.warn("proxy.routes", "Upstream response contained no choices")
            return ""

    except httpx.HTTPStatusError as exc:
        log.error("proxy.routes", f"Upstream HTTP error: {exc.response.status_code}")
        raise HTTPException(
            status_code=502,
            detail=f"Upstream LLM returned {exc.response.status_code}",
        )
    except httpx.RequestError as exc:
        log.error("proxy.routes", f"Upstream connection error: {exc}")
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to upstream LLM: {exc}",
        )
