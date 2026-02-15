"""
Proxy Server — FastAPI application factory and server runner.

Creates and configures the FastAPI application with CORS middleware,
security middleware, and route registration.
"""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis.config import get_config
from aegis.proxy.middleware import SecurityMiddleware
from aegis.proxy.routes import create_routes
from aegis.shield.guardrail.classifier import PromptInjectionClassifier
from aegis.utils.logging import log


def create_app(
    middleware: SecurityMiddleware | None = None,
    guardrail: PromptInjectionClassifier | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        middleware: Custom SecurityMiddleware. Uses default if None.
        guardrail: Custom guardrail classifier. Created from config if None.

    Returns:
        Configured FastAPI application.
    """
    config = get_config()

    app = FastAPI(
        title="Aegis Security Sidecar",
        description="Self-evolving security proxy for LLM applications",
        version="0.1.0",
    )

    # CORS — permissive for local development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security middleware
    sec_middleware = middleware or SecurityMiddleware()

    # Guardrail classifier — created from config
    if guardrail is None:
        guardrail = PromptInjectionClassifier(
            model_name=config.guardrail_model,
            backend=config.guardrail_backend,
            injection_threshold=config.injection_threshold,
            jailbreak_threshold=config.jailbreak_threshold,
            groq_api_key=config.guardrail_groq_key,
        )

    # Register routes (guardrail runs async alongside LLM at route level)
    create_routes(app, sec_middleware, guardrail)

    log.info("proxy.server", "Aegis proxy application created")
    log.info(
        "proxy.server",
        f"Guardrail backend={config.guardrail_backend}, "
        f"model={config.guardrail_model}",
    )

    return app


def run_server(
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Run the Aegis proxy server.

    Args:
        host: Host to bind to. Defaults to config value.
        port: Port to bind to. Defaults to config value.
    """
    config = get_config()

    host = host or config.host
    port = port or config.port

    log.info("proxy.server", f"Starting Aegis proxy on {host}:{port}")
    log.info("proxy.server", f"Upstream LLM: {config.upstream_url}")

    app = create_app()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )
