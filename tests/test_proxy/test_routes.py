"""
Unit tests for aegis.proxy.routes — FastAPI Route Handlers.

Tests cover:
- Health endpoint returns correct status
- Chat completions endpoint structure (without upstream)
- App creation and route registration
"""

import pytest
from fastapi.testclient import TestClient

from aegis.proxy.middleware import SecurityMiddleware
from aegis.proxy.server import create_app


@pytest.fixture
def client():
    """Create a test client for the Aegis app."""
    app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_response_body(self, client):
        data = client.get("/health").json()
        assert data["status"] == "healthy"
        assert data["version"] == "0.1.0"
        assert "shield" in data["components"]
        assert "lens" in data["components"]


class TestChatCompletionsEndpoint:
    def test_missing_messages_returns_422(self, client):
        """Pydantic validation should reject a request with no messages."""
        resp = client.post("/v1/chat/completions", json={"model": "test"})
        assert resp.status_code == 422

    def test_valid_request_without_upstream(self, client):
        """Without AEGIS_UPSTREAM_URL set, should return 502."""
        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "test",
                "messages": [{"role": "user", "content": "Hello"}],
            },
        )
        # Should fail because no upstream is configured
        assert resp.status_code == 502


class TestAppCreation:
    def test_app_has_routes(self):
        app = create_app()
        routes = [r.path for r in app.routes]
        assert "/health" in routes
        assert "/v1/chat/completions" in routes
