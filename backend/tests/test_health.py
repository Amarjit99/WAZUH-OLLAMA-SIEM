"""Unit tests for liveness and readiness endpoints."""

import pytest
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.schemas.health import DependencyStatus, ServiceStatus
from app.services.health_service import HealthService


def test_health_live(client: TestClient):
    """Verify liveness endpoint returns ok."""
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    # Also check root mount
    root_resp = client.get("/health/live")
    assert root_resp.status_code == 200
    assert root_resp.json() == {"status": "ok"}


def test_health_ready_unconfigured(client: TestClient):
    """Verify readiness returns unconfigured statuses when env variables are empty."""
    response = client.get("/api/v1/health/ready")
    # Status code is 200 (if degraded/not_configured) or 503 (if unavailable)
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "dependencies" in data
    assert "wazuh_api" in data["dependencies"]
    assert "opensearch" in data["dependencies"]
    assert "ollama" in data["dependencies"]
    assert "retrieved_at" in data
    assert "request_id" in data


@pytest.mark.asyncio
async def test_health_service_unconfigured():
    """Verify HealthService accurately marks unconfigured dependencies."""
    settings = Settings(
        WAZUH_API_USERNAME=None,
        WAZUH_API_PASSWORD=None,
        OPENSEARCH_USERNAME=None,
        OPENSEARCH_PASSWORD=None,
        OLLAMA_MODEL="",
    )
    service = HealthService(settings)
    overall, deps = await service.check_all()
    assert overall == ServiceStatus.DEGRADED
    assert deps["wazuh_api"].status == DependencyStatus.NOT_CONFIGURED
    assert deps["opensearch"].status == DependencyStatus.NOT_CONFIGURED
    assert deps["ollama"].status == DependencyStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_health_service_offline_host_fails_visibly():
    """Verify HealthService does NOT fabricate status and reports offline hosts as unavailable."""
    from pydantic import SecretStr

    # Non-routable or unused port 59999
    settings = Settings(
        WAZUH_API_URL="https://127.0.0.1:59999",
        WAZUH_API_USERNAME="user",
        WAZUH_API_PASSWORD=SecretStr("pass"),
        OPENSEARCH_URL="https://127.0.0.1:59998",
        OPENSEARCH_USERNAME="admin",
        OPENSEARCH_PASSWORD=SecretStr("admin"),
        OLLAMA_BASE_URL="http://127.0.0.1:59997",
        OLLAMA_MODEL="target-model",
    )
    service = HealthService(settings)
    overall, deps = await service.check_all()
    assert overall == ServiceStatus.UNAVAILABLE
    assert deps["wazuh_api"].status == DependencyStatus.UNAVAILABLE
    assert deps["opensearch"].status == DependencyStatus.UNAVAILABLE
    assert deps["ollama"].status == DependencyStatus.UNAVAILABLE
