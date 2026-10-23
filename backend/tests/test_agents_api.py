"""Unit and integration tests for Wazuh Agent Fleet Management API."""

from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, MagicMock

from app.core.config import Settings
from app.core.errors import AppException
from app.main import create_app
from app.schemas.error import ErrorCode
from app.services.wazuh_client import WazuhClient


MOCK_WAZUH_AGENTS_RESPONSE = {
    "data": {
        "affected_items": [
            {
                "id": "000",
                "name": "wazuh.manager",
                "ip": "127.0.0.1",
                "registerIP": "127.0.0.1",
                "status": "active",
                "node_name": "node01",
                "version": "Wazuh v4.14.9",
                "dateAdd": "2026-10-19T19:09:59+00:00",
                "lastKeepAlive": "9999-12-31T23:59:59+00:00",
                "manager": "wazuh.manager",
                "os": {
                    "arch": "x86_64",
                    "major": "2023",
                    "name": "Amazon Linux",
                    "platform": "amzn",
                    "uname": "Linux |wazuh.manager |6.6.87.2-microsoft-standard-WSL2",
                    "version": "2023",
                },
            },
            {
                "id": "001",
                "name": "win-endpoint-01",
                "ip": "192.168.1.105",
                "registerIP": "192.168.1.105",
                "status": "disconnected",
                "node_name": "node01",
                "version": "Wazuh v4.14.9",
                "dateAdd": "2026-10-20T10:00:00+00:00",
                "lastKeepAlive": "2026-10-22T08:00:00+00:00",
                "manager": "wazuh.manager",
                "os": {
                    "arch": "x86_64",
                    "major": "10",
                    "name": "Windows",
                    "platform": "windows",
                    "uname": "Microsoft Windows 11 Enterprise",
                    "version": "10.0.22631",
                },
            },
        ],
        "total_affected_items": 2,
        "total_failed_items": 0,
    },
    "message": "All selected agents information was returned",
    "error": 0,
}


@pytest.fixture
def mock_wazuh_client():
    client = MagicMock(spec=WazuhClient)
    client.get_agents = AsyncMock(return_value=MOCK_WAZUH_AGENTS_RESPONSE)
    return client


@pytest.fixture
def app_with_mock_wazuh(mock_wazuh_client):
    app = create_app()
    app.state.wazuh_client = mock_wazuh_client
    return app


@pytest.mark.asyncio
async def test_list_agents_success(app_with_mock_wazuh, mock_wazuh_client):
    """Verify GET /api/v1/agents returns normalized agent list with accurate summary."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_mock_wazuh),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/agents?limit=10")

    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "summary" in data
    assert data["total_items"] == 2
    assert len(data["items"]) == 2

    # Verify Agent 000 details
    agent_0 = data["items"][0]
    assert agent_0["id"] == "000"
    assert agent_0["name"] == "wazuh.manager"
    assert agent_0["status"] == "active"
    assert agent_0["ip"] == "127.0.0.1"
    assert agent_0["os"]["name"] == "Amazon Linux"

    # Verify Agent 001 details
    agent_1 = data["items"][1]
    assert agent_1["id"] == "001"
    assert agent_1["name"] == "win-endpoint-01"
    assert agent_1["status"] == "disconnected"
    assert agent_1["os"]["name"] == "Windows"

    # Verify Summary counts
    summary = data["summary"]
    assert summary["total"] == 2
    assert summary["active"] == 1
    assert summary["disconnected"] == 1
    assert summary["never_connected"] == 0

    mock_wazuh_client.get_agents.assert_awaited_once_with(limit=10, offset=0)


@pytest.mark.asyncio
async def test_list_agents_status_filter(app_with_mock_wazuh):
    """Verify in-memory filtering by agent status."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_mock_wazuh),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/agents?status=active")

    assert resp.status_code == 200
    data = resp.json()
    assert data["total_items"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == "000"
    assert data["items"][0]["status"] == "active"


@pytest.mark.asyncio
async def test_list_agents_wazuh_failure_handled():
    """Verify 503 response when Wazuh Manager API is unreachable."""
    client_mock = MagicMock(spec=WazuhClient)
    client_mock.get_agents = AsyncMock(
        side_effect=AppException(
            code=ErrorCode.DEPENDENCY_UNAVAILABLE,
            message="Cannot connect to Wazuh Manager API",
            status_code=503,
        )
    )
    app = create_app()
    app.state.wazuh_client = client_mock

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/agents")

    assert resp.status_code == 503
    err = resp.json()["error"]
    assert err["code"] == "DEPENDENCY_UNAVAILABLE"
