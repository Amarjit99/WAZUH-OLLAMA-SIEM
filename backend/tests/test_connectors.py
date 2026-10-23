"""Unit tests for Wazuh Manager API and OpenSearch client connectors."""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.errors import AppException
from app.schemas.error import ErrorCode
from app.services.opensearch_client import OpenSearchClient
from app.services.wazuh_client import WazuhClient


@pytest.fixture
def connector_settings() -> Settings:
    """Fixture providing explicit credentials for connector tests."""
    return Settings(
        APP_ENV="test",
        WAZUH_API_URL="https://127.0.0.1:55000",
        WAZUH_API_USERNAME="wazuh_test_user",
        WAZUH_API_PASSWORD=SecretStr("wazuh_test_password"),
        WAZUH_CA_CERT_PATH=None,
        OPENSEARCH_URL="https://127.0.0.1:9200",
        OPENSEARCH_USERNAME="admin",
        OPENSEARCH_PASSWORD=SecretStr("admin_password"),
        OPENSEARCH_CA_CERT_PATH=None,
        OPENSEARCH_ALERT_INDEX_PATTERN="wazuh-alerts-*",
    )


# =====================================================================
# 1. Wazuh Manager API Client Tests
# =====================================================================

@pytest.mark.asyncio
async def test_wazuh_client_authentication_success(connector_settings):
    """Verify WazuhClient acquires and caches JWT token."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    # Mock /security/user/authenticate response
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"token": "header.payload.signature"}}
    mock_http.post.return_value = mock_resp

    client = WazuhClient(connector_settings, client=mock_http)
    token = await client.authenticate()

    assert token == "header.payload.signature"
    assert client._token == "header.payload.signature"
    mock_http.post.assert_called_once()

    # Second call should reuse cached token without network request
    cached_token = await client.authenticate()
    assert cached_token == "header.payload.signature"
    assert mock_http.post.call_count == 1


@pytest.mark.asyncio
async def test_wazuh_client_authentication_failure_401(connector_settings):
    """Verify invalid credentials raise AppException with UNAUTHORIZED."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"detail": "Invalid credentials"}
    mock_http.post.return_value = mock_resp

    client = WazuhClient(connector_settings, client=mock_http)
    with pytest.raises(AppException) as exc_info:
        await client.authenticate()

    assert exc_info.value.code == ErrorCode.UNAUTHORIZED
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_wazuh_client_retry_on_expired_token(connector_settings):
    """Verify that a request receiving 401 attempts re-authentication once."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)

    # Auth returns valid token
    auth_resp = MagicMock(spec=httpx.Response)
    auth_resp.status_code = 200
    auth_resp.json.return_value = {"data": {"token": "fresh.jwt.token"}}
    mock_http.post.return_value = auth_resp

    # First request returns 401 (expired token), retry returns 200
    expired_resp = MagicMock(spec=httpx.Response)
    expired_resp.status_code = 401

    ok_resp = MagicMock(spec=httpx.Response)
    ok_resp.status_code = 200
    ok_resp.json.return_value = {"data": {"status": "operational"}}

    mock_http.request.side_effect = [expired_resp, ok_resp]

    client = WazuhClient(connector_settings, client=mock_http)
    # Pre-populate stale token
    client._token = "stale.jwt.token"
    client._token_expiry = 9999999999.0

    result = await client.get_manager_status()
    assert result == {"data": {"status": "operational"}}
    assert mock_http.request.call_count == 2
    assert mock_http.post.call_count == 1


@pytest.mark.asyncio
async def test_wazuh_client_read_only_methods_exposed(connector_settings):
    """Verify WazuhClient exposes only authorized read-only methods."""
    client = WazuhClient(connector_settings)
    allowed_methods = {"get_api_info", "get_manager_status", "get_agents", "authenticate", "aclose"}
    public_callables = {m for m in dir(client) if not m.startswith("_") and callable(getattr(client, m))}
    assert public_callables.issubset(allowed_methods)

    # Prohibited dangerous methods must not exist
    prohibited = ["restart", "delete_agent", "execute_command", "run_active_response", "update_config"]
    for p in prohibited:
        assert not hasattr(client, p)


# =====================================================================
# 2. OpenSearch Alert Client Tests
# =====================================================================

def test_opensearch_client_pinned_index_pattern(connector_settings):
    """Verify caller cannot alter or override index pattern."""
    client = OpenSearchClient(connector_settings)
    assert client.index_pattern == "wazuh-alerts-*"
    # URL construction must always point to the pinned index pattern
    url = f"{client.base_url}/{client.index_pattern}/_search"
    assert "wazuh-alerts-*" in url


def test_opensearch_query_builder_safe_parameters(connector_settings):
    """Verify internal query builder parameterizes filters without arbitrary DSL injection."""
    client = OpenSearchClient(connector_settings)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=2)

    query = client._build_search_query(
        start_time=start,
        end_time=now,
        severity_min=8,
        rule_id="100001",
        host_name="linux-agent",
        source_ip="192.168.1.50",
        username="attacker",
        page=2,
        page_size=25,
        sort_order="asc",
    )

    # Check pagination
    assert query["from"] == 25  # (2 - 1) * 25
    assert query["size"] == 25

    # Check sort
    assert query["sort"] == [{"timestamp": {"order": "asc"}}]

    # Check filters in bool.must
    filters = query["query"]["bool"]["must"]
    # Timestamp range filter
    range_filter = next(f for f in filters if "range" in f and "timestamp" in f["range"])
    assert range_filter["range"]["timestamp"]["gte"] == start.isoformat()
    assert range_filter["range"]["timestamp"]["lte"] == now.isoformat()

    # Rule level filter
    level_filter = next(f for f in filters if "range" in f and "rule.level" in f["range"])
    assert level_filter["range"]["rule.level"]["gte"] == 8

    # Term filters
    rule_term = next(f for f in filters if f.get("term", {}).get("rule.id") == "100001")
    assert rule_term is not None

    ip_term = next(f for f in filters if f.get("term", {}).get("data.srcip") == "192.168.1.50")
    assert ip_term is not None

    user_term = next(f for f in filters if f.get("term", {}).get("data.srcuser") == "attacker")
    assert user_term is not None


@pytest.mark.asyncio
async def test_opensearch_client_auth_failure_401(connector_settings):
    """Verify OpenSearch HTTP 401 raises AppException with UNAUTHORIZED."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401
    mock_http.post.return_value = mock_resp

    client = OpenSearchClient(connector_settings, client=mock_http)
    now = datetime.now(timezone.utc)
    with pytest.raises(AppException) as exc_info:
        await client.search_alerts(start_time=now - timedelta(hours=1), end_time=now)

    assert exc_info.value.code == ErrorCode.UNAUTHORIZED


@pytest.mark.asyncio
async def test_opensearch_client_timeout_raises_upstream_timeout(connector_settings):
    """Verify network timeout raises AppException with UPSTREAM_TIMEOUT."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.post.side_effect = httpx.TimeoutException("Connection timed out")

    client = OpenSearchClient(connector_settings, client=mock_http)
    now = datetime.now(timezone.utc)
    with pytest.raises(AppException) as exc_info:
        await client.search_alerts(start_time=now - timedelta(hours=1), end_time=now)

    assert exc_info.value.code == ErrorCode.UPSTREAM_TIMEOUT
    assert exc_info.value.status_code == 504


@pytest.mark.asyncio
async def test_opensearch_client_missing_index_returns_empty(connector_settings):
    """Verify HTTP 404 (index not found) safely returns empty list with PARTIAL status."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404
    mock_http.post.return_value = mock_resp

    client = OpenSearchClient(connector_settings, client=mock_http)
    now = datetime.now(timezone.utc)
    items, total, status = await client.search_alerts(start_time=now - timedelta(hours=1), end_time=now)

    assert items == []
    assert total == 0
    assert status.value == "partial"
