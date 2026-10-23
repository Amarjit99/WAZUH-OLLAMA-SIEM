"""Opt-in live integration tests against running Wazuh deployment.

Excluded by default in pyproject.toml via addopts = "-m 'not live'".
Run explicitly with: pytest -m live
"""

from datetime import datetime, timedelta, timezone
import pytest

from app.core.config import Settings
from app.services.opensearch_client import OpenSearchClient
from app.services.wazuh_client import WazuhClient


@pytest.fixture
def live_settings() -> Settings:
    """Load real settings from backend .env and verify service reachability."""
    settings = Settings()
    if not settings.is_wazuh_configured() or not settings.is_opensearch_configured():
        pytest.skip("Live services not configured in .env")

    import socket
    try:
        with socket.create_connection(("127.0.0.1", 9200), timeout=0.5):
            pass
    except (OSError, socket.timeout):
        pytest.skip("Live OpenSearch service is not reachable on 127.0.0.1:9200 (services stopped)")

    try:
        with socket.create_connection(("127.0.0.1", 55000), timeout=0.5):
            pass
    except (OSError, socket.timeout):
        pytest.skip("Live Wazuh Manager API is not reachable on 127.0.0.1:55000 (services stopped)")

    return settings


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_client_authentication(live_settings):
    """Live read-only test: Wazuh Manager API authentication and info check."""
    client = WazuhClient(live_settings)
    try:
        token = await client.authenticate()
        assert token is not None
        assert len(token) > 20

        info = await client.get_api_info()
        assert "data" in info
        assert "title" in info["data"] or "version" in info["data"]
    finally:
        await client.aclose()


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_opensearch_client_alerts_search(live_settings):
    """Live read-only test: Query real alerts from OpenSearch within last 24h."""
    client = OpenSearchClient(live_settings)
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)

        items, total, status = await client.search_alerts(
            start_time=start,
            end_time=now,
            page=1,
            page_size=10,
        )

        assert status.value in ("fresh", "partial")
        assert total >= 0
        assert isinstance(items, list)
        if items:
            first = items[0]
            assert first.alert_id is not None
            assert first.rule_id is not None
            assert first.timestamp is not None
            assert first.source_system == "Wazuh"
    finally:
        await client.aclose()


@pytest.mark.live
def test_live_api_alerts_endpoint(live_settings):
    """Live read-only test: GET /api/v1/alerts returns real alerts through FastAPI endpoint."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    resp = client.get("/api/v1/alerts", params={
        "start_time": start.isoformat(),
        "end_time": now.isoformat(),
        "page": 1,
        "page_size": 5,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert data["data_status"] in ("fresh", "partial")
    assert data["pagination"]["total_items"] > 0
    assert len(data["items"]) > 0

    first_alert = data["items"][0]
    assert first_alert["source_system"] == "Wazuh"
    assert first_alert["alert_id"] is not None

    # Test single alert lookup by authoritative ID
    single_resp = client.get(f"/api/v1/alerts/{first_alert['alert_id']}")
    assert single_resp.status_code == 200
    assert single_resp.json()["alert_id"] == first_alert["alert_id"]


@pytest.mark.live
def test_live_api_investigate_endpoint(live_settings):
    """Live read-only test: POST /api/v1/alerts/{alert_id}/investigate with real Ollama model."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.schemas.investigation import InvestigationResult

    if not live_settings.is_ollama_configured():
        pytest.skip("OLLAMA_MODEL not configured in .env")

    client = TestClient(app)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    resp = client.get(
        "/api/v1/alerts",
        params={
            "start_time": start.isoformat(),
            "end_time": now.isoformat(),
            "page": 1,
            "page_size": 1,
        },
    )
    assert resp.status_code == 200
    alerts = resp.json().get("items", [])
    if not alerts:
        pytest.skip("No alerts found in OpenSearch to investigate")

    target_alert_id = alerts[0]["alert_id"]
    inv_resp = client.post(
        f"/api/v1/alerts/{target_alert_id}/investigate",
        json={"include_related_events": False, "max_evidence_items": 5},
    )
    assert inv_resp.status_code == 200
    data = inv_resp.json()
    result = InvestigationResult.model_validate(data)
    assert result.alert_id == target_alert_id
    assert result.status.value in ("valid", "completed")
    assert result.model_tag == live_settings.OLLAMA_MODEL
    assert len(result.observed_facts) > 0
    assert len(result.disclaimer) > 0

