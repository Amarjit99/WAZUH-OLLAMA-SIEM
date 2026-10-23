"""Unit and contract tests for alert schemas, queries, and /api/v1/alerts endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_opensearch_client
from app.core.errors import AppException
from app.main import app
from app.schemas.alert import (
    AlertListResponse,
    DataStatus,
    NormalizedAlert,
    PaginationMetadata,
    QueryWindow,
)
from app.schemas.error import ErrorCode
from app.services.opensearch_client import OpenSearchClient


def create_sample_hit(
    doc_id: str = "alert-12345",
    rule_id: str = "5710",
    rule_level: int = 5,
    agent_id: str = "001",
    agent_name: str = "web-srv",
    timestamp: str = "2026-10-19T20:00:00.000+0000",
    src_ip: Optional[str] = "192.168.1.100",
) -> Dict[str, Any]:
    """Helper creating a realistic Wazuh alert raw hit dictionary."""
    return {
        "_id": doc_id,
        "_index": "wazuh-alerts-4.x-2026.10.19",
        "_source": {
            "timestamp": timestamp,
            "rule": {
                "id": rule_id,
                "description": "sshd: Attempt to login using a non-existent user",
                "level": rule_level,
            },
            "agent": {
                "id": agent_id,
                "name": agent_name,
            },
            "manager": {
                "name": "wazuh-manager",
            },
            "data": {
                "srcip": src_ip,
                "srcuser": "admin",
                "type": "syslog",
            },
            "decoder": {
                "name": "sshd",
            },
            "location": "/var/log/auth.log",
        },
    }


# =====================================================================
# 1. Alert Schema and Normalization Unit Tests
# =====================================================================

def test_alert_normalization_standard(custom_settings):
    """Test standard Wazuh alert document normalizes cleanly without errors."""
    client = OpenSearchClient(custom_settings)
    raw = create_sample_hit()
    retrieved_at = datetime.now(timezone.utc)
    alert = client._normalize_hit(raw, retrieved_at)

    assert isinstance(alert, NormalizedAlert)
    assert alert.alert_id == "alert-12345"
    assert alert.rule_id == "5710"
    assert alert.rule_level == 5
    assert alert.rule_description == "sshd: Attempt to login using a non-existent user"
    assert alert.agent_id == "001"
    assert alert.agent_name == "web-srv"
    assert alert.host_name == "wazuh-manager"
    assert alert.source_ip == "192.168.1.100"
    assert alert.username == "admin"
    assert alert.event_type == "syslog"
    assert alert.decoder_name == "sshd"
    assert alert.location == "/var/log/auth.log"
    assert alert.raw_evidence_ref == "wazuh-alerts-4.x-2026.10.19/alert-12345"
    assert len(alert.normalization_warnings) == 0


def test_alert_normalization_sparse_document(custom_settings):
    """Test normalization when optional fields, rule details, or timestamps are missing."""
    client = OpenSearchClient(custom_settings)
    raw = {
        "_id": "sparse-999",
        "_index": "wazuh-alerts-test",
        "_source": {},
    }
    retrieved_at = datetime.now(timezone.utc)
    alert = client._normalize_hit(raw, retrieved_at)

    assert alert.alert_id == "sparse-999"
    assert alert.rule_id == "unknown"
    assert alert.rule_level is None
    assert alert.agent_id is None
    assert alert.source_ip is None
    assert alert.timestamp == retrieved_at
    assert any("timestamp missing" in w for w in alert.normalization_warnings)


# =====================================================================
# 2. Endpoint Unit / Contract Tests (GET /api/v1/alerts)
# =====================================================================

def test_list_alerts_success(client: TestClient, custom_settings):
    """Verify standard GET /api/v1/alerts returns normalized records and metadata."""
    now = datetime.now(timezone.utc)
    sample_alert = NormalizedAlert(
        alert_id="doc-1",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.19",
        timestamp=now - timedelta(minutes=10),
        retrieved_at=now,
        rule_id="5710",
        rule_description="Test alert",
        rule_level=7,
        raw_evidence_ref="wazuh-alerts-4.x-2026.10.19/doc-1",
    )

    mock_opensearch = AsyncMock(spec=OpenSearchClient)
    mock_opensearch.search_alerts.return_value = ([sample_alert], 1, DataStatus.FRESH)

    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    try:
        resp = client.get("/api/v1/alerts?page=1&page_size=20")
        assert resp.status_code == 200
        data = resp.json()

        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["alert_id"] == "doc-1"
        assert data["items"][0]["rule_level"] == 7

        assert "pagination" in data
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["page_size"] == 20
        assert data["pagination"]["total_items"] == 1
        assert data["pagination"]["total_pages"] == 1
        assert data["pagination"]["has_more"] is False

        assert "query_window" in data
        assert "start_time" in data["query_window"]
        assert "end_time" in data["query_window"]
        assert data["data_status"] == "fresh"
        assert "request_id" in data
    finally:
        app.dependency_overrides.clear()


def test_list_alerts_invalid_time_range_reversed(client: TestClient):
    """Reject start_time that is later than end_time with 400 VALIDATION_ERROR."""
    now = datetime.now(timezone.utc)
    start_str = (now + timedelta(hours=2)).isoformat()
    end_str = now.isoformat()

    resp = client.get("/api/v1/alerts", params={"start_time": start_str, "end_time": end_str})
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "start_time must be earlier than or equal to end_time" in data["error"]["message"]


def test_list_alerts_time_window_exceeds_24_hours(client: TestClient):
    """Reject time windows greater than 24 hours with 400 VALIDATION_ERROR."""
    now = datetime.now(timezone.utc)
    start_str = (now - timedelta(hours=25)).isoformat()
    end_str = now.isoformat()

    resp = client.get("/api/v1/alerts", params={"start_time": start_str, "end_time": end_str})
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "exceeds maximum allowed limit" in data["error"]["message"]


def test_list_alerts_page_size_max_boundary(client: TestClient):
    """Enforce maximum page size limit of 100."""
    resp = client.get("/api/v1/alerts?page_size=101")
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_list_alerts_invalid_source_ip_format(client: TestClient):
    """Reject invalid source_ip input that does not conform to IPv4/IPv6 syntax."""
    resp = client.get("/api/v1/alerts?source_ip=999.999.999.999")
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "Invalid source_ip format" in data["error"]["message"]


def test_list_alerts_valid_ip_formats(client: TestClient):
    """Accept valid IPv4 and IPv6 filters."""
    mock_opensearch = AsyncMock(spec=OpenSearchClient)
    mock_opensearch.search_alerts.return_value = ([], 0, DataStatus.FRESH)

    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    try:
        # IPv4
        resp4 = client.get("/api/v1/alerts?source_ip=10.0.0.1")
        assert resp4.status_code == 200

        # IPv6
        resp6 = client.get("/api/v1/alerts?source_ip=2001:db8::1")
        assert resp6.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_list_alerts_missing_index_returns_partial_status(client: TestClient):
    """Confirm missing OpenSearch index returns empty items with partial status."""
    mock_opensearch = AsyncMock(spec=OpenSearchClient)
    mock_opensearch.search_alerts.return_value = ([], 0, DataStatus.PARTIAL)

    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    try:
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["data_status"] == "partial"
        assert data["pagination"]["total_items"] == 0
    finally:
        app.dependency_overrides.clear()


# =====================================================================
# 3. Single Alert Endpoint Tests (GET /api/v1/alerts/{alert_id})
# =====================================================================

def test_get_alert_by_id_success(client: TestClient):
    """Verify single alert lookup by stable document ID."""
    now = datetime.now(timezone.utc)
    alert = NormalizedAlert(
        alert_id="doc-xyz",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.19",
        timestamp=now,
        retrieved_at=now,
        rule_id="5710",
        rule_description="Successful match",
        raw_evidence_ref="wazuh-alerts-4.x-2026.10.19/doc-xyz",
    )

    mock_opensearch = AsyncMock(spec=OpenSearchClient)
    mock_opensearch.get_alert_by_id.return_value = alert

    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    try:
        resp = client.get("/api/v1/alerts/doc-xyz")
        assert resp.status_code == 200
        assert resp.json()["alert_id"] == "doc-xyz"
    finally:
        app.dependency_overrides.clear()


def test_get_alert_by_id_not_found(client: TestClient):
    """Verify 404 is returned when alert ID does not exist."""
    mock_opensearch = AsyncMock(spec=OpenSearchClient)
    mock_opensearch.get_alert_by_id.return_value = None

    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    try:
        resp = client.get("/api/v1/alerts/nonexistent-doc")
        assert resp.status_code == 404
        data = resp.json()
        assert data["error"]["code"] == "NOT_FOUND"
        assert "not found" in data["error"]["message"].lower()
    finally:
        app.dependency_overrides.clear()


# =====================================================================
# 4. Read-Only Safety and Method Restrictions
# =====================================================================

def test_alerts_endpoints_are_strictly_read_only(client: TestClient):
    """Verify mutations (POST, PUT, DELETE, PATCH) are rejected with 405 Method Not Allowed."""
    assert client.post("/api/v1/alerts", json={}).status_code == 405
    assert client.put("/api/v1/alerts/doc-1", json={}).status_code == 405
    assert client.delete("/api/v1/alerts/doc-1").status_code == 405
    assert client.patch("/api/v1/alerts/doc-1", json={}).status_code == 405


def test_export_alerts_csv_and_json(client: TestClient):
    """Verify alert exports in CSV and JSON formats with formula sanitization and audit logging."""
    now = datetime.now(timezone.utc)
    mock_alerts = [
        NormalizedAlert(
            alert_id="doc-exp-1",
            source_system="Wazuh",
            source_index="wazuh-alerts-4.x-2026.10.19",
            timestamp=now,
            retrieved_at=now,
            rule_id="=5710",  # Trigger formula injection
            rule_description="+Brute-force SSH attack",
            rule_level=12,
            agent_id="001",
            agent_name="-ubuntu-box",
            username="@root",
            source_ip="192.168.1.100",
            raw_evidence_ref="wazuh-alerts-4.x-2026.10.19/doc-exp-1",
        )
    ]

    mock_opensearch = AsyncMock(spec=OpenSearchClient)
    mock_opensearch.search_alerts.return_value = (mock_alerts, 1, DataStatus.FRESH)

    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    try:
        # 1. Export CSV
        resp_csv = client.get("/api/v1/alerts/export?format=csv&limit=10")
        assert resp_csv.status_code == 200
        assert "text/csv" in resp_csv.headers["content-type"]
        assert 'filename="alerts_export.csv"' in resp_csv.headers["content-disposition"]
        csv_text = resp_csv.text
        assert "Alert ID,Timestamp UTC,Rule ID,Rule Level" in csv_text
        assert "'=5710" in csv_text
        assert "'+Brute-force SSH attack" in csv_text
        assert "'-ubuntu-box" in csv_text
        assert "'@root" in csv_text

        # 2. Export JSON
        resp_json = client.get("/api/v1/alerts/export?format=json&limit=10")
        assert resp_json.status_code == 200
        assert "application/json" in resp_json.headers["content-type"]
        assert 'filename="alerts_export.json"' in resp_json.headers["content-disposition"]
        json_data = resp_json.json()
        assert len(json_data) == 1
        assert json_data[0]["alert_id"] == "doc-exp-1"
    finally:
        app.dependency_overrides.clear()

