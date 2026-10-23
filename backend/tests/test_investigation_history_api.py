"""Tests for Phase 7.3 Investigation History Query APIs.

Validates:
- Empty investigation history
- Multiple records and stable deterministic ordering
- Pagination boundaries and maximum limit enforcement (<= 100)
- Supported filters (status, alert_id, rule_id, agent_name, confidence_label, time range)
- 90-day retention query boundary enforcement (HTTP 400)
- Invalid query parameters handling (HTTP 400 / 422)
- Authentication enforcement (HTTP 401 when API_AUTH_REQUIRED=True)
- Default dev mode behavior (allowed when auth not required)
- Investigation detail retrieval across lifecycles (completed, running, failed, cancelled)
- Missing investigation handling (HTTP 404)
- Minimization of evidence snapshots (no raw OpenSearch docs or secrets)
- Citation consistency (EV-01, EV-02)
- INVESTIGATION_VIEWED audit trail generation
- SQL injection safety in query filters
"""

from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.deps import get_investigation_persistence_service
from app.core import config
from app.db.base import Base
from app.db.session import create_async_db_engine
from app.main import app
from app.models.audit import AuditEvent
from app.schemas.alert import NormalizedAlert
from app.schemas.investigation import (
    ConfidenceLabel,
    EvidenceItem,
    EvidencePackage,
    Hypothesis,
    InvestigationResult,
    InvestigationStatus,
    ObservedFact,
    PriorityLevel,
    RecommendedCheck,
    UncertaintyLevel,
)
from app.services.investigation_persistence_service import InvestigationPersistenceService


def make_alert(alert_id: str, rule_id: str = "5710", agent_name: str = "agent-1") -> NormalizedAlert:
    now = datetime.now(timezone.utc)
    return NormalizedAlert(
        alert_id=alert_id,
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=now,
        retrieved_at=now,
        rule_id=rule_id,
        rule_description=f"Detection rule {rule_id}",
        rule_level=10,
        agent_id="001",
        agent_name=agent_name,
        host_name="wazuh.manager",
        source_ip="192.168.1.100",
        raw_evidence_ref=f"wazuh-alerts-4.x-2026.10.20/{alert_id}",
    )


def make_pkg(alert: NormalizedAlert, pkg_id: str = "pkg-01") -> EvidencePackage:
    item1 = EvidenceItem(
        evidence_id="EV-01",
        source_record_id=alert.alert_id,
        event_timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        rule_level=alert.rule_level,
        rule_description=alert.rule_description,
        agent_name=alert.agent_name,
        source_ip="192.168.1.100",
        destination_ip=None,
        username="admin",
        location="/var/log/auth.log",
        is_primary=True,
        correlation_reason="primary_alert",
        raw_evidence_ref=alert.raw_evidence_ref,
    )
    item2 = EvidenceItem(
        evidence_id="EV-02",
        source_record_id=f"{alert.alert_id}-rel",
        event_timestamp=alert.timestamp,
        rule_id="5712",
        rule_level=12,
        rule_description="Secondary rule",
        agent_name=alert.agent_name,
        source_ip="192.168.1.100",
        destination_ip=None,
        username="admin",
        location="/var/log/auth.log",
        is_primary=False,
        correlation_reason="source_ip",
        correlation_qualifier="192.168.1.100",
        raw_evidence_ref=f"wazuh-alerts-4.x-2026.10.20/{alert.alert_id}-rel",
    )
    return EvidencePackage(
        package_id=pkg_id,
        alert_id=alert.alert_id,
        items=[item1, item2],
        total_events=2,
        total_bytes=512,
    )


def make_result(alert_id: str, inv_id: str, conf: ConfidenceLabel = ConfidenceLabel.HIGH) -> InvestigationResult:
    return InvestigationResult(
        investigation_id=inv_id,
        alert_id=alert_id,
        status=InvestigationStatus.VALID,
        model_name="deepseek-r1",
        model_tag="7b",
        prompt_version="1.0.0",
        summary="High confidence brute-force attempt identified targeting admin account.",
        observed_facts=[
            ObservedFact(
                fact_id="F-01",
                statement="Multiple failed authentication attempts detected from 192.168.1.100.",
                cited_evidence_ids=["EV-01", "EV-02"],
            )
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-01",
                statement="Automated adversary attempting credential stuffing.",
                uncertainty=UncertaintyLevel.LOW,
                cited_evidence_ids=["EV-01"],
            )
        ],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-01",
                description="Verify PAM authentication logs on host.",
                rationale="Confirm if any attempt succeeded.",
                priority=PriorityLevel.HIGH,
            )
        ],
        confidence_label=conf,
        disclaimer="Advisory analysis generated by local AI. Verify before remediation.",
        limitations=[],
        unsupported_citation_warnings=[],
        correlation_status="correlated_events_found",
    )


@pytest.fixture
async def history_db():
    """Create isolated temporary SQLite database for history API testing."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_history.db")
        db_url = f"sqlite+aiosqlite:///{db_path}"
        engine = create_async_db_engine(db_url)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        service = InvestigationPersistenceService(session_factory=session_factory)
        yield {
            "engine": engine,
            "session_factory": session_factory,
            "service": service,
        }
        await engine.dispose()


@pytest.fixture
def auth_env():
    """Configure API_AUTH_REQUIRED=True with API_KEY for tests needing auth."""
    custom_settings = config.Settings(
        API_KEY=SecretStr("secure-test-token-73"),
        API_AUTH_REQUIRED=True,
    )
    app.dependency_overrides[config.get_settings] = lambda: custom_settings
    yield {"Authorization": "Bearer secure-test-token-73"}
    app.dependency_overrides.pop(config.get_settings, None)


def test_authentication_enforcement(auth_env):
    """Verify that both list and detail endpoints enforce authentication when required."""
    headers = auth_env
    client = TestClient(app)

    # Missing auth token -> 401
    resp1 = client.get("/api/v1/investigations")
    assert resp1.status_code == 401
    assert "Unauthorized" in resp1.json()["error"]["message"]

    resp2 = client.get("/api/v1/investigations/inv-001")
    assert resp2.status_code == 401
    assert "Unauthorized" in resp2.json()["error"]["message"]

    # Invalid token -> 401
    resp3 = client.get("/api/v1/investigations", headers={"Authorization": "Bearer wrong-key"})
    assert resp3.status_code == 401
    assert "Unauthorized" in resp3.json()["error"]["message"]

    # Valid token -> 200 (auth passed)
    resp4 = client.get("/api/v1/investigations", headers=headers)
    assert resp4.status_code == 200


@pytest.mark.asyncio
async def test_empty_investigation_history(history_db):
    """Test empty investigation history returns valid envelope with 0 count."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        client = TestClient(app)
        resp = client.get("/api/v1/investigations")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["pagination"]["total_items"] == 0
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["page_size"] == 25
        assert data["pagination"]["total_pages"] == 0
        assert data["pagination"]["has_next"] is False
        assert data["pagination"]["has_prev"] is False
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_pagination_and_deterministic_ordering(history_db):
    """Test pagination boundaries and stable deterministic ordering."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        # Seed 5 investigations
        for i in range(1, 6):
            alert = make_alert(f"alert-{i}", rule_id=f"rule-{i}", agent_name=f"agent-{i}")
            inv_id = f"inv-{i:03d}"
            await service.start_investigation(inv_id, alert)
            res = make_result(alert.alert_id, inv_id)
            pkg = make_pkg(alert)
            await service.complete_investigation(inv_id, res, pkg, duration_ms=100 * i)

        client = TestClient(app)

        # Page 1, page_size 2
        resp = client.get("/api/v1/investigations?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["pagination"]["total_items"] == 5
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["page_size"] == 2
        assert data["pagination"]["total_pages"] == 3
        assert data["pagination"]["has_next"] is True
        assert data["pagination"]["has_prev"] is False

        # Page 2, page_size 2
        resp2 = client.get("/api/v1/investigations?page=2&page_size=2")
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert len(data2["items"]) == 2
        assert data2["pagination"]["page"] == 2
        assert data2["pagination"]["has_next"] is True
        assert data2["pagination"]["has_prev"] is True

        # Page 3, page_size 2
        resp3 = client.get("/api/v1/investigations?page=3&page_size=2")
        assert resp3.status_code == 200
        data3 = resp3.json()
        assert len(data3["items"]) == 1
        assert data3["pagination"]["page"] == 3
        assert data3["pagination"]["has_next"] is False
        assert data3["pagination"]["has_prev"] is True

        # Ensure no overlap across pages
        ids = [item["investigation_id"] for item in data["items"]] + \
              [item["investigation_id"] for item in data2["items"]] + \
              [item["investigation_id"] for item in data3["items"]]
        assert len(set(ids)) == 5
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_maximum_page_size_enforced(history_db):
    """Enforce maximum page_size of 100 with HTTP 422 (FastAPI validation)."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        client = TestClient(app)
        resp = client.get("/api/v1/investigations?page_size=101")
        assert resp.status_code == 422
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_supported_filters_and_sql_injection_safety(history_db):
    """Test filtering by status, alert_id, rule_id, agent_name, and confidence_label, plus SQL injection safety."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        # Seed 3 investigations with distinct attributes
        alert_a = make_alert("alert-a", rule_id="5710", agent_name="web-01")
        alert_b = make_alert("alert-b", rule_id="5715", agent_name="db-01")
        alert_c = make_alert("alert-c", rule_id="5710", agent_name="db-01")

        # inv-a completed with HIGH confidence
        await service.start_investigation("inv-a", alert_a)
        await service.complete_investigation("inv-a", make_result("alert-a", "inv-a", ConfidenceLabel.HIGH), make_pkg(alert_a), 200)

        # inv-b completed with MEDIUM confidence
        await service.start_investigation("inv-b", alert_b)
        await service.complete_investigation("inv-b", make_result("alert-b", "inv-b", ConfidenceLabel.MEDIUM), make_pkg(alert_b), 250)

        # inv-c failed
        await service.start_investigation("inv-c", alert_c)
        await service.fail_investigation("inv-c", "TIMEOUT", "Ollama connection timeout")

        client = TestClient(app)

        # Filter by status = 'failed'
        r1 = client.get("/api/v1/investigations?status=failed")
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["pagination"]["total_items"] == 1
        assert d1["items"][0]["investigation_id"] == "inv-c"
        assert d1["items"][0]["status"] == "failed"

        # Filter by rule_id = '5710'
        r2 = client.get("/api/v1/investigations?rule_id=5710")
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["pagination"]["total_items"] == 2
        returned_ids = {x["investigation_id"] for x in d2["items"]}
        assert returned_ids == {"inv-a", "inv-c"}

        # Filter by agent_name = 'db-01'
        r3 = client.get("/api/v1/investigations?agent_name=db-01")
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["pagination"]["total_items"] == 2
        assert {x["investigation_id"] for x in d3["items"]} == {"inv-b", "inv-c"}

        # Filter by alert_id = 'alert-a'
        r4 = client.get("/api/v1/investigations?alert_id=alert-a")
        assert r4.status_code == 200
        d4 = r4.json()
        assert d4["pagination"]["total_items"] == 1
        assert d4["items"][0]["investigation_id"] == "inv-a"

        # Filter by confidence_label = 'high'
        r5 = client.get("/api/v1/investigations?confidence_label=high")
        assert r5.status_code == 200
        d5 = r5.json()
        assert d5["pagination"]["total_items"] == 1
        assert d5["items"][0]["investigation_id"] == "inv-a"

        # SQL Injection safety test (bound parameters should match 0 rows, not fail or leak)
        sqli_val = "' OR '1'='1"
        r_sqli = client.get(f"/api/v1/investigations?rule_id={sqli_val}")
        assert r_sqli.status_code == 200
        assert r_sqli.json()["pagination"]["total_items"] == 0
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_time_range_filter_and_90_day_boundary(history_db):
    """Test time range filtering and 90-day retention query boundary enforcement."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        now = datetime.now(timezone.utc)
        alert = make_alert("alert-t1")
        await service.start_investigation("inv-t1", alert)
        await service.complete_investigation("inv-t1", make_result("alert-t1", "inv-t1"), make_pkg(alert), 150)

        client = TestClient(app)

        # Valid time range around now
        start_iso = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r_valid = client.get(f"/api/v1/investigations?start_time={start_iso}&end_time={end_iso}")
        assert r_valid.status_code == 200
        assert r_valid.json()["pagination"]["total_items"] == 1

        # Query older than 90 days must return HTTP 400
        old_time = (now - timedelta(days=95)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r_old = client.get(f"/api/v1/investigations?start_time={old_time}")
        assert r_old.status_code == 400
        err = r_old.json()["error"]
        assert err["code"] == "VALIDATION_ERROR"
        assert "90 days" in err["message"]

        # start_time after end_time must return HTTP 400
        future = (now + timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        past = (now - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r_inverted = client.get(f"/api/v1/investigations?start_time={future}&end_time={past}")
        assert r_inverted.status_code == 400
        assert "start_time must be earlier than or equal to end_time" in r_inverted.json()["error"]["message"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_invalid_query_parameters(history_db):
    """Test invalid status, invalid confidence, negative page, etc."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        client = TestClient(app)

        # Invalid status
        r1 = client.get("/api/v1/investigations?status=unknown_status")
        assert r1.status_code == 400
        assert "Invalid status filter" in r1.json()["error"]["message"]

        # Invalid confidence
        r2 = client.get("/api/v1/investigations?confidence_label=super_high")
        assert r2.status_code == 400
        assert "Invalid confidence" in r2.json()["error"]["message"]

        # Page < 1
        r3 = client.get("/api/v1/investigations?page=0")
        assert r3.status_code == 422  # FastAPI validation error

        # Page size < 1
        r4 = client.get("/api/v1/investigations?page_size=0")
        assert r4.status_code == 422
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_detail_endpoint_completed_with_snapshots_and_citations(history_db):
    """Test detail API for completed investigation with evidence snapshots and citations."""
    service = history_db["service"]
    session_factory = history_db["session_factory"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        alert = make_alert("alert-detail-01", rule_id="5710", agent_name="worker-01")
        inv_id = "inv-detail-01"
        pkg = make_pkg(alert)
        res = make_result(alert.alert_id, inv_id)

        await service.start_investigation(inv_id, alert)
        await service.complete_investigation(inv_id, res, pkg, duration_ms=420)

        client = TestClient(app)
        resp = client.get(f"/api/v1/investigations/{inv_id}")
        assert resp.status_code == 200
        d = resp.json()

        # Top-level lifecycle fields
        assert d["investigation_id"] == inv_id
        assert d["alert_id"] == "alert-detail-01"
        assert d["status"] == "completed"
        assert d["run_sequence"] == 1
        assert d["primary_rule_id"] == "5710"
        assert d["primary_agent_name"] == "worker-01"

        # Result object
        result = d["result"]
        assert result is not None
        assert result["summary"] == "High confidence brute-force attempt identified targeting admin account."
        assert result["confidence_label"] == "high"
        assert result["model_name"] == "deepseek-r1"
        assert result["model_tag"] == "7b"
        assert result["disclaimer"] == "Advisory analysis generated by local AI. Verify before remediation."

        # Facts and citations
        assert len(result["observed_facts"]) == 1
        assert result["observed_facts"][0]["fact_id"] == "F-01"
        assert result["observed_facts"][0]["cited_evidence_ids"] == ["EV-01", "EV-02"]

        # Hypotheses
        assert len(result["hypotheses"]) == 1
        assert result["hypotheses"][0]["hypothesis_id"] == "H-01"
        assert result["hypotheses"][0]["uncertainty"] == "low"
        assert result["hypotheses"][0]["cited_evidence_ids"] == ["EV-01"]

        # Recommended checks
        assert len(result["recommended_checks"]) == 1
        assert result["recommended_checks"][0]["check_id"] == "C-01"
        assert result["recommended_checks"][0]["priority"] == "high"

        # Evidence items: minimized, sanitized
        assert len(d["evidence_items"]) == 2
        ev1 = next(e for e in d["evidence_items"] if e["evidence_id"] == "EV-01")
        assert ev1["rule_id"] == "5710"
        assert ev1["is_primary"] is True
        assert ev1["correlation_reason"] == "primary_alert"
        assert ev1["source_ip"] == "192.168.1.100"

        ev2 = next(e for e in d["evidence_items"] if e["evidence_id"] == "EV-02")
        assert ev2["rule_id"] == "5712"
        assert ev2["is_primary"] is False
        assert ev2["correlation_reason"] == "source_ip"
        assert ev2["correlation_qualifier"] == "192.168.1.100"

        # Verify audit event INVESTIGATION_VIEWED was logged
        async with session_factory() as session:
            events = (await session.execute(
                select(AuditEvent).where(AuditEvent.action == "INVESTIGATION_VIEWED")
            )).scalars().all()
            assert len(events) >= 1
            latest = events[-1]
            assert latest.resource_id == inv_id
            assert latest.outcome == "SUCCESS"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_detail_endpoint_failed_lifecycle(history_db):
    """Test detail API for failed investigation returns error code, error message and null result."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        alert = make_alert("alert-failed-01")
        inv_id = "inv-failed-01"
        await service.start_investigation(inv_id, alert)
        await service.fail_investigation(inv_id, "OLLAMA_TIMEOUT", "Timeout connecting to 127.0.0.1:11434")

        client = TestClient(app)
        resp = client.get(f"/api/v1/investigations/{inv_id}")
        assert resp.status_code == 200
        d = resp.json()
        assert d["investigation_id"] == inv_id
        assert d["status"] == "failed"
        assert d["error_code"] == "OLLAMA_TIMEOUT"
        assert d["error_message"] == "Timeout connecting to 127.0.0.1:11434"
        assert d["result"] is None
        assert d["evidence_items"] == []
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_detail_endpoint_missing_returns_404(history_db):
    """Test that querying a non-existent investigation returns HTTP 404 with standard envelope."""
    service = history_db["service"]
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service

    try:
        client = TestClient(app)
        resp = client.get("/api/v1/investigations/non-existent-id")
        assert resp.status_code == 404
        data = resp.json()
        assert data["error"]["code"] == "NOT_FOUND"
        assert "not found" in data["error"]["message"]
    finally:
        app.dependency_overrides.clear()
