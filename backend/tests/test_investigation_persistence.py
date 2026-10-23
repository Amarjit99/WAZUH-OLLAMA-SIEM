"""Tests for Phase 7.2 Investigation and Evidence-Snapshot Persistence.

Validates:
- Complete investigation lifecycle (running -> completed / failed)
- Minimized, sanitized evidence snapshots with citations
- In-flight concurrent conflict detection (HTTP 409)
- Sequential run_sequence increments
- Startup crash recovery for orphaned investigations (ORPHANED_PROCESS_CRASH)
- Transaction atomicity and rollback
- Local audit log SHA-256 hash-chain integrity
- Integration with POST /api/v1/alerts/{alert_id}/investigate
"""

from datetime import datetime, timezone
import json
import os
import tempfile
from unittest.mock import AsyncMock, patch
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.base import Base
from app.db.session import create_async_db_engine
from app.models.audit import AuditEvent
from app.models.investigation import (
    Investigation,
    InvestigationCheck,
    InvestigationEvidenceSnapshot,
    InvestigationFact,
    InvestigationHypothesis,
    InvestigationResult as InvestigationResultModel,
)
from app.repositories.audit_repository import AuditRepository
from app.repositories.investigation_repository import InvestigationRepository
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


def make_sample_alert(alert_id: str = "alert-001") -> NormalizedAlert:
    now = datetime.now(timezone.utc)
    return NormalizedAlert(
        alert_id=alert_id,
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=now,
        retrieved_at=now,
        rule_id="5710",
        rule_description="SSHD brute force attempt detected",
        rule_level=10,
        agent_id="001",
        agent_name="web-server-prod",
        host_name="wazuh.manager",
        source_ip="203.0.113.42",
        raw_evidence_ref=f"wazuh-alerts-4.x-2026.10.20/{alert_id}",
    )


def make_sample_evidence_package(alert: NormalizedAlert, package_id: str = "pkg-001") -> EvidencePackage:
    item1 = EvidenceItem(
        evidence_id="EV-01",
        source_record_id=alert.alert_id,
        event_timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        rule_level=alert.rule_level,
        rule_description=alert.rule_description,
        agent_name=alert.agent_name,
        source_ip="203.0.113.42",
        destination_ip=None,
        username="root",
        location="/var/log/auth.log",
        is_primary=True,
        correlation_reason="primary_alert",
        raw_evidence_ref=alert.raw_evidence_ref,
    )
    item2 = EvidenceItem(
        evidence_id="EV-02",
        source_record_id="related-002",
        event_timestamp=datetime.now(timezone.utc),
        rule_id="5712",
        rule_level=12,
        rule_description="SSHD brute force: excessive authentication failures",
        agent_name=alert.agent_name,
        source_ip="203.0.113.42",
        destination_ip=None,
        username="root",
        location="/var/log/auth.log",
        is_primary=False,
        correlation_reason="source_ip",
        correlation_qualifier="203.0.113.42",
        raw_evidence_ref="wazuh-alerts-4.x-2026.10.20/related-002",
    )
    return EvidencePackage(
        package_id=package_id,
        alert_id=alert.alert_id,
        items=[item1, item2],
        total_events=2,
        total_bytes=512,
    )


def make_sample_result(alert_id: str, investigation_id: str) -> InvestigationResult:
    return InvestigationResult(
        investigation_id=investigation_id,
        alert_id=alert_id,
        status=InvestigationStatus.VALID,
        model_name="deepseek-r1",
        model_tag="7b",
        prompt_version="1.0.0",
        summary="High-volume SSH authentication failures from external IP targeting root.",
        observed_facts=[
            ObservedFact(
                fact_id="F-01",
                statement="Multiple SSH authentication failures targeting root were observed from 203.0.113.42.",
                cited_evidence_ids=["EV-01", "EV-02"],
            )
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-01",
                statement="Automated credential stuffing or brute-force attack against SSH.",
                uncertainty=UncertaintyLevel.LOW,
                cited_evidence_ids=["EV-01", "EV-02"],
            )
        ],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-01",
                description="Check firewall logs for further inbound connections from 203.0.113.42.",
                rationale="Determine if actor is probing other ports.",
                priority=PriorityLevel.HIGH,
            )
        ],
        confidence_label=ConfidenceLabel.HIGH,
        disclaimer="Advisory analysis generated by local AI. Verify before remediation.",
        limitations=[],
        unsupported_citation_warnings=[],
        correlation_status="correlated_events_found",
    )


@pytest.fixture
async def test_db():
    """Create isolated temporary SQLite database with all tables for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_persistence.db")
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


@pytest.mark.asyncio
async def test_investigation_start_and_complete_lifecycle(test_db):
    """Test standard investigation flow: start (running) -> complete (completed) with child entities."""
    service: InvestigationPersistenceService = test_db["service"]
    session_factory = test_db["session_factory"]

    alert = make_sample_alert("alert-test-01")
    inv_id = "inv-test-01"
    pkg = make_sample_evidence_package(alert)

    # 1. Start investigation
    inv = await service.start_investigation(
        investigation_id=inv_id,
        alert=alert,
        window_minutes=30,
        max_items=10,
        actor_id="analyst_alice",
    )
    assert inv.status == "running"
    assert inv.run_sequence == 1
    assert inv.investigation_id == inv_id
    assert inv.primary_rule_id == "5710"

    # 2. Check in-flight query
    running = await service.get_running_investigation_for_alert("alert-test-01")
    assert running is not None
    assert running.investigation_id == inv_id

    # 3. Complete investigation
    result = make_sample_result(alert.alert_id, inv_id)
    await service.complete_investigation(
        investigation_id=inv_id,
        result=result,
        evidence_package=pkg,
        duration_ms=1250,
        actor_id="analyst_alice",
        request_id="req-test-1",
        client_ip="127.0.0.1",
    )

    # 4. In-flight query now returns None
    running_after = await service.get_running_investigation_for_alert("alert-test-01")
    assert running_after is None

    # 5. Retrieve full persisted investigation
    persisted = await service.get_investigation_by_id(inv_id)
    assert persisted is not None
    assert persisted.status == "completed"
    assert persisted.execution_duration_ms == 1250

    # Verify result model
    assert persisted.result is not None
    assert persisted.result.model_name == "deepseek-r1"
    assert persisted.result.confidence_label == "high"

    # Verify facts
    assert len(persisted.result.facts) == 1
    fact = persisted.result.facts[0]
    assert fact.fact_identifier == "F-01"
    assert json.loads(fact.cited_evidence_ids_json) == ["EV-01", "EV-02"]

    # Verify hypotheses
    assert len(persisted.result.hypotheses) == 1
    hyp = persisted.result.hypotheses[0]
    assert hyp.hypothesis_identifier == "H-01"
    assert hyp.uncertainty == "low"

    # Verify checks (read-only)
    assert len(persisted.result.checks) == 1
    check = persisted.result.checks[0]
    assert check.check_identifier == "C-01"
    assert check.is_read_only is True

    # Verify evidence snapshots
    assert len(persisted.evidence_snapshots) == 2
    ev1 = next(s for s in persisted.evidence_snapshots if s.evidence_id == "EV-01")
    assert ev1.is_primary is True
    assert ev1.source_record_id == "alert-test-01"
    assert ev1.source_ip == "203.0.113.42"
    assert ev1.raw_evidence_ref == "wazuh-alerts-4.x-2026.10.20/alert-test-01"

    ev2 = next(s for s in persisted.evidence_snapshots if s.evidence_id == "EV-02")
    assert ev2.is_primary is False
    assert ev2.correlation_reason == "source_ip"

    # Verify audit event logged
    async with session_factory() as session:
        audit_events = (await session.execute(select(AuditEvent).order_by(AuditEvent.timestamp.asc()))).scalars().all()
        assert len(audit_events) == 1
        audit = audit_events[0]
        assert audit.action == "INVESTIGATION_COMPLETED"
        assert audit.resource_id == inv_id
        assert audit.outcome == "SUCCESS"
        assert audit.previous_hash == "0" * 64


@pytest.mark.asyncio
async def test_investigation_failure_lifecycle(test_db):
    """Test recording investigation failure when inference fails."""
    service: InvestigationPersistenceService = test_db["service"]
    session_factory = test_db["session_factory"]

    alert = make_sample_alert("alert-fail-01")
    inv_id = "inv-fail-01"

    # Start
    await service.start_investigation(
        investigation_id=inv_id,
        alert=alert,
        actor_id="analyst_bob",
    )

    # Fail
    await service.fail_investigation(
        investigation_id=inv_id,
        error_code="UPSTREAM_TIMEOUT",
        error_message="Ollama inference request timed out after 60 seconds",
        duration_ms=60000,
        actor_id="analyst_bob",
        request_id="req-fail-01",
        client_ip="127.0.0.1",
    )

    persisted = await service.get_investigation_by_id(inv_id)
    assert persisted is not None
    assert persisted.status == "failed"
    assert persisted.error_code == "UPSTREAM_TIMEOUT"
    assert "timed out" in persisted.error_message
    assert persisted.execution_duration_ms == 60000
    assert persisted.result is None

    # In-flight query returns None because it is failed, not running
    running = await service.get_running_investigation_for_alert("alert-fail-01")
    assert running is None

    # Verify failure audit event
    async with session_factory() as session:
        audit_res = await session.execute(select(AuditEvent).where(AuditEvent.resource_id == inv_id))
        audit = audit_res.scalar_one()
        assert audit.action == "INVESTIGATION_FAILED"
        assert audit.outcome == "FAILURE"


@pytest.mark.asyncio
async def test_sequential_investigations_increment_run_sequence(test_db):
    """Verify that multiple consecutive investigations for the same alert increment run_sequence."""
    service: InvestigationPersistenceService = test_db["service"]
    alert = make_sample_alert("alert-rerun-01")
    pkg = make_sample_evidence_package(alert)

    # Run 1
    inv1_id = "inv-seq-01"
    await service.start_investigation(inv1_id, alert)
    res1 = make_sample_result(alert.alert_id, inv1_id)
    await service.complete_investigation(inv1_id, res1, pkg, duration_ms=500)

    p1 = await service.get_investigation_by_id(inv1_id)
    assert p1.run_sequence == 1

    # Run 2
    inv2_id = "inv-seq-02"
    await service.start_investigation(inv2_id, alert)
    res2 = make_sample_result(alert.alert_id, inv2_id)
    await service.complete_investigation(inv2_id, res2, pkg, duration_ms=600)

    p2 = await service.get_investigation_by_id(inv2_id)
    assert p2.run_sequence == 2

    # Run 3 (failed)
    inv3_id = "inv-seq-03"
    await service.start_investigation(inv3_id, alert)
    await service.fail_investigation(inv3_id, "OLLAMA_ERROR", "Model crashed")

    p3 = await service.get_investigation_by_id(inv3_id)
    assert p3.run_sequence == 3


@pytest.mark.asyncio
async def test_startup_crash_recovery_reconciles_running_investigations(test_db):
    """Verify that startup crash recovery marks orphaned 'running' records as failed with ORPHANED_PROCESS_CRASH."""
    service: InvestigationPersistenceService = test_db["service"]
    session_factory = test_db["session_factory"]

    # 1. Create 2 investigations left in running state (simulated process crash)
    alert1 = make_sample_alert("alert-crash-01")
    alert2 = make_sample_alert("alert-crash-02")
    await service.start_investigation("inv-crash-01", alert1)
    await service.start_investigation("inv-crash-02", alert2)

    # 2. Create 1 completed investigation (should NOT be modified)
    alert3 = make_sample_alert("alert-crash-03")
    await service.start_investigation("inv-done-03", alert3)
    res3 = make_sample_result(alert3.alert_id, "inv-done-03")
    pkg3 = make_sample_evidence_package(alert3)
    await service.complete_investigation("inv-done-03", res3, pkg3, duration_ms=800)

    # 3. Execute startup crash recovery
    reconciled_count = await service.reconcile_orphaned_at_startup()
    assert reconciled_count == 2

    # 4. Verify orphaned investigations are failed with ORPHANED_PROCESS_CRASH
    c1 = await service.get_investigation_by_id("inv-crash-01")
    assert c1.status == "failed"
    assert c1.error_code == "ORPHANED_PROCESS_CRASH"
    assert "process terminated unexpectedly" in c1.error_message

    c2 = await service.get_investigation_by_id("inv-crash-02")
    assert c2.status == "failed"
    assert c2.error_code == "ORPHANED_PROCESS_CRASH"

    # Completed investigation remains completed
    c3 = await service.get_investigation_by_id("inv-done-03")
    assert c3.status == "completed"

    # 5. Idempotent: running recovery again finds 0 orphaned investigations
    assert await service.reconcile_orphaned_at_startup() == 0

    # 6. Verify audit logs for crash recovery
    async with session_factory() as session:
        events = (await session.execute(
            select(AuditEvent).where(AuditEvent.action == "CRASH_RECOVERY_RECONCILED")
        )).scalars().all()
        assert len(events) == 2
        assert {e.resource_id for e in events} == {"inv-crash-01", "inv-crash-02"}


@pytest.mark.asyncio
async def test_atomic_rollback_on_persistence_failure(test_db):
    """Verify that failure during result/snapshot insertion rolls back cleanly without leaking partial records."""
    service: InvestigationPersistenceService = test_db["service"]
    session_factory = test_db["session_factory"]

    alert = make_sample_alert("alert-rollback-01")
    inv_id = "inv-rollback-01"
    await service.start_investigation(inv_id, alert)

    pkg = make_sample_evidence_package(alert)
    res = make_sample_result(alert.alert_id, inv_id)

    # Monkeypatch record_investigation_success to raise an error mid-flight
    with patch.object(
        service.investigation_repo,
        "record_investigation_success",
        side_effect=RuntimeError("Simulated database failure during snapshot insertion"),
    ):
        with pytest.raises(RuntimeError):
            await service.complete_investigation(inv_id, res, pkg, duration_ms=500)

    # Investigation must NOT be completed
    persisted = await service.get_investigation_by_id(inv_id)
    assert persisted is not None
    assert persisted.status == "running"  # Rolled back
    assert persisted.result is None
    assert len(persisted.evidence_snapshots) == 0

    # No audit event was committed
    async with session_factory() as session:
        audit_events = (await session.execute(
            select(AuditEvent).where(AuditEvent.resource_id == inv_id)
        )).scalars().all()
        assert len(audit_events) == 0


@pytest.mark.asyncio
async def test_audit_hash_chain_integrity_and_tamper_detection(test_db):
    """Verify that audit events maintain a cryptographically unbroken SHA-256 hash chain and detect tampering."""
    service: InvestigationPersistenceService = test_db["service"]
    session_factory = test_db["session_factory"]
    audit_repo = service.audit_repo

    alert = make_sample_alert("alert-hash-01")
    pkg = make_sample_evidence_package(alert)

    # Perform 3 operations
    await service.start_investigation("inv-h1", alert)
    res = make_sample_result(alert.alert_id, "inv-h1")
    await service.complete_investigation("inv-h1", res, pkg, duration_ms=450)

    await service.start_investigation("inv-h2", alert)
    await service.fail_investigation("inv-h2", "CANCELLED", "Analyst cancelled")

    # Verify chain integrity
    async with session_factory() as session:
        is_valid, count, err = await audit_repo.verify_chain_integrity(session)
        assert is_valid is True
        assert count == 2
        assert err is None

    # Simulate deliberate tampering with first record in the database
    from sqlalchemy import update
    async with session_factory() as session:
        events = (await session.execute(select(AuditEvent).order_by(AuditEvent.timestamp.asc()))).scalars().all()
        target_id = events[0].audit_id
        await session.execute(
            update(AuditEvent)
            .where(AuditEvent.audit_id == target_id)
            .values(actor_id="hacker_malicious")
        )
        await session.commit()

    # Re-verify: must fail integrity check at index 0
    async with session_factory() as session:
        is_valid, tampered_idx, reason = await audit_repo.verify_chain_integrity(session)
        assert is_valid is False
        assert tampered_idx == 0
        assert "Tamper detected" in reason


@pytest.mark.asyncio
async def test_endpoint_investigate_persistence_and_conflict(test_db):
    """Test full integration with POST /api/v1/alerts/{alert_id}/investigate."""
    from fastapi.testclient import TestClient
    from app.api.deps import (
        get_evidence_service,
        get_investigation_persistence_service,
        get_ollama_client,
        get_opensearch_client,
    )
    from app.main import app

    service: InvestigationPersistenceService = test_db["service"]
    alert = make_sample_alert("alert-api-01")
    pkg = make_sample_evidence_package(alert)
    res = make_sample_result("alert-api-01", "inv-api-01")

    mock_opensearch = AsyncMock()
    mock_opensearch.get_alert_by_id.return_value = alert

    mock_evidence = AsyncMock()
    mock_evidence.build_evidence_package.return_value = pkg

    mock_ollama = AsyncMock()
    mock_ollama.investigate_alert.return_value = res

    # Override dependencies
    app.dependency_overrides[get_investigation_persistence_service] = lambda: service
    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch
    app.dependency_overrides[get_evidence_service] = lambda: mock_evidence
    app.dependency_overrides[get_ollama_client] = lambda: mock_ollama

    try:
        client = TestClient(app)

        # 1. Trigger investigation -> 200 OK
        resp = client.post("/api/v1/alerts/alert-api-01/investigate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert_id"] == "alert-api-01"
        assert data["confidence_label"] == "high"

        # Verify persisted
        inv = await service.get_running_investigation_for_alert("alert-api-01")
        assert inv is None  # Completed, so not running

        # 2. Test in-flight conflict: set an investigation to 'running'
        await service.start_investigation("inv-inflight-01", alert)

        # Attempting another investigation on alert-api-01 must return 409 Conflict
        conflict_resp = client.post("/api/v1/alerts/alert-api-01/investigate")
        assert conflict_resp.status_code == 409
        conflict_data = conflict_resp.json()
        assert conflict_data["error"]["code"] == "CONFLICT"
        assert "already in progress" in conflict_data["error"]["message"]
        assert conflict_data["error"]["details"]["investigation_id"] == "inv-inflight-01"

    finally:
        app.dependency_overrides.clear()
