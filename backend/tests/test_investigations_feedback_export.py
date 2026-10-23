"""Tests for Investigation Feedback and Report Export endpoints."""

from datetime import datetime, timezone
import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.deps import get_investigation_persistence_service
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


def make_alert(alert_id: str = "alert-export-01") -> NormalizedAlert:
    now = datetime.now(timezone.utc)
    return NormalizedAlert(
        alert_id=alert_id,
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=now,
        retrieved_at=now,
        rule_id="=5710",  # Test formula injection prefix
        rule_level=10,
        rule_description="+SSH brute-force attempt",
        agent_id="001",
        agent_name="-ubuntu-server",
        agent_ip="192.168.1.50",
        raw_evidence_ref=f"wazuh-alerts-4.x-2026.10.20/{alert_id}",
    )


def make_pkg(alert: NormalizedAlert) -> EvidencePackage:
    item1 = EvidenceItem(
        evidence_id="EV-01",
        source_record_id=alert.alert_id,
        event_timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        rule_level=alert.rule_level,
        rule_description=alert.rule_description,
        agent_name=alert.agent_name,
        source_ip="@192.168.1.100",  # formula injection prefix
        destination_ip=None,
        username="admin",
        location="/var/log/auth.log",
        is_primary=True,
        correlation_reason="primary_alert",
        raw_evidence_ref=alert.raw_evidence_ref,
    )
    return EvidencePackage(
        package_id="pkg-exp-01",
        alert_id=alert.alert_id,
        items=[item1],
        total_events=1,
        total_bytes=256,
    )


def make_result(alert_id: str, inv_id: str) -> InvestigationResult:
    return InvestigationResult(
        investigation_id=inv_id,
        alert_id=alert_id,
        status=InvestigationStatus.VALID,
        model_name="deepseek-r1",
        model_tag="7b",
        prompt_version="1.0.0",
        summary="=1+1 Suspicious brute-force sequence identified.",
        observed_facts=[
            ObservedFact(
                fact_id="F-01",
                statement="Multiple failed attempts from @attacker.",
                cited_evidence_ids=["EV-01"],
            )
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-01",
                statement="Host compromise attempted.",
                uncertainty=UncertaintyLevel.LOW,
                cited_evidence_ids=["EV-01"],
            )
        ],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-01",
                description="Check SSH auth log for success.",
                rationale="Confirm if password succeeded.",
                priority=PriorityLevel.HIGH,
                is_read_only=True,
            )
        ],
        limitations=["Only 30m window evaluated."],
        unsupported_citation_warnings=[],
        correlation_status="correlated_events_found",
    )


@pytest.fixture
async def test_env():
    """Setup isolated SQLite DB and wire into dependency override."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_exp.db")
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
        app.dependency_overrides[get_investigation_persistence_service] = lambda: service

        yield {
            "engine": engine,
            "session_factory": session_factory,
            "service": service,
        }

        app.dependency_overrides.pop(get_investigation_persistence_service, None)
        await engine.dispose()


@pytest.mark.asyncio
async def test_submit_investigation_feedback_lifecycle(test_env):
    """Test feedback submission, validation, persistence, and audit logging."""
    service = test_env["service"]
    session_factory = test_env["session_factory"]

    # Seed an investigation
    alert = make_alert("alt-feedback-01")
    inv = await service.start_investigation(
        investigation_id="inv-feedback-01",
        alert=alert,
    )
    pkg = make_pkg(alert)
    res = make_result(alert.alert_id, inv.investigation_id)
    await service.complete_investigation(
        investigation_id=inv.investigation_id,
        evidence_package=pkg,
        result=res,
        duration_ms=120,
    )

    client = TestClient(app)

    # 1. Invalid rating -> 400
    bad_resp = client.post(
        f"/api/v1/investigations/{inv.investigation_id}/feedback",
        json={"rating": "great", "notes": "Not a valid enum"},
    )
    assert bad_resp.status_code == 400

    # 2. Non-existent ID -> 404
    missing_resp = client.post(
        "/api/v1/investigations/inv-does-not-exist/feedback",
        json={"rating": "helpful", "notes": "None"},
    )
    assert missing_resp.status_code == 404

    # 3. Valid feedback -> 200
    good_resp = client.post(
        f"/api/v1/investigations/{inv.investigation_id}/feedback",
        json={"rating": "helpful", "notes": "Accurate hypothesis and evidence."},
    )
    assert good_resp.status_code == 200
    data = good_resp.json()
    assert data["analyst_rating"] == "helpful"
    assert data["analyst_notes"] == "Accurate hypothesis and evidence."
    assert data["feedback_submitted_at"] is not None

    # Verify audit event in DB
    async with session_factory() as session:
        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.action == "INVESTIGATION_FEEDBACK_SUBMITTED",
                AuditEvent.resource_id == inv.investigation_id,
            )
        )
        audit_entry = audit_res.scalar_one_or_none()
        assert audit_entry is not None
        assert audit_entry.outcome == "SUCCESS"


@pytest.mark.asyncio
async def test_export_investigation_markdown_and_json(test_env):
    """Test sanitized markdown and JSON report exports with formula-injection mitigation."""
    service = test_env["service"]

    alert = make_alert("alt-export-02")
    inv = await service.start_investigation(
        investigation_id="inv-export-02",
        alert=alert,
    )
    pkg = make_pkg(alert)
    res = make_result(alert.alert_id, inv.investigation_id)
    await service.complete_investigation(
        investigation_id=inv.investigation_id,
        evidence_package=pkg,
        result=res,
        duration_ms=150,
    )

    client = TestClient(app)

    # 1. Export as Markdown
    md_resp = client.get(f"/api/v1/investigations/{inv.investigation_id}/export?format=markdown")
    assert md_resp.status_code == 200
    assert "text/markdown" in md_resp.headers["content-type"]
    assert f'filename="investigation_{inv.investigation_id}.md"' in md_resp.headers["content-disposition"]

    md_text = md_resp.text
    # Verify formula-injection characters are escaped with leading single-quote
    assert "'+SSH brute-force attempt" in md_text
    assert "'-ubuntu-server" in md_text
    assert "'=5710" in md_text
    assert "'@192.168.1.100" in md_text
    assert "Forensic Investigation Report" in md_text
    assert "Executive Summary" in md_text
    assert "Defensive Recommended Checks (Read-Only)" in md_text

    # 2. Export as JSON
    json_resp = client.get(f"/api/v1/investigations/{inv.investigation_id}/export?format=json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    assert f'filename="investigation_{inv.investigation_id}.json"' in json_resp.headers["content-disposition"]

    json_data = json_resp.json()
    assert json_data["investigation_id"] == inv.investigation_id
    assert json_data["primary_rule_id"] == "'=5710"  # formula mitigated
    assert json_data["result"] is not None
    assert len(json_data["evidence_items"]) == 1

    # 3. Export as CSV
    csv_resp = client.get(f"/api/v1/investigations/{inv.investigation_id}/export?format=csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert f'filename="investigation_{inv.investigation_id}.csv"' in csv_resp.headers["content-disposition"]
    csv_text = csv_resp.text
    assert "Investigation ID,Evidence ID,Role,Timestamp UTC" in csv_text
    assert "'=5710" in csv_text
    assert "'+SSH brute-force attempt" in csv_text
    assert "'-ubuntu-server" in csv_text
    assert "'@192.168.1.100" in csv_text

    # 4. Verify audit event for export was created
    async with test_env["session_factory"]() as session:
        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.action == "INVESTIGATION_EXPORTED",
                AuditEvent.resource_id == inv.investigation_id,
            )
        )
        exports = audit_res.scalars().all()
        assert len(exports) >= 3

    # 5. Invalid format -> 422
    invalid_resp = client.get(f"/api/v1/investigations/{inv.investigation_id}/export?format=pdf")
    assert invalid_resp.status_code == 422
