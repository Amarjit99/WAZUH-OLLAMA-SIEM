"""Tests for Case Management API (/api/v1/cases)."""

from datetime import datetime, timezone
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.deps import get_case_repository
from app.db.base import Base
from app.db.session import create_async_db_engine
from app.main import app
from app.models.audit import AuditEvent
from app.models.case import Case
from app.repositories.case_repository import CaseRepository


@pytest.fixture
async def case_env():
    """Setup isolated SQLite DB for Case API testing."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_cases.db")
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

        from app.db import session as db_session
        orig_factory = db_session._session_factory
        db_session._session_factory = session_factory

        repo = CaseRepository()
        app.dependency_overrides[get_case_repository] = lambda: repo

        yield {
            "engine": engine,
            "session_factory": session_factory,
            "repo": repo,
        }

        db_session._session_factory = orig_factory
        app.dependency_overrides.pop(get_case_repository, None)
        await engine.dispose()


@pytest.mark.asyncio
async def test_case_lifecycle(case_env):
    """Test full CRUD lifecycle, status transitions, closed_at logic, and audit events."""
    session_factory = case_env["session_factory"]
    client = TestClient(app)

    # 1. Create a Case
    create_payload = {
        "title": "Brute Force Investigation on Agent-01",
        "description": "Correlated multiple SSH failures from single external IP.",
        "priority": "high",
        "assignee": "alice",
        "alert_id": "alt-test-99",
        "analyst_notes": "Initial review: looks like credential stuffing.",
    }
    create_resp = client.post("/api/v1/cases", json=create_payload)
    assert create_resp.status_code == 201
    case_data = create_resp.json()
    case_id = case_data["case_id"]
    assert case_id.lower().startswith("case-")
    assert case_data["status"] == "open"

    assert case_data["priority"] == "high"
    assert case_data["assignee"] == "alice"
    assert case_data["closed_at"] is None

    # 2. Get Case by ID
    get_resp = client.get(f"/api/v1/cases/{case_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["case_id"] == case_id

    # 3. List Cases with filters
    list_resp = client.get("/api/v1/cases?status=open&priority=high")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["pagination"]["total_items"] == 1
    assert list_data["items"][0]["case_id"] == case_id

    # Filter with non-matching status
    list_none = client.get("/api/v1/cases?status=closed")
    assert list_none.status_code == 200
    assert list_none.json()["pagination"]["total_items"] == 0

    # 4. Update Case: change status to in_progress, update notes
    patch_resp = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "in_progress", "analyst_notes": "Investigating logs in detail."},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "in_progress"
    assert patch_resp.json()["analyst_notes"] == "Investigating logs in detail."
    assert patch_resp.json()["closed_at"] is None

    # 5. Close Case: verify closed_at is set
    close_resp = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "closed"},
    )
    assert close_resp.status_code == 200
    assert close_resp.json()["status"] == "closed"
    assert close_resp.json()["closed_at"] is not None

    # 6. Reopen Case: verify closed_at is cleared
    reopen_resp = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "open"},
    )
    assert reopen_resp.status_code == 200
    assert reopen_resp.json()["status"] == "open"
    assert reopen_resp.json()["closed_at"] is None

    # 7. Soft Delete Case
    del_resp = client.delete(f"/api/v1/cases/{case_id}")
    assert del_resp.status_code == 200

    # Verify deleted case cannot be retrieved
    get_deleted = client.get(f"/api/v1/cases/{case_id}")
    assert get_deleted.status_code == 404

    # 8. Verify Audit Log entries for CREATED, UPDATED, DELETED
    async with session_factory() as session:
        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.resource_id == case_id,
            ).order_by(AuditEvent.timestamp.asc())
        )
        actions = [e.action for e in audit_res.scalars().all()]
        assert "CASE_CREATED" in actions
        assert "CASE_UPDATED" in actions
        assert "CASE_DELETED" in actions


@pytest.mark.asyncio
async def test_case_validation_and_errors(case_env):
    """Test validation errors for invalid priority, status, and missing resources."""
    client = TestClient(app)

    # Invalid priority on create
    bad_pri = client.post(
        "/api/v1/cases",
        json={"title": "Test", "priority": "super-urgent"},
    )
    assert bad_pri.status_code == 422  # pydantic literal validation

    # Invalid status filter
    bad_stat = client.get("/api/v1/cases?status=invalid_status")
    assert bad_stat.status_code == 400

    # Non-existent case
    not_found = client.get("/api/v1/cases/CASE-99999999-000000")
    assert not_found.status_code == 404


@pytest.mark.asyncio
async def test_export_cases_csv_and_json(case_env):
    """Test case export in CSV and JSON formats with formula injection mitigation and audit logging."""
    session_factory = case_env["session_factory"]
    client = TestClient(app)

    # Create cases with trigger formula characters
    c1 = client.post(
        "/api/v1/cases",
        json={
            "title": "=SUM(1+1) Trigger Formula",
            "description": "@malicious_command_here",
            "priority": "critical",
            "assignee": "+sysadmin",
            "alert_id": "alt-test-01",
        },
    )
    assert c1.status_code == 201

    c2 = client.post(
        "/api/v1/cases",
        json={
            "title": "Standard Case Investigation",
            "priority": "medium",
            "assignee": "analyst1",
        },
    )
    assert c2.status_code == 201

    # 1. Export as CSV
    csv_resp = client.get("/api/v1/cases/export?format=csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert 'filename="cases_export.csv"' in csv_resp.headers["content-disposition"]
    csv_text = csv_resp.text
    assert "Case ID,Title,Status,Priority,Assignee,Created At UTC" in csv_text
    # Formula injection characters must be quoted
    assert "'=SUM(1+1) Trigger Formula" in csv_text
    assert "'@malicious_command_here" in csv_text
    assert "'+sysadmin" in csv_text

    # 2. Export as JSON
    json_resp = client.get("/api/v1/cases/export?format=json&priority=critical")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    assert 'filename="cases_export.json"' in json_resp.headers["content-disposition"]
    json_data = json_resp.json()
    assert len(json_data) == 1
    assert json_data[0]["priority"] == "critical"

    # 3. Verify audit log entry
    async with session_factory() as session:
        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.action == "CASES_EXPORTED",
            )
        )
        exports = audit_res.scalars().all()
        assert len(exports) >= 2

