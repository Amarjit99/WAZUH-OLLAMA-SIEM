"""Schema, migration, and relational integrity tests for Phase 7 persistence.

Covers T-MIG-1, T-MIG-2, and T-MIG-3 from specs/PHASE_7_TEST_PLAN.md.
"""

import asyncio
from datetime import datetime, timezone
import os
import tempfile
from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import create_async_db_engine
from app.models import (
    AuditEvent,
    Investigation,
    InvestigationCheck,
    InvestigationEvidenceSnapshot,
    InvestigationFact,
    InvestigationHypothesis,
    InvestigationResult,
)


def _sync_alembic_upgrade(db_url: str, revision: str = "head") -> None:
    """Execute Alembic upgrade synchronously in worker thread."""
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, revision)


def _sync_alembic_downgrade(db_url: str, revision: str = "base") -> None:
    """Execute Alembic downgrade synchronously in worker thread."""
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.downgrade(cfg, revision)


async def run_alembic_upgrade(db_url: str, revision: str = "head") -> None:
    """Run Alembic upgrade safely without asyncio event loop conflicts."""
    await asyncio.to_thread(_sync_alembic_upgrade, db_url, revision)


async def run_alembic_downgrade(db_url: str, revision: str = "base") -> None:
    """Run Alembic downgrade safely without asyncio event loop conflicts."""
    await asyncio.to_thread(_sync_alembic_downgrade, db_url, revision)


@pytest.mark.asyncio
async def test_migration_upgrade_and_downgrade_lifecycle():
    """T-MIG-1: Verify that upgrade head, downgrade base, and re-upgrade head execute without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "lifecycle_test.db").replace("\\", "/")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        # 1. Forward migration
        await run_alembic_upgrade(db_url, "head")

        # 2. Backward migration
        await run_alembic_downgrade(db_url, "base")

        # 3. Re-upgrade
        await run_alembic_upgrade(db_url, "head")


@pytest.mark.asyncio
async def test_all_seven_tables_and_columns_exist():
    """Verify that all 7 approved persistence tables and required columns exist after migration."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "tables_test.db").replace("\\", "/")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        await run_alembic_upgrade(db_url, "head")

        engine = create_async_db_engine(database_url=db_url)
        try:
            async with engine.connect() as conn:
                tables = await conn.run_sync(
                    lambda sync_conn: set(inspect(sync_conn).get_table_names())
                )

                expected_tables = {
                    "investigations",
                    "investigation_results",
                    "investigation_facts",
                    "investigation_hypotheses",
                    "investigation_checks",
                    "investigation_evidence_snapshots",
                    "audit_events",
                    "alembic_version",
                }
                assert expected_tables.issubset(tables), f"Missing tables. Found: {tables}"

                # Verify critical columns on investigations
                inv_cols = await conn.run_sync(
                    lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("investigations")}
                )
                assert {
                    "investigation_id",
                    "alert_id",
                    "run_sequence",
                    "status",
                    "primary_rule_id",
                    "primary_rule_level",
                    "primary_agent_name",
                    "query_window_minutes",
                    "max_evidence_items",
                    "error_code",
                    "error_message",
                    "execution_duration_ms",
                    "actor_id",
                    "created_at",
                    "updated_at",
                    "deleted_at",
                }.issubset(inv_cols)

                # Verify critical columns on audit_events (hash chaining)
                audit_cols = await conn.run_sync(
                    lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("audit_events")}
                )
                assert {
                    "audit_id",
                    "timestamp",
                    "actor_id",
                    "action",
                    "resource_type",
                    "resource_id",
                    "outcome",
                    "request_id",
                    "client_ip",
                    "metadata_json",
                    "previous_hash",
                    "event_hash",
                }.issubset(audit_cols)
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_foreign_key_enforcement():
    """T-MIG-2: Verify that inserting child rows with non-existent parent foreign keys raises IntegrityError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "fk_test.db").replace("\\", "/")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        await run_alembic_upgrade(db_url, "head")

        engine = create_async_db_engine(database_url=db_url)
        try:
            async with AsyncSession(engine) as session:
                invalid_result = InvestigationResult(
                    result_id="res-invalid-001",
                    investigation_id="non-existent-inv-id",
                    model_name="ollama",
                    model_tag="llama3.2:3b",
                    prompt_version="v1.0",
                    summary="Test summary",
                    confidence_label="medium",
                    disclaimer="Test disclaimer",
                    limitations_json="[]",
                    warnings_json="[]",
                    correlation_status="no_related_events_found",
                    created_at=datetime.now(timezone.utc),
                )
                session.add(invalid_result)
                with pytest.raises(IntegrityError):
                    await session.commit()
                await session.rollback()
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_cascade_delete_semantics():
    """T-MIG-3: Verify ON DELETE CASCADE for child entities while preserving independent audit_events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "cascade_test.db").replace("\\", "/")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        await run_alembic_upgrade(db_url, "head")

        engine = create_async_db_engine(database_url=db_url)
        try:
            now = datetime.now(timezone.utc)
            inv_id = "inv-cascade-001"
            res_id = "res-cascade-001"

            async with AsyncSession(engine) as session:
                # 1. Create Investigation
                inv = Investigation(
                    investigation_id=inv_id,
                    alert_id="alert-001",
                    run_sequence=1,
                    status="completed",
                    primary_rule_id="5710",
                    primary_agent_name="db-prod-01",
                    actor_id="test_analyst",
                    created_at=now,
                    updated_at=now,
                )
                session.add(inv)

                # 2. Create Result
                res = InvestigationResult(
                    result_id=res_id,
                    investigation_id=inv_id,
                    model_name="ollama",
                    model_tag="llama3.2:3b",
                    prompt_version="v1.0",
                    summary="Test cascade summary",
                    confidence_label="high",
                    disclaimer="Advisory only",
                    limitations_json="[]",
                    warnings_json="[]",
                    correlation_status="enriched",
                    created_at=now,
                )
                session.add(res)

                # 3. Create Fact, Hypothesis, Check
                session.add(InvestigationFact(
                    fact_id="fact-001",
                    result_id=res_id,
                    fact_identifier="F-1",
                    statement="Fact statement",
                    cited_evidence_ids_json='["EV-01"]',
                ))
                session.add(InvestigationHypothesis(
                    hypothesis_id="hypo-001",
                    result_id=res_id,
                    hypothesis_identifier="H-1",
                    statement="Hypothesis statement",
                    uncertainty="low",
                    cited_evidence_ids_json='["EV-01"]',
                ))
                session.add(InvestigationCheck(
                    check_id="check-001",
                    result_id=res_id,
                    check_identifier="C-1",
                    description="Check action",
                    priority="high",
                    is_read_only=True,
                ))

                # 4. Create Evidence Snapshot
                session.add(InvestigationEvidenceSnapshot(
                    snapshot_id="snap-001",
                    investigation_id=inv_id,
                    evidence_id="EV-01",
                    source_record_id="opensearch-doc-123",
                    event_timestamp=now,
                    is_primary=True,
                    rule_id="5710",
                    raw_evidence_ref="wazuh-alerts-4.x-2026.10.20/123",
                ))

                # 5. Create Independent Audit Event
                session.add(AuditEvent(
                    audit_id="audit-001",
                    timestamp=now,
                    actor_id="test_analyst",
                    action="INVESTIGATION_CREATED",
                    resource_type="investigation",
                    resource_id=inv_id,
                    outcome="SUCCESS",
                    request_id="req-001",
                    client_ip="127.0.0.1",
                    previous_hash="0" * 64,
                    event_hash="a" * 64,
                ))

                await session.commit()

            # Verify records exist
            async with AsyncSession(engine) as session:
                inv_check = await session.get(Investigation, inv_id)
                assert inv_check is not None

                res_check = await session.get(InvestigationResult, res_id)
                assert res_check is not None

                audit_check = await session.get(AuditEvent, "audit-001")
                assert audit_check is not None

            # 6. Delete Investigation and commit
            async with AsyncSession(engine) as session:
                inv_to_delete = await session.get(Investigation, inv_id)
                await session.delete(inv_to_delete)
                await session.commit()

            # 7. Verify Cascade Deletion and Audit Independence
            async with AsyncSession(engine) as session:
                assert await session.get(Investigation, inv_id) is None
                assert await session.get(InvestigationResult, res_id) is None
                assert await session.get(InvestigationFact, "fact-001") is None
                assert await session.get(InvestigationHypothesis, "hypo-001") is None
                assert await session.get(InvestigationCheck, "check-001") is None
                assert await session.get(InvestigationEvidenceSnapshot, "snap-001") is None

                # Audit event MUST remain untouched
                audit_remaining = await session.get(AuditEvent, "audit-001")
                assert audit_remaining is not None, "Audit events must not be deleted on investigation cascade"
        finally:
            await engine.dispose()
