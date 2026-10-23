"""Unit and integration tests for safe SQLite WAL online backup and isolated recovery.

Conforms strictly to Phase 7.9 Workstream A requirements:
- Tests SQLite online backup with active WAL pages in isolated temporary files
- Validates PRAGMA integrity_check, foreign keys, and Alembic revision checks
- Verifies non-overwriting guarantees and atomic temporary file staging
- Verifies isolated disaster recovery and representative relationship verification
- Strictly guarantees source database remains completely untouched throughout
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sqlite3
import pytest

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.base import Base
from app.models.audit import AuditEvent
from app.models.investigation import (
    Investigation,
    InvestigationCheck,
    InvestigationEvidenceSnapshot,
    InvestigationHypothesis,
    InvestigationResult,
)
from app.services.database_backup_service import (
    DatabaseBackupError,
    DatabaseBackupService,
    DatabaseCorruptionError,
)


@pytest.fixture
def backup_env(tmp_path):
    """Set up isolated directory structure and Settings instance."""
    db_path = tmp_path / "live_data" / "source_test.db"
    backup_dir = tmp_path / "backups"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        DATABASE_URL=f"sqlite+aiosqlite:///{db_path}",
        DATABASE_BACKUP_DIR=str(backup_dir),
        AUDIT_ARCHIVE_DIR=str(tmp_path / "archives"),
    )
    service = DatabaseBackupService(settings=settings)
    return {
        "db_path": db_path,
        "backup_dir": backup_dir,
        "settings": settings,
        "service": service,
        "tmp_path": tmp_path,
    }


@pytest.fixture
async def populated_wal_db(backup_env):
    """Create a fully schema-migrated SQLite DB in WAL mode with dirty pages."""
    db_path = backup_env["db_path"]
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)

    # 1. Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Manually create alembic_version table to emulate migration state
        await conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL, PRIMARY KEY (version_num));"
        )
        await conn.exec_driver_sql(
            "INSERT INTO alembic_version (version_num) VALUES ('20261021_0002');"
        )

    # 2. Configure WAL mode on raw connection
    raw_conn = sqlite3.connect(str(db_path))
    raw_conn.execute("PRAGMA journal_mode = WAL;")
    raw_conn.execute("PRAGMA synchronous = NORMAL;")
    raw_conn.close()

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    now = datetime(2026, 10, 21, 18, 0, 0, tzinfo=timezone.utc)

    # 3. Insert representative investigation and audit records
    async with session_factory() as session:
        async with session.begin():
            inv = Investigation(
                investigation_id="inv-test-backup-001",
                alert_id="alt-wazuh-101",
                run_sequence=1,
                status="completed",
                primary_rule_id="100002",
                primary_rule_level=7,
                primary_agent_name="agent-win11",
                created_at=now,
                updated_at=now,
            )
            session.add(inv)

            res = InvestigationResult(
                result_id="res-test-001",
                investigation_id="inv-test-backup-001",
                model_name="llama3.2:3b",
                model_tag="llama3.2:3b",
                prompt_version="v1.0",
                summary="Verified test investigation summary for backup validation.",
                confidence_label="HIGH",
                disclaimer="Local AI advisory assessment.",
                limitations_json="[]",
                warnings_json="[]",
                correlation_status="COMPLETED",
                created_at=now,
            )
            session.add(res)

            hyp = InvestigationHypothesis(
                hypothesis_id="hyp-test-001",
                result_id="res-test-001",
                hypothesis_identifier="H1",
                statement="Benign administrator maintenance activity.",
                uncertainty="LOW",
                cited_evidence_ids_json='["E1"]',
            )
            session.add(hyp)

            chk = InvestigationCheck(
                check_id="chk-test-001",
                result_id="res-test-001",
                check_identifier="CHECK-1",
                description="Verify user logon event",
                rationale="Confirm authorized user credentials",
                priority="HIGH",
                is_read_only=True,
            )
            session.add(chk)

            ev_snap = InvestigationEvidenceSnapshot(
                snapshot_id="snap-test-001",
                investigation_id="inv-test-backup-001",
                evidence_id="E1",
                source_record_id="rec-101",
                event_timestamp=now,
                is_primary=True,
                rule_id="100002",
                raw_evidence_ref="event_log_ref_01",
            )
            session.add(ev_snap)

            audit_ev = AuditEvent(
                audit_id="audit-test-001",
                timestamp=now,
                actor_id="local_analyst",
                action="INVESTIGATION_CREATED",
                resource_type="investigation",
                resource_id="inv-test-backup-001",
                outcome="SUCCESS",
                request_id="req-test-001",
                client_ip="127.0.0.1",
                previous_hash="0" * 64,
                event_hash=hashlib.sha256(b"test_event_data").hexdigest(),
            )
            session.add(audit_ev)

    await engine.dispose()
    return backup_env


def test_online_backup_captures_wal_state_safely(populated_wal_db):
    """Confirm online backup captures active WAL records, validates integrity, and preserves source untouched."""
    env = populated_wal_db
    service: DatabaseBackupService = env["service"]
    source_path: Path = env["db_path"]

    # Record source file metadata and mtime before backup
    source_stat_before = source_path.stat()
    hasher_before = hashlib.sha256()
    with open(source_path, "rb") as f:
        hasher_before.update(f.read())
    source_hash_before = hasher_before.hexdigest()

    # Execute online backup
    result = service.create_online_backup()

    assert result.success is True
    assert result.integrity_status == "VERIFIED"
    assert result.alembic_version == "20261021_0002"
    assert Path(result.backup_path).exists()
    assert result.file_size_bytes > 0
    assert len(result.backup_sha256) == 64

    # Verify table row counts match expected persisted entities
    counts = result.table_counts
    assert counts.get("investigations") == 1
    assert counts.get("investigation_results") == 1
    assert counts.get("investigation_hypotheses") == 1
    assert counts.get("investigation_checks") == 1
    assert counts.get("investigation_evidence_snapshots") == 1
    assert counts.get("audit_events") == 1
    assert counts.get("alembic_version") == 1

    # Confirm source database was not modified
    hasher_after = hashlib.sha256()
    with open(source_path, "rb") as f:
        hasher_after.update(f.read())
    source_hash_after = hasher_after.hexdigest()
    assert source_hash_after == source_hash_before


def test_backup_refuses_to_overwrite_existing_file(populated_wal_db):
    """Confirm create_online_backup refuses to overwrite an existing backup destination."""
    env = populated_wal_db
    service: DatabaseBackupService = env["service"]
    backup_dir: Path = env["backup_dir"]

    dest_file = "siem_fixed_name.db"
    # First backup succeeds
    res1 = service.create_online_backup(backup_filename=dest_file)
    assert res1.success is True

    # Second backup with same destination must fail closed
    with pytest.raises(FileExistsError) as exc_info:
        service.create_online_backup(backup_filename=dest_file)

    assert "already exists; overwriting is strictly prohibited" in str(exc_info.value)


def test_interrupted_backup_cleans_up_staging_file(populated_wal_db, monkeypatch):
    """Confirm that an interrupted backup does not leave an incomplete or mistaken database file."""
    env = populated_wal_db
    service: DatabaseBackupService = env["service"]
    backup_dir: Path = env["backup_dir"]
    target_name = "test_interrupted.db"
    staging_file = backup_dir / f"{target_name}.tmp"
    final_file = backup_dir / target_name

    # Mock validation failure midway through backup staging
    def mock_validate(path, *args, **kwargs):
        raise sqlite3.OperationalError("Simulated validation crash on staging backup")

    monkeypatch.setattr(service, "validate_sqlite_database", mock_validate)

    with pytest.raises(sqlite3.OperationalError):
        service.create_online_backup(backup_filename=target_name)

    # Assert neither the final file nor the staging temporary file exists
    assert not final_file.exists()
    assert not staging_file.exists()


def test_isolated_recovery_and_relationship_verification(populated_wal_db):
    """Restore backup into a temporary database and verify relationships and foreign keys."""
    env = populated_wal_db
    service: DatabaseBackupService = env["service"]
    tmp_path: Path = env["tmp_path"]

    # 1. Create verified backup
    backup_result = service.create_online_backup()
    backup_path = Path(backup_result.backup_path)

    # 2. Restore into a new isolated destination
    restore_target = tmp_path / "restored_drill" / "restored_siem_history.db"
    restore_result = service.restore_backup(
        backup_path=backup_path,
        target_db_path=restore_target,
    )

    assert restore_result.success is True
    assert restore_result.integrity_status == "VERIFIED"
    assert restore_result.alembic_version == "20261021_0002"
    assert restore_target.exists()

    # 3. Verify representative records and foreign-key joins in restored database
    conn = sqlite3.connect(f"file:{restore_target.as_posix()}?mode=ro", uri=True)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    # Foreign key check
    cursor.execute("PRAGMA foreign_key_check;")
    assert cursor.fetchall() == []

    # Join investigation -> results -> hypotheses -> checks
    cursor.execute("""
        SELECT 
            i.investigation_id, 
            i.alert_id, 
            r.confidence_label, 
            r.correlation_status,
            h.statement,
            c.check_identifier,
            s.evidence_id
        FROM investigations i
        JOIN investigation_results r ON i.investigation_id = r.investigation_id
        JOIN investigation_hypotheses h ON r.result_id = h.result_id
        JOIN investigation_checks c ON r.result_id = c.result_id
        JOIN investigation_evidence_snapshots s ON i.investigation_id = s.investigation_id;
    """)
    rows = cursor.fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == "inv-test-backup-001"
    assert row[1] == "alt-wazuh-101"
    assert row[2] == "HIGH"
    assert row[3] == "COMPLETED"
    assert row[4] == "Benign administrator maintenance activity."
    assert row[5] == "CHECK-1"
    assert row[6] == "E1"

    cursor.close()
    conn.close()


def test_corrupt_database_fails_validation_and_recovery(backup_env):
    """Confirm validation and restore fail closed when presented with a corrupt file."""
    env = backup_env
    service: DatabaseBackupService = env["service"]
    tmp_path: Path = env["tmp_path"]

    corrupt_file = tmp_path / "corrupt.db"
    # Write garbage bytes
    corrupt_file.write_bytes(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_DATA_123456789")

    # Validation must report False
    valid, _, err = service.validate_sqlite_database(corrupt_file)
    assert valid is False
    assert err is not None

    # Restoration attempt must raise DatabaseCorruptionError
    restore_target = tmp_path / "target_corrupt.db"
    with pytest.raises(DatabaseCorruptionError) as exc_info:
        service.restore_backup(backup_path=corrupt_file, target_db_path=restore_target)

    assert "Cannot restore from corrupt backup" in str(exc_info.value)
    assert not restore_target.exists()
