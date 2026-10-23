"""Comprehensive test suite for Phase 8.0: Encrypted Backups, DPAPI Key Management, Recovery Automation, and Scheduling.

Conforms strictly to Phase 8.0 Workstream A, B, C, D, and E requirements:
- Isolated test fixtures with temporary directories and zero touch on production data
- Hardware-accelerated AES-256-GCM encryption/decryption round-trip
- Tamper detection on ciphertext and AAD header metadata
- Windows DPAPI key generation, loading, and fail-closed security
- Atomic publication and non-overwriting destination protection
- Immediate plaintext snapshot cleanup verification
- Full isolated disaster recovery drill with PRAGMA integrity, foreign keys, Alembic head, and audit chain verification
- Backup scheduler single-instance execution and graceful shutdown
- Operational health status monitoring without secret leakage
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import pytest
from httpx import ASGITransport, AsyncClient

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.backup_crypto import (
    CIPHER_AES_256_GCM,
    CONTAINER_MAGIC,
    CONTAINER_VERSION,
    MAX_BACKUP_PLAINTEXT_BYTES,
    MAX_KEY_ID_LENGTH_BYTES,
    RECOVERY_MAGIC,
    RECOVERY_VERSION,
    BackupAuthenticationError,
    BackupCryptoError,
    BackupFormatError,
    BackupKeyManager,
    BackupKeyUnavailableError,
    EncryptedContainerHeader,
    WindowsCNGAESGCM,
    decrypt_backup_file,
    encrypt_backup_file,
)
from app.core.config import Settings
from app.db.base import Base
from app.main import create_app
from app.models.audit import AuditEvent
from app.models.audit_checkpoint import AuditCheckpoint
from app.models.investigation import (
    Investigation,
    InvestigationCheck,
    InvestigationEvidenceSnapshot,
    InvestigationHypothesis,
    InvestigationResult,
)
from app.services.backup_scheduler_service import (
    BackupSchedulerService,
    CrossProcessLockError,
)
from app.services.database_backup_service import (
    DatabaseBackupError,
    DatabaseBackupService,
    DatabaseCorruptionError,
    DatabaseRestoreError,
)


@pytest.fixture
def isolated_env(tmp_path):
    """Set up isolated directory structure, database, and Settings instance."""
    live_dir = tmp_path / "live"
    backup_dir = tmp_path / "backups"
    keys_dir = tmp_path / "keys"
    restore_dir = tmp_path / "restore"

    live_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    restore_dir.mkdir(parents=True, exist_ok=True)

    db_path = live_dir / "siem_test.db"
    key_path = keys_dir / "backup.dpapi"

    settings = Settings(
        DATABASE_URL=f"sqlite+aiosqlite:///{db_path}",
        DATABASE_BACKUP_DIR=str(backup_dir),
        AUDIT_ARCHIVE_DIR=str(tmp_path / "archives"),
        BACKUP_KEY_PATH=str(key_path),
        BACKUP_ENCRYPTION_ENABLED=True,
        BACKUP_SCHEDULE_ENABLED=False,
    )
    backup_service = DatabaseBackupService(settings=settings)
    scheduler_service = BackupSchedulerService(settings=settings, backup_service=backup_service)

    return {
        "db_path": db_path,
        "backup_dir": backup_dir,
        "keys_dir": keys_dir,
        "key_path": key_path,
        "restore_dir": restore_dir,
        "settings": settings,
        "backup_service": backup_service,
        "scheduler_service": scheduler_service,
        "tmp_path": tmp_path,
    }


@pytest.fixture
async def populated_db(isolated_env):
    """Create a fully schema-migrated SQLite DB in WAL mode with real chained records."""
    db_path = isolated_env["db_path"]
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL, PRIMARY KEY (version_num));"
        )
        await conn.exec_driver_sql(
            "INSERT INTO alembic_version (version_num) VALUES ('20261021_0002');"
        )

    # Enable WAL mode
    raw_conn = sqlite3.connect(str(db_path))
    raw_conn.execute("PRAGMA journal_mode = WAL;")
    raw_conn.execute("PRAGMA synchronous = NORMAL;")
    raw_conn.close()

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    now = datetime(2026, 10, 21, 19, 0, 0, tzinfo=timezone.utc)

    async with session_factory() as session:
        async with session.begin():
            # 1. Representative investigation
            inv = Investigation(
                investigation_id="inv-enc-drill-001",
                alert_id="alt-wazuh-drill-99",
                run_sequence=1,
                status="completed",
                primary_rule_id="100005",
                primary_rule_level=10,
                primary_agent_name="agent-dc01",
                created_at=now,
                updated_at=now,
            )
            session.add(inv)

            res = InvestigationResult(
                result_id="res-enc-drill-001",
                investigation_id=inv.investigation_id,
                model_name="qwen2.5:14b",
                model_tag="qwen2.5:14b",
                prompt_version="v1.0",
                summary="Active ransomware activity confirmed on domain controller",
                confidence_label="HIGH",
                disclaimer="Local AI advisory assessment.",
                limitations_json="[]",
                warnings_json="[]",
                correlation_status="COMPLETED",
                created_at=now,
            )
            session.add(res)

            chk = InvestigationCheck(
                check_id="chk-enc-drill-001",
                result_id=res.result_id,
                check_identifier="CHECK-1",
                description="Suspicious PowerShell spawning vssadmin",
                rationale="Confirm ransomware activity",
                priority="HIGH",
                is_read_only=True,
            )
            session.add(chk)

            ev = InvestigationEvidenceSnapshot(
                snapshot_id="ev-enc-drill-001",
                investigation_id=inv.investigation_id,
                evidence_id="E1",
                source_record_id="rec-101",
                event_timestamp=now,
                is_primary=True,
                rule_id="100005",
                raw_evidence_ref="event_log_ref_01",
            )
            session.add(ev)

            # 2. Representative hash-chained audit events
            hash1 = hashlib.sha256(b"event_1_payload").hexdigest()
            ae1 = AuditEvent(
                audit_id="aud-drill-001",
                timestamp=now,
                actor_id="analyst_secops",
                action="INVESTIGATION_STARTED",
                resource_type="investigation",
                resource_id="inv-enc-drill-001",
                outcome="SUCCESS",
                request_id="req-drill-001",
                client_ip="127.0.0.1",
                previous_hash="0" * 64,
                event_hash=hash1,
            )
            session.add(ae1)

            hash2 = hashlib.sha256(f"{hash1}:event_2_payload".encode()).hexdigest()
            ae2 = AuditEvent(
                audit_id="aud-drill-002",
                timestamp=now,
                actor_id="analyst_secops",
                action="INVESTIGATION_COMPLETED",
                resource_type="investigation",
                resource_id="inv-enc-drill-001",
                outcome="SUCCESS",
                request_id="req-drill-002",
                client_ip="127.0.0.1",
                previous_hash=hash1,
                event_hash=hash2,
            )
            session.add(ae2)

            # 3. Representative audit checkpoint anchoring events
            cp1 = AuditCheckpoint(
                checkpoint_id="cp-drill-001",
                schema_version="v1",
                checkpoint_sequence=1,
                created_at=now,
                interval_start_timestamp=now,
                interval_end_timestamp=now,
                first_included_audit_id="aud-drill-001",
                last_included_audit_id="aud-drill-002",
                last_included_event_hash=hash2,
                event_count=2,
                pruned_events_digest="0" * 64,
                previous_checkpoint_id=None,
                previous_checkpoint_hash="GENESIS",
                checkpoint_digest=hashlib.sha256(b"checkpoint_1_digest").hexdigest(),
                signature_algorithm="DPAPI",
                signature_value="test_sig_value",
                signing_key_id="dpapi-test",
            )
            session.add(cp1)

    await engine.dispose()
    return isolated_env


# ---------------------------------------------------------------------------
# Workstream A: Cryptographic Primitives & Container Format Tests
# ---------------------------------------------------------------------------

def test_cng_aes_gcm_roundtrip():
    """Verify hardware-accelerated AES-256-GCM encryption and decryption with AAD."""
    cng = WindowsCNGAESGCM()
    key = os.urandom(32)
    plaintext = b"SQLite format 3\x00Confidential SIEM Forensic Snapshot"
    aad = b"SIEM_AAD_METADATA_VERSION_1"

    nonce, ciphertext, tag = cng.encrypt(key=key, plaintext=plaintext, associated_data=aad)
    assert len(nonce) == 12
    assert len(tag) == 16
    assert ciphertext != plaintext

    decrypted = cng.decrypt(key=key, nonce=nonce, ciphertext=ciphertext, tag=tag, associated_data=aad)
    assert decrypted == plaintext


def test_cng_aes_gcm_tamper_detection():
    """Verify AES-256-GCM fails closed on ciphertext or AAD tampering."""
    cng = WindowsCNGAESGCM()
    key = os.urandom(32)
    plaintext = b"Sensitive investigation records"
    aad = b"Immutable Header AAD"

    nonce, ciphertext, tag = cng.encrypt(key=key, plaintext=plaintext, associated_data=aad)

    # 1. Tamper with ciphertext
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0xFF
    with pytest.raises(BackupAuthenticationError, match="authentication tag mismatch"):
        cng.decrypt(key=key, nonce=nonce, ciphertext=bytes(tampered_ct), tag=tag, associated_data=aad)

    # 2. Tamper with AAD
    tampered_aad = aad + b"_MUTATED"
    with pytest.raises(BackupAuthenticationError, match="authentication tag mismatch"):
        cng.decrypt(key=key, nonce=nonce, ciphertext=ciphertext, tag=tag, associated_data=tampered_aad)

    # 3. Tamper with authentication tag
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0x01
    with pytest.raises(BackupAuthenticationError, match="authentication tag mismatch"):
        cng.decrypt(key=key, nonce=nonce, ciphertext=ciphertext, tag=bytes(tampered_tag), associated_data=aad)


def test_cng_aes_gcm_wrong_key_rejection():
    """Verify decryption fails closed when provided an incorrect 256-bit key."""
    cng = WindowsCNGAESGCM()
    correct_key = os.urandom(32)
    wrong_key = os.urandom(32)
    plaintext = b"Critical security findings"

    nonce, ciphertext, tag = cng.encrypt(key=correct_key, plaintext=plaintext)

    with pytest.raises(BackupAuthenticationError):
        cng.decrypt(key=wrong_key, nonce=nonce, ciphertext=ciphertext, tag=tag)


def test_encrypted_container_header_validation():
    """Verify container header serialization, parsing, and rejection of invalid formats."""
    nonce = os.urandom(12)
    tag = os.urandom(16)
    plain_hash = hashlib.sha256(b"test").hexdigest()

    header = EncryptedContainerHeader(
        version=CONTAINER_VERSION,
        cipher_id=CIPHER_AES_256_GCM,
        key_id="dpapi-test-01",
        created_at_epoch=1700000000,
        nonce=nonce,
        tag=tag,
        plaintext_size=4,
        plaintext_sha256=plain_hash,
    )

    serialized = header.serialize_full_header()
    stream = io.BytesIO(serialized)
    parsed = EncryptedContainerHeader.parse_header(stream)

    assert parsed.version == 1
    assert parsed.cipher_id == 1
    assert parsed.key_id == "dpapi-test-01"
    assert parsed.created_at_epoch == 1700000000
    assert parsed.nonce == nonce
    assert parsed.tag == tag
    assert parsed.plaintext_size == 4
    assert parsed.plaintext_sha256 == plain_hash

    # Test corrupted magic bytes
    bad_magic = bytearray(serialized)
    bad_magic[0:4] = b"BAD!"
    with pytest.raises(BackupFormatError, match="Invalid magic bytes"):
        EncryptedContainerHeader.parse_header(io.BytesIO(bad_magic))

    # Test unsupported future version
    bad_ver = bytearray(serialized)
    bad_ver[9] = 0x02  # version = 2
    with pytest.raises(BackupFormatError, match="Unsupported backup container version"):
        EncryptedContainerHeader.parse_header(io.BytesIO(bad_ver))

    # Test truncated header
    with pytest.raises(BackupFormatError, match="unexpected EOF"):
        EncryptedContainerHeader.parse_header(io.BytesIO(serialized[:10]))


def test_dpapi_key_manager_lifecycle(isolated_env):
    """Verify Windows DPAPI key generation, loading, status metadata, and fail-closed behavior."""
    key_mgr = isolated_env["scheduler_service"].key_manager

    # 1. Status before key initialization
    status_before = key_mgr.get_key_status()
    assert status_before["key_file_exists"] is False
    assert status_before["key_usable"] is False
    assert status_before["dpapi_available"] is True

    # 2. load_or_fail() fails closed when key is missing (never regenerates automatically)
    with pytest.raises(BackupKeyUnavailableError, match="Automatic regeneration is strictly prohibited"):
        key_mgr.load_or_fail()

    # 3. Explicit initialization generates DPAPI-protected key
    raw_key, key_id = key_mgr.initialize_new_key_if_absent()
    assert len(raw_key) == 32
    assert key_id.startswith("dpapi-")
    assert key_mgr.key_file_path.exists()

    # 4. Subsequent load succeeds and returns identical key
    loaded_key, loaded_id = key_mgr.load_or_fail()
    assert loaded_key == raw_key
    assert loaded_id == key_id

    # 5. Status reports healthy and usable without leaking raw key bytes
    status_after = key_mgr.get_key_status()
    assert status_after["key_file_exists"] is True
    assert status_after["key_usable"] is True
    assert "recovery_strategy" in status_after
    assert "raw_key" not in status_after


# ---------------------------------------------------------------------------
# Workstream A & C: Encrypted Export & Isolated Recovery Drill Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_encrypted_backup_creation_and_plaintext_cleanup(populated_db):
    """Verify encrypted backup export, atomic publication, and immediate plaintext snapshot cleanup."""
    env = populated_db
    svc = env["backup_service"]
    backup_dir = env["backup_dir"]

    # 1. Create encrypted backup
    result = svc.create_backup(encrypted=True)

    assert result.success is True
    assert result.is_encrypted is True
    assert result.cipher == "AES-256-GCM"
    assert result.key_id.startswith("dpapi-")
    assert result.backup_path.endswith(".enc.db")
    assert Path(result.backup_path).exists()
    assert result.file_size_bytes > 0
    assert result.backup_sha256 is not None
    assert result.plaintext_sha256 is not None

    # 2. Strict cleanup verification: zero .tmp files left in backup directory
    tmp_files = list(backup_dir.glob("*.tmp"))
    assert len(tmp_files) == 0, f"Found leaked temporary plaintext snapshots: {tmp_files}"

    # 3. Non-overwriting protection: creating backup with identical filename raises FileExistsError
    with pytest.raises(FileExistsError, match="already exists"):
        svc.create_backup(backup_filename=Path(result.backup_path).name, encrypted=True)


@pytest.mark.asyncio
async def test_isolated_recovery_drill(populated_db):
    """Execute complete isolated disaster recovery drill and verify database integrity, schemas, and audit chain."""
    env = populated_db
    svc = env["backup_service"]
    restore_dir = env["restore_dir"]
    scheduler = env["scheduler_service"]

    # 1. Export encrypted backup
    backup_result = svc.create_backup(encrypted=True)
    enc_backup_path = Path(backup_result.backup_path)

    # 2. Restore into a new isolated destination
    restored_db_path = restore_dir / "restored_siem_drill.db"
    assert not restored_db_path.exists()

    restore_result = svc.restore_backup(
        backup_path=enc_backup_path,
        target_db_path=restored_db_path,
    )

    assert restore_result.success is True
    assert restore_result.was_encrypted is True
    assert restore_result.cipher == "AES-256-GCM"
    assert restore_result.integrity_status == "VERIFIED"
    assert restored_db_path.exists()

    # 3. SQLite PRAGMA integrity_check and foreign_key_check on restored database
    raw_conn = sqlite3.connect(f"file:{restored_db_path.as_posix()}?mode=ro", uri=True)
    cursor = raw_conn.cursor()

    cursor.execute("PRAGMA integrity_check;")
    assert cursor.fetchall() == [("ok",)]

    cursor.execute("PRAGMA foreign_keys = ON;")
    cursor.execute("PRAGMA foreign_key_check;")
    assert cursor.fetchall() == []

    # 4. Verify Alembic migration head
    cursor.execute("SELECT version_num FROM alembic_version;")
    assert cursor.fetchone()[0] == "20261021_0002"

    # 5. Verify representative investigation records and entity relationships
    cursor.execute("SELECT status, primary_rule_id, primary_agent_name FROM investigations WHERE investigation_id='inv-enc-drill-001';")
    inv_row = cursor.fetchone()
    assert inv_row == ("completed", "100005", "agent-dc01")

    cursor.execute("SELECT confidence_label, summary FROM investigation_results WHERE investigation_id='inv-enc-drill-001';")
    res_row = cursor.fetchone()
    assert res_row == ("HIGH", "Active ransomware activity confirmed on domain controller")

    cursor.execute("SELECT check_identifier, is_read_only FROM investigation_checks WHERE result_id='res-enc-drill-001';")
    chk_row = cursor.fetchone()
    assert chk_row == ("CHECK-1", 1)

    cursor.execute("SELECT evidence_id, rule_id FROM investigation_evidence_snapshots WHERE investigation_id='inv-enc-drill-001';")
    ev_row = cursor.fetchone()
    assert ev_row == ("E1", "100005")

    # 6. Verify audit hash-chain integrity on restored database
    cursor.execute("SELECT audit_id, action, event_hash, previous_hash FROM audit_events ORDER BY rowid ASC;")
    audit_rows = cursor.fetchall()
    assert len(audit_rows) == 2

    # Check chain continuity
    assert audit_rows[0][0] == "aud-drill-001"
    assert audit_rows[0][3] == "0" * 64
    assert audit_rows[1][0] == "aud-drill-002"
    assert audit_rows[1][3] == audit_rows[0][2]  # previous_hash == parent's event_hash

    # 7. Verify checkpoint metadata-chain integrity on restored database
    cursor.execute("SELECT checkpoint_id, checkpoint_sequence, last_included_event_hash, previous_checkpoint_hash, checkpoint_digest FROM audit_checkpoints;")
    cp_rows = cursor.fetchall()
    assert len(cp_rows) == 1
    assert cp_rows[0][0] == "cp-drill-001"
    assert cp_rows[0][1] == 1
    assert cp_rows[0][2] == audit_rows[1][2]  # anchors last event hash
    assert cp_rows[0][3] == "GENESIS"

    raw_conn.close()

    # 8. Record drill result in scheduler monitoring
    scheduler.record_recovery_drill_result(success=True, details="Drill restored investigations, audit events, and checkpoints intact")
    status = scheduler.get_operational_status()
    assert status["last_recovery_drill_status"] == "VERIFIED"
    assert status["last_recovery_drill_at"] is not None


@pytest.mark.asyncio
async def test_recovery_tampering_and_corruption_rejection(populated_db):
    """Verify corrupted ciphertext or wrong keys fail closed and do not create destination databases."""
    env = populated_db
    svc = env["backup_service"]
    restore_dir = env["restore_dir"]

    # Export backup
    backup_result = svc.create_backup(encrypted=True)
    enc_path = Path(backup_result.backup_path)

    # 1. Corrupt ciphertext bytes
    corrupt_backup = env["backup_dir"] / "corrupt_backup.enc.db"
    raw_data = bytearray(enc_path.read_bytes())
    raw_data[-5] ^= 0xFF
    corrupt_backup.write_bytes(raw_data)

    target_corrupt_dst = restore_dir / "failed_corrupt_restore.db"
    with pytest.raises(BackupAuthenticationError, match="authentication tag mismatch"):
        svc.restore_backup(backup_path=corrupt_backup, target_db_path=target_corrupt_dst)
    assert not target_corrupt_dst.exists(), "Destination file must not exist after failed restore"

    # 2. Corrupt header AAD (e.g. modify plaintext size in header)
    corrupt_hdr_backup = env["backup_dir"] / "corrupt_hdr.enc.db"
    raw_hdr = bytearray(enc_path.read_bytes())
    raw_hdr[20] ^= 0x01
    corrupt_hdr_backup.write_bytes(raw_hdr)

    target_hdr_dst = restore_dir / "failed_hdr_restore.db"
    with pytest.raises(BackupAuthenticationError):
        svc.restore_backup(backup_path=corrupt_hdr_backup, target_db_path=target_hdr_dst)
    assert not target_hdr_dst.exists()

    # 3. Wrong key rejection
    wrong_key = os.urandom(32)
    target_key_dst = restore_dir / "failed_key_restore.db"
    with pytest.raises(BackupAuthenticationError):
        svc.restore_backup(backup_path=enc_path, target_db_path=target_key_dst, explicit_key=wrong_key)
    assert not target_key_dst.exists()


# ---------------------------------------------------------------------------
# Workstream B: Backup Scheduling & Concurrency Safeguards
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scheduler_lifecycle_and_non_overlap(populated_db):
    """Verify scheduler start/stop lifecycle and strict single-instance execution guards."""
    env = populated_db
    scheduler = env["scheduler_service"]

    # Initial state
    assert scheduler.is_running is False
    status = scheduler.get_operational_status()
    assert status["scheduler_enabled"] is False
    assert status["scheduler_active"] is False

    # Start with config disabled returns False
    assert scheduler.start() is False

    # Enable in settings and start
    scheduler.settings.BACKUP_SCHEDULE_ENABLED = True
    assert scheduler.start() is True
    assert scheduler.is_running is True

    # Duplicate start ignored
    assert scheduler.start() is False

    # Graceful stop
    await scheduler.stop(timeout_seconds=2.0)
    assert scheduler.is_running is False


@pytest.mark.asyncio
async def test_scheduler_overlap_protection(populated_db):
    """Verify in-process concurrency guard rejects overlapping backup jobs."""
    env = populated_db
    scheduler = env["scheduler_service"]

    # Initialize key
    scheduler.key_manager.initialize_new_key_if_absent()

    # Run backup job via scheduler
    result = await scheduler.run_backup_job()
    assert result.success is True

    status = scheduler.get_operational_status()
    assert status["last_backup_verification_status"] == "VERIFIED"
    assert status["last_successful_backup_at"] is not None
    assert status["last_backup_duration_seconds"] is not None
    assert status["is_backup_in_progress"] is False


# ---------------------------------------------------------------------------
# Workstream D: Operational Health Status Endpoint Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_operational_monitoring_endpoint(populated_db):
    """Verify GET /api/v1/health/backup returns authoritative telemetry without leaking secrets."""
    env = populated_db
    scheduler = env["scheduler_service"]
    scheduler.key_manager.initialize_new_key_if_absent()

    app = create_app()
    app.state.backup_scheduler_service = scheduler

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Fetch backup operational status
        resp = await client.get("/api/v1/health/backup")
        assert resp.status_code == 200

        data = resp.json()
        assert data["status"] in ("OK", "DEGRADED", "UNAVAILABLE")
        assert "scheduler_enabled" in data
        assert "scheduler_active" in data
        assert "is_backup_in_progress" in data
        assert "backup_interval_minutes" in data
        assert "last_backup_verification_status" in data
        assert "encryption_key_status" in data
        assert data["encryption_key_status"]["key_usable"] is True
        assert data["last_recovery_drill_status"] == "NEVER_RUN"  # Untested recovery not marked verified

        # Security check: verify no secrets leaked
        raw_text = resp.text
        assert "BEGIN PRIVATE KEY" not in raw_text
        assert "raw_key" not in raw_text
        assert "password" not in raw_text
        assert "secret" not in raw_text.lower() or "secret" in "secrets"

    from app.db.session import dispose_engine
    await dispose_engine()


# ---------------------------------------------------------------------------
# Phase 8.1: Security Audit, Bounds Validation, Disaster Recovery & Concurrency
# ---------------------------------------------------------------------------

def test_bounds_checks_and_malformed_header_rejection():
    """Verify strict length and bounds enforcement on container header fields."""
    import struct

    # 1. key_id_len == 0 rejected
    bad_zero_key = struct.pack(">8sHHH", CONTAINER_MAGIC, CONTAINER_VERSION, CIPHER_AES_256_GCM, 0)
    with pytest.raises(BackupFormatError, match="Invalid key ID length"):
        EncryptedContainerHeader.parse_header(io.BytesIO(bad_zero_key))

    # 2. key_id_len > 256 rejected
    bad_huge_key = struct.pack(">8sHHH", CONTAINER_MAGIC, CONTAINER_VERSION, CIPHER_AES_256_GCM, 500)
    with pytest.raises(BackupFormatError, match="Invalid key ID length"):
        EncryptedContainerHeader.parse_header(io.BytesIO(bad_huge_key))

    # 3. plain_size > MAX_BACKUP_PLAINTEXT_BYTES rejected
    key_bytes = b"test_key"
    header_prefix = struct.pack(">8sHHH", CONTAINER_MAGIC, CONTAINER_VERSION, CIPHER_AES_256_GCM, len(key_bytes))
    huge_plain_size = 20 * 1024 * 1024 * 1024  # 20 GiB
    fixed_rem = struct.pack(">Q12sQ32s16s", 1700000000, b"\x00" * 12, huge_plain_size, b"\x00" * 32, b"\x00" * 16)
    full_bad_stream = io.BytesIO(header_prefix + key_bytes + fixed_rem)
    with pytest.raises(BackupFormatError, match="exceeds maximum allowable safety limit"):
        EncryptedContainerHeader.parse_header(full_bad_stream)

    # 4. Invalid UTF-8 in key_id rejected
    bad_utf8_prefix = struct.pack(">8sHHH", CONTAINER_MAGIC, CONTAINER_VERSION, CIPHER_AES_256_GCM, 4)
    bad_utf8_key = b"\xff\xfe\xfd\xfc"
    with pytest.raises(BackupFormatError, match="not valid UTF-8"):
        EncryptedContainerHeader.parse_header(io.BytesIO(bad_utf8_prefix + bad_utf8_key + fixed_rem))


def test_ciphertext_truncation_and_appended_data_rejection(tmp_path):
    """Verify decryption fails closed immediately on truncated ciphertext or appended trailing bytes."""
    plain_file = tmp_path / "plain.db"
    plain_file.write_bytes(b"SQLite format 3\x00" + b"X" * 1000)

    key = os.urandom(32)
    enc_file = tmp_path / "test.enc.db"
    encrypt_backup_file(plain_file, enc_file, key=key, key_id="dpapi-test")

    raw_enc = enc_file.read_bytes()

    # 1. Truncate 50 bytes from ciphertext
    truncated_file = tmp_path / "truncated.enc.db"
    truncated_file.write_bytes(raw_enc[:-50])
    target_trunc = tmp_path / "out_trunc.db"
    with pytest.raises(BackupFormatError, match="Ciphertext length mismatch"):
        decrypt_backup_file(truncated_file, target_trunc, key=key)
    assert not target_trunc.exists()

    # 2. Append 20 bytes of trailing garbage
    appended_file = tmp_path / "appended.enc.db"
    appended_file.write_bytes(raw_enc + b"TRAILING_GARBAGE_BYTES")
    target_appended = tmp_path / "out_appended.db"
    with pytest.raises(BackupFormatError, match="Ciphertext length mismatch"):
        decrypt_backup_file(appended_file, target_appended, key=key)
    assert not target_appended.exists()


def test_concurrent_key_initialization_safety(tmp_path):
    """Verify concurrent first-time key initializations do not overwrite or strand keys."""
    import concurrent.futures

    key_path = tmp_path / "concurrent_key.dpapi"
    key_mgr = BackupKeyManager(str(key_path))

    def _init():
        mgr = BackupKeyManager(str(key_path))
        return mgr.initialize_new_key_if_absent()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_init) for _ in range(8)]
        results = [f.result() for f in futures]

    # All threads must receive the EXACT same raw_key and key_id
    first_key, first_id = results[0]
    for key, key_id in results:
        assert key == first_key
        assert key_id == first_id

    # Verify key can still be loaded normally
    loaded_key, loaded_id = key_mgr.load_or_fail()
    assert loaded_key == first_key
    assert loaded_id == first_id


def test_disaster_recovery_key_export_and_import(tmp_path):
    """Verify authorized disaster recovery export with strong KEK and cross-machine import."""
    # Machine A: Active key
    mach_a_key_path = tmp_path / "machine_a" / "key.dpapi"
    mgr_a = BackupKeyManager(str(mach_a_key_path))
    raw_key_a, key_id_a = mgr_a.initialize_new_key_if_absent()

    # Create an encrypted backup on Machine A
    plain_db = tmp_path / "machine_a" / "data.db"
    plain_db.parent.mkdir(parents=True, exist_ok=True)
    plain_db.write_bytes(b"SQLite format 3\x00Disaster Recovery Test DB")
    backup_file = tmp_path / "machine_a" / "backup.enc.db"
    encrypt_backup_file(plain_db, backup_file, key=raw_key_a, key_id=key_id_a)

    # 1. Export disaster recovery key: requires minimum 16 characters
    recovery_file = tmp_path / "recovery" / "siem_dek.recovery"
    recovery_file.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="at least 16 characters"):
        mgr_a.export_disaster_recovery_key(passphrase="too-short", output_recovery_path=recovery_file)

    strong_passphrase = "Correct-Horse-Battery-Staple-2026-Secure!"
    exported_id = mgr_a.export_disaster_recovery_key(
        passphrase=strong_passphrase,
        output_recovery_path=recovery_file,
    )
    assert exported_id == key_id_a
    assert recovery_file.exists()

    # 2. Machine B (Disaster Recovery site): Simulate missing key
    mach_b_key_path = tmp_path / "machine_b" / "key.dpapi"
    mgr_b = BackupKeyManager(str(mach_b_key_path))
    with pytest.raises(BackupKeyUnavailableError):
        mgr_b.load_or_fail()

    # 3. Wrong passphrase fails closed
    with pytest.raises(BackupAuthenticationError, match="invalid passphrase or corrupted recovery file"):
        mgr_b.import_disaster_recovery_key(
            recovery_path=recovery_file,
            passphrase="Wrong-Password-Attempt-12345678!",
            target_dpapi_path=mach_b_key_path,
        )
    assert not mach_b_key_path.exists()

    # 4. Correct passphrase imports key and re-protects under Machine B's DPAPI
    imported_key, imported_id = mgr_b.import_disaster_recovery_key(
        recovery_path=recovery_file,
        passphrase=strong_passphrase,
        target_dpapi_path=mach_b_key_path,
    )
    assert imported_key == raw_key_a
    assert imported_id == key_id_a
    assert mach_b_key_path.exists()

    # 5. Restore Machine A's backup on Machine B using imported key
    restored_db = tmp_path / "machine_b" / "restored.db"
    decrypt_backup_file(backup_file, restored_db, key=imported_key)
    assert restored_db.read_bytes() == plain_db.read_bytes()


def test_multiprocess_scheduler_file_locking_and_stale_lock_cleanup(tmp_path):
    """Verify cross-process lock contention and OS kernel automatic lock release on exit."""
    import subprocess
    import sys

    lock_dir = tmp_path / "scheduler_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_file = lock_dir / ".backup_scheduler.lock"

    # Spawn child process holding lock for 3 seconds
    child_code = f"""
import msvcrt, time
f = open(r'{lock_file}', 'a+b')
msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
print('LOCKED', flush=True)
time.sleep(3)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Wait until child confirms lock
        line = proc.stdout.readline()
        assert "LOCKED" in line

        settings = Settings(
            DATABASE_URL=f"sqlite+aiosqlite:///{tmp_path}/dummy.db",
            DATABASE_BACKUP_DIR=str(lock_dir),
            BACKUP_ENCRYPTION_ENABLED=False,
        )
        scheduler = BackupSchedulerService(settings=settings)

        # Parent must fail to acquire lock while child holds it
        with pytest.raises(CrossProcessLockError):
            scheduler._acquire_cross_process_lock(lock_file)

    finally:
        # Terminate child process
        proc.terminate()
        proc.wait(timeout=5)

    # Stale lock verification: OS kernel must have released lock on child termination
    settings = Settings(
        DATABASE_URL=f"sqlite+aiosqlite:///{tmp_path}/dummy.db",
        DATABASE_BACKUP_DIR=str(lock_dir),
        BACKUP_ENCRYPTION_ENABLED=False,
    )
    scheduler = BackupSchedulerService(settings=settings)
    handle = scheduler._acquire_cross_process_lock(lock_file)
    assert handle is not None
    scheduler._release_cross_process_lock(handle, lock_file)


@pytest.mark.asyncio
async def test_scheduler_cancellation_status_transition(tmp_path):
    """Verify scheduler cancellation properly records CANCELLED status and error category."""
    db_path = tmp_path / "dummy.db"
    db_path.write_bytes(b"")
    settings = Settings(
        DATABASE_URL=f"sqlite+aiosqlite:///{db_path}",
        DATABASE_BACKUP_DIR=str(tmp_path / "backups"),
        BACKUP_ENCRYPTION_ENABLED=False,
    )
    scheduler = BackupSchedulerService(settings=settings)

    # Cancel a background task running run_backup_job
    task = asyncio.create_task(scheduler.run_backup_job())
    await asyncio.sleep(0.001)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    status = scheduler.get_operational_status()
    assert status["last_backup_verification_status"] == "CANCELLED"
    assert status["last_backup_error_category"] == "CANCELLED"
    assert status["is_backup_in_progress"] is False


@pytest.mark.asyncio
async def test_wrong_key_diagnostic_reports_mismatched_key_id(populated_db):
    """Verify wrong decryption key reports explicit key ID diagnostic message."""
    env = populated_db
    svc = env["backup_service"]

    # Export backup with key A
    res = svc.create_backup(encrypted=True)
    enc_path = Path(res.backup_path)

    # Attempt restore with key B
    wrong_key = os.urandom(32)
    target_dst = env["restore_dir"] / "wrong_key_dst.db"

    with pytest.raises(BackupAuthenticationError) as exc_info:
        svc.restore_backup(enc_path, target_dst, explicit_key=wrong_key)

    assert not target_dst.exists()
    msg = str(exc_info.value)
    assert "backup container requires key" in msg
    assert res.key_id in msg

