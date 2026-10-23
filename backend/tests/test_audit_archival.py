"""Unit and integration tests for AuditArchivalService, compressed offline verification, and path safety.

Conforms strictly to specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md and approved ADR-013.
Uses isolated temporary directories and databases.
"""

from datetime import datetime, timedelta, timezone
import gzip
import json
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.audit_crypto import (
    compute_canonical_event_hash,
    compute_rolling_events_digest,
    format_canonical_timestamp,
    sign_digest_hmac,
)
from app.db.base import Base
from app.models.audit import AuditEvent
from app.repositories.audit_repository import AuditRepository
from app.services.audit_archival_service import (
    AuditArchivalError,
    AuditArchivalService,
    AuditTrailVerificationReport,
    PathTraversalError,
)
from app.services.retention_service import RetentionService


@pytest.fixture
def archival_service(tmp_path):
    """Archival service initialized to an isolated temporary directory."""
    archive_dir = tmp_path / "archives"
    return AuditArchivalService(archive_base_dir=str(archive_dir))


@pytest.fixture
async def sample_events(tmp_path):
    """Create a list of 5 valid, sequential AuditEvent records in an isolated DB."""
    db_file = tmp_path / "test_archival.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 6):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id=f"analyst-{i}",
                    action=f"AUDIT_ARCHIVE_ACTION_{i}",
                    resource_type="investigation",
                    resource_id=f"inv-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    yield events
    await engine.dispose()


def test_archive_export_and_offline_verification(archival_service, sample_events):
    """Export audit events to compressed JSON archive and verify offline integrity."""
    now = sample_events[0].timestamp
    interval_start = now
    interval_end = sample_events[-1].timestamp

    archive_path, file_sha256, rolling_digest = archival_service.export_archive(
        checkpoint_sequence=1,
        interval_start=interval_start,
        interval_end=interval_end,
        events=sample_events,
    )

    assert archive_path.exists()
    assert archive_path.name.endswith(".json.gz")
    assert len(file_sha256) == 64
    assert len(rolling_digest) == 64

    # Verify archive offline
    valid, count, err = archival_service.verify_archive_file(
        archive_path=archive_path,
        expected_sha256=file_sha256,
        expected_count=len(sample_events),
        expected_first_id=sample_events[0].audit_id,
        expected_last_id=sample_events[-1].audit_id,
        expected_last_hash=sample_events[-1].event_hash,
        expected_rolling_digest=rolling_digest,
    )

    assert valid is True
    assert count == len(sample_events)
    assert err is None


def test_archive_verification_detects_physical_file_tampering(archival_service, sample_events):
    """Detect byte-level modification of the physical archive file."""
    archive_path, file_sha256, rolling_digest = archival_service.export_archive(
        checkpoint_sequence=1,
        interval_start=sample_events[0].timestamp,
        interval_end=sample_events[-1].timestamp,
        events=sample_events,
    )

    # Tamper with the archive file by corrupting one byte at the end
    with open(archive_path, "r+b") as f:
        f.seek(-5, 2)
        f.write(b"\x00\x00")

    # Verifier must detect file hash mismatch and fail closed
    valid, count, err = archival_service.verify_archive_file(
        archive_path=archive_path,
        expected_sha256=file_sha256,
        expected_count=len(sample_events),
        expected_first_id=sample_events[0].audit_id,
        expected_last_id=sample_events[-1].audit_id,
        expected_last_hash=sample_events[-1].event_hash,
        expected_rolling_digest=rolling_digest,
    )

    assert valid is False
    assert "ARCHIVE_FILE_TAMPERED" in err


def test_archive_verification_detects_event_count_and_boundary_mismatch(archival_service, sample_events):
    """Detect discrepancies in event count or boundary audit IDs."""
    archive_path, file_sha256, rolling_digest = archival_service.export_archive(
        checkpoint_sequence=1,
        interval_start=sample_events[0].timestamp,
        interval_end=sample_events[-1].timestamp,
        events=sample_events,
    )

    # Wrong event count
    valid, count, err = archival_service.verify_archive_file(
        archive_path=archive_path,
        expected_sha256=file_sha256,
        expected_count=99,
        expected_first_id=sample_events[0].audit_id,
        expected_last_id=sample_events[-1].audit_id,
        expected_last_hash=sample_events[-1].event_hash,
        expected_rolling_digest=rolling_digest,
    )
    assert valid is False
    assert "ARCHIVE_COUNT_MISMATCH" in err

    # Wrong first ID
    valid, count, err = archival_service.verify_archive_file(
        archive_path=archive_path,
        expected_sha256=file_sha256,
        expected_count=len(sample_events),
        expected_first_id="fake-id-000",
        expected_last_id=sample_events[-1].audit_id,
        expected_last_hash=sample_events[-1].event_hash,
        expected_rolling_digest=rolling_digest,
    )
    assert valid is False
    assert "ARCHIVE_BOUNDARY_MISMATCH" in err


def test_archive_path_traversal_rejection(archival_service):
    """Ensure path traversal payloads are strictly rejected."""
    bad_filenames = [
        "../escaped.json.gz",
        "..\\escaped.json.gz",
        "sub/dir/test.json.gz",
        "../../../../Windows/System32/malicious.gz",
    ]

    for bad_name in bad_filenames:
        with pytest.raises(PathTraversalError):
            archival_service.validate_archive_path(bad_name)


def test_archive_missing_file_detection(archival_service, tmp_path):
    """Detect missing archive file gracefully."""
    fake_path = tmp_path / "archives" / "does_not_exist.json.gz"
    valid, count, err = archival_service.verify_archive_file(
        archive_path=fake_path,
        expected_sha256="a" * 64,
        expected_count=5,
        expected_first_id="id-1",
        expected_last_id="id-5",
        expected_last_hash="h-5",
        expected_rolling_digest="d-1",
    )
    assert valid is False
    assert "ARCHIVE_FILE_MISSING" in err


@pytest.mark.asyncio
async def test_retention_service_reports_checkpoint_and_preserves_hard_block(tmp_path):
    """Verify that RetentionService reports active checkpoint in dry-run and maintains physical block."""
    db_file = tmp_path / "test_retention_safeguard.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    retention_svc = RetentionService(session_factory=session_factory, audit_repo=audit_repo)

    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    cutoff = now - timedelta(days=365)

    # 1. Seed 2 expired audit events and 1 active checkpoint
    async with session_factory() as session:
        async with session.begin():
            ev1 = await audit_repo.log_event(
                session=session,
                actor_id="test",
                action="EXP_1",
                resource_type="inv",
                resource_id="1",
                outcome="SUCCESS",
                request_id="r-1",
                timestamp=cutoff - timedelta(days=5),
            )
            ev2 = await audit_repo.log_event(
                session=session,
                actor_id="test",
                action="EXP_2",
                resource_type="inv",
                resource_id="1",
                outcome="SUCCESS",
                request_id="r-2",
                timestamp=cutoff - timedelta(days=4),
            )
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=ev1.audit_id,
                last_included_audit_id=ev2.audit_id,
                last_included_event_hash=ev2.event_hash,
                event_count=2,
                pruned_events_digest=compute_rolling_events_digest([ev1.event_hash, ev2.event_hash]),
                interval_start=ev1.timestamp,
                interval_end=ev2.timestamp,
            )

    # 2. Dry-run reports active_checkpoint_seq == 1 and archive_dir
    dry_run_res = await retention_svc.prune_expired_audit_events(dry_run=True, now=now)
    assert dry_run_res.dry_run is True
    assert dry_run_res.eligible_count == 2
    assert dry_run_res.deleted_count == 0
    assert dry_run_res.active_checkpoint_seq == 1
    assert dry_run_res.archive_dir == "data/archives"
    assert dry_run_res.status == "DRY_RUN"

    # 3. Destructive execution is strictly BLOCKED pending separate authorization
    blocked_res = await retention_svc.prune_expired_audit_events(dry_run=False, now=now)
    assert blocked_res.dry_run is False
    assert blocked_res.deleted_count == 0
    assert blocked_res.active_checkpoint_seq == 1
    assert blocked_res.status == "BLOCKED"
    assert "strictly blocked pending separate explicit authorization" in blocked_res.reason

    # Verify zero database rows were deleted
    async with session_factory() as session:
        remaining = await audit_repo.count_expired_audit_events(session, cutoff=cutoff)
        assert remaining == 2

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_end_to_end_success(tmp_path):
    """Confirm verify_complete_audit_trail returns VERIFIED when meta-chain, archive, and suffix are intact."""
    db_file = tmp_path / "test_e2e_verified.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archive_dir = tmp_path / "archives"
    archival_svc = AuditArchivalService(archive_base_dir=str(archive_dir))
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Create 4 sequential events
    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 5):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id=f"user-{i}",
                    action=f"ACTION_{i}",
                    resource_type="inv",
                    resource_id=f"id-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    # 2. Export archive covering events 0 and 1
    pruned_events = events[:2]
    retained_events = events[2:]
    arch_path, arch_sha, rolling_digest = archival_svc.export_archive(
        checkpoint_sequence=1,
        interval_start=pruned_events[0].timestamp,
        interval_end=pruned_events[-1].timestamp,
        events=pruned_events,
    )

    # 3. Create Checkpoint #1 and prune events 0 and 1
    async with session_factory() as session:
        async with session.begin():
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=pruned_events[0].audit_id,
                last_included_audit_id=pruned_events[-1].audit_id,
                last_included_event_hash=pruned_events[-1].event_hash,
                event_count=len(pruned_events),
                pruned_events_digest=rolling_digest,
                interval_start=pruned_events[0].timestamp,
                interval_end=pruned_events[-1].timestamp,
                archive_file_path=str(arch_path),
                archive_sha256=arch_sha,
            )
            for pe in pruned_events:
                await session.delete(await session.get(AuditEvent, pe.audit_id))

    # 4. End-to-end verification must report VERIFIED
    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "VERIFIED"
        assert report.meta_chain_valid is True
        assert report.checkpoints_count == 1
        assert report.archives_verified_count == 1
        assert report.live_suffix_valid is True
        assert report.live_events_count == len(retained_events)
        assert report.error_stage is None

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_detects_archive_tamper(tmp_path):
    """Confirm verify_complete_audit_trail fails closed at ARCHIVE stage if archive file is corrupted."""
    db_file = tmp_path / "test_e2e_archive_tamper.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archive_dir = tmp_path / "archives"
    archival_svc = AuditArchivalService(archive_base_dir=str(archive_dir))
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Create events, archive, and checkpoint
    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 4):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id=f"user-{i}",
                    action=f"ACT_{i}",
                    resource_type="inv",
                    resource_id=f"id-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    arch_path, arch_sha, rolling_digest = archival_svc.export_archive(
        checkpoint_sequence=1,
        interval_start=events[0].timestamp,
        interval_end=events[1].timestamp,
        events=events[:2],
    )

    async with session_factory() as session:
        async with session.begin():
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=events[0].audit_id,
                last_included_audit_id=events[1].audit_id,
                last_included_event_hash=events[1].event_hash,
                event_count=2,
                pruned_events_digest=rolling_digest,
                interval_start=events[0].timestamp,
                interval_end=events[1].timestamp,
                archive_file_path=str(arch_path),
                archive_sha256=arch_sha,
            )
            for pe in events[:2]:
                await session.delete(await session.get(AuditEvent, pe.audit_id))

    # Corrupt one byte of physical archive
    with open(arch_path, "r+b") as f:
        f.seek(-4, 2)
        f.write(b"\xff\xff")

    # Verification must fail closed at ARCHIVE stage
    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "FAILED"
        assert report.meta_chain_valid is True
        assert report.error_stage == "ARCHIVE"
        assert "ARCHIVE_FILE_TAMPERED" in (report.error_reason or "")

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_empty_history(tmp_path):
    """Verify empty database reports VERIFIED while correctly distinguishing skipped stages as NOT_APPLICABLE."""
    db_file = tmp_path / "test_empty_history.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archival_svc = AuditArchivalService(archive_base_dir=str(tmp_path / "archives"))

    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "VERIFIED"
        assert report.meta_chain_status == "NOT_APPLICABLE"
        assert report.archive_status == "NOT_APPLICABLE"
        assert report.live_suffix_status == "VERIFIED"
        assert report.trust_anchor_status == "NOT_APPLICABLE"
        assert report.checkpoints_count == 0
        assert report.archives_verified_count == 0
        assert report.live_events_count == 0
        assert report.stages_executed == ["LIVE_SUFFIX"]
        assert report.stages_skipped == ["META_CHAIN", "ARCHIVE"]
        assert report.error_stage is None

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_genesis_only_history(tmp_path):
    """Verify history without checkpoints verifies from genesis hash and reports skipped stages accurately."""
    db_file = tmp_path / "test_genesis_only.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archival_svc = AuditArchivalService(archive_base_dir=str(tmp_path / "archives"))
    now = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 4):
                await audit_repo.log_event(
                    session=session,
                    actor_id="analyst",
                    action=f"GENESIS_ACTION_{i}",
                    resource_type="alert",
                    resource_id=f"alt-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )

    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "VERIFIED"
        assert report.meta_chain_status == "NOT_APPLICABLE"
        assert report.archive_status == "NOT_APPLICABLE"
        assert report.live_suffix_status == "VERIFIED"
        assert report.trust_anchor_status == "NOT_APPLICABLE"
        assert report.checkpoints_count == 0
        assert report.archives_verified_count == 0
        assert report.live_events_count == 3
        assert report.stages_executed == ["LIVE_SUFFIX"]
        assert report.stages_skipped == ["META_CHAIN", "ARCHIVE"]

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_missing_archive_file(tmp_path):
    """Confirm verification fails closed when a checkpoint references an archive that does not exist."""
    db_file = tmp_path / "test_missing_archive.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archival_svc = AuditArchivalService(archive_base_dir=str(tmp_path / "archives"))
    now = datetime(2026, 10, 21, 15, 0, 0, tzinfo=timezone.utc)

    # Create checkpoint referencing non-existent file
    async with session_factory() as session:
        async with session.begin():
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id="audit-first",
                last_included_audit_id="audit-last",
                last_included_event_hash="h" * 64,
                event_count=5,
                pruned_events_digest="d" * 64,
                interval_start=now,
                interval_end=now + timedelta(hours=1),
                archive_file_path=str(tmp_path / "archives" / "does_not_exist.json.gz"),
                archive_sha256="s" * 64,
            )

    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "FAILED"
        assert report.error_stage == "ARCHIVE"
        assert report.archive_status == "FAILED"
        assert "ARCHIVE_FILE_MISSING" in (report.error_reason or "")

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_hmac_signature_validation(tmp_path):
    """Confirm HMAC-signed checkpoints fail closed when the signature is invalid or secret is missing."""
    db_file = tmp_path / "test_hmac_verify.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archival_svc = AuditArchivalService(archive_base_dir=str(tmp_path / "archives"))
    now = datetime(2026, 10, 21, 16, 0, 0, tzinfo=timezone.utc)

    correct_secret = b"correct_32_byte_secret_key_1234"
    wrong_secret = b"wrong_32_byte_secret_key_567890"

    # Create event and export archive
    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 3):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id="analyst",
                    action=f"HMAC_ACTION_{i}",
                    resource_type="alert",
                    resource_id=f"alt-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    arch_path, arch_sha, rolling_digest = archival_svc.export_archive(
        checkpoint_sequence=1,
        interval_start=events[0].timestamp,
        interval_end=events[-1].timestamp,
        events=events,
    )

    # Compute valid HMAC signature
    async with session_factory() as session:
        async with session.begin():
            cp = await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=events[0].audit_id,
                last_included_audit_id=events[-1].audit_id,
                last_included_event_hash=events[-1].event_hash,
                event_count=len(events),
                pruned_events_digest=rolling_digest,
                interval_start=events[0].timestamp,
                interval_end=events[-1].timestamp,
                archive_file_path=str(arch_path),
                archive_sha256=arch_sha,
                signature_algorithm="HMAC-SHA256",
            )
            # Sign the digest
            sig = sign_digest_hmac(cp.checkpoint_digest, correct_secret)
            cp.signature_value = sig
            cp.signing_key_id = "key-v1"
            for ev in events:
                await session.delete(await session.get(AuditEvent, ev.audit_id))

    # 1. Missing secret when HMAC required -> UNVERIFIED at TRUST_ANCHOR stage
    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo, signing_secret=None)
        assert report.status == "UNVERIFIED"
        assert report.error_stage == "TRUST_ANCHOR"
        assert report.trust_anchor_status == "UNVERIFIED"

    # 2. Wrong secret -> FAILED at TRUST_ANCHOR stage
    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo, signing_secret=wrong_secret)
        assert report.status == "FAILED"
        assert report.error_stage == "TRUST_ANCHOR"
        assert report.trust_anchor_status == "FAILED"

    # 3. Correct secret -> VERIFIED
    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo, signing_secret=correct_secret)
        assert report.status == "VERIFIED"
        assert report.meta_chain_status == "VERIFIED"
        assert report.archive_status == "VERIFIED"
        assert report.live_suffix_status == "VERIFIED"
        assert report.trust_anchor_status == "VERIFIED"

    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_complete_audit_trail_broken_boundary_and_corrupted_record(tmp_path):
    """Confirm broken anchor boundary and in-place record corruption both fail closed at LIVE_SUFFIX stage."""
    db_file = tmp_path / "test_broken_boundary.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()
    archival_svc = AuditArchivalService(archive_base_dir=str(tmp_path / "archives"))
    now = datetime(2026, 10, 21, 17, 0, 0, tzinfo=timezone.utc)

    # 1. Create 3 events: 2 archived, 1 live
    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 4):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id="analyst",
                    action=f"BOUNDARY_ACTION_{i}",
                    resource_type="alert",
                    resource_id=f"alt-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    arch_path, arch_sha, rolling_digest = archival_svc.export_archive(
        checkpoint_sequence=1,
        interval_start=events[0].timestamp,
        interval_end=events[1].timestamp,
        events=events[:2],
    )

    async with session_factory() as session:
        async with session.begin():
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=events[0].audit_id,
                last_included_audit_id=events[1].audit_id,
                last_included_event_hash=events[1].event_hash,
                event_count=2,
                pruned_events_digest=rolling_digest,
                interval_start=events[0].timestamp,
                interval_end=events[1].timestamp,
                archive_file_path=str(arch_path),
                archive_sha256=arch_sha,
            )
            for pe in events[:2]:
                await session.delete(await session.get(AuditEvent, pe.audit_id))

    # Test broken boundary: modify the live event's previous_hash so it doesn't match checkpoint anchor
    async with session_factory() as session:
        async with session.begin():
            live_ev = await session.get(AuditEvent, events[2].audit_id)
            live_ev.previous_hash = "f" * 64

    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "FAILED"
        assert report.error_stage == "LIVE_SUFFIX"
        assert "UNVERIFIED_GAP_DETECTED" in (report.error_reason or "")

    # Test record tamper: restore previous_hash but tamper action
    async with session_factory() as session:
        async with session.begin():
            live_ev = await session.get(AuditEvent, events[2].audit_id)
            live_ev.previous_hash = events[1].event_hash  # restored anchor
            live_ev.action = "TAMPERED_ACTION"  # tampered payload

    async with session_factory() as session:
        report = await archival_svc.verify_complete_audit_trail(session, audit_repo)
        assert report.status == "FAILED"
        assert report.error_stage == "LIVE_SUFFIX"
        assert "TAMPER_DETECTED" in (report.error_reason or "")

    await engine.dispose()


