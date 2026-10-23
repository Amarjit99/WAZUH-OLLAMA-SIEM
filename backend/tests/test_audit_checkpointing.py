"""Tests for audit checkpoint protocol, dual-chain verification, and DPAPI key management.

Conforms strictly to specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md and approved ADR-013.
Uses isolated temporary SQLite databases.
"""

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.audit_crypto import (
    GENESIS_CHECKPOINT_HASH,
    GENESIS_HASH,
    compute_rolling_events_digest,
    dpapi_protect,
    dpapi_unprotect,
    format_canonical_timestamp,
    is_dpapi_available,
    sign_digest_hmac,
    verify_digest_hmac,
)
from app.db.base import Base
from app.models.audit import AuditEvent
from app.models.audit_checkpoint import AuditCheckpoint
from app.repositories.audit_repository import AuditRepository


@pytest.fixture
async def cp_db(tmp_path):
    """Isolated temporary SQLite database with all tables created."""
    db_file = tmp_path / "test_checkpoints.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    audit_repo = AuditRepository()

    yield {
        "engine": engine,
        "session_factory": session_factory,
        "audit_repo": audit_repo,
    }

    await engine.dispose()


@pytest.mark.asyncio
async def test_dpapi_key_protection_and_hmac_signing():
    """Verify Windows DPAPI key encryption and HMAC-SHA256 signature round-trip."""
    if not is_dpapi_available():
        pytest.skip("DPAPI tests require a Windows environment.")

    raw_secret = b"soc-audit-machine-secret-2026-key"
    encrypted_blob = dpapi_protect(raw_secret)
    assert encrypted_blob != raw_secret

    decrypted_secret = dpapi_unprotect(encrypted_blob)
    assert decrypted_secret == raw_secret

    # Verify HMAC signing
    digest = "a" * 64
    sig = sign_digest_hmac(digest, decrypted_secret)
    assert isinstance(sig, str)
    assert len(sig) > 0

    assert verify_digest_hmac(digest, sig, decrypted_secret) is True
    # Tampered digest fails
    assert verify_digest_hmac("b" * 64, sig, decrypted_secret) is False
    # Tampered signature fails
    assert verify_digest_hmac(digest, sig[:-2] + "==", decrypted_secret) is False


@pytest.mark.asyncio
async def test_empty_chain_and_genesis_verification(cp_db):
    """Verify chain integrity on empty table and unbroken genesis chain."""
    session_factory = cp_db["session_factory"]
    audit_repo: AuditRepository = cp_db["audit_repo"]

    # 1. Empty table returns valid
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session)
        assert valid is True
        assert count == 0
        assert err is None

    # 2. Add 3 sequential events without checkpoints
    async with session_factory() as session:
        async with session.begin():
            await audit_repo.log_event(
                session=session,
                actor_id="analyst",
                action="TEST_ACTION_1",
                resource_type="alert",
                resource_id="alt-1",
                outcome="SUCCESS",
                request_id="req-1",
            )
            await audit_repo.log_event(
                session=session,
                actor_id="analyst",
                action="TEST_ACTION_2",
                resource_type="alert",
                resource_id="alt-1",
                outcome="SUCCESS",
                request_id="req-2",
            )
            await audit_repo.log_event(
                session=session,
                actor_id="analyst",
                action="TEST_ACTION_3",
                resource_type="alert",
                resource_id="alt-1",
                outcome="SUCCESS",
                request_id="req-3",
            )

    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session)
        assert valid is True
        assert count == 3
        assert err is None


@pytest.mark.asyncio
async def test_checkpoint_creation_and_suffix_verification(cp_db):
    """Verify that a checkpoint anchors the retained suffix after older events are pruned."""
    session_factory = cp_db["session_factory"]
    audit_repo: AuditRepository = cp_db["audit_repo"]
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Create 5 sequential events
    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 6):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id="analyst",
                    action=f"ACTION_{i}",
                    resource_type="investigation",
                    resource_id=f"inv-{i}",
                    outcome="SUCCESS",
                    request_id=f"req-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    # 2. Create Checkpoint #1 covering first 3 events (events[0..2])
    pruned_events = events[:3]
    retained_events = events[3:]
    rolling_digest = compute_rolling_events_digest([e.event_hash for e in pruned_events])

    async with session_factory() as session:
        async with session.begin():
            cp = await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=pruned_events[0].audit_id,
                last_included_audit_id=pruned_events[-1].audit_id,
                last_included_event_hash=pruned_events[-1].event_hash,
                event_count=len(pruned_events),
                pruned_events_digest=rolling_digest,
                interval_start=pruned_events[0].timestamp,
                interval_end=pruned_events[-1].timestamp,
            )
            assert cp.checkpoint_sequence == 1
            assert cp.status == "ACTIVE"

            # Prune first 3 events from database
            for pe in pruned_events:
                db_event = await session.get(AuditEvent, pe.audit_id)
                await session.delete(db_event)

    # 3. Verify active suffix: events[3..4] anchored to Checkpoint #1
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session)
        assert valid is True
        assert count == len(retained_events)
        assert err is None


@pytest.mark.asyncio
async def test_checkpoint_digest_tamper_detection(cp_db):
    """Detect tampering with the checkpoint metadata itself."""
    session_factory = cp_db["session_factory"]
    audit_repo: AuditRepository = cp_db["audit_repo"]
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Create 3 events and checkpoint 2
    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 4):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id="analyst",
                    action=f"ACT_{i}",
                    resource_type="alert",
                    resource_id="alt-1",
                    outcome="SUCCESS",
                    request_id=f"r-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    async with session_factory() as session:
        async with session.begin():
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=events[0].audit_id,
                last_included_audit_id=events[1].audit_id,
                last_included_event_hash=events[1].event_hash,
                event_count=2,
                pruned_events_digest=compute_rolling_events_digest([e.event_hash for e in events[:2]]),
                interval_start=events[0].timestamp,
                interval_end=events[1].timestamp,
            )
            # Delete first 2 events
            for e in events[:2]:
                await session.delete(await session.get(AuditEvent, e.audit_id))

    # Tamper with checkpoint in database
    async with session_factory() as session:
        async with session.begin():
            cp = await audit_repo.get_latest_checkpoint(session)
            cp.event_count = 999  # Tampered count

    # Verifier must detect tampering and fail closed
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session)
        assert valid is False
        assert "CHECKPOINT_INVALID" in err


@pytest.mark.asyncio
async def test_checkpoint_boundary_gap_detection(cp_db):
    """Detect an unanchored gap where an event between checkpoint and suffix was deleted."""
    session_factory = cp_db["session_factory"]
    audit_repo: AuditRepository = cp_db["audit_repo"]
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    events = []
    async with session_factory() as session:
        async with session.begin():
            for i in range(1, 5):
                ev = await audit_repo.log_event(
                    session=session,
                    actor_id="analyst",
                    action=f"GAP_TEST_{i}",
                    resource_type="inv",
                    resource_id="1",
                    outcome="SUCCESS",
                    request_id=f"r-{i}",
                    timestamp=now + timedelta(minutes=i),
                )
                events.append(ev)

    # Checkpoint events 0 and 1
    async with session_factory() as session:
        async with session.begin():
            await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=events[0].audit_id,
                last_included_audit_id=events[1].audit_id,
                last_included_event_hash=events[1].event_hash,
                event_count=2,
                pruned_events_digest=compute_rolling_events_digest([e.event_hash for e in events[:2]]),
                interval_start=events[0].timestamp,
                interval_end=events[1].timestamp,
            )
            # Delete events 0, 1 AND delete event 2 (leaving only event 3 in live table)
            await session.delete(await session.get(AuditEvent, events[0].audit_id))
            await session.delete(await session.get(AuditEvent, events[1].audit_id))
            await session.delete(await session.get(AuditEvent, events[2].audit_id))

    # Event 3's previous_hash points to event 2, NOT to checkpoint anchor (event 1)
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session)
        assert valid is False
        assert "UNVERIFIED_GAP_DETECTED" in err


@pytest.mark.asyncio
async def test_checkpoint_meta_chain_verification(cp_db):
    """Verify that multiple checkpoints chain monotonically and detect gaps."""
    session_factory = cp_db["session_factory"]
    audit_repo: AuditRepository = cp_db["audit_repo"]
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Create 3 chained checkpoints
    async with session_factory() as session:
        async with session.begin():
            cp1 = await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id="id-1",
                last_included_audit_id="id-2",
                last_included_event_hash="h-2",
                event_count=2,
                pruned_events_digest="d-1",
                interval_start=now,
                interval_end=now + timedelta(hours=1),
            )
            cp2 = await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=2,
                first_included_audit_id="id-3",
                last_included_audit_id="id-4",
                last_included_event_hash="h-4",
                event_count=2,
                pruned_events_digest="d-2",
                interval_start=now + timedelta(hours=1),
                interval_end=now + timedelta(hours=2),
                previous_checkpoint=cp1,
            )
            cp3 = await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=3,
                first_included_audit_id="id-5",
                last_included_audit_id="id-6",
                last_included_event_hash="h-6",
                event_count=2,
                pruned_events_digest="d-3",
                interval_start=now + timedelta(hours=2),
                interval_end=now + timedelta(hours=3),
                previous_checkpoint=cp2,
            )

    # Verify unbroken meta-chain
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_checkpoint_meta_chain(session)
        assert valid is True
        assert count == 3
        assert err is None

    # Break link in cp2
    async with session_factory() as session:
        async with session.begin():
            cp2_db = (await session.execute(
                select(AuditCheckpoint).where(AuditCheckpoint.checkpoint_sequence == 2)
            )).scalar_one()
            cp2_db.previous_checkpoint_hash = "f" * 64

    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_checkpoint_meta_chain(session)
        assert valid is False
        assert "CHECKPOINT_META_CHAIN_BROKEN" in err


@pytest.mark.asyncio
async def test_checkpoint_hmac_signature_verification_and_tampering(cp_db):
    """Verify HMAC signature validation and fail-closed behavior on tampered signatures."""
    session_factory = cp_db["session_factory"]
    audit_repo: AuditRepository = cp_db["audit_repo"]
    secret = b"my-test-hmac-secret-32-bytes-long!"
    now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Create 2 events
    async with session_factory() as session:
        async with session.begin():
            ev = await audit_repo.log_event(
                session=session,
                actor_id="analyst",
                action="HMAC_TEST_1",
                resource_type="alert",
                resource_id="1",
                outcome="SUCCESS",
                request_id="r-1",
                timestamp=now,
            )
            ev2 = await audit_repo.log_event(
                session=session,
                actor_id="analyst",
                action="HMAC_TEST_2",
                resource_type="alert",
                resource_id="1",
                outcome="SUCCESS",
                request_id="r-2",
                timestamp=now + timedelta(minutes=1),
            )

    # 2. Create signed checkpoint covering ev
    async with session_factory() as session:
        async with session.begin():
            cp = await audit_repo.create_checkpoint(
                session=session,
                checkpoint_sequence=1,
                first_included_audit_id=ev.audit_id,
                last_included_audit_id=ev.audit_id,
                last_included_event_hash=ev.event_hash,
                event_count=1,
                pruned_events_digest=compute_rolling_events_digest([ev.event_hash]),
                interval_start=ev.timestamp,
                interval_end=ev.timestamp,
                signature_algorithm="HMAC-SHA256",
                signing_key_id="key-hmac-1",
            )
            # Sign the computed digest
            cp.signature_value = sign_digest_hmac(cp.checkpoint_digest, secret)
            # Prune ev
            await session.delete(await session.get(AuditEvent, ev.audit_id))

    # 3. Verification succeeds with valid secret (ev2 anchors to cp)
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session, signing_secret=secret)
        assert valid is True
        assert count == 1
        assert err is None

    # 4. Verification fails closed if secret is missing
    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session, signing_secret=None)
        assert valid is False
        assert "TRUST_ANCHOR_UNAVAILABLE" in err

    # 5. Verification fails closed if signature is tampered
    async with session_factory() as session:
        async with session.begin():
            cp_db_item = await audit_repo.get_latest_checkpoint(session)
            cp_db_item.signature_value = "invalid-sig=="

    async with session_factory() as session:
        valid, count, err = await audit_repo.verify_chain_integrity(session, signing_secret=secret)
        assert valid is False
        assert "CHECKPOINT_SIGNATURE_INVALID" in err
