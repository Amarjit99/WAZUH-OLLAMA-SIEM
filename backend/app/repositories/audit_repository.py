"""Repository for tamper-evident audit event persistence and verification.

Conforms strictly to specs/PHASE_7_SECURITY_AND_RETENTION.md and specs/PHASE_7_DATABASE_SCHEMA.md.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_crypto import (
    GENESIS_CHECKPOINT_HASH,
    GENESIS_HASH,
    compute_canonical_event_hash,
    compute_checkpoint_digest,
    compute_rolling_events_digest,
    format_canonical_timestamp,
    verify_digest_hmac,
)
from app.models.audit import AuditEvent
from app.models.audit_checkpoint import AuditCheckpoint

logger = logging.getLogger(__name__)


class AuditRepository:
    """Manages creation, query, and cryptographic hash-chain verification of audit events."""

    @staticmethod
    def compute_canonical_hash(
        audit_id: str,
        timestamp_iso: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        request_id: str,
        client_ip: str,
        metadata_json: Optional[str],
        previous_hash: str,
    ) -> str:
        """Calculate deterministic SHA-256 event hash over canonical JSON concatenated with previous_hash."""
        payload = {
            "action": action,
            "actor_id": actor_id,
            "audit_id": audit_id,
            "client_ip": client_ip,
            "metadata_json": metadata_json,
            "outcome": outcome,
            "request_id": request_id,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "timestamp": timestamp_iso,
        }
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        combined = canonical_json.encode("utf-8") + previous_hash.encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    async def get_latest_hash(self, session: AsyncSession) -> str:
        """Retrieve the event_hash of the most recent audit record, or return GENESIS_HASH if empty."""
        stmt = select(AuditEvent.event_hash).order_by(
            AuditEvent.timestamp.desc(),
            text("rowid DESC"),
        ).limit(1)
        result = await session.execute(stmt)
        latest_hash = result.scalar_one_or_none()
        return latest_hash if latest_hash is not None else GENESIS_HASH

    async def log_event(
        self,
        session: AsyncSession,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        request_id: str,
        client_ip: str = "127.0.0.1",
        metadata: Optional[Dict[str, Any]] = None,
        audit_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> AuditEvent:
        """Persist a new audit event linked to the previous row via SHA-256 hash chaining."""
        event_id = audit_id or str(uuid.uuid4())
        event_time = timestamp or datetime.now(timezone.utc)
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        else:
            event_time = event_time.astimezone(timezone.utc)

        if timestamp is None:
            # Guarantee strictly monotonic timestamp to preserve deterministic ordering
            stmt_last = select(AuditEvent.timestamp).order_by(
                AuditEvent.timestamp.desc(),
                text("rowid DESC"),
            ).limit(1)
            last_ts = (await session.execute(stmt_last)).scalar_one_or_none()
            if last_ts is not None:
                if last_ts.tzinfo is None:
                    last_ts = last_ts.replace(tzinfo=timezone.utc)
                if last_ts >= event_time:
                    event_time = last_ts + timedelta(microseconds=1)

        canonical_ts = format_canonical_timestamp(event_time)
        meta_json = json.dumps(metadata, sort_keys=True) if metadata is not None else None
        prev_hash = await self.get_latest_hash(session)

        event_hash = self.compute_canonical_hash(
            audit_id=event_id,
            timestamp_iso=canonical_ts,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            request_id=request_id,
            client_ip=client_ip,
            metadata_json=meta_json,
            previous_hash=prev_hash,
        )

        audit_entry = AuditEvent(
            audit_id=event_id,
            timestamp=event_time,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            request_id=request_id,
            client_ip=client_ip,
            metadata_json=meta_json,
            previous_hash=prev_hash,
            event_hash=event_hash,
        )

        session.add(audit_entry)
        await session.flush()
        return audit_entry

    async def get_latest_checkpoint(self, session: AsyncSession) -> Optional[AuditCheckpoint]:
        """Retrieve the latest active checkpoint record, or None if no checkpoints exist."""
        stmt = (
            select(AuditCheckpoint)
            .where(AuditCheckpoint.status == "ACTIVE")
            .order_by(AuditCheckpoint.checkpoint_sequence.desc())
            .limit(1)
        )
        return (await session.execute(stmt)).scalar_one_or_none()

    async def create_checkpoint(
        self,
        session: AsyncSession,
        checkpoint_sequence: int,
        first_included_audit_id: str,
        last_included_audit_id: str,
        last_included_event_hash: str,
        event_count: int,
        pruned_events_digest: str,
        interval_start: datetime,
        interval_end: datetime,
        previous_checkpoint: Optional[AuditCheckpoint] = None,
        signature_algorithm: str = "NONE",
        signature_value: Optional[str] = None,
        signing_key_id: Optional[str] = None,
        archive_file_path: Optional[str] = None,
        archive_sha256: Optional[str] = None,
        checkpoint_id: Optional[str] = None,
    ) -> AuditCheckpoint:
        """Create and persist a new AuditCheckpoint record."""
        cp_id = checkpoint_id or str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)
        prev_cp_id = previous_checkpoint.checkpoint_id if previous_checkpoint else None
        prev_cp_hash = (
            previous_checkpoint.checkpoint_digest
            if previous_checkpoint
            else GENESIS_CHECKPOINT_HASH
        )

        cp_digest = compute_checkpoint_digest(
            checkpoint_id=cp_id,
            checkpoint_sequence=checkpoint_sequence,
            created_at_iso=format_canonical_timestamp(created_at),
            interval_start_iso=format_canonical_timestamp(interval_start),
            interval_end_iso=format_canonical_timestamp(interval_end),
            first_included_audit_id=first_included_audit_id,
            last_included_audit_id=last_included_audit_id,
            last_included_event_hash=last_included_event_hash,
            event_count=event_count,
            pruned_events_digest=pruned_events_digest,
            previous_checkpoint_id=prev_cp_id,
            previous_checkpoint_hash=prev_cp_hash,
            schema_version="v1",
        )

        checkpoint = AuditCheckpoint(
            checkpoint_id=cp_id,
            schema_version="v1",
            checkpoint_sequence=checkpoint_sequence,
            created_at=created_at,
            interval_start_timestamp=interval_start,
            interval_end_timestamp=interval_end,
            first_included_audit_id=first_included_audit_id,
            last_included_audit_id=last_included_audit_id,
            last_included_event_hash=last_included_event_hash,
            event_count=event_count,
            pruned_events_digest=pruned_events_digest,
            previous_checkpoint_id=prev_cp_id,
            previous_checkpoint_hash=prev_cp_hash,
            checkpoint_digest=cp_digest,
            signature_algorithm=signature_algorithm,
            signature_value=signature_value,
            signing_key_id=signing_key_id,
            archive_file_path=archive_file_path,
            archive_sha256=archive_sha256,
            status="ACTIVE",
        )

        # Mark previous checkpoint as SUPERSEDED if present
        if previous_checkpoint:
            previous_checkpoint.status = "SUPERSEDED"

        session.add(checkpoint)
        await session.flush()
        return checkpoint

    async def verify_checkpoint_meta_chain(
        self, session: AsyncSession
    ) -> Tuple[bool, int, Optional[str]]:
        """Verify the integrity of all checkpoints from sequence 1 to tip."""
        stmt = select(AuditCheckpoint).order_by(AuditCheckpoint.checkpoint_sequence.asc())
        result = await session.execute(stmt)
        checkpoints: List[AuditCheckpoint] = list(result.scalars().all())

        if not checkpoints:
            return True, 0, None

        expected_prev_hash = GENESIS_CHECKPOINT_HASH
        for idx, cp in enumerate(checkpoints):
            expected_seq = idx + 1
            if cp.checkpoint_sequence != expected_seq:
                reason = f"CHECKPOINT_SEQUENCE_GAP: Expected seq {expected_seq}, got {cp.checkpoint_sequence}"
                logger.warning(reason)
                return False, idx, reason

            if cp.previous_checkpoint_hash != expected_prev_hash:
                reason = (
                    f"CHECKPOINT_META_CHAIN_BROKEN: Hash break at checkpoint {cp.checkpoint_id} (seq {cp.checkpoint_sequence}): "
                    f"expected previous '{expected_prev_hash}', got '{cp.previous_checkpoint_hash}'"
                )
                logger.warning(reason)
                return False, idx, reason

            recomputed_digest = compute_checkpoint_digest(
                checkpoint_id=cp.checkpoint_id,
                checkpoint_sequence=cp.checkpoint_sequence,
                created_at_iso=format_canonical_timestamp(cp.created_at),
                interval_start_iso=format_canonical_timestamp(cp.interval_start_timestamp),
                interval_end_iso=format_canonical_timestamp(cp.interval_end_timestamp),
                first_included_audit_id=cp.first_included_audit_id,
                last_included_audit_id=cp.last_included_audit_id,
                last_included_event_hash=cp.last_included_event_hash,
                event_count=cp.event_count,
                pruned_events_digest=cp.pruned_events_digest,
                previous_checkpoint_id=cp.previous_checkpoint_id,
                previous_checkpoint_hash=cp.previous_checkpoint_hash,
                schema_version=cp.schema_version,
            )

            if recomputed_digest != cp.checkpoint_digest:
                reason = (
                    f"CHECKPOINT_INVALID: Tampered checkpoint {cp.checkpoint_id} (seq {cp.checkpoint_sequence}): "
                    f"stored digest '{cp.checkpoint_digest}' != recomputed '{recomputed_digest}'"
                )
                logger.warning(reason)
                return False, idx, reason

            expected_prev_hash = cp.checkpoint_digest

        return True, len(checkpoints), None

    async def verify_chain_integrity(
        self, session: AsyncSession, signing_secret: Optional[bytes] = None
    ) -> Tuple[bool, int, Optional[str]]:
        """Verify the integrity of the audit hash chain from genesis or latest active checkpoint to tip.

        Returns (True, verified_count, None) if the chain is intact, or (False, failed_index, error_reason) if broken.
        """
        # 1. Fetch latest active checkpoint
        latest_cp = await self.get_latest_checkpoint(session)
        expected_prev_hash = GENESIS_HASH

        if latest_cp is not None:
            # Validate checkpoint internal integrity
            recomputed_cp_digest = compute_checkpoint_digest(
                checkpoint_id=latest_cp.checkpoint_id,
                checkpoint_sequence=latest_cp.checkpoint_sequence,
                created_at_iso=format_canonical_timestamp(latest_cp.created_at),
                interval_start_iso=format_canonical_timestamp(latest_cp.interval_start_timestamp),
                interval_end_iso=format_canonical_timestamp(latest_cp.interval_end_timestamp),
                first_included_audit_id=latest_cp.first_included_audit_id,
                last_included_audit_id=latest_cp.last_included_audit_id,
                last_included_event_hash=latest_cp.last_included_event_hash,
                event_count=latest_cp.event_count,
                pruned_events_digest=latest_cp.pruned_events_digest,
                previous_checkpoint_id=latest_cp.previous_checkpoint_id,
                previous_checkpoint_hash=latest_cp.previous_checkpoint_hash,
                schema_version=latest_cp.schema_version,
            )

            if recomputed_cp_digest != latest_cp.checkpoint_digest:
                reason = f"CHECKPOINT_INVALID: Active checkpoint {latest_cp.checkpoint_id} digest mismatch"
                logger.warning(reason)
                return False, 0, reason

            # Validate signature if algorithm is HMAC-SHA256
            if latest_cp.signature_algorithm == "HMAC-SHA256":
                if not signing_secret:
                    reason = "TRUST_ANCHOR_UNAVAILABLE: Checkpoint requires HMAC verification but signing_secret is missing"
                    logger.warning(reason)
                    return False, 0, reason
                if not latest_cp.signature_value or not verify_digest_hmac(
                    latest_cp.checkpoint_digest, latest_cp.signature_value, signing_secret
                ):
                    reason = f"CHECKPOINT_SIGNATURE_INVALID: Checkpoint {latest_cp.checkpoint_id} signature invalid"
                    logger.warning(reason)
                    return False, 0, reason

            # Anchor live suffix to checkpoint's last included event hash
            expected_prev_hash = latest_cp.last_included_event_hash

        # 2. Fetch live audit events
        stmt = select(AuditEvent).order_by(AuditEvent.timestamp.asc(), text("rowid ASC"))
        result = await session.execute(stmt)
        events: List[AuditEvent] = list(result.scalars().all())

        if not events:
            return True, 0, None

        # 3. If checkpoint exists, check boundary gap
        if latest_cp is not None and events[0].previous_hash != expected_prev_hash:
            reason = (
                f"UNVERIFIED_GAP_DETECTED: First live event {events[0].audit_id} previous_hash "
                f"'{events[0].previous_hash}' does not match checkpoint anchor '{expected_prev_hash}'"
            )
            logger.warning(reason)
            return False, 0, reason

        # 4. Verify live chain
        for idx, event in enumerate(events):
            if event.previous_hash != expected_prev_hash:
                reason = (
                    f"PREDECESSOR_MISMATCH: Hash chain broken at event index {idx} ({event.audit_id}): "
                    f"expected previous_hash '{expected_prev_hash}', got '{event.previous_hash}'"
                )
                logger.warning(reason)
                return False, idx, reason

            canonical_ts = format_canonical_timestamp(event.timestamp)
            computed_hash = self.compute_canonical_hash(
                audit_id=event.audit_id,
                timestamp_iso=canonical_ts,
                actor_id=event.actor_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                outcome=event.outcome,
                request_id=event.request_id,
                client_ip=event.client_ip,
                metadata_json=event.metadata_json,
                previous_hash=event.previous_hash,
            )

            if computed_hash != event.event_hash:
                reason = (
                    f"TAMPER_DETECTED: Tamper detected in event {event.audit_id} at index {idx}: "
                    f"stored event_hash '{event.event_hash}' != recomputed '{computed_hash}'"
                )
                logger.warning(reason)
                return False, idx, reason

            expected_prev_hash = event.event_hash

        return True, len(events), None

    async def count_expired_audit_events(
        self, session: AsyncSession, cutoff: datetime
    ) -> int:
        """Count audit events strictly older than the specified UTC cutoff timestamp."""
        stmt = select(func.count(AuditEvent.audit_id)).where(AuditEvent.timestamp < cutoff)
        return int((await session.execute(stmt)).scalar_one())

    async def get_expired_audit_ids(
        self, session: AsyncSession, cutoff: datetime, limit: int = 100
    ) -> List[str]:
        """Retrieve audit event IDs strictly older than the cutoff timestamp."""
        stmt = (
            select(AuditEvent.audit_id)
            .where(AuditEvent.timestamp < cutoff)
            .order_by(AuditEvent.timestamp.asc(), AuditEvent.audit_id.asc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
