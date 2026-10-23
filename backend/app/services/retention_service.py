"""Retention and cleanup service for historical investigations and audit logs.

Conforms strictly to specs/PHASE_7_SECURITY_AND_RETENTION.md, specs/PHASE_7_DATABASE_SCHEMA.md,
and specs/PHASE_7_ADR.md (ADR-011 and ADR-012).
"""

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import get_session_factory
from app.repositories.audit_repository import AuditRepository
from app.repositories.investigation_repository import InvestigationRepository

logger = logging.getLogger("siem.retention")


class RetentionCutoffs(BaseModel):
    """Calculated UTC retention cutoff timestamps."""
    model_config = ConfigDict(extra="ignore")

    now_utc: datetime = Field(description="Base UTC reference timestamp")
    investigation_retention_days: int = Field(description="Investigation retention window in days")
    investigation_cutoff: datetime = Field(description="Investigation expiration boundary (exclusive)")
    audit_retention_days: int = Field(description="Audit log retention window in days")
    audit_cutoff: datetime = Field(description="Audit log expiration boundary (exclusive)")


class RetentionCandidatesSummary(BaseModel):
    """Summary of records eligible for retention expiration."""
    model_config = ConfigDict(extra="ignore")

    cutoffs: RetentionCutoffs
    expired_investigations_count: int
    expired_audit_events_count: int


class InvestigationPruneResult(BaseModel):
    """Outcome of investigation retention pruning operation."""
    model_config = ConfigDict(extra="ignore")

    dry_run: bool
    cutoff: datetime
    deleted_count: int = 0
    batches_processed: int = 0
    batch_size: int
    remaining_count: int = 0
    status: str  # "COMPLETED", "DRY_RUN", "PARTIAL", "FAILED"
    error: Optional[str] = None


class AuditPruneResult(BaseModel):
    """Outcome of audit event retention pruning operation."""
    model_config = ConfigDict(extra="ignore")

    dry_run: bool
    cutoff: datetime
    eligible_count: int = 0
    deleted_count: int = 0
    active_checkpoint_seq: Optional[int] = None
    archive_dir: Optional[str] = None
    status: str  # "BLOCKED", "DRY_RUN", "COMPLETED", "FAILED"
    reason: str


class RetentionSweepSummary(BaseModel):
    """Aggregate result of complete retention cleanup sweep."""
    model_config = ConfigDict(extra="ignore")

    dry_run: bool
    cutoffs: RetentionCutoffs
    investigations: InvestigationPruneResult
    audit_events: AuditPruneResult
    wal_checkpoint_executed: bool = False
    wal_checkpoint_result: Optional[str] = None
    duration_ms: int = 0


class RetentionService:
    """Manages bounded, transactional retention pruning for investigations and audit trails."""

    def __init__(
        self,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
        investigation_repo: Optional[InvestigationRepository] = None,
        audit_repo: Optional[AuditRepository] = None,
        settings: Optional[Settings] = None,
    ):
        self.session_factory = session_factory or get_session_factory()
        self.investigation_repo = investigation_repo or InvestigationRepository()
        self.audit_repo = audit_repo or AuditRepository()
        self.settings = settings or get_settings()

    def calculate_cutoffs(self, now: Optional[datetime] = None) -> RetentionCutoffs:
        """Calculate deterministic UTC cutoff timestamps for investigation and audit retention."""
        if now is None:
            now_utc = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now_utc = now.replace(tzinfo=timezone.utc)
        else:
            now_utc = now.astimezone(timezone.utc)

        inv_days = self.settings.INVESTIGATION_RETENTION_DAYS
        audit_days = self.settings.AUDIT_RETENTION_DAYS

        inv_cutoff = now_utc - timedelta(days=inv_days)
        audit_cutoff = now_utc - timedelta(days=audit_days)

        return RetentionCutoffs(
            now_utc=now_utc,
            investigation_retention_days=inv_days,
            investigation_cutoff=inv_cutoff,
            audit_retention_days=audit_days,
            audit_cutoff=audit_cutoff,
        )

    async def estimate_cleanup_candidates(
        self, now: Optional[datetime] = None
    ) -> RetentionCandidatesSummary:
        """Dry-run estimation returning counts of all eligible records without modifying data."""
        cutoffs = self.calculate_cutoffs(now)
        async with self.session_factory() as session:
            inv_count = await self.investigation_repo.count_expired_investigations(
                session=session, cutoff=cutoffs.investigation_cutoff
            )
            audit_count = await self.audit_repo.count_expired_audit_events(
                session=session, cutoff=cutoffs.audit_cutoff
            )

        return RetentionCandidatesSummary(
            cutoffs=cutoffs,
            expired_investigations_count=inv_count,
            expired_audit_events_count=audit_count,
        )

    async def prune_expired_investigations(
        self,
        batch_size: int = 100,
        max_batches: Optional[int] = None,
        dry_run: bool = True,
        now: Optional[datetime] = None,
        actor_id: str = "retention_worker",
        request_id: str = "req-retention",
    ) -> InvestigationPruneResult:
        """Prune investigations strictly older than the 90-day cutoff in bounded batches.

        - Bounded: deletes at most batch_size records (<= 100) per transaction.
        - Cascading: database ON DELETE CASCADE removes associated facts, hypotheses, checks, and snapshots.
        - Isolated: audit_events are NOT deleted or affected.
        - Idempotent: safe to stop and resume.
        - Default: dry_run=True performs zero deletions.
        """
        # Clamp batch_size to strictly adhere to bounded limits (max 100)
        bounded_batch_size = max(1, min(100, batch_size))
        cutoffs = self.calculate_cutoffs(now)
        cutoff = cutoffs.investigation_cutoff

        if dry_run:
            async with self.session_factory() as session:
                eligible = await self.investigation_repo.count_expired_investigations(
                    session=session, cutoff=cutoff
                )
            logger.info(
                "Investigation retention dry-run: %d record(s) older than %s eligible for deletion",
                eligible,
                cutoff.isoformat(),
            )
            return InvestigationPruneResult(
                dry_run=True,
                cutoff=cutoff,
                deleted_count=0,
                batches_processed=0,
                batch_size=bounded_batch_size,
                remaining_count=eligible,
                status="DRY_RUN",
            )

        # Destructive execution in bounded batches
        total_deleted = 0
        batches = 0
        logger.info(
            "Executing destructive investigation retention pruning: cutoff=%s, batch_size=%d",
            cutoff.isoformat(),
            bounded_batch_size,
        )

        try:
            while True:
                if max_batches is not None and batches >= max_batches:
                    logger.info("Reached max_batches limit (%d); pausing pruning", max_batches)
                    break

                async with self.session_factory() as session:
                    async with session.begin():
                        target_ids = await self.investigation_repo.get_expired_investigation_ids(
                            session=session, cutoff=cutoff, limit=bounded_batch_size
                        )
                        if not target_ids:
                            # No more expired investigations
                            break

                        batch_count = await self.investigation_repo.delete_investigations_by_ids(
                            session=session, investigation_ids=target_ids
                        )
                        total_deleted += batch_count
                        batches += 1

                logger.debug(
                    "Pruned batch #%d: deleted %d investigation(s)",
                    batches,
                    len(target_ids),
                )
                # Yield execution to allow concurrent reader/writer transactions on SQLite WAL
                await asyncio.sleep(0.01)

            # Record audit event for non-empty prunes
            if total_deleted > 0:
                async with self.session_factory() as session:
                    async with session.begin():
                        await self.audit_repo.log_event(
                            session=session,
                            actor_id=actor_id,
                            action="INVESTIGATION_EXPIRED_PRUNED",
                            resource_type="investigation",
                            resource_id="batch_cleanup",
                            outcome="SUCCESS",
                            request_id=request_id,
                            client_ip="127.0.0.1",
                            metadata={
                                "deleted_count": total_deleted,
                                "batches_processed": batches,
                                "cutoff": cutoff.isoformat(),
                                "retention_days": self.settings.INVESTIGATION_RETENTION_DAYS,
                            },
                        )

            # Verify remaining count
            async with self.session_factory() as session:
                remaining = await self.investigation_repo.count_expired_investigations(
                    session=session, cutoff=cutoff
                )

            return InvestigationPruneResult(
                dry_run=False,
                cutoff=cutoff,
                deleted_count=total_deleted,
                batches_processed=batches,
                batch_size=bounded_batch_size,
                remaining_count=remaining,
                status="COMPLETED" if remaining == 0 else "PARTIAL",
            )

        except Exception as exc:
            err_msg = f"Investigation retention batch pruning failed: {exc}"
            logger.error(err_msg, exc_info=True)
            return InvestigationPruneResult(
                dry_run=False,
                cutoff=cutoff,
                deleted_count=total_deleted,
                batches_processed=batches,
                batch_size=bounded_batch_size,
                remaining_count=-1,
                status="FAILED",
                error=err_msg,
            )

    async def prune_expired_audit_events(
        self,
        batch_size: int = 100,
        dry_run: bool = True,
        now: Optional[datetime] = None,
    ) -> AuditPruneResult:
        """Evaluate audit events older than the 365-day cutoff.

        SECURITY GOVERNANCE INVARIANT:
        In accordance with Section 5 of Phase 7.4 specifications and ADR-012, destructive deletion
        of audit events is BLOCKED. The current database schema stores a sequential SHA-256 hash
        chain starting from GENESIS_HASH without a checkpoint or anchoring mechanism.
        Pruning an expired prefix from audit_events would cause verify_chain_integrity() to fail
        on the first surviving record (because its previous_hash points to a deleted event),
        permanently invalidating forensic audit integrity.

        Therefore, destructive pruning is halted until a formal schema migration and ADR amendment
        defining an approved hash-chain checkpoint table is authorized by the project owner.
        """
        cutoffs = self.calculate_cutoffs(now)
        cutoff = cutoffs.audit_cutoff

        async with self.session_factory() as session:
            eligible = await self.audit_repo.count_expired_audit_events(
                session=session, cutoff=cutoff
            )
            latest_cp = await self.audit_repo.get_latest_checkpoint(session)
            active_seq = latest_cp.checkpoint_sequence if latest_cp else None

        archive_dir = self.settings.AUDIT_ARCHIVE_DIR

        if dry_run:
            logger.info(
                "Audit retention dry-run: %d record(s) older than %s eligible for evaluation (active checkpoint: %s, archive_dir: %s)",
                eligible,
                cutoff.isoformat(),
                active_seq,
                archive_dir,
            )
            return AuditPruneResult(
                dry_run=True,
                cutoff=cutoff,
                eligible_count=eligible,
                deleted_count=0,
                active_checkpoint_seq=active_seq,
                archive_dir=archive_dir,
                status="DRY_RUN",
                reason=(
                    f"Dry run identified {eligible} audit event(s) older than 365 days cutoff ({cutoff.isoformat()}). "
                    f"Active checkpoint sequence: {active_seq}. Configured archive destination: {archive_dir}."
                ),
            )

        # Destructive execution is explicitly blocked to preserve cryptographic hash chain
        blocker_reason = (
            "AUDIT PRUNING BLOCKED: ADR-012 sequential SHA-256 hash-chain protection active. "
            "ADR-013 checkpointing and verifiable archival architecture approved. "
            "Physical deletion of audit records remains strictly blocked pending separate explicit authorization."
        )
        logger.warning(blocker_reason)
        return AuditPruneResult(
            dry_run=False,
            cutoff=cutoff,
            eligible_count=eligible,
            deleted_count=0,
            active_checkpoint_seq=active_seq,
            archive_dir=archive_dir,
            status="BLOCKED",
            reason=blocker_reason,
        )

    async def execute_wal_checkpoint(self, mode: str = "PASSIVE") -> Optional[str]:
        """Execute SQLite WAL checkpoint (PASSIVE or TRUNCATE) to reclaim disk space."""
        clean_mode = mode.strip().upper()
        if clean_mode not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
            clean_mode = "PASSIVE"

        async with self.session_factory() as session:
            # Check if dialect is sqlite
            bind = session.bind
            if bind and "sqlite" in bind.dialect.name.lower():
                try:
                    result = await session.execute(text(f"PRAGMA wal_checkpoint({clean_mode});"))
                    row = result.fetchone()
                    checkpoint_str = str(row) if row else "OK"
                    logger.info("Executed SQLite PRAGMA wal_checkpoint(%s): %s", clean_mode, checkpoint_str)
                    return checkpoint_str
                except Exception as exc:
                    logger.warning("PRAGMA wal_checkpoint failed: %s", exc)
                    return None
            return None

    async def run_retention_sweep(
        self,
        batch_size: int = 100,
        dry_run: bool = True,
        now: Optional[datetime] = None,
        run_wal_checkpoint: bool = False,
        actor_id: str = "retention_worker",
        request_id: str = "req-retention-sweep",
    ) -> RetentionSweepSummary:
        """Run complete retention maintenance sweep across investigations and audit events."""
        start_time = datetime.now(timezone.utc)
        cutoffs = self.calculate_cutoffs(now)

        inv_result = await self.prune_expired_investigations(
            batch_size=batch_size,
            dry_run=dry_run,
            now=now,
            actor_id=actor_id,
            request_id=request_id,
        )

        audit_result = await self.prune_expired_audit_events(
            batch_size=batch_size,
            dry_run=dry_run,
            now=now,
        )

        wal_result: Optional[str] = None
        wal_executed = False
        if not dry_run and run_wal_checkpoint and inv_result.deleted_count > 0:
            wal_result = await self.execute_wal_checkpoint(mode="TRUNCATE")
            wal_executed = wal_result is not None

        elapsed_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

        return RetentionSweepSummary(
            dry_run=dry_run,
            cutoffs=cutoffs,
            investigations=inv_result,
            audit_events=audit_result,
            wal_checkpoint_executed=wal_executed,
            wal_checkpoint_result=wal_result,
            duration_ms=elapsed_ms,
        )
