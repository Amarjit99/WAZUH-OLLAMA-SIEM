"""Service for compressed audit event archival, offline integrity verification, and storage safety.

Conforms strictly to specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md and approved ADR-013.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_crypto import (
    compute_canonical_event_hash,
    compute_rolling_events_digest,
    format_canonical_timestamp,
)
from app.models.audit import AuditEvent
from app.models.audit_checkpoint import AuditCheckpoint

logger = logging.getLogger(__name__)

# Minimum required free disk space in bytes (1 GB)
MIN_FREE_DISK_BYTES = 1024 * 1024 * 1024


@dataclass
class AuditTrailVerificationReport:
    """Authoritative end-to-end audit verification report across meta-chain, archives, and live suffix."""
    status: str  # "VERIFIED", "UNVERIFIED", "FAILED"
    meta_chain_valid: bool
    checkpoints_count: int
    archives_verified_count: int
    live_suffix_valid: bool
    live_events_count: int
    meta_chain_status: str = "NOT_APPLICABLE"  # "VERIFIED", "NOT_APPLICABLE", "FAILED"
    archive_status: str = "NOT_APPLICABLE"  # "VERIFIED", "NOT_APPLICABLE", "UNVERIFIED", "FAILED"
    live_suffix_status: str = "NOT_APPLICABLE"  # "VERIFIED", "FAILED", "UNVERIFIED"
    trust_anchor_status: str = "NOT_APPLICABLE"  # "VERIFIED", "NOT_APPLICABLE", "UNVERIFIED", "FAILED"
    stages_executed: List[str] = field(default_factory=list)
    stages_skipped: List[str] = field(default_factory=list)
    error_stage: Optional[str] = None  # "META_CHAIN", "ARCHIVE", "LIVE_SUFFIX", "TRUST_ANCHOR"
    error_reason: Optional[str] = None



class AuditArchivalError(Exception):
    """Base exception for audit archival and verification failures."""
    pass


class PathTraversalError(AuditArchivalError):
    """Raised when an archive path resolves outside the designated root directory."""
    pass


class InsufficientDiskSpaceError(AuditArchivalError):
    """Raised when available disk space is below safety threshold."""
    pass


class AuditArchivalService:
    """Manages offline compressed archival and verification for expired audit records."""

    def __init__(self, archive_base_dir: str = "data/archives"):
        self.archive_base_dir = Path(archive_base_dir).resolve()

    def _ensure_and_validate_directory(self) -> Path:
        """Ensure archive directory exists and validate against path traversal."""
        # Create directory with parent directories if needed
        self.archive_base_dir.mkdir(parents=True, exist_ok=True)
        resolved = self.archive_base_dir.resolve()
        return resolved

    def validate_archive_path(self, target_filename: str) -> Path:
        """Validate filename against path traversal and return safe absolute Path."""
        base_dir = self._ensure_and_validate_directory()

        # Reject path separators or directory traversal tokens in filename
        if ".." in target_filename or "/" in target_filename or "\\" in target_filename:
            raise PathTraversalError(f"Invalid archive filename '{target_filename}': path traversal prohibited.")

        target_path = (base_dir / target_filename).resolve()
        # Enforce that target_path is strictly inside base_dir
        if not target_path.is_relative_to(base_dir):
            raise PathTraversalError(f"Target path '{target_path}' escapes base directory '{base_dir}'.")

        return target_path

    def assert_sufficient_disk_space(self, target_dir: Optional[Path] = None) -> int:
        """Assert that the target volume has at least MIN_FREE_DISK_BYTES (1 GB) free."""
        check_dir = target_dir or self._ensure_and_validate_directory()
        try:
            usage = shutil.disk_usage(check_dir)
            if usage.free < MIN_FREE_DISK_BYTES:
                raise InsufficientDiskSpaceError(
                    f"Insufficient disk space on {check_dir}: {usage.free} bytes free, "
                    f"minimum required: {MIN_FREE_DISK_BYTES} bytes (1 GB)."
                )
            return usage.free
        except OSError as exc:
            logger.warning("Could not determine disk usage for %s: %s", check_dir, exc)
            return -1

    def export_archive(
        self,
        checkpoint_sequence: int,
        interval_start: datetime,
        interval_end: datetime,
        events: List[AuditEvent],
    ) -> Tuple[Path, str, str]:
        """Stream and compress audit events to a JSON.GZ archive file.

        Returns (archive_path, physical_file_sha256, rolling_events_digest).
        """
        if not events:
            raise AuditArchivalError("Cannot create archive for empty event list.")

        self.assert_sufficient_disk_space()

        start_str = interval_start.strftime("%Y%m%d%H%M%S")
        end_str = interval_end.strftime("%Y%m%d%H%M%S")
        filename = f"audit_archive_seq{checkpoint_sequence}_{start_str}_{end_str}.json.gz"
        final_path = self.validate_archive_path(filename)
        temp_path = self.validate_archive_path(f"{filename}.tmp")

        # Prepare serializable events payload
        serializable_events = []
        event_hashes = []
        for ev in events:
            event_hashes.append(ev.event_hash)
            serializable_events.append({
                "action": ev.action,
                "actor_id": ev.actor_id,
                "audit_id": ev.audit_id,
                "client_ip": ev.client_ip,
                "event_hash": ev.event_hash,
                "metadata_json": ev.metadata_json,
                "outcome": ev.outcome,
                "previous_hash": ev.previous_hash,
                "request_id": ev.request_id,
                "resource_id": ev.resource_id,
                "resource_type": ev.resource_type,
                "timestamp": format_canonical_timestamp(ev.timestamp),
            })

        rolling_digest = compute_rolling_events_digest(event_hashes)
        manifest = {
            "archive_format_version": "v1",
            "checkpoint_sequence": checkpoint_sequence,
            "created_at": format_canonical_timestamp(datetime.now(timezone.utc)),
            "event_count": len(events),
            "first_included_audit_id": events[0].audit_id,
            "interval_end_timestamp": format_canonical_timestamp(interval_end),
            "interval_start_timestamp": format_canonical_timestamp(interval_start),
            "last_included_audit_id": events[-1].audit_id,
            "last_included_event_hash": events[-1].event_hash,
            "pruned_events_digest": rolling_digest,
            "events": serializable_events,
        }

        # Write compressed archive to temp file
        raw_json_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
        try:
            with gzip.open(temp_path, "wb", compresslevel=9) as gz_out:
                gz_out.write(raw_json_bytes)

            # Compute physical file SHA-256
            hasher = hashlib.sha256()
            with open(temp_path, "rb") as f_in:
                while chunk := f_in.read(65536):
                    hasher.update(chunk)
            file_sha256 = hasher.hexdigest()

            # Atomic rename from .tmp to final path
            if final_path.exists():
                final_path.unlink()
            temp_path.rename(final_path)

            logger.info(
                "Exported audit archive seq #%d with %d events to %s (SHA256: %s)",
                checkpoint_sequence,
                len(events),
                final_path,
                file_sha256,
            )
            return final_path, file_sha256, rolling_digest

        except Exception as exc:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise AuditArchivalError(f"Failed to export archive: {exc}") from exc

    def verify_archive_file(
        self,
        archive_path: Path,
        expected_sha256: str,
        expected_count: int,
        expected_first_id: str,
        expected_last_id: str,
        expected_last_hash: str,
        expected_rolling_digest: str,
    ) -> Tuple[bool, int, Optional[str]]:
        """Verify the integrity of an offline archive file against expected checkpoint metadata.

        Returns (is_valid: bool, event_count: int, error_reason: Optional[str]).
        """
        if not archive_path.exists():
            return False, 0, f"ARCHIVE_FILE_MISSING: File not found at '{archive_path}'"

        # 1. Verify physical file SHA-256
        hasher = hashlib.sha256()
        with open(archive_path, "rb") as f_in:
            while chunk := f_in.read(65536):
                hasher.update(chunk)
        computed_file_sha256 = hasher.hexdigest()

        if computed_file_sha256 != expected_sha256:
            return (
                False,
                0,
                f"ARCHIVE_FILE_TAMPERED: Physical file hash '{computed_file_sha256}' != expected '{expected_sha256}'",
            )

        # 2. Decompress and parse manifest
        try:
            with gzip.open(archive_path, "rb") as gz_in:
                content = json.loads(gz_in.read().decode("utf-8"))
        except Exception as exc:
            return False, 0, f"ARCHIVE_DECOMPRESS_FAILED: Corrupt gzip stream ({exc})"

        events = content.get("events", [])
        if len(events) != expected_count:
            return (
                False,
                len(events),
                f"ARCHIVE_COUNT_MISMATCH: Stated event count {len(events)} != expected {expected_count}",
            )

        if not events:
            return False, 0, "ARCHIVE_EMPTY: Archive has zero events"

        # 3. Verify boundary IDs and hashes
        if events[0]["audit_id"] != expected_first_id:
            return (
                False,
                0,
                f"ARCHIVE_BOUNDARY_MISMATCH: First audit_id '{events[0]['audit_id']}' != expected '{expected_first_id}'",
            )

        if events[-1]["audit_id"] != expected_last_id:
            return (
                False,
                0,
                f"ARCHIVE_BOUNDARY_MISMATCH: Last audit_id '{events[-1]['audit_id']}' != expected '{expected_last_id}'",
            )

        if events[-1]["event_hash"] != expected_last_hash:
            return (
                False,
                0,
                f"ARCHIVE_ANCHOR_MISMATCH: Last event_hash '{events[-1]['event_hash']}' != expected '{expected_last_hash}'",
            )

        # 4. Verify internal sequential hash chain
        event_hashes = []
        for idx, ev in enumerate(events):
            event_hashes.append(ev["event_hash"])
            recomputed = compute_canonical_event_hash(
                audit_id=ev["audit_id"],
                timestamp_iso=ev["timestamp"],
                actor_id=ev["actor_id"],
                action=ev["action"],
                resource_type=ev["resource_type"],
                resource_id=ev["resource_id"],
                outcome=ev["outcome"],
                request_id=ev["request_id"],
                client_ip=ev["client_ip"],
                metadata_json=ev.get("metadata_json"),
                previous_hash=ev["previous_hash"],
            )
            if recomputed != ev["event_hash"]:
                return (
                    False,
                    idx,
                    f"ARCHIVE_EVENT_TAMPERED: Event {ev['audit_id']} at index {idx} has invalid hash",
                )

            if idx > 0 and ev["previous_hash"] != events[idx - 1]["event_hash"]:
                return (
                    False,
                    idx,
                    f"ARCHIVE_CHAIN_BROKEN: Event {ev['audit_id']} predecessor link broken at index {idx}",
                )

        # 5. Verify rolling digest
        computed_rolling = compute_rolling_events_digest(event_hashes)
        if computed_rolling != expected_rolling_digest:
            return (
                False,
                len(events),
                f"ARCHIVE_DIGEST_MISMATCH: Rolling digest '{computed_rolling}' != expected '{expected_rolling_digest}'",
            )

        return True, len(events), None

    async def verify_complete_audit_trail(
        self,
        session: AsyncSession,
        audit_repo: Any,
        signing_secret: Optional[bytes] = None,
        require_archives: bool = True,
    ) -> AuditTrailVerificationReport:
        """Execute end-to-end audit trail verification across meta-chain, archives, and live suffix.

        Fail-closed rules:
        - Meta-chain gaps/corruption -> status="FAILED", error_stage="META_CHAIN"
        - Corrupt/tampered/missing archive -> status="FAILED" (or "UNVERIFIED"), error_stage="ARCHIVE"
        - Live suffix tampering/gap -> status="FAILED", error_stage="LIVE_SUFFIX"
        - Missing signing secret when required -> status="UNVERIFIED", error_stage="TRUST_ANCHOR"
        - Only returns status="VERIFIED" when all applicable stages succeed with complete trust.
        - Accurately reports executed vs skipped stages (0 checkpoints -> meta-chain and archives marked NOT_APPLICABLE).
        """
        stages_executed: List[str] = []
        stages_skipped: List[str] = []

        # 1. Verify Checkpoint Meta-Chain from genesis sequence 1 to tip
        meta_valid, cp_count, meta_err = await audit_repo.verify_checkpoint_meta_chain(session)
        if not meta_valid:
            logger.warning("Audit trail verification failed at meta-chain stage: %s", meta_err)
            return AuditTrailVerificationReport(
                status="FAILED",
                meta_chain_valid=False,
                checkpoints_count=cp_count,
                archives_verified_count=0,
                live_suffix_valid=False,
                live_events_count=0,
                meta_chain_status="FAILED",
                archive_status="NOT_APPLICABLE",
                live_suffix_status="NOT_APPLICABLE",
                trust_anchor_status="NOT_APPLICABLE",
                stages_executed=["META_CHAIN"],
                stages_skipped=["ARCHIVE", "LIVE_SUFFIX"],
                error_stage="META_CHAIN",
                error_reason=meta_err,
            )

        if cp_count > 0:
            stages_executed.append("META_CHAIN")
            meta_chain_status = "VERIFIED"
        else:
            stages_skipped.append("META_CHAIN")
            meta_chain_status = "NOT_APPLICABLE"

        # 2. Verify all offline archives associated with checkpoints
        stmt = (
            select(AuditCheckpoint)
            .where(AuditCheckpoint.status.in_(["ACTIVE", "SUPERSEDED"]))
            .order_by(AuditCheckpoint.checkpoint_sequence.asc())
        )
        checkpoints: List[AuditCheckpoint] = list((await session.execute(stmt)).scalars().all())
        archives_verified = 0

        if cp_count > 0:
            stages_executed.append("ARCHIVE")
            for cp in checkpoints:
                if cp.archive_file_path:
                    archive_path = Path(cp.archive_file_path)
                    if not archive_path.is_absolute():
                        archive_path = (self.archive_base_dir / archive_path.name).resolve()

                    valid_arch, count, arch_err = self.verify_archive_file(
                        archive_path=archive_path,
                        expected_sha256=cp.archive_sha256 or "",
                        expected_count=cp.event_count,
                        expected_first_id=cp.first_included_audit_id,
                        expected_last_id=cp.last_included_audit_id,
                        expected_last_hash=cp.last_included_event_hash,
                        expected_rolling_digest=cp.pruned_events_digest,
                    )
                    if not valid_arch:
                        logger.warning(
                            "Audit trail verification failed at archive stage for checkpoint seq %d: %s",
                            cp.checkpoint_sequence,
                            arch_err,
                        )
                        return AuditTrailVerificationReport(
                            status="FAILED",
                            meta_chain_valid=True,
                            checkpoints_count=cp_count,
                            archives_verified_count=archives_verified,
                            live_suffix_valid=False,
                            live_events_count=0,
                            meta_chain_status=meta_chain_status,
                            archive_status="FAILED",
                            live_suffix_status="NOT_APPLICABLE",
                            trust_anchor_status="NOT_APPLICABLE",
                            stages_executed=stages_executed,
                            stages_skipped=["LIVE_SUFFIX"],
                            error_stage="ARCHIVE",
                            error_reason=f"Checkpoint seq {cp.checkpoint_sequence} archive failure: {arch_err}",
                        )
                    archives_verified += 1
                elif require_archives:
                    reason = f"ARCHIVE_UNAVAILABLE: Checkpoint seq {cp.checkpoint_sequence} has no archive configured"
                    logger.warning("Audit trail verification unverified: %s", reason)
                    return AuditTrailVerificationReport(
                        status="UNVERIFIED",
                        meta_chain_valid=True,
                        checkpoints_count=cp_count,
                        archives_verified_count=archives_verified,
                        live_suffix_valid=False,
                        live_events_count=0,
                        meta_chain_status=meta_chain_status,
                        archive_status="UNVERIFIED",
                        live_suffix_status="NOT_APPLICABLE",
                        trust_anchor_status="NOT_APPLICABLE",
                        stages_executed=stages_executed,
                        stages_skipped=["LIVE_SUFFIX"],
                        error_stage="ARCHIVE",
                        error_reason=reason,
                    )
            archive_status = "VERIFIED"
        else:
            stages_skipped.append("ARCHIVE")
            archive_status = "NOT_APPLICABLE"

        # 3. Verify Live Suffix (or full genesis chain if 0 checkpoints)
        stages_executed.append("LIVE_SUFFIX")
        live_valid, live_count, live_err = await audit_repo.verify_chain_integrity(
            session=session, signing_secret=signing_secret
        )
        if not live_valid:
            if "TRUST_ANCHOR_UNAVAILABLE" in (live_err or ""):
                logger.warning("Audit trail verification unverified at trust anchor stage: %s", live_err)
                return AuditTrailVerificationReport(
                    status="UNVERIFIED",
                    meta_chain_valid=True,
                    checkpoints_count=cp_count,
                    archives_verified_count=archives_verified,
                    live_suffix_valid=False,
                    live_events_count=0,
                    meta_chain_status=meta_chain_status,
                    archive_status=archive_status,
                    live_suffix_status="UNVERIFIED",
                    trust_anchor_status="UNVERIFIED",
                    stages_executed=stages_executed,
                    stages_skipped=stages_skipped,
                    error_stage="TRUST_ANCHOR",
                    error_reason=live_err,
                )
            if "CHECKPOINT_SIGNATURE_INVALID" in (live_err or ""):
                logger.warning("Audit trail verification failed at trust anchor signature verification: %s", live_err)
                return AuditTrailVerificationReport(
                    status="FAILED",
                    meta_chain_valid=True,
                    checkpoints_count=cp_count,
                    archives_verified_count=archives_verified,
                    live_suffix_valid=False,
                    live_events_count=0,
                    meta_chain_status=meta_chain_status,
                    archive_status=archive_status,
                    live_suffix_status="FAILED",
                    trust_anchor_status="FAILED",
                    stages_executed=stages_executed,
                    stages_skipped=stages_skipped,
                    error_stage="TRUST_ANCHOR",
                    error_reason=live_err,
                )
            logger.warning("Audit trail verification failed at live suffix stage: %s", live_err)
            return AuditTrailVerificationReport(
                status="FAILED",
                meta_chain_valid=True,
                checkpoints_count=cp_count,
                archives_verified_count=archives_verified,
                live_suffix_valid=False,
                live_events_count=0,
                meta_chain_status=meta_chain_status,
                archive_status=archive_status,
                live_suffix_status="FAILED",
                trust_anchor_status="NOT_APPLICABLE",
                stages_executed=stages_executed,
                stages_skipped=stages_skipped,
                error_stage="LIVE_SUFFIX",
                error_reason=live_err,
            )

        # 4. Complete End-to-End Success
        trust_anchor_status = "VERIFIED" if (cp_count > 0 and signing_secret is not None) else "NOT_APPLICABLE"
        logger.info(
            "Audit trail end-to-end verification VERIFIED: meta_chain=%s, archive=%s, live_suffix=VERIFIED "
            "(%d checkpoints, %d archives, %d live events)",
            meta_chain_status,
            archive_status,
            cp_count,
            archives_verified,
            live_count,
        )
        return AuditTrailVerificationReport(
            status="VERIFIED",
            meta_chain_valid=True,
            checkpoints_count=cp_count,
            archives_verified_count=archives_verified,
            live_suffix_valid=True,
            live_events_count=live_count,
            meta_chain_status=meta_chain_status,
            archive_status=archive_status,
            live_suffix_status="VERIFIED",
            trust_anchor_status=trust_anchor_status,
            stages_executed=stages_executed,
            stages_skipped=stages_skipped,
            error_stage=None,
            error_reason=None,
        )

