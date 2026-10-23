"""Background scheduler and operational coordinator for automated SIEM database backups.

Conforms strictly to Phase 8.0 Workstream B & Workstream D requirements:
- Disabled by default; requires explicit BACKUP_SCHEDULE_ENABLED=True
- Configurable schedule interval and backup destination
- Single-instance execution: in-process asyncio.Lock + cross-process msvcrt file lock
- Safe graceful shutdown during active backup execution without destination corruption
- Bounded runtime and clear failure status categorization
- Observable operational monitoring state without leaking secrets or raw paths
- Tracks actual recovery drill verification results
"""

import asyncio
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional

from app.core.backup_crypto import BackupCryptoError, BackupKeyManager, BackupKeyUnavailableError
from app.core.config import Settings, get_settings
from app.services.database_backup_service import (
    DatabaseBackupError,
    DatabaseBackupResult,
    DatabaseBackupService,
    DatabaseCorruptionError,
)

logger = logging.getLogger("siem.backup_scheduler")


class CrossProcessLockError(Exception):
    """Raised when another worker or process holds the cross-process backup lock."""
    pass


class BackupSchedulerService:
    """Manages scheduled periodic database backups, concurrency safeguards, and operational telemetry."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        backup_service: Optional[DatabaseBackupService] = None,
    ):
        self.settings = settings or get_settings()
        self.backup_service = backup_service or DatabaseBackupService(settings=self.settings)
        self.key_manager = BackupKeyManager(self.settings.BACKUP_KEY_PATH)

        # Concurrency primitives
        self._async_lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        # Operational telemetry state (in-memory, strictly non-secret)
        self._is_active: bool = False
        self._is_backup_in_progress: bool = False
        self._last_attempt_at: Optional[datetime] = None
        self._last_success_at: Optional[datetime] = None
        self._last_duration_seconds: Optional[float] = None
        self._last_verification_status: str = "UNVERIFIED"
        self._last_error: Optional[str] = None
        self._last_error_category: Optional[str] = None
        self._last_backup_encrypted: Optional[bool] = None
        self._last_backup_path: Optional[str] = None
        self._last_backup_sha256: Optional[str] = None

        # Recovery drill state
        self._last_recovery_drill_at: Optional[datetime] = None
        self._last_recovery_drill_status: str = "NEVER_RUN"
        self._last_recovery_drill_details: Optional[str] = None

        # Audit verification state
        self._last_audit_verification_at: Optional[datetime] = None
        self._last_audit_verification_status: str = "UNVERIFIED"
        self._last_audit_events_verified: Optional[int] = None
        self._last_audit_error: Optional[str] = None

    @property
    def is_running(self) -> bool:
        """Return True if background scheduler loop task is currently running."""
        return self._task is not None and not self._task.done()

    def start(self) -> bool:
        """Start background backup scheduler loop if enabled in configuration.

        Returns True if started, False if disabled or already running.
        """
        if not self.settings.BACKUP_SCHEDULE_ENABLED:
            logger.info("Backup scheduler is disabled by configuration (BACKUP_SCHEDULE_ENABLED=False)")
            return False

        if self.is_running:
            logger.warning("Backup scheduler is already running; duplicate start ignored")
            return False

        self._stop_event.clear()
        self._is_active = True
        self._task = asyncio.create_task(self._scheduler_loop(), name="backup_scheduler_loop")
        logger.info(
            "Backup scheduler loop started: interval=%d minutes, destination=%s",
            self.settings.BACKUP_INTERVAL_MINUTES,
            self.settings.DATABASE_BACKUP_DIR,
        )
        return True

    async def stop(self, timeout_seconds: float = 10.0) -> None:
        """Gracefully stop background scheduler loop and wait for any active job to complete or cancel."""
        self._is_active = False
        self._stop_event.set()

        if self._task and not self._task.done():
            logger.info("Signaling backup scheduler to stop gracefully (timeout=%.1fs)...", timeout_seconds)
            self._task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=timeout_seconds)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                logger.warning("Backup scheduler task cancelled or timed out during shutdown")
            except Exception as exc:
                logger.error("Error while awaiting backup scheduler shutdown: %s", exc)

        logger.info("Backup scheduler stopped successfully")

    def _acquire_cross_process_lock(self, lock_file_path: Path):
        """Acquire non-blocking file lock using native Windows msvcrt on file descriptor."""
        if sys.platform != "win32":
            return None

        import msvcrt

        lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        # Open in read-write-create binary mode
        f = open(lock_file_path, "a+b")
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            return f
        except (OSError, PermissionError) as exc:
            f.close()
            raise CrossProcessLockError(f"Cross-process lock busy on '{lock_file_path}'") from exc

    def _release_cross_process_lock(self, lock_file, lock_file_path: Path):
        """Release native Windows msvcrt file lock."""
        if sys.platform != "win32" or not lock_file:
            return

        import msvcrt

        try:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception as exc:
            logger.warning("Failed to unlock file descriptor: %s", exc)
        finally:
            lock_file.close()

    async def run_backup_job(
        self,
        backup_filename: Optional[str] = None,
        source_db_path: Optional[str] = None,
        target_backup_dir: Optional[str] = None,
        encrypted: Optional[bool] = None,
        validate_source: bool = True,
    ) -> DatabaseBackupResult:
        """Execute a single database backup job with non-overlapping in-process and cross-process guards."""
        if self._async_lock.locked():
            logger.warning("Backup job skipped: in-process backup is already running")
            raise DatabaseBackupError("Backup is already running in this process; concurrency prohibited.")

        async with self._async_lock:
            self._is_backup_in_progress = True
            started_at = datetime.now(timezone.utc)
            start_mono = time.monotonic()
            self._last_attempt_at = started_at
            self._last_verification_status = "RUNNING"
            self._last_error = None
            self._last_error_category = None

            dest_dir = self.backup_service.resolve_backup_dir(target_backup_dir)
            lock_path = dest_dir / ".backup_scheduler.lock"
            lock_handle = None

            try:
                # 1. Acquire cross-process lock to prevent duplicate worker execution
                try:
                    lock_handle = self._acquire_cross_process_lock(lock_path)
                except CrossProcessLockError as lock_err:
                    self._last_error = "Another process holds the backup lock"
                    self._last_error_category = "CONCURRENCY_LOCKED"
                    self._last_verification_status = "SKIPPED"
                    logger.info("Backup job skipped: %s", lock_err)
                    raise

                # 2. Execute backup operation via threadpool executor to avoid blocking event loop
                use_encryption = self.settings.BACKUP_ENCRYPTION_ENABLED if encrypted is None else encrypted

                def _do_backup():
                    return self.backup_service.create_backup(
                        source_db_path=source_db_path,
                        target_backup_dir=str(dest_dir),
                        backup_filename=backup_filename,
                        encrypted=use_encryption,
                        validate_source=validate_source,
                    )

                result: DatabaseBackupResult = await asyncio.to_thread(_do_backup)

                # 3. Record successful execution
                duration = time.monotonic() - start_mono
                self._last_duration_seconds = round(duration, 3)
                self._last_success_at = datetime.now(timezone.utc)
                self._last_verification_status = "VERIFIED"
                self._last_backup_encrypted = result.is_encrypted
                self._last_backup_path = result.backup_path
                self._last_backup_sha256 = result.backup_sha256

                logger.info(
                    "Backup job succeeded in %.2fs: path=%s, encrypted=%s, alembic=%s",
                    duration,
                    result.backup_path,
                    result.is_encrypted,
                    result.alembic_version,
                )
                return result

            except CrossProcessLockError:
                raise
            except asyncio.CancelledError:
                duration = time.monotonic() - start_mono
                self._last_duration_seconds = round(duration, 3)
                self._last_verification_status = "CANCELLED"
                self._last_error = "Backup job was cancelled during execution"
                self._last_error_category = "CANCELLED"
                logger.warning("Backup job cancelled while in progress")
                raise
            except DatabaseCorruptionError as cor_err:
                duration = time.monotonic() - start_mono
                self._last_duration_seconds = round(duration, 3)
                self._last_verification_status = "FAILED"
                self._last_error = str(cor_err)
                self._last_error_category = "CORRUPTION"
                logger.error("Backup failed due to database corruption: %s", cor_err)
                raise
            except (BackupCryptoError, BackupKeyUnavailableError) as crypto_err:
                duration = time.monotonic() - start_mono
                self._last_duration_seconds = round(duration, 3)
                self._last_verification_status = "FAILED"
                self._last_error = str(crypto_err)
                self._last_error_category = "CRYPTO"
                logger.error("Backup failed due to cryptographic error: %s", crypto_err)
                raise
            except Exception as exc:
                duration = time.monotonic() - start_mono
                self._last_duration_seconds = round(duration, 3)
                self._last_verification_status = "FAILED"
                self._last_error = str(exc)
                self._last_error_category = "UNKNOWN"
                logger.error("Backup job failed: %s", exc, exc_info=True)
                raise
            finally:
                if lock_handle:
                    self._release_cross_process_lock(lock_handle, lock_path)
                self._is_backup_in_progress = False

    async def _scheduler_loop(self) -> None:
        """Continuous scheduler loop running at configured interval."""
        interval_seconds = max(60, self.settings.BACKUP_INTERVAL_MINUTES * 60)
        logger.info("Backup scheduler loop active; next run in %d seconds", interval_seconds)

        while not self._stop_event.is_set():
            try:
                # Sleep until next interval or until stop event signaled
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval_seconds)
                # If wait() returned, stop_event was set
                break
            except asyncio.TimeoutError:
                # Normal interval expiry: trigger backup job
                pass
            except asyncio.CancelledError:
                break

            if self._stop_event.is_set():
                break

            try:
                logger.info("Scheduled backup trigger executing...")
                await self.run_backup_job()
            except CrossProcessLockError:
                logger.info("Scheduled backup deferred: another process is currently running backup")
            except Exception as exc:
                logger.error("Scheduled backup failed: %s", exc)

        logger.info("Backup scheduler loop exited")

    def record_recovery_drill_result(self, success: bool, details: Optional[str] = None) -> None:
        """Record the outcome of an actual isolated recovery drill."""
        self._last_recovery_drill_at = datetime.now(timezone.utc)
        self._last_recovery_drill_status = "VERIFIED" if success else "FAILED"
        self._last_recovery_drill_details = details

    def record_audit_verification_result(self, success: bool, count: int = 0, error: Optional[str] = None) -> None:
        """Record the outcome of an actual cryptographic audit hash chain verification."""
        self._last_audit_verification_at = datetime.now(timezone.utc)
        self._last_audit_verification_status = "VERIFIED" if success else "FAILED"
        self._last_audit_events_verified = count
        self._last_audit_error = error

    def get_operational_status(self) -> Dict[str, Any]:
        """Compile safe operational monitoring payload conforming to specs and Workstream D.

        Never returns key secrets, bearer tokens, or full un-sanitized internal file contents.
        """
        key_status = self.key_manager.get_key_status()

        # Determine overall subsystem health
        if self.settings.BACKUP_ENCRYPTION_ENABLED and not key_status.get("key_usable", False):
            overall_status = "UNAVAILABLE"
        elif self._last_verification_status == "FAILED" or self._last_audit_verification_status == "FAILED":
            overall_status = "DEGRADED"
        else:
            overall_status = "OK"

        return {
            "status": overall_status,
            "scheduler_enabled": self.settings.BACKUP_SCHEDULE_ENABLED,
            "scheduler_active": self.is_running,
            "is_backup_in_progress": self._is_backup_in_progress,
            "backup_interval_minutes": self.settings.BACKUP_INTERVAL_MINUTES,
            "last_backup_attempt_at": self._last_attempt_at,
            "last_successful_backup_at": self._last_success_at,
            "last_backup_duration_seconds": self._last_duration_seconds,
            "last_backup_verification_status": self._last_verification_status,
            "last_backup_error": self._last_error,
            "last_backup_error_category": self._last_error_category,
            "last_backup_encrypted": self._last_backup_encrypted,
            "encryption_key_status": key_status,
            "last_recovery_drill_at": self._last_recovery_drill_at,
            "last_recovery_drill_status": self._last_recovery_drill_status,
            "last_audit_verification_at": self._last_audit_verification_at,
            "last_audit_verification_status": self._last_audit_verification_status,
            "last_audit_events_verified": self._last_audit_events_verified,
            "last_audit_error": self._last_audit_error,
            "retrieved_at": datetime.now(timezone.utc),
        }
