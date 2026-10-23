"""Service for safe SQLite online backup and isolated disaster recovery in WAL mode.

Conforms strictly to Phase 7.9 Operational Hardening specifications:
- Uses SQLite's supported online backup API (sqlite3.Connection.backup)
- Correctly flushes and captures active WAL state without copying naked .db files
- Preserves source database completely unmodified (zero VACUUM, zero maintenance, zero writes)
- Enforces atomic non-overwriting destination writes via temporary file staging
- Validates integrity using PRAGMA integrity_check, foreign_key_check, schema checks, and Alembic state
- Provides safe, isolated restoration and verification
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.backup_crypto import (
    CONTAINER_MAGIC,
    CIPHER_AES_256_GCM,
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
from app.core.config import Settings, get_settings

logger = logging.getLogger("siem.backup")

# Required tables per Alembic migration head 20261021_0002
REQUIRED_APPLICATION_TABLES: Set[str] = {
    "investigations",
    "investigation_results",
    "investigation_facts",
    "investigation_hypotheses",
    "investigation_checks",
    "investigation_evidence_snapshots",
    "audit_events",
    "audit_checkpoints",
    "alembic_version",
}

EXPECTED_ALEMBIC_HEAD: str = "20261021_0002"


class DatabaseBackupError(Exception):
    """Base exception for database backup operations."""
    pass


class DatabaseRestoreError(Exception):
    """Base exception for database restore operations."""
    pass


class DatabaseCorruptionError(DatabaseBackupError):
    """Raised when SQLite database fails integrity or foreign-key verification."""
    pass


@dataclass
class DatabaseBackupResult:
    """Authoritative metadata and validation report for a completed database backup."""
    success: bool
    backup_path: str
    backup_sha256: str
    file_size_bytes: int
    alembic_version: str
    table_counts: Dict[str, int]
    created_at: datetime
    wal_pages_included: bool = True
    integrity_status: str = "VERIFIED"
    is_encrypted: bool = False
    cipher: Optional[str] = None
    key_id: Optional[str] = None
    plaintext_sha256: Optional[str] = None


@dataclass
class DatabaseRestoreResult:
    """Authoritative metadata and validation report for a restored database snapshot."""
    success: bool
    restored_db_path: str
    alembic_version: str
    table_counts: Dict[str, int]
    restored_at: datetime
    integrity_status: str = "VERIFIED"
    was_encrypted: bool = False
    cipher: Optional[str] = None
    key_id: Optional[str] = None


class DatabaseBackupService:
    """Orchestrates non-destructive SQLite online backups and verified isolated recovery."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def resolve_source_db_path(self, override_path: Optional[str] = None) -> Path:
        """Resolve absolute filesystem Path for the configured or requested source SQLite database."""
        if override_path:
            return Path(override_path).resolve()

        url = self.settings.DATABASE_URL.split("?")[0]
        match = re.match(r"^sqlite(?:\+[a-z0-9_]+)?:///(.*)$", url)
        if not match:
            raise DatabaseBackupError(f"Cannot resolve local SQLite file from DATABASE_URL: '{url}'")

        raw_path = match.group(1)
        if not raw_path or raw_path == ":memory:":
            raise DatabaseBackupError("Cannot backup in-memory SQLite database via file operations.")

        return Path(raw_path).resolve()

    def resolve_backup_dir(self, override_dir: Optional[str] = None) -> Path:
        """Resolve and ensure backup destination directory exists."""
        target_dir = Path(override_dir or self.settings.DATABASE_BACKUP_DIR).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def validate_sqlite_database(
        self,
        db_path: Path,
        expected_alembic_head: Optional[str] = EXPECTED_ALEMBIC_HEAD,
        required_tables: Optional[Set[str]] = None,
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Validate SQLite database file using integrity check, foreign key check, and schema checks.

        Returns (valid, metadata_dict, error_message).
        """
        if not db_path.exists():
            return False, {}, f"Database file not found: {db_path}"

        expected_tables = required_tables if required_tables is not None else REQUIRED_APPLICATION_TABLES
        meta: Dict[str, Any] = {
            "path": str(db_path),
            "file_size_bytes": db_path.stat().st_size,
            "table_counts": {},
            "alembic_version": "UNKNOWN",
        }

        conn: Optional[sqlite3.Connection] = None
        try:
            # Open URI connection with foreign keys strictly enabled
            conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
            cursor = conn.cursor()

            # 1. PRAGMA integrity_check
            cursor.execute("PRAGMA integrity_check;")
            integrity_rows = cursor.fetchall()
            if not integrity_rows or integrity_rows[0][0] != "ok":
                reasons = [r[0] for r in integrity_rows]
                return False, meta, f"PRAGMA integrity_check failed: {', '.join(reasons)}"

            # 2. PRAGMA foreign_key_check
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute("PRAGMA foreign_key_check;")
            fk_violations = cursor.fetchall()
            if fk_violations:
                return False, meta, f"PRAGMA foreign_key_check detected violations: {fk_violations}"

            # 3. Check existing tables in sqlite_master
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = {row[0] for row in cursor.fetchall()}
            meta["existing_tables"] = sorted(list(existing_tables))

            missing_tables = expected_tables - existing_tables
            if missing_tables:
                return (
                    False,
                    meta,
                    f"Schema verification failed: missing required tables {sorted(list(missing_tables))}",
                )

            # 4. Count rows in application tables
            for tbl in sorted(list(existing_tables)):
                if not tbl.startswith("sqlite_"):
                    cursor.execute(f"SELECT COUNT(*) FROM \"{tbl}\";")
                    meta["table_counts"][tbl] = cursor.fetchone()[0]

            # 5. Check Alembic revision state
            if "alembic_version" in existing_tables:
                cursor.execute("SELECT version_num FROM alembic_version LIMIT 1;")
                row = cursor.fetchone()
                if row:
                    meta["alembic_version"] = row[0]
                    if expected_alembic_head and row[0] != expected_alembic_head:
                        return (
                            False,
                            meta,
                            f"Alembic revision mismatch: found '{row[0]}', expected '{expected_alembic_head}'",
                        )
                else:
                    return False, meta, "alembic_version table is empty; unmigrated database state."

            cursor.close()
            return True, meta, None

        except sqlite3.DatabaseError as db_err:
            return False, meta, f"SQLite validation error: {str(db_err)}"
        finally:
            if conn:
                conn.close()

    def create_online_backup(
        self,
        source_db_path: Optional[str] = None,
        target_backup_dir: Optional[str] = None,
        backup_filename: Optional[str] = None,
        validate_source: bool = True,
    ) -> DatabaseBackupResult:
        """Create a safe, verified online backup snapshot using sqlite3.Connection.backup().

        Guarantees:
        - Source database and WAL state remain completely unmodified.
        - Destination file is written to an atomic temporary staging path (.tmp) before validation.
        - Refuses to overwrite existing files.
        - Backups are validated with PRAGMA integrity_check, foreign keys, and schema checks.
        """
        source_path = self.resolve_source_db_path(source_db_path)
        if not source_path.exists():
            raise DatabaseBackupError(f"Source database file does not exist: {source_path}")

        backup_dir = self.resolve_backup_dir(target_backup_dir)

        # Optional pre-flight validation of source
        if validate_source:
            valid, _, err = self.validate_sqlite_database(source_path)
            if not valid:
                raise DatabaseCorruptionError(f"Pre-flight source database check failed: {err}")

        # Generate unique non-overwriting destination filename
        if not backup_filename:
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            entropy = hashlib.sha256(os.urandom(8)).hexdigest()[:8]
            target_filename = f"siem_backup_{timestamp_str}_{entropy}.db"
        else:
            target_filename = backup_filename

        target_path = backup_dir / target_filename
        if target_path.exists():
            raise FileExistsError(f"Backup target file '{target_path}' already exists; overwriting is strictly prohibited.")

        staging_path = backup_dir / f"{target_filename}.tmp"
        if staging_path.exists():
            staging_path.unlink()

        logger.info("Initiating SQLite online backup: source=%s -> staging=%s", source_path, staging_path)

        source_conn: Optional[sqlite3.Connection] = None
        dest_conn: Optional[sqlite3.Connection] = None

        try:
            # 1. Connect to source in read-only mode to prevent any chance of write or lock conflict
            source_conn = sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)

            # 2. Open destination staging connection
            dest_conn = sqlite3.connect(str(staging_path))

            # 3. Execute SQLite online backup API
            # This safely flushes active WAL pages from source_path-wal into the standalone destination
            source_conn.backup(dest_conn, pages=250)

            # Close connections cleanly
            dest_conn.close()
            dest_conn = None
            source_conn.close()
            source_conn = None

            # 4. Perform post-backup validation on staging file
            is_valid, meta, val_err = self.validate_sqlite_database(staging_path)
            if not is_valid:
                raise DatabaseCorruptionError(f"Backup validation failed on staged snapshot: {val_err}")

            # 5. Atomically commit backup file to final target name
            staging_path.replace(target_path)

            # 6. Compute SHA-256 digest of verified backup file
            hasher = hashlib.sha256()
            with open(target_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            backup_sha256 = hasher.hexdigest()

            result = DatabaseBackupResult(
                success=True,
                backup_path=str(target_path),
                backup_sha256=backup_sha256,
                file_size_bytes=target_path.stat().st_size,
                alembic_version=meta.get("alembic_version", "UNKNOWN"),
                table_counts=meta.get("table_counts", {}),
                created_at=datetime.now(timezone.utc),
                wal_pages_included=True,
                integrity_status="VERIFIED",
            )
            logger.info(
                "SQLite online backup completed successfully: path=%s, size=%d bytes, alembic_version=%s",
                result.backup_path,
                result.file_size_bytes,
                result.alembic_version,
            )
            return result

        except Exception as exc:
            logger.error("SQLite online backup failed: %s", str(exc), exc_info=True)
            if staging_path.exists():
                try:
                    staging_path.unlink()
                    logger.debug("Cleaned up incomplete staging backup file: %s", staging_path)
                except OSError as cleanup_err:
                    logger.warning("Could not unlink staging backup file %s: %s", staging_path, cleanup_err)
            raise
        finally:
            if dest_conn:
                dest_conn.close()
            if source_conn:
                source_conn.close()

    def is_encrypted_backup(self, file_path: Path | str) -> bool:
        """Check if backup file is an authenticated encrypted container."""
        p = Path(file_path).resolve()
        if not p.exists() or p.stat().st_size < 14:
            return False
        try:
            with open(p, "rb") as f:
                magic = f.read(len(CONTAINER_MAGIC))
                return magic == CONTAINER_MAGIC
        except Exception:
            return False

    def verify_encrypted_backup_container(
        self,
        backup_path: Path | str,
        key: bytes,
    ) -> EncryptedContainerHeader:
        """Verify an encrypted backup container: validates header format, tag, AAD, and digest without saving plaintext."""
        target = Path(backup_path).resolve()
        if not target.exists():
            raise BackupCryptoError(f"Container file not found: {target}")

        with open(target, "rb") as f:
            header = EncryptedContainerHeader.parse_header(f)
            ciphertext = f.read()

        aad = header.serialize_aad()
        cng = WindowsCNGAESGCM()
        plaintext = cng.decrypt(
            key=key,
            nonce=header.nonce,
            ciphertext=ciphertext,
            tag=header.tag,
            associated_data=aad,
        )

        if len(plaintext) != header.plaintext_size:
            raise BackupFormatError(
                f"Decrypted size mismatch: expected {header.plaintext_size}, got {len(plaintext)}"
            )

        calc_sha256 = hashlib.sha256(plaintext).hexdigest()
        if calc_sha256 != header.plaintext_sha256:
            raise BackupAuthenticationError(
                f"Decrypted SHA-256 digest mismatch: expected {header.plaintext_sha256}, got {calc_sha256}"
            )

        return header

    def create_encrypted_backup(
        self,
        source_db_path: Optional[str] = None,
        target_backup_dir: Optional[str] = None,
        backup_filename: Optional[str] = None,
        key_path: Optional[str] = None,
        explicit_key: Optional[bytes] = None,
        explicit_key_id: Optional[str] = None,
        validate_source: bool = True,
    ) -> DatabaseBackupResult:
        """Create a safe, authenticated AES-256-GCM encrypted database backup.

        Guarantees:
        - Creates a verified SQLite online snapshot first.
        - Encrypts snapshot with unique 96-bit nonce and AAD authenticated header.
        - Cleans up temporary plaintext snapshot immediately under all exit paths.
        - Verifies the encrypted container before declaring success.
        - Atomic publication to destination, refusing to overwrite existing files.
        - Returns metadata containing cipher, key_id, plaintext SHA-256, and container SHA-256.
        """
        source_path = self.resolve_source_db_path(source_db_path)
        if not source_path.exists():
            raise DatabaseBackupError(f"Source database file does not exist: {source_path}")

        backup_dir = self.resolve_backup_dir(target_backup_dir)

        # 1. Resolve encryption key
        if explicit_key is not None:
            raw_key = explicit_key
            key_id = explicit_key_id or f"test-{hashlib.sha256(raw_key).hexdigest()[:8]}"
        else:
            resolved_key_path = key_path or self.settings.BACKUP_KEY_PATH
            key_mgr = BackupKeyManager(resolved_key_path)
            raw_key, key_id = key_mgr.initialize_new_key_if_absent()

        # Generate unique destination filename if not specified
        if not backup_filename:
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            entropy = hashlib.sha256(os.urandom(8)).hexdigest()[:8]
            target_filename = f"siem_backup_{timestamp_str}_{entropy}.enc.db"
        else:
            target_filename = backup_filename

        target_enc_path = backup_dir / target_filename
        if target_enc_path.exists():
            raise FileExistsError(f"Target encrypted backup '{target_enc_path}' already exists; refuse to overwrite.")

        # Staging plaintext snapshot path
        temp_entropy = hashlib.sha256(os.urandom(8)).hexdigest()[:8]
        temp_plaintext_path = backup_dir / f".staging_snapshot_{temp_entropy}.tmp"

        logger.info(
            "Creating encrypted backup: source=%s, target=%s, key_id=%s",
            source_path,
            target_enc_path,
            key_id,
        )

        try:
            # 2. Online backup into temporary plaintext staging snapshot
            online_result = self.create_online_backup(
                source_db_path=str(source_path),
                target_backup_dir=str(backup_dir),
                backup_filename=temp_plaintext_path.name,
                validate_source=validate_source,
            )

            # 3. Encrypt the verified temporary snapshot
            header = encrypt_backup_file(
                input_sqlite_path=temp_plaintext_path,
                output_enc_path=target_enc_path,
                key=raw_key,
                key_id=key_id,
            )

            # 4. Immediate post-export container verification drill
            self.verify_encrypted_backup_container(target_enc_path, key=raw_key)

            # 5. Compute SHA-256 of encrypted container
            hasher = hashlib.sha256()
            with open(target_enc_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            container_sha256 = hasher.hexdigest()

            result = DatabaseBackupResult(
                success=True,
                backup_path=str(target_enc_path),
                backup_sha256=container_sha256,
                file_size_bytes=target_enc_path.stat().st_size,
                alembic_version=online_result.alembic_version,
                table_counts=online_result.table_counts,
                created_at=datetime.now(timezone.utc),
                wal_pages_included=True,
                integrity_status="VERIFIED",
                is_encrypted=True,
                cipher="AES-256-GCM",
                key_id=key_id,
                plaintext_sha256=header.plaintext_sha256,
            )
            logger.info(
                "Encrypted database backup published successfully: path=%s, size=%d bytes, key_id=%s",
                result.backup_path,
                result.file_size_bytes,
                result.key_id,
            )
            return result

        except Exception as exc:
            logger.error("Failed to create encrypted backup: %s", exc, exc_info=True)
            if target_enc_path.exists():
                try:
                    target_enc_path.unlink()
                except OSError:
                    pass
            raise
        finally:
            # Guarantee zero plaintext residue in backup directory
            for companion in [
                temp_plaintext_path,
                temp_plaintext_path.with_name(f"{temp_plaintext_path.name}-wal"),
                temp_plaintext_path.with_name(f"{temp_plaintext_path.name}-shm"),
                temp_plaintext_path.with_name(f"{temp_plaintext_path.name}.tmp-wal"),
                temp_plaintext_path.with_name(f"{temp_plaintext_path.name}.tmp-shm"),
            ]:
                if companion.exists():
                    try:
                        companion.unlink()
                        logger.debug("Cleaned up temporary plaintext residue: %s", companion)
                    except OSError as cleanup_err:
                        logger.warning("Could not unlink temporary residue %s: %s", companion, cleanup_err)

    def restore_encrypted_backup(
        self,
        backup_path: Path | str,
        target_db_path: Path | str,
        key_path: Optional[str] = None,
        explicit_key: Optional[bytes] = None,
        overwrite: bool = False,
    ) -> DatabaseRestoreResult:
        """Authenticate, decrypt, and restore an encrypted database backup to an isolated target.

        Guarantees:
        - Authenticates container header AAD and ciphertext tag.
        - Fails closed on key mismatch, corrupted header, or ciphertext tampering.
        - Validates decrypted SQLite database with PRAGMA integrity_check, foreign keys, schema, and Alembic head.
        - Writes atomically to staging path before replacing destination.
        - Refuses to overwrite target unless overwrite=True.
        - Cleans up temporary staging file on failure.
        """
        src_path = Path(backup_path).resolve()
        dst_path = Path(target_db_path).resolve()

        if not src_path.exists():
            raise DatabaseRestoreError(f"Backup file not found: {src_path}")

        if dst_path.exists() and not overwrite:
            raise FileExistsError(f"Target database file '{dst_path}' already exists and overwrite=False.")

        # 1. Resolve key
        if explicit_key is not None:
            raw_key = explicit_key
            key_id = f"test-{hashlib.sha256(raw_key).hexdigest()[:8]}"
        else:
            resolved_key_path = key_path or self.settings.BACKUP_KEY_PATH
            key_mgr = BackupKeyManager(resolved_key_path)
            raw_key, key_id = key_mgr.load_or_fail()

        dst_path.parent.mkdir(parents=True, exist_ok=True)
        staging_dst = dst_path.parent / f"{dst_path.name}.restore.tmp"
        if staging_dst.exists():
            staging_dst.unlink()

        logger.info("Initiating encrypted restore: backup=%s -> target=%s", src_path, dst_path)

        try:
            # 2. Authenticate and decrypt to staging file
            try:
                header = decrypt_backup_file(
                    input_enc_path=src_path,
                    output_sqlite_path=staging_dst,
                    key=raw_key,
                    overwrite=True,
                )
            except BackupAuthenticationError as auth_err:
                try:
                    with open(src_path, "rb") as f:
                        hdr = EncryptedContainerHeader.parse_header(f)
                    if hdr.key_id != key_id:
                        raise BackupAuthenticationError(
                            f"Decryption failed: backup container requires key '{hdr.key_id}', "
                            f"but loaded key is '{key_id}'."
                        ) from auth_err
                except BackupAuthenticationError:
                    raise
                except (BackupFormatError, OSError):
                    pass
                raise

            # 3. Validate restored SQLite database
            is_valid, meta, val_err = self.validate_sqlite_database(staging_dst)
            if not is_valid:
                raise DatabaseCorruptionError(f"Restored database failed integrity validation: {val_err}")

            # 4. Atomically commit restored database
            staging_dst.replace(dst_path)

            result = DatabaseRestoreResult(
                success=True,
                restored_db_path=str(dst_path),
                alembic_version=meta.get("alembic_version", "UNKNOWN"),
                table_counts=meta.get("table_counts", {}),
                restored_at=datetime.now(timezone.utc),
                integrity_status="VERIFIED",
                was_encrypted=True,
                cipher="AES-256-GCM",
                key_id=header.key_id,
            )
            logger.info("Encrypted backup restored and verified successfully: path=%s", result.restored_db_path)
            return result

        except Exception as exc:
            logger.error("Encrypted backup restore failed: %s", exc, exc_info=True)
            if staging_dst.exists():
                try:
                    staging_dst.unlink()
                except OSError:
                    pass
            raise

    def create_backup(
        self,
        source_db_path: Optional[str] = None,
        target_backup_dir: Optional[str] = None,
        backup_filename: Optional[str] = None,
        encrypted: Optional[bool] = None,
        validate_source: bool = True,
    ) -> DatabaseBackupResult:
        """Create a backup according to configuration or explicit request."""
        use_encryption = self.settings.BACKUP_ENCRYPTION_ENABLED if encrypted is None else encrypted
        if use_encryption:
            return self.create_encrypted_backup(
                source_db_path=source_db_path,
                target_backup_dir=target_backup_dir,
                backup_filename=backup_filename,
                validate_source=validate_source,
            )
        else:
            return self.create_online_backup(
                source_db_path=source_db_path,
                target_backup_dir=target_backup_dir,
                backup_filename=backup_filename,
                validate_source=validate_source,
            )

    def restore_backup(
        self,
        backup_path: Path | str,
        target_db_path: Path | str,
        overwrite: bool = False,
        validate_backup_first: bool = True,
        key_path: Optional[str] = None,
        explicit_key: Optional[bytes] = None,
    ) -> DatabaseRestoreResult:
        """Restore a verified SQLite database snapshot to a target destination.

        Transparently handles both encrypted containers and raw online backup snapshots.
        """
        src_path = Path(backup_path).resolve()
        dst_path = Path(target_db_path).resolve()

        if not src_path.exists():
            raise DatabaseRestoreError(f"Backup file not found: {src_path}")

        # Check if file is an encrypted container
        if self.is_encrypted_backup(src_path):
            return self.restore_encrypted_backup(
                backup_path=src_path,
                target_db_path=dst_path,
                key_path=key_path,
                explicit_key=explicit_key,
                overwrite=overwrite,
            )

        if dst_path.exists() and not overwrite:
            raise FileExistsError(f"Target database file '{dst_path}' already exists and overwrite=False.")

        dst_path.parent.mkdir(parents=True, exist_ok=True)
        staging_dst = dst_path.parent / f"{dst_path.name}.restore.tmp"
        if staging_dst.exists():
            staging_dst.unlink()

        if validate_backup_first:
            is_valid, _, val_err = self.validate_sqlite_database(src_path)
            if not is_valid:
                raise DatabaseCorruptionError(f"Cannot restore from corrupt backup: {val_err}")

        logger.info("Initiating SQLite restore: backup=%s -> target=%s", src_path, dst_path)

        src_conn: Optional[sqlite3.Connection] = None
        dst_conn: Optional[sqlite3.Connection] = None

        try:
            src_conn = sqlite3.connect(f"file:{src_path.as_posix()}?mode=ro", uri=True)
            dst_conn = sqlite3.connect(str(staging_dst))

            # Restore using online backup API from backup into staging target
            src_conn.backup(dst_conn, pages=250)

            dst_conn.close()
            dst_conn = None
            src_conn.close()
            src_conn = None

            # Validate restored staging file
            is_valid, meta, val_err = self.validate_sqlite_database(staging_dst)
            if not is_valid:
                raise DatabaseCorruptionError(f"Restored database failed integrity validation: {val_err}")

            # Atomically replace destination
            staging_dst.replace(dst_path)

            result = DatabaseRestoreResult(
                success=True,
                restored_db_path=str(dst_path),
                alembic_version=meta.get("alembic_version", "UNKNOWN"),
                table_counts=meta.get("table_counts", {}),
                restored_at=datetime.now(timezone.utc),
                integrity_status="VERIFIED",
                was_encrypted=False,
            )
            logger.info("SQLite restore completed and verified successfully: path=%s", result.restored_db_path)
            return result

        except Exception as exc:
            logger.error("SQLite restore failed: %s", str(exc), exc_info=True)
            if staging_dst.exists():
                try:
                    staging_dst.unlink()
                except OSError:
                    pass
            raise
        finally:
            if dst_conn:
                dst_conn.close()
            if src_conn:
                src_conn.close()
