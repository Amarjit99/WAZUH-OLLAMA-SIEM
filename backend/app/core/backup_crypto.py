"""Cryptographic utilities for authenticated AES-256-GCM backup encryption and DPAPI key management.

Conforms strictly to Phase 8.0 Workstream A requirements:
- FIPS-validated authenticated encryption using native Windows CNG (bcrypt.dll)
- AES-256-GCM with 96-bit unique nonce per operation and 128-bit authentication tag
- Authenticates header metadata as Associated Authenticated Data (AAD)
- Protected Data Encryption Key (DEK) storage via Windows DPAPI (crypt32.dll)
- Refuses to regenerate missing or inaccessible keys to prevent stranding existing backups
- Zero third-party C-extension dependencies required
"""

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import struct
import sys
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("siem.backup_crypto")

# Container header constants
CONTAINER_MAGIC = b"SIEM_ENC"  # 8 bytes
CONTAINER_VERSION = 1          # uint16
CIPHER_AES_256_GCM = 1         # uint16
NONCE_LENGTH_BYTES = 12        # 96 bits for GCM
TAG_LENGTH_BYTES = 16          # 128 bits authentication tag
KEY_LENGTH_BYTES = 32          # 256 bits
MAX_KEY_ID_LENGTH_BYTES = 256  # Maximum key ID length in bytes
MAX_BACKUP_PLAINTEXT_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB maximum safety bound

# Disaster recovery constants (Phase 8.1)
RECOVERY_MAGIC = b"SIEM_REC"   # 8 bytes
RECOVERY_VERSION = 1           # uint16
RECOVERY_PBKDF2_ITERATIONS = 600_000  # OWASP / NIST SP 800-132 recommendation for SHA-256

# NTSTATUS codes
STATUS_SUCCESS = 0x00000000
STATUS_AUTH_TAG_MISMATCH = 0xC000A002


class BackupCryptoError(Exception):
    """Base exception for backup cryptographic operations."""
    pass


class BackupKeyUnavailableError(BackupCryptoError):
    """Raised when an encryption key is missing, inaccessible, or DPAPI unprotect fails."""
    pass


class BackupAuthenticationError(BackupCryptoError):
    """Raised when authentication tag mismatch or container tampering is detected."""
    pass


class BackupFormatError(BackupCryptoError):
    """Raised when backup container header is invalid, corrupted, or unsupported."""
    pass


# ---------------------------------------------------------------------------
# Windows CNG Structures and Wrappers
# ---------------------------------------------------------------------------

class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwInfoVersion", wintypes.ULONG),
        ("pbNonce", ctypes.c_void_p),
        ("cbNonce", wintypes.ULONG),
        ("pbAuthData", ctypes.c_void_p),
        ("cbAuthData", wintypes.ULONG),
        ("pbTag", ctypes.c_void_p),
        ("cbTag", wintypes.ULONG),
        ("pbMacContext", ctypes.c_void_p),
        ("cbMacContext", wintypes.ULONG),
        ("cbAAD", wintypes.ULONG),
        ("cbData", ctypes.c_ulonglong),
        ("dwFlags", wintypes.ULONG),
    ]


class WindowsCNGAESGCM:
    """Hardware-accelerated AES-256-GCM using native Windows BCrypt CNG primitives."""

    def __init__(self):
        if sys.platform != "win32":
            raise BackupCryptoError("Windows CNG AES-GCM is only available on Windows platforms.")
        self.bcrypt = ctypes.windll.bcrypt

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        associated_data: bytes = b"",
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt plaintext using AES-256-GCM.

        Returns: (nonce, ciphertext, tag)
        """
        if len(key) != KEY_LENGTH_BYTES:
            raise ValueError(f"AES-256 requires a 32-byte key; got {len(key)} bytes.")

        use_nonce = nonce if nonce is not None else os.urandom(NONCE_LENGTH_BYTES)
        if len(use_nonce) != NONCE_LENGTH_BYTES:
            raise ValueError(f"GCM requires a 12-byte nonce; got {len(use_nonce)} bytes.")

        h_alg = wintypes.HANDLE()
        h_key = wintypes.HANDLE()

        # Open AES algorithm provider
        status = self.bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(h_alg), ctypes.c_wchar_p("AES"), None, 0
        )
        if status != STATUS_SUCCESS:
            raise BackupCryptoError(f"BCryptOpenAlgorithmProvider failed with status {status:#x}")

        try:
            # Set chaining mode to GCM
            chain_mode = "ChainingModeGCM\0".encode("utf-16le")
            status = self.bcrypt.BCryptSetProperty(
                h_alg, ctypes.c_wchar_p("ChainingMode"), chain_mode, len(chain_mode), 0
            )
            if status != STATUS_SUCCESS:
                raise BackupCryptoError(f"BCryptSetProperty(ChainingModeGCM) failed with status {status:#x}")

            # Generate symmetric key object
            status = self.bcrypt.BCryptGenerateSymmetricKey(
                h_alg, ctypes.byref(h_key), None, 0, key, len(key), 0
            )
            if status != STATUS_SUCCESS:
                raise BackupCryptoError(f"BCryptGenerateSymmetricKey failed with status {status:#x}")

            # Setup authenticated cipher mode info
            tag_buf = ctypes.create_string_buffer(TAG_LENGTH_BYTES)
            ciphertext_buf = ctypes.create_string_buffer(len(plaintext))
            cb_result = wintypes.ULONG()

            auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            auth_info.cbSize = ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            auth_info.dwInfoVersion = 1
            auth_info.pbNonce = ctypes.cast(use_nonce, ctypes.c_void_p)
            auth_info.cbNonce = len(use_nonce)
            auth_info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
            auth_info.cbTag = TAG_LENGTH_BYTES

            if associated_data:
                auth_info.pbAuthData = ctypes.cast(associated_data, ctypes.c_void_p)
                auth_info.cbAuthData = len(associated_data)

            status = self.bcrypt.BCryptEncrypt(
                h_key,
                plaintext,
                len(plaintext),
                ctypes.byref(auth_info),
                None,
                0,
                ciphertext_buf,
                len(plaintext),
                ctypes.byref(cb_result),
                0,
            )
            if status != STATUS_SUCCESS:
                raise BackupCryptoError(f"BCryptEncrypt failed with status {status:#x}")

            return use_nonce, ciphertext_buf.raw, tag_buf.raw

        finally:
            if h_key:
                self.bcrypt.BCryptDestroyKey(h_key)
            if h_alg:
                self.bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt and authenticate ciphertext using AES-256-GCM.

        Raises BackupAuthenticationError if tag or associated data does not match.
        """
        if len(key) != KEY_LENGTH_BYTES:
            raise ValueError(f"AES-256 requires a 32-byte key; got {len(key)} bytes.")
        if len(nonce) != NONCE_LENGTH_BYTES:
            raise ValueError(f"GCM requires a 12-byte nonce; got {len(nonce)} bytes.")
        if len(tag) != TAG_LENGTH_BYTES:
            raise ValueError(f"GCM requires a 16-byte tag; got {len(tag)} bytes.")

        h_alg = wintypes.HANDLE()
        h_key = wintypes.HANDLE()

        status = self.bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(h_alg), ctypes.c_wchar_p("AES"), None, 0
        )
        if status != STATUS_SUCCESS:
            raise BackupCryptoError(f"BCryptOpenAlgorithmProvider failed with status {status:#x}")

        try:
            chain_mode = "ChainingModeGCM\0".encode("utf-16le")
            status = self.bcrypt.BCryptSetProperty(
                h_alg, ctypes.c_wchar_p("ChainingMode"), chain_mode, len(chain_mode), 0
            )
            if status != STATUS_SUCCESS:
                raise BackupCryptoError(f"BCryptSetProperty(ChainingModeGCM) failed with status {status:#x}")

            status = self.bcrypt.BCryptGenerateSymmetricKey(
                h_alg, ctypes.byref(h_key), None, 0, key, len(key), 0
            )
            if status != STATUS_SUCCESS:
                raise BackupCryptoError(f"BCryptGenerateSymmetricKey failed with status {status:#x}")

            decrypted_buf = ctypes.create_string_buffer(len(ciphertext))
            cb_result = wintypes.ULONG()

            auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            auth_info.cbSize = ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            auth_info.dwInfoVersion = 1
            auth_info.pbNonce = ctypes.cast(nonce, ctypes.c_void_p)
            auth_info.cbNonce = len(nonce)
            auth_info.pbTag = ctypes.cast(tag, ctypes.c_void_p)
            auth_info.cbTag = len(tag)

            if associated_data:
                auth_info.pbAuthData = ctypes.cast(associated_data, ctypes.c_void_p)
                auth_info.cbAuthData = len(associated_data)

            status = self.bcrypt.BCryptDecrypt(
                h_key,
                ciphertext,
                len(ciphertext),
                ctypes.byref(auth_info),
                None,
                0,
                decrypted_buf,
                len(ciphertext),
                ctypes.byref(cb_result),
                0,
            )
            # Check for authentication tag mismatch
            if status == ctypes.c_long(STATUS_AUTH_TAG_MISMATCH).value or status == STATUS_AUTH_TAG_MISMATCH:
                raise BackupAuthenticationError(
                    "Decryption failed: cryptographic authentication tag mismatch (tampering detected)."
                )
            if status != STATUS_SUCCESS:
                raise BackupCryptoError(f"BCryptDecrypt failed with status {status:#x}")

            return decrypted_buf.raw

        finally:
            if h_key:
                self.bcrypt.BCryptDestroyKey(h_key)
            if h_alg:
                self.bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


# ---------------------------------------------------------------------------
# Encrypted Container Structure & Serialization
# ---------------------------------------------------------------------------

@dataclass
class EncryptedContainerHeader:
    """Authenticated header for versioned SIEM encrypted backup container."""
    version: int
    cipher_id: int
    key_id: str
    created_at_epoch: int
    nonce: bytes
    tag: bytes
    plaintext_size: int
    plaintext_sha256: str  # 64 hex characters

    def serialize_aad(self) -> bytes:
        """Serialize header elements that form the Authenticated Associated Data (AAD).

        Excludes the tag itself to avoid circular dependency.
        Format:
        [MAGIC (8B)][VER (2B)][CIPHER (2B)][KEY_ID_LEN (2B)][KEY_ID][EPOCH (8B)][NONCE (12B)][SIZE (8B)][PLAIN_SHA256 (32B)]
        """
        key_id_bytes = self.key_id.encode("utf-8")
        plain_hash_bytes = bytes.fromhex(self.plaintext_sha256)

        header_prefix = struct.pack(
            ">8sHHH",
            CONTAINER_MAGIC,
            self.version,
            self.cipher_id,
            len(key_id_bytes),
        )
        header_body = struct.pack(
            f">{len(key_id_bytes)}sQ12sQ32s",
            key_id_bytes,
            self.created_at_epoch,
            self.nonce,
            self.plaintext_size,
            plain_hash_bytes,
        )
        return header_prefix + header_body

    def serialize_full_header(self) -> bytes:
        """Serialize complete header including authentication tag.

        Full header = AAD + [TAG (16B)]
        """
        aad = self.serialize_aad()
        return aad + self.tag

    @classmethod
    def parse_header(cls, stream) -> "EncryptedContainerHeader":
        """Parse and validate header from a binary stream."""
        prefix = stream.read(14)
        if len(prefix) < 14:
            raise BackupFormatError("Incomplete backup container header: unexpected EOF.")

        magic, version, cipher_id, key_id_len = struct.unpack(">8sHHH", prefix)
        if magic != CONTAINER_MAGIC:
            raise BackupFormatError(f"Invalid magic bytes '{magic}'; expected {CONTAINER_MAGIC}.")
        if version != CONTAINER_VERSION:
            raise BackupFormatError(f"Unsupported backup container version {version}; expected {CONTAINER_VERSION}.")
        if cipher_id != CIPHER_AES_256_GCM:
            raise BackupFormatError(f"Unsupported cipher ID {cipher_id}; expected {CIPHER_AES_256_GCM} (AES-256-GCM).")
        if key_id_len == 0 or key_id_len > MAX_KEY_ID_LENGTH_BYTES:
            raise BackupFormatError(
                f"Invalid key ID length {key_id_len}; must be between 1 and {MAX_KEY_ID_LENGTH_BYTES} bytes."
            )

        key_id_bytes = stream.read(key_id_len)
        if len(key_id_bytes) < key_id_len:
            raise BackupFormatError("Incomplete key ID in container header: unexpected EOF.")
        try:
            key_id = key_id_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BackupFormatError("Key ID in header is not valid UTF-8.") from exc

        fixed_rem = stream.read(8 + 12 + 8 + 32 + 16)
        if len(fixed_rem) < (8 + 12 + 8 + 32 + 16):
            raise BackupFormatError("Incomplete header metadata in container: unexpected EOF.")

        epoch, nonce, plain_size, plain_hash_bytes, tag = struct.unpack(">Q12sQ32s16s", fixed_rem)

        if plain_size > MAX_BACKUP_PLAINTEXT_BYTES:
            raise BackupFormatError(
                f"Plaintext size {plain_size} exceeds maximum allowable safety limit ({MAX_BACKUP_PLAINTEXT_BYTES} bytes)."
            )

        return cls(
            version=version,
            cipher_id=cipher_id,
            key_id=key_id,
            created_at_epoch=epoch,
            nonce=nonce,
            tag=tag,
            plaintext_size=plain_size,
            plaintext_sha256=plain_hash_bytes.hex(),
        )


# ---------------------------------------------------------------------------
# Windows DPAPI Backup Key Manager
# ---------------------------------------------------------------------------

class BackupKeyManager:
    """Manages secure generation, DPAPI protection, and retrieval of the backup Data Encryption Key (DEK)."""

    def __init__(self, key_file_path: Optional[str] = None):
        self.key_file_path = Path(key_file_path or "data/keys/backup_encryption_key.dpapi").resolve()
        self.entropy = b"SIEM_BACKUP_DEK_v1_ENTROPY"

    def get_key_status(self) -> Dict[str, Any]:
        """Return safe key metadata without revealing secret key bytes."""
        exists = self.key_file_path.exists()
        can_decrypt = False
        if exists:
            try:
                self.load_or_fail()
                can_decrypt = True
            except Exception:
                can_decrypt = False

        return {
            "key_file_path": str(self.key_file_path.name),
            "key_file_exists": exists,
            "dpapi_available": sys.platform == "win32",
            "key_usable": can_decrypt,
            "recovery_strategy": (
                "Windows DPAPI User Profile / Local Security Authority key protection. "
                "Disaster recovery requires restoring host machine DPAPI credentials or offline recovery token."
            ),
        }

    def load_or_fail(self) -> Tuple[bytes, str]:
        """Load and unprotect the existing DPAPI key blob.

        Strictly fails closed: never regenerates a missing or unreadable key.
        """
        from app.core.audit_crypto import dpapi_unprotect

        if not self.key_file_path.exists():
            raise BackupKeyUnavailableError(
                f"Backup encryption key file not found at '{self.key_file_path}'. "
                "Automatic regeneration is strictly prohibited to prevent stranding existing backups."
            )

        try:
            protected_blob = self.key_file_path.read_bytes()
            raw_key = dpapi_unprotect(protected_blob, entropy=self.entropy)
            if len(raw_key) != KEY_LENGTH_BYTES:
                raise BackupKeyUnavailableError(
                    f"Decrypted backup key has invalid length {len(raw_key)} bytes; expected {KEY_LENGTH_BYTES}."
                )
            key_id = f"dpapi-{hashlib.sha256(raw_key).hexdigest()[:8]}"
            return raw_key, key_id
        except Exception as exc:
            raise BackupKeyUnavailableError(
                f"Failed to unprotect backup key at '{self.key_file_path}' via Windows DPAPI: {exc}. "
                "Ensure application is running under the authorized Windows user account."
            ) from exc

    def initialize_new_key_if_absent(self) -> Tuple[bytes, str]:
        """Generate a new 256-bit DEK protected via DPAPI only if no key currently exists.

        Uses file locking to guarantee race-free initialization under concurrent execution.
        """
        from app.core.audit_crypto import dpapi_protect

        if self.key_file_path.exists():
            return self.load_or_fail()

        self.key_file_path.parent.mkdir(parents=True, exist_ok=True)
        init_lock_path = self.key_file_path.with_suffix(".init.lock")

        # Acquire lock to synchronize initialization across threads / processes
        if sys.platform == "win32":
            import msvcrt
            lock_file = open(init_lock_path, "a+b")
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                # Re-check existence inside lock
                if self.key_file_path.exists():
                    return self.load_or_fail()

                raw_key = os.urandom(KEY_LENGTH_BYTES)
                protected_blob = dpapi_protect(raw_key, entropy=self.entropy)

                staging_key_path = self.key_file_path.with_suffix(
                    f".tmp_{os.getpid()}_{os.urandom(4).hex()}"
                )
                try:
                    staging_key_path.write_bytes(protected_blob)
                    staging_key_path.replace(self.key_file_path)
                finally:
                    if staging_key_path.exists():
                        try:
                            staging_key_path.unlink()
                        except OSError:
                            pass

                key_id = f"dpapi-{hashlib.sha256(raw_key).hexdigest()[:8]}"
                logger.info("Initialized new DPAPI-protected backup encryption key: id=%s at %s", key_id, self.key_file_path)
                return raw_key, key_id
            finally:
                try:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
                lock_file.close()
        else:
            if self.key_file_path.exists():
                return self.load_or_fail()
            raw_key = os.urandom(KEY_LENGTH_BYTES)
            protected_blob = dpapi_protect(raw_key, entropy=self.entropy)
            staging_key_path = self.key_file_path.with_suffix(f".tmp_{os.getpid()}_{os.urandom(4).hex()}")
            staging_key_path.write_bytes(protected_blob)
            staging_key_path.replace(self.key_file_path)
            key_id = f"dpapi-{hashlib.sha256(raw_key).hexdigest()[:8]}"
            return raw_key, key_id

    def export_disaster_recovery_key(
        self,
        passphrase: str,
        output_recovery_path: Path | str,
    ) -> str:
        """Export the active Data Encryption Key protected with a strong passphrase for cross-machine recovery.

        Conforms strictly to Phase 8.1 Disaster Recovery requirements:
        - Requires a passphrase with minimum 16 characters.
        - Derives a 256-bit Key Encryption Key (KEK) using PBKDF2-HMAC-SHA256 with 600,000 iterations.
        - Encrypts raw DEK using AES-256-GCM with a unique 96-bit nonce and authenticated header.
        - Commits atomically using temporary file staging.
        - Never exposes or logs raw key material.
        """
        if not passphrase or len(passphrase.strip()) < 16:
            raise ValueError("Disaster recovery passphrase must be at least 16 characters long.")

        out_path = Path(output_recovery_path).resolve()
        if out_path.exists():
            raise FileExistsError(f"Recovery key destination '{out_path}' already exists; refuse to overwrite.")

        raw_key, key_id = self.load_or_fail()

        salt = os.urandom(16)
        kek = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.strip().encode("utf-8"),
            salt,
            iterations=RECOVERY_PBKDF2_ITERATIONS,
            dklen=KEY_LENGTH_BYTES,
        )

        cng = WindowsCNGAESGCM()
        nonce = os.urandom(NONCE_LENGTH_BYTES)
        aad = b"SIEM_BACKUP_RECOVERY_KEY_v1"
        _, encrypted_key, tag = cng.encrypt(key=kek, plaintext=raw_key, associated_data=aad, nonce=nonce)

        key_id_bytes = key_id.encode("utf-8")
        header = struct.pack(
            f">8sHI16s12s16sH{len(key_id_bytes)}s",
            RECOVERY_MAGIC,
            RECOVERY_VERSION,
            RECOVERY_PBKDF2_ITERATIONS,
            salt,
            nonce,
            tag,
            len(key_id_bytes),
            key_id_bytes,
        )

        out_path.parent.mkdir(parents=True, exist_ok=True)
        staging_path = out_path.with_suffix(f".staging_{os.urandom(4).hex()}")
        try:
            with open(staging_path, "wb") as f:
                f.write(header)
                f.write(encrypted_key)
            staging_path.replace(out_path)
            logger.info("Exported disaster recovery key for key_id=%s to %s", key_id, out_path)
            return key_id
        finally:
            if staging_path.exists():
                try:
                    staging_path.unlink()
                except OSError:
                    pass

    def import_disaster_recovery_key(
        self,
        recovery_path: Path | str,
        passphrase: str,
        target_dpapi_path: Optional[Path | str] = None,
    ) -> Tuple[bytes, str]:
        """Import a disaster recovery key on a new or recovered host machine and protect it via local DPAPI.

        Guarantees:
        - Validates container magic, version, and PBKDF2 iterations.
        - Authenticates KEK and decrypted DEK via AES-256-GCM tag.
        - Fails closed on wrong passphrase or file tampering.
        - Protects the recovered DEK immediately under local host DPAPI.
        - Atomic publication to destination DPAPI key path.
        """
        from app.core.audit_crypto import dpapi_protect

        in_path = Path(recovery_path).resolve()
        if not in_path.exists():
            raise BackupKeyUnavailableError(f"Disaster recovery key file not found: {in_path}")

        dst_path = Path(target_dpapi_path or self.key_file_path).resolve()
        if dst_path.exists():
            raise FileExistsError(f"Target DPAPI key file '{dst_path}' already exists; refuse to overwrite.")

        with open(in_path, "rb") as f:
            fixed_header = f.read(8 + 2 + 4 + 16 + 12 + 16 + 2)
            if len(fixed_header) < 60:
                raise BackupFormatError("Incomplete disaster recovery key header.")

            magic, version, iterations, salt, nonce, tag, key_id_len = struct.unpack(
                ">8sHI16s12s16sH", fixed_header
            )
            if magic != RECOVERY_MAGIC:
                raise BackupFormatError(f"Invalid recovery key magic '{magic}'; expected {RECOVERY_MAGIC}.")
            if version != RECOVERY_VERSION:
                raise BackupFormatError(f"Unsupported recovery key version {version}.")

            key_id_bytes = f.read(key_id_len)
            if len(key_id_bytes) < key_id_len:
                raise BackupFormatError("Incomplete key ID in recovery file.")
            key_id = key_id_bytes.decode("utf-8", errors="replace")

            encrypted_key = f.read()

        if len(encrypted_key) != KEY_LENGTH_BYTES:
            raise BackupFormatError(f"Invalid recovery payload size {len(encrypted_key)}; expected {KEY_LENGTH_BYTES}.")

        kek = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.strip().encode("utf-8"),
            salt,
            iterations=iterations,
            dklen=KEY_LENGTH_BYTES,
        )

        cng = WindowsCNGAESGCM()
        aad = b"SIEM_BACKUP_RECOVERY_KEY_v1"
        try:
            raw_key = cng.decrypt(
                key=kek,
                nonce=nonce,
                ciphertext=encrypted_key,
                tag=tag,
                associated_data=aad,
            )
        except BackupAuthenticationError as auth_err:
            raise BackupAuthenticationError(
                "Disaster recovery key decryption failed: invalid passphrase or corrupted recovery file."
            ) from auth_err

        # Protect with local host DPAPI
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        protected_blob = dpapi_protect(raw_key, entropy=self.entropy)

        staging_path = dst_path.with_suffix(f".tmp_{os.getpid()}_{os.urandom(4).hex()}")
        try:
            staging_path.write_bytes(protected_blob)
            staging_path.replace(dst_path)
            logger.info("Successfully imported disaster recovery key id=%s into local DPAPI at %s", key_id, dst_path)
            return raw_key, key_id
        finally:
            if staging_path.exists():
                try:
                    staging_path.unlink()
                except OSError:
                    pass


def encrypt_backup_file(
    input_sqlite_path: Path,
    output_enc_path: Path,
    key: bytes,
    key_id: str,
) -> EncryptedContainerHeader:
    """Encrypt a verified SQLite backup snapshot using AES-256-GCM into an authenticated container file.

    Guarantees:
    - Verifies input file exists.
    - Computes plaintext SHA-256 and size.
    - Generates unique 96-bit nonce.
    - Authenticates container header as Associated Authenticated Data (AAD).
    - Writes to temporary staging file (.enc.staging) before atomically renaming to target.
    - Refuses to overwrite existing files.
    - Cleans up staging file on any failure.
    """
    input_path = Path(input_sqlite_path).resolve()
    target_path = Path(output_enc_path).resolve()

    if not input_path.exists():
        raise BackupCryptoError(f"Input database file not found: {input_path}")

    if target_path.exists():
        raise FileExistsError(f"Encrypted backup target file '{target_path}' already exists; overwriting is strictly prohibited.")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path = target_path.parent / f"{target_path.name}.enc.staging"
    if staging_path.exists():
        staging_path.unlink()

    try:
        plaintext = input_path.read_bytes()
        plain_size = len(plaintext)
        plain_sha256 = hashlib.sha256(plaintext).hexdigest()

        nonce = os.urandom(NONCE_LENGTH_BYTES)
        epoch = int(datetime.now(timezone.utc).timestamp())

        header = EncryptedContainerHeader(
            version=CONTAINER_VERSION,
            cipher_id=CIPHER_AES_256_GCM,
            key_id=key_id,
            created_at_epoch=epoch,
            nonce=nonce,
            tag=b"\x00" * TAG_LENGTH_BYTES,
            plaintext_size=plain_size,
            plaintext_sha256=plain_sha256,
        )

        aad = header.serialize_aad()
        cng = WindowsCNGAESGCM()
        _, ciphertext, tag = cng.encrypt(key=key, plaintext=plaintext, associated_data=aad, nonce=nonce)
        header.tag = tag

        full_header = header.serialize_full_header()

        with open(staging_path, "wb") as f:
            f.write(full_header)
            f.write(ciphertext)

        staging_path.replace(target_path)
        logger.info(
            "Encrypted backup created: path=%s, size=%d bytes, key_id=%s",
            target_path,
            target_path.stat().st_size,
            key_id,
        )
        return header

    except Exception as exc:
        logger.error("Failed to encrypt backup file %s: %s", input_path, exc, exc_info=True)
        if staging_path.exists():
            try:
                staging_path.unlink()
            except OSError:
                pass
        raise


def decrypt_backup_file(
    input_enc_path: Path,
    output_sqlite_path: Path,
    key: bytes,
    overwrite: bool = False,
) -> EncryptedContainerHeader:
    """Authenticate and decrypt an encrypted backup container into a SQLite database file.

    Guarantees:
    - Parses and verifies container header format and version.
    - Validates authenticated tag against header AAD and ciphertext.
    - Verifies plaintext size and SHA-256 integrity check.
    - Writes decrypted plaintext to temporary staging file before atomically renaming to target.
    - Refuses to overwrite existing files unless overwrite=True.
    - Cleans up staging file on failure.
    """
    input_path = Path(input_enc_path).resolve()
    target_path = Path(output_sqlite_path).resolve()

    if not input_path.exists():
        raise BackupCryptoError(f"Encrypted backup container not found: {input_path}")

    if target_path.exists() and not overwrite:
        raise FileExistsError(f"Restored target database file '{target_path}' already exists and overwrite=False.")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path = target_path.parent / f"{target_path.name}.restore.staging"
    if staging_path.exists():
        staging_path.unlink()

    try:
        with open(input_path, "rb") as f:
            header = EncryptedContainerHeader.parse_header(f)
            ciphertext = f.read()

        if len(ciphertext) != header.plaintext_size:
            raise BackupFormatError(
                f"Ciphertext length mismatch: container has {len(ciphertext)} bytes, "
                f"expected {header.plaintext_size} bytes (file may be truncated or appended with trailing data)."
            )

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
                f"Decrypted size mismatch: expected {header.plaintext_size} bytes, got {len(plaintext)} bytes."
            )

        calc_sha256 = hashlib.sha256(plaintext).hexdigest()
        if calc_sha256 != header.plaintext_sha256:
            raise BackupAuthenticationError(
                f"Decrypted SHA-256 digest mismatch: expected {header.plaintext_sha256}, got {calc_sha256}."
            )

        staging_path.write_bytes(plaintext)
        staging_path.replace(target_path)
        logger.info(
            "Encrypted backup successfully restored and verified: source=%s -> target=%s",
            input_path,
            target_path,
        )
        return header

    except Exception as exc:
        logger.error("Failed to decrypt backup container %s: %s", input_path, exc, exc_info=True)
        if staging_path.exists():
            try:
                staging_path.unlink()
            except OSError:
                pass
        raise
