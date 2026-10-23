"""Cryptographic utilities for audit hash chains, checkpoints, and DPAPI key protection.

Conforms strictly to specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md and approved ADR-013.
"""

import base64
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
GENESIS_CHECKPOINT_HASH = "0" * 64


def format_canonical_timestamp(ts: datetime) -> str:
    """Format timestamp as deterministic canonical ISO 8601 UTC string with fixed microsecond precision."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_canonical_event_hash(
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


def compute_checkpoint_digest(
    checkpoint_id: str,
    checkpoint_sequence: int,
    created_at_iso: str,
    interval_start_iso: str,
    interval_end_iso: str,
    first_included_audit_id: str,
    last_included_audit_id: str,
    last_included_event_hash: str,
    event_count: int,
    pruned_events_digest: str,
    previous_checkpoint_id: Optional[str],
    previous_checkpoint_hash: str,
    schema_version: str = "v1",
) -> str:
    """Compute deterministic SHA-256 checkpoint digest over canonical JSON header."""
    payload = {
        "checkpoint_id": checkpoint_id,
        "checkpoint_sequence": checkpoint_sequence,
        "created_at": created_at_iso,
        "event_count": event_count,
        "first_included_audit_id": first_included_audit_id,
        "interval_end_timestamp": interval_end_iso,
        "interval_start_timestamp": interval_start_iso,
        "last_included_audit_id": last_included_audit_id,
        "last_included_event_hash": last_included_event_hash,
        "previous_checkpoint_hash": previous_checkpoint_hash,
        "previous_checkpoint_id": previous_checkpoint_id,
        "pruned_events_digest": pruned_events_digest,
        "schema_version": schema_version,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_rolling_events_digest(event_hashes: List[str]) -> str:
    """Compute rolling SHA-256 digest across a sequential list of event hashes."""
    if not event_hashes:
        return GENESIS_HASH

    current = hashlib.sha256(event_hashes[0].encode("utf-8")).digest()
    for eh in event_hashes[1:]:
        current = hashlib.sha256(current + eh.encode("utf-8")).digest()
    return current.hex()


# ---------------------------------------------------------------------------
# Windows DPAPI Implementation (Native ctypes - Zero external dependencies)
# ---------------------------------------------------------------------------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def is_dpapi_available() -> bool:
    """Return True if Windows DPAPI (crypt32.dll) is available in current runtime."""
    return sys.platform == "win32"


def dpapi_protect(plaintext: bytes, entropy: Optional[bytes] = None) -> bytes:
    """Encrypt raw bytes using Windows Data Protection API (DPAPI)."""
    if not is_dpapi_available():
        raise RuntimeError("Windows DPAPI is only supported on Windows platforms.")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB()
    in_blob.cbData = len(plaintext)
    in_blob.pbData = ctypes.cast(
        ctypes.create_string_buffer(plaintext, len(plaintext)),
        ctypes.POINTER(ctypes.c_byte),
    )

    entropy_blob_ptr = None
    if entropy:
        entropy_blob = DATA_BLOB()
        entropy_blob.cbData = len(entropy)
        entropy_blob.pbData = ctypes.cast(
            ctypes.create_string_buffer(entropy, len(entropy)),
            ctypes.POINTER(ctypes.c_byte),
        )
        entropy_blob_ptr = ctypes.byref(entropy_blob)

    out_blob = DATA_BLOB()

    # CRYPTPROTECT_UI_FORBIDDEN = 0x01
    flags = 0x01
    res = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "audit_signing_key",
        entropy_blob_ptr,
        None,
        None,
        flags,
        ctypes.byref(out_blob),
    )
    if not res:
        err = kernel32.GetLastError()
        raise OSError(f"CryptProtectData failed with error code: {err}")

    try:
        raw_out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return raw_out
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect(ciphertext: bytes, entropy: Optional[bytes] = None) -> bytes:
    """Decrypt raw bytes using Windows Data Protection API (DPAPI)."""
    if not is_dpapi_available():
        raise RuntimeError("Windows DPAPI is only supported on Windows platforms.")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB()
    in_blob.cbData = len(ciphertext)
    in_blob.pbData = ctypes.cast(
        ctypes.create_string_buffer(ciphertext, len(ciphertext)),
        ctypes.POINTER(ctypes.c_byte),
    )

    entropy_blob_ptr = None
    if entropy:
        entropy_blob = DATA_BLOB()
        entropy_blob.cbData = len(entropy)
        entropy_blob.pbData = ctypes.cast(
            ctypes.create_string_buffer(entropy, len(entropy)),
            ctypes.POINTER(ctypes.c_byte),
        )
        entropy_blob_ptr = ctypes.byref(entropy_blob)

    out_blob = DATA_BLOB()

    # CRYPTPROTECT_UI_FORBIDDEN = 0x01
    flags = 0x01
    res = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        entropy_blob_ptr,
        None,
        None,
        flags,
        ctypes.byref(out_blob),
    )
    if not res:
        err = kernel32.GetLastError()
        raise OSError(f"CryptUnprotectData failed with error code: {err}")

    try:
        raw_out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return raw_out
    finally:
        kernel32.LocalFree(out_blob.pbData)


def sign_digest_hmac(digest: str, secret: bytes) -> str:
    """Compute Base64-encoded HMAC-SHA256 signature over digest hex string."""
    mac = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(mac).decode("utf-8")


def verify_digest_hmac(digest: str, signature_b64: str, secret: bytes) -> bool:
    """Verify Base64-encoded HMAC-SHA256 signature using constant-time comparison."""
    try:
        expected = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).digest()
        provided = base64.b64decode(signature_b64.encode("utf-8"))
        return hmac.compare_digest(expected, provided)
    except Exception:
        return False
