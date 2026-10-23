# Specification: Audit Checkpoint Protocol & Schema (v1)
## Cryptographic Anchoring for Retained Suffix & Verifiable Archival

**Document ID:** `specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md`  
**Status:** PROPOSED PROTOCOL SPECIFICATION (Implementation Authorization Withheld)  
**Version:** 1.0.0-draft  
**Target Platform:** Python 3.11+, SQLite 3.40+, SQLAlchemy 2.0  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Date:** October 20, 2026  

---

## 1. Protocol Purpose and Scope

This document specifies the exact data schema, serialization rules, state transitions, and verification algorithms for **Audit Retention Checkpoints**.

The checkpoint protocol solves the hash-chain truncation problem:
- It creates an immutable cryptographic summary over an expired, contiguous block of audit events $[e_{\text{first}}, \dots, e_{\text{last}}]$.
- It links checkpoints into an append-only **Checkpoint Meta-Chain**.
- It provides a verifiable anchor ($h_{\text{last}}$) for the surviving active audit events $[e_{\text{last}+1}, \dots, e_N]$ stored in `audit_events`.
- It enables independent verification of both the live SQLite table and offline archive files.

---

## 2. Checkpoint Schema Definition

### 2.1 Proposed Database Schema (`audit_checkpoints` Table)

```sql
CREATE TABLE audit_checkpoints (
    checkpoint_id               VARCHAR(36)  NOT NULL PRIMARY KEY,
    schema_version              VARCHAR(16)  NOT NULL DEFAULT 'v1',
    checkpoint_sequence         INTEGER      NOT NULL UNIQUE,
    created_at                  TIMESTAMP    NOT NULL,
    interval_start_timestamp    TIMESTAMP    NOT NULL,
    interval_end_timestamp      TIMESTAMP    NOT NULL,
    first_included_audit_id     VARCHAR(36)  NOT NULL,
    last_included_audit_id      VARCHAR(36)  NOT NULL,
    last_included_event_hash    VARCHAR(64)  NOT NULL,
    event_count                 INTEGER      NOT NULL,
    pruned_events_digest        VARCHAR(64)  NOT NULL,
    previous_checkpoint_id      VARCHAR(36)  NULL,
    previous_checkpoint_hash    VARCHAR(64)  NOT NULL,
    checkpoint_digest           VARCHAR(64)  NOT NULL,
    signature_algorithm         VARCHAR(32)  NOT NULL DEFAULT 'NONE',
    signature_value             TEXT         NULL,
    signing_key_id              VARCHAR(64)  NULL,
    archive_file_path           VARCHAR(255) NULL,
    archive_sha256              VARCHAR(64)  NULL,
    status                      VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE'
);

CREATE INDEX idx_checkpoints_seq ON audit_checkpoints (checkpoint_sequence ASC);
CREATE INDEX idx_checkpoints_hash ON audit_checkpoints (checkpoint_digest);
CREATE INDEX idx_checkpoints_last_event ON audit_checkpoints (last_included_event_hash);
```

---

### 2.2 Field Classification & Data Dictionary

| Field | Type | Classification | Description & Validation Rules |
|---|---|---|---|
| `checkpoint_id` | UUID4 (36 chars) | **Required** | Globally unique identifier generated via RFC 4122. |
| `schema_version` | String (16 chars) | **Required** | Constant string `'v1'`. Enforces forward-compatible deserialization. |
| `checkpoint_sequence` | Integer | **Required** | Monotonically increasing sequence number ($1, 2, 3, \dots$). Checkpoint 1 represents the initial prune from `GENESIS_HASH`. |
| `created_at` | ISO 8601 UTC | **Required** | Timestamp when the checkpoint was generated, formatted to microsecond precision. |
| `interval_start_timestamp` | ISO 8601 UTC | **Required** | Timestamp of the earliest event included in this checkpoint block ($e_{\text{first}}.\text{timestamp}$). |
| `interval_end_timestamp` | ISO 8601 UTC | **Required** | Timestamp of the latest event included in this checkpoint block ($e_{\text{last}}.\text{timestamp}$). Must be $\le \text{interval\_start\_timestamp}$. |
| `first_included_audit_id` | UUID4 (36 chars) | **Required** | Primary key of the first audit event in the pruned block. |
| `last_included_audit_id` | UUID4 (36 chars) | **Required** | Primary key of the last audit event in the pruned block. |
| `last_included_event_hash` | Hex String (64 chars) | **Required** | The exact `event_hash` of the last event in the pruned block. **This is the anchor for the active retained suffix.** |
| `event_count` | Positive Integer | **Required** | Exact count of audit events enclosed in the pruned block ($\ge 1$). |
| `pruned_events_digest` | Hex String (64 chars) | **Required** | SHA-256 rolling digest or Merkle root computed across all event hashes in the block: $\text{SHA256}(h_1 \,\|\, h_2 \,\|\, \dots \,\|\, h_k)$. |
| `previous_checkpoint_id` | UUID4 or NULL | **Conditional** | `NULL` for `checkpoint_sequence == 1`; strictly required and non-null for `checkpoint_sequence > 1`. |
| `previous_checkpoint_hash` | Hex String (64 chars) | **Required** | If `checkpoint_sequence == 1`, must equal `GENESIS_CHECKPOINT_HASH` (`"0"`*64). Otherwise, must equal the `checkpoint_digest` of sequence $m-1$. |
| `checkpoint_digest` | Hex String (64 chars) | **Required** | SHA-256 digest of the canonical JSON representation of this checkpoint's header fields. |
| `signature_algorithm` | String (32 chars) | **Required** | Identifies the signature scheme: `'NONE'` (unauthenticated local), `'HMAC-SHA256'` (machine secret), or `'ED25519'` (asymmetric key). |
| `signature_value` | Base64 String or NULL | **Conditional** | `NULL` if `signature_algorithm == 'NONE'`; valid Base64 signature over `checkpoint_digest` if algorithm is enabled. |
| `signing_key_id` | String (64 chars) or NULL | **Conditional** | Identifier of the key container or certificate used for signing. `NULL` if unsigned. |
| `archive_file_path` | String (255 chars) or NULL | **Optional** | Relative filesystem path to the offline compressed archive (`data/archives/audit_archive_seq1.json.gz`). |
| `archive_sha256` | Hex String (64 chars) or NULL | **Conditional** | SHA-256 digest of the physical archive file. Required if `archive_file_path` is populated. |
| `status` | String (32 chars) | **Required** | State machine enum: `'PENDING'`, `'ACTIVE'`, `'SUPERSEDED'`, `'REVOKED'`. |

---

## 3. Canonical Serialization & Hashing Protocol

### 3.1 Checkpoint Header Canonicalization
To compute `checkpoint_digest`, serialize the following exact dictionary using **RFC 8785 Canonical JSON** (sorted keys, no whitespace separators):

```python
canonical_payload = {
    "checkpoint_id": checkpoint.checkpoint_id,
    "checkpoint_sequence": checkpoint.checkpoint_sequence,
    "created_at": format_canonical_timestamp(checkpoint.created_at),
    "event_count": checkpoint.event_count,
    "first_included_audit_id": checkpoint.first_included_audit_id,
    "interval_end_timestamp": format_canonical_timestamp(checkpoint.interval_end_timestamp),
    "interval_start_timestamp": format_canonical_timestamp(checkpoint.interval_start_timestamp),
    "last_included_audit_id": checkpoint.last_included_audit_id,
    "last_included_event_hash": checkpoint.last_included_event_hash,
    "previous_checkpoint_hash": checkpoint.previous_checkpoint_hash,
    "previous_checkpoint_id": checkpoint.previous_checkpoint_id,
    "pruned_events_digest": checkpoint.pruned_events_digest,
    "schema_version": "v1",
}

canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
checkpoint_digest = hashlib.sha256(canonical_bytes).hexdigest()
```

### 3.2 Constants
- `GENESIS_EVENT_HASH`: `"0000000000000000000000000000000000000000000000000000000000000000"` (64 zeros).
- `GENESIS_CHECKPOINT_HASH`: `"0000000000000000000000000000000000000000000000000000000000000000"` (64 zeros).

---

## 4. Checkpoint State Machine

```
      +-------------+
      |   PENDING   |  (Archive written, checkpoint staged in memory)
      +------+------+
             |
      [Atomic SQLite Transaction: Insert Checkpoint + Delete Events]
             |
             v
      +-------------+
      |   ACTIVE    |  (Currently serves as the anchor for the active suffix)
      +------+------+
             |
      [Next Checkpoint Committed]
             |
             v
      +-------------+
      | SUPERSEDED  |  (Historical checkpoint; verified via meta-chain)
      +-------------+
```

- **`PENDING`:** Checkpoint is being generated; archive file is being written to disk. Not yet authoritative.
- **`ACTIVE`:** Checkpoint is committed. The earliest row in `audit_events` MUST anchor directly to this checkpoint's `last_included_event_hash`.
- **`SUPERSEDED`:** A newer checkpoint has been committed. Historical checkpoints remain in the table to preserve the complete meta-chain back to sequence 1.
- **`REVOKED`:** Operator or verifier has identified corruption or administrative revocation. Halts all retention operations.

---

## 5. Verification Algorithms

### Algorithm 1: Live Suffix Verification (Operational Integrity)
Verifies that the live SQLite `audit_events` table is intact and anchored to the latest active checkpoint.

```text
Input: session (AsyncSession)
Output: (is_valid: bool, verified_count: int, error_code: str, error_details: str)

1. Fetch latest checkpoint:
   CP = SELECT * FROM audit_checkpoints WHERE status = 'ACTIVE' ORDER BY checkpoint_sequence DESC LIMIT 1;
   
2. If NO checkpoint exists:
   // Fall back to full chain from genesis (current Phase 7.4 behavior)
   Return verify_chain_from_genesis(session)

3. Validate CP internal integrity:
   Recompute CP.checkpoint_digest over canonical JSON.
   If computed != CP.checkpoint_digest:
       Return (False, 0, "CHECKPOINT_INVALID", "Active checkpoint digest mismatch")

4. Fetch live audit events in ascending order:
   events = SELECT * FROM audit_events ORDER BY timestamp ASC, audit_id ASC;
   
5. If events is empty:
   Return (True, 0, "SUCCESS_EMPTY_SUFFIX", None)

6. Verify Anchor Link:
   first_event = events[0]
   If first_event.previous_hash != CP.last_included_event_hash:
       Return (False, 0, "UNVERIFIED_GAP_DETECTED", 
               f"First event previous_hash '{first_event.previous_hash}' does not match checkpoint anchor '{CP.last_included_event_hash}'")

7. Verify Subsequent Event Chain:
   expected_prev = first_event.event_hash
   For idx from 1 to len(events) - 1:
       e = events[idx]
       If e.previous_hash != expected_prev:
           Return (False, idx, "PREDECESSOR_MISMATCH", f"Broken link at event {e.audit_id}")
       
       computed_hash = compute_canonical_hash(e, e.previous_hash)
       If computed_hash != e.event_hash:
           Return (False, idx, "TAMPER_DETECTED", f"Tampered content in event {e.audit_id}")
           
       expected_prev = e.event_hash

8. Return (True, len(events), "SUCCESS", None)
```

---

### Algorithm 2: Checkpoint Meta-Chain Verification
Verifies that all checkpoints form an unbroken sequence from sequence 1 to the active tip.

```text
Input: session (AsyncSession)
Output: (is_valid: bool, count: int, error_code: str, error_details: str)

1. checkpoints = SELECT * FROM audit_checkpoints ORDER BY checkpoint_sequence ASC;
2. If checkpoints is empty: Return (True, 0, "SUCCESS", None)

3. expected_prev_hash = GENESIS_CHECKPOINT_HASH
4. For seq_idx, cp in enumerate(checkpoints):
   If cp.checkpoint_sequence != seq_idx + 1:
       Return (False, seq_idx, "CHECKPOINT_SEQUENCE_GAP", f"Expected seq {seq_idx+1}, got {cp.checkpoint_sequence}")
       
   If cp.previous_checkpoint_hash != expected_prev_hash:
       Return (False, seq_idx, "CHECKPOINT_META_CHAIN_BROKEN", f"Hash link broken at seq {cp.checkpoint_sequence}")
       
   computed_digest = compute_checkpoint_digest(cp)
   If computed_digest != cp.checkpoint_digest:
       Return (False, seq_idx, "CHECKPOINT_INVALID", f"Digest mismatch at seq {cp.checkpoint_sequence}")
       
   expected_prev_hash = cp.checkpoint_digest

5. Return (True, len(checkpoints), "SUCCESS", None)
```

---

### Algorithm 3: Archived Event Verification (Cold-Storage Audit)
Verifies an offline compressed archive file against its database checkpoint.

```text
Input: archive_file_path, checkpoint_id, session
Output: (is_valid: bool, event_count: int, error_code: str)

1. Read CP from audit_checkpoints WHERE checkpoint_id = :checkpoint_id
2. Stream decompress archive_file_path and compute physical SHA-256:
   If computed_sha256 != CP.archive_sha256:
       Return (False, 0, "ARCHIVE_FILE_TAMPERED")

3. Parse events from archive JSON.
4. Verify event count == CP.event_count.
5. Verify first event audit_id == CP.first_included_audit_id.
6. Verify last event audit_id == CP.last_included_audit_id.
7. Verify last event event_hash == CP.last_included_event_hash.
8. Verify event-to-event hash chain from first to last.
9. Verify rolling digest matches CP.pruned_events_digest.
10. Return (True, len(events), "ARCHIVE_VERIFIED_SUCCESS")
```

---

## 6. Crash Recovery & Idempotency Rules

1. **Pre-Commit Isolation:**
   - The archive file must be written to `data/archives/audit_archive_{id}.tmp` and verified before beginning the SQLite transaction.
   - If writing the archive fails (e.g. disk full), no database locks are held and no records are deleted.
2. **Atomic Transition:**
   - The SQLite transaction must execute both `INSERT INTO audit_checkpoints` and `DELETE FROM audit_events` inside a single `BEGIN IMMEDIATE ... COMMIT` block.
   - SQLite WAL guarantees that either both operations persist or neither persists.
3. **Post-Commit Finalization:**
   - Rename `.tmp` archive file to `.json.gz`.
   - Update previous active checkpoint `status = 'SUPERSEDED'`.

---

## 7. Fail-Closed Verification Enforcement

Under no condition may any verifier:
- Return `True` if any checkpoint hash is unanchored or missing.
- Silently ignore gaps between checkpoints and the live table.
- Assume missing records were "cleanly deleted" without an active checkpoint proving the boundary.
- Ignore signature verification errors when signatures are enabled.
