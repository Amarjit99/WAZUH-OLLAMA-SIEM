# Technical Requirements Document (TRD) — Phase 7.5 / 7.5A
## Audit Retention Checkpoint Architecture, DPAPI Signing & Verifiable Archival

**Document ID:** `specs/PHASE_7_5_TRD.md`  
**Status:** PROPOSED TECHNICAL ARCHITECTURE SPECIFICATION  
**Phase:** 7.5 / 7.5A  
**Target Platform:** Local Single-User Host, FastAPI Backend, SQLite 3.40+ (WAL mode)  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Date:** October 20, 2026 (Updated in Phase 7.5A)  

---

## 1. Architectural Overview & Context

In the current persistence layer:
- `AuditEvent` records are persisted to SQLite table `audit_events`.
- Each event is cryptographically linked to its predecessor via SHA-256:
  $$h_i = \text{SHA-256}(\text{CanonicalJSON}(e_i) \,\|\, h_{i-1})$$
  with $h_0 = \text{GENESIS\_HASH} = \text{"0"}\times 64$.
- `AuditRepository.verify_chain_integrity()` traverses the entire table from genesis to tip to confirm that no records were deleted, inserted, modified, or reordered.

To satisfy the 365-day audit retention mandate without causing unbounded SQLite file growth over multi-year deployments, the system requires an architecture to prune expired records while preserving cryptographic proof of integrity for both the **retained active suffix** and the **exported historical archive**.

---

## 2. Comparative Evaluation of Architectural Options

```
+---------------------------------------------------------------------------------------------------------+
|                                    ARCHITECTURAL OPTIONS COMPARISON                                     |
+-------------------+-----------------------------+-----------------------------+-------------------------+
| Option 1:         | Option 2:                   | Option 3:                   | Option 4:               |
| No Physical Audit | Signed Checkpoint with      | Externally Anchored         | Merkle-Based Archival   |
| Pruning           | Retained Chain Anchor       | Checkpoints                 | & Segmented Chains      |
|                   |                             |                             |                         |
| [All Events Kept] | [Table: audit_checkpoints]  | [External Trust Anchor]     | [Epoch Blocks + Merkle] |
|   e0 -> e1 -> e2  |   CP1(e0..ek) -> ek+1..eN   |   Windows DPAPI / Syslog    |   Root -> Leaves        |
+-------------------+-----------------------------+-----------------------------+-------------------------+
```

### 2.1 Option 1: No Physical Audit Pruning (Indefinite Retention)
- **Concept:** Retain 100% of audit records in `audit_events` indefinitely.
- **Security:** Complete unbroken hash chain from day zero. No checkpoint boundary complexity.
- **Limitations:** Causes unbounded SQLite file growth over multi-year deployments (~20,000–75,000 rows/year) and forces verification time to scale linearly ($O(N)$) forever.
- **Evaluation:** Operationally safe fallback, but undesirable for long-term production storage bounding.

### 2.2 Option 2: Signed Checkpoint with Retained Chain Anchor (Local Table)
- **Concept:** Store structured checkpoints in a local `audit_checkpoints` table. Suffix verification anchors to `last_included_event_hash`.
- **Security:** Preserves mathematical continuity for retained records; bounds live verification time ($O(N - k)$).
- **Limitations:** If keys are stored in plaintext on disk, a local administrator can forge checkpoints as easily as they forge audit rows.

### 2.3 Option 3: Externally Anchored Checkpoints (Windows DPAPI / Machine Key Store)
- **Concept:** Checkpoint digests are signed using cryptographic keys protected by the **Windows Data Protection API (DPAPI)** or transmitted to an external append-only log.
- **Security:** Protects signing keys against unprivileged local users and cold-disk extraction without requiring external network services.
- **Limitations:** Introduces Windows-specific DPAPI API calls (`win32crypt` / `ctypes`); does not protect against a fully privileged administrator running as `NT AUTHORITY\SYSTEM` or the application account.

### 2.4 Option 4: Merkle-Based Archival & Segmented Chains (Epoch-Based)
- **Concept:** Segments audit events into discrete epochs. When an epoch expires, it is exported to a compressed archive file with a Merkle root, and local rows are pruned.
- **Security:** Self-contained, independently auditable archives with compact proof-of-inclusion.
- **Limitations:** Higher state machine complexity; requires disciplined archive file management.

---

## 3. Comprehensive Evaluation Matrix

| Criterion | Option 1: No Pruning | Option 2: Local Signed Checkpoint | Option 3: Windows DPAPI Anchoring | Option 4: Merkle Epoch Archival |
|---|---|---|---|---|
| **Cryptographic Integrity** | High (full chain) | High (anchored suffix) | Very High (DPAPI anchor) | Very High (Merkle proof + chain) |
| **Tamper Resistance (Local User)** | Low (re-hashable) | Medium | High (DPAPI protected) | High |
| **Tamper Resistance (Local Admin)** | Zero (re-hashable) | Zero (re-hashable) | Zero (DPAPI decryptable by SYSTEM) | Zero (re-hashable) |
| **Active Query Performance** | Degrades over years | Constant ($O(1)$) | Constant ($O(1)$) | Constant ($O(1)$) |
| **Operational Simplicity** | Very High (trivial) | High | Medium | Medium-Low |
| **Offline / Loopback Guarantee** | 100% offline | 100% offline | 100% offline | 100% offline |
| **Archived Event Verifiability** | N/A (no archive) | Linear scan against export | Linear scan against export | Fast Merkle inclusion verification |

---

## 4. Recommended Technical Architecture: The Hybrid DPAPI Checkpointed Model

We recommend the **Segmented Checkpoint & Verifiable Archival Architecture with Windows DPAPI Signing**:

### 4.1 Dedicated Checkpoint Storage (`audit_checkpoints`)
- Introduce an `audit_checkpoints` table tracking checkpoint sequence, event ID boundaries, timestamp ranges, and boundary hashes (`last_included_event_hash`).
- Checkpoints link together via `previous_checkpoint_hash`, forming a **Checkpoint Meta-Chain** anchored at `GENESIS_CHECKPOINT_HASH`.

### 4.2 Windows DPAPI Key Management & Signing Lifecycle
1. **Key Storage:** Checkpoint headers are signed with an HMAC-SHA256 secret or Ed25519 private key. The raw key bytes are encrypted at rest using Windows DPAPI (`CryptProtectData`) under Current User or Local Machine scope:
   $$\text{EncryptedKey} = \text{DPAPI\_Encrypt}(\text{RawKeyBytes})$$
2. **Key Rotation:** Each key has an identifier `signing_key_id` (e.g. `dpapi-v1-202610`). The checkpoint record embeds `signing_key_id` and `signature_algorithm` (`'HMAC-SHA256'` or `'ED25519'`). Rotating a key involves generating a new secret, encrypting it with DPAPI, and appending its ID to the application key registry.
3. **Key Backup & Recovery:** The encrypted key blob is stored within the application's configuration directory. Disaster recovery requires restoring the host user profile or DPAPI recovery keys via Windows domain/local administration.
4. **Trust Boundary Ceiling:** DPAPI prevents unauthorized processes and non-administrative local users from accessing the signing key. However, **any process running with Administrator or SYSTEM privileges on the host can invoke `CryptUnprotectData`**, decrypt the signing key, and sign fraudulent checkpoints. True non-repudiation against a hostile local administrator requires an off-host external trust anchor.

### 4.3 Configurable Archive Destination (`AUDIT_ARCHIVE_DIR`)
- Prior to database deletion, expired records ($> 365$ days old) are streamed and compressed to an immutable JSON archive file:
  `{AUDIT_ARCHIVE_DIR}/audit_archive_{sequence}_{start_ts}_{end_ts}.json.gz`
- **Configurability:** Supported via backend setting `AUDIT_ARCHIVE_DIR`, defaulting to `data/archives/`.
- **Path Traversal Protection:** The directory path is resolved and validated strictly; relative traversal components (`..`) or paths outside approved boundaries are rejected.
- **Disk Quota Guard:** A pre-flight check asserts at least $1\text{ GB}$ of free disk space on the target volume before initiating archive streaming.
- **NTFS Permissions:** The archive directory is protected via Windows `icacls`, granting access exclusively to the application service user and `NT AUTHORITY\SYSTEM`.

### 4.4 Strict Fail-Closed Verification Policy
The verification engine strictly **fails closed** (`is_valid=False`):
- If any event in the active suffix has a mismatched `previous_hash` or tampered payload.
- If the earliest live event does not anchor to the active checkpoint's `last_included_event_hash` (`UNVERIFIED_GAP_DETECTED`).
- If a checkpoint's recomputed digest does not match its header (`CHECKPOINT_INVALID`).
- If checkpoint signature verification fails (`CHECKPOINT_SIGNATURE_INVALID`).
- If the DPAPI signing key is unreachable (`TRUST_ANCHOR_UNAVAILABLE`).
- If an offline archive file's physical SHA-256 does not match `archive_sha256` in the database (`ARCHIVE_FILE_TAMPERED`).
- The system will **never** silently downgrade from signed to unsigned mode or report an unverified chain as valid.

### 4.5 Hard Block on Audit Pruning Preserved
- Approval of this technical specification does **not** enable physical audit deletion.
- Destructive audit pruning remains **strictly blocked** in `RetentionService.prune_expired_audit_events()`.
- Unblocking deletion requires a separate implementation phase (Phase 7.6) with explicit owner sign-off.

---

## 5. Database Transaction & SQLite WAL Safety

To maintain strict single-writer SQLite WAL stability:
1. Candidate queries execute in read-only transactions (`BEGIN DEFERRED`).
2. The archive file is streamed to a `.tmp` file and its SHA-256 is verified **before** opening a write transaction.
3. Checkpoint insertion and event deletion execute in a single atomic write transaction (`BEGIN IMMEDIATE`):
   ```sql
   BEGIN IMMEDIATE;
   INSERT INTO audit_checkpoints (...) VALUES (...);
   DELETE FROM audit_events WHERE audit_id IN (...);
   COMMIT;
   ```
4. Transaction duration is kept strictly under $100\text{ ms}$ (bounded to 100–500 rows per batch) to avoid violating SQLite's 5000ms `busy_timeout`.
5. Following commit, the temporary archive file is renamed to its final `.json.gz` filename, and `PRAGMA wal_checkpoint(PASSIVE)` is executed.

---

## 6. Failure Handling & Recovery Specifications

- **Crash before archive write:** Zero database changes; next sweep restarts safely.
- **Crash after archive write, before DB commit:** The `.tmp` archive is detected on next startup. Because no checkpoint was committed in SQLite, the archive is cleaned up. Zero data loss.
- **Crash during DB commit:** Handled atomically by SQLite WAL rollback. Either both the checkpoint is inserted and rows are pruned, or neither occurs.

---

## 7. Acceptance Criteria for Technical Architecture

Phase 7.5 / 7.5A TRD requirements are satisfied when:
1. Windows DPAPI signing is fully specified, including key lifecycle, rotation, and realistic trust-boundary limitations.
2. Configurable archive destination (`AUDIT_ARCHIVE_DIR`) with path traversal and disk space protections is codified.
3. Strict fail-closed verification policies are documented across all failure modes.
4. The hard block on physical audit deletion is explicitly preserved.
5. All design elements confirm that offline, loopback-only operation is maintained without cloud dependencies.
