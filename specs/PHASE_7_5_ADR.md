# Architecture Decision Record (ADR-013) — Phase 7.5 / 7.5A
## Audit Retention Checkpoint Architecture, DPAPI Signing & Verifiable Archival

**Document ID:** `specs/PHASE_7_5_ADR.md`  
**ADR Identifier:** ADR-013  
**Status:** **APPROVED (Explicitly Approved by Project Owner)**  
**Prior ADRs In Effect:** ADR-007 through ADR-012 (Fully Preserved and Unchanged)  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Date:** October 20, 2026 (Finalized in Phase 7.5A)  

---

## 1. Context and Problem Statement

Under ADR-011 and ADR-012, audit events must be retained for at least 365 days (`AUDIT_RETENTION_DAYS=365`) and are cryptographically chained using SHA-256 from a fixed `GENESIS_HASH` (`0`*64).

During Phase 7.4 implementation, an architectural blocker was identified:
- Physically deleting an expired prefix of audit records ($e_0, \dots, e_k$) breaks the sequential hash chain because the first surviving record ($e_{k+1}$) has its `previous_hash` pointing to deleted record $e_k$.
- Without a trusted cryptographic anchor, `verify_chain_integrity()` immediately fails at index 0 on the surviving records.
- Consequently, physical audit pruning was **safely blocked** in Phase 7.4 (`status="BLOCKED"`, `deleted_count=0`).

To allow periodic archival and pruning of audit events older than 365 days over multi-year deployments without destroying audit continuity, a formal checkpoint and integrity architecture must be established.

---

## 2. Decision: Proposed Checkpointed Epoch, DPAPI Signing & Verifiable Archival

We propose adopting the **Segmented Checkpoint & Verifiable Archival Architecture with Windows DPAPI Signing**:

### 2.1 Dedicated Checkpoint Storage (`audit_checkpoints` Table)
- Introduce an `audit_checkpoints` table in SQLite storing monotonic checkpoint records.
- Each checkpoint records the range boundary (`first_included_audit_id`, `last_included_audit_id`, `last_included_event_hash`), event count, and a rolling digest of the pruned block.
- Checkpoints link to one another via `previous_checkpoint_hash`, forming a **Checkpoint Meta-Chain** anchored at `GENESIS_CHECKPOINT_HASH`.

### 2.2 Windows DPAPI-Backed Checkpoint Signing
- Checkpoint headers are signed using a symmetric HMAC-SHA256 secret or asymmetric Ed25519 private key protected by the **Windows Data Protection API (DPAPI)**.
- **Key Storage:** The key material is encrypted at rest using Windows DPAPI machine or current-user scope (`CryptProtectData` / `CryptUnprotectData` via `win32crypt` or `ctypes`).
- **Key Rotation & Lifecycle:** Keys are tagged with a monotonic `signing_key_id` (e.g. `dpapi-v1-202610`). Key rotation is supported by maintaining historical public/verification metadata in the application configuration.
- **Key Backup & Recovery:** The DPAPI-encrypted key blob can be backed up alongside application configuration. Disaster recovery procedures require host machine restoration or DPAPI password recovery via the domain/local security authority.
- **Trust-Boundary Reality Check:** DPAPI protects the signing key against unprivileged local users and cold-disk extraction. However, **DPAPI does NOT protect against a fully privileged local administrator or malicious process running as `NT AUTHORITY\SYSTEM` or the application user account**, as such an entity can call `CryptUnprotectData` to recover the key and re-sign forged checkpoints.

### 2.3 Configurable Archive Destination
- Pruned records are streamed and compressed to an immutable JSON archive file prior to database deletion.
- The archive directory is configurable via the application setting `AUDIT_ARCHIVE_DIR`, defaulting to `data/archives/`.
- Strict path traversal guards and directory permission checks (`icacls` restricted to current user and SYSTEM) are enforced before writing archive files.
- The physical SHA-256 digest of the archive file is permanently recorded in the database checkpoint row (`archive_sha256`).

### 2.4 Strict Fail-Closed Verification Policy
The verification engine must **fail closed** (`is_valid=False`, returning a descriptive error code):
- If the live audit chain is broken or has unanchored gaps (`UNVERIFIED_GAP_DETECTED`).
- If an event hash does not match its canonical recomputation (`TAMPER_DETECTED`).
- If the checkpoint digest or signature cannot be verified (`CHECKPOINT_INVALID` / `CHECKPOINT_SIGNATURE_INVALID`).
- If the archive file digest does not match the checkpoint record (`ARCHIVE_FILE_TAMPERED`).
- If the DPAPI trust anchor or signing key is missing or unavailable (`TRUST_ANCHOR_UNAVAILABLE`).
- Under no circumstances will the system silently downgrade from signed to unsigned verification or report an unverified chain as valid.

### 2.5 Hard Block on Audit Pruning Preserved
- Approval of this architecture design **does NOT authorize or enable physical deletion**.
- Destructive audit pruning remains **strictly blocked** in `RetentionService.prune_expired_audit_events()`.
- Physical deletion may only be enabled in a future implementation phase (Phase 7.6) after explicit owner authorization, schema migration, and isolated test verification.

### 2.6 Strictly Local & Offline Operation
- Checkpoint creation, signing, and verification are 100% self-contained on the local host.
- Zero mandatory cloud dependencies, external SaaS services, or remote network calls are introduced.

---

## 3. Options Considered & Alternatives Evaluated

| Option | Summary | Decision | Rationale |
|---|---|---|---|
| **Option 1: Indefinite Retention (No Pruning)** | Retain 100% of audit events in SQLite forever. | **Deferred (Safe Fallback)** | Operationally trivial, but leads to unbounded disk growth over multi-year deployments and $O(N)$ verification scaling. Retained as default until ADR-013 is implemented. |
| **Option 2: Plain In-Table Anchor (No Archival)** | Prune expired events without writing an offline archive. | **REJECTED** | Violates compliance and SOC forensic standards by permanently destroying audit records older than 365 days. |
| **Option 3: Mandatory Cloud or Remote Syslog Anchoring** | Stream all checkpoint digests to remote WORM or cloud ledger. | **REJECTED as Baseline** | Violates the core system requirement for loopback-only, offline-capable, local single-user operation. Retained as an enterprise extension hook. |
| **Option 4: Merkle-Based Epoch Archival & DPAPI Checkpoints** | Checkpoint blocks with DPAPI signing and compressed file archives. | **RECOMMENDED (Proposed ADR-013)** | Balances cryptographic integrity, local storage bounding, compliance archival, and local offline operation. |

---

## 4. Trust Boundary Analysis & Residual Risks

```
+-----------------------------------------------------------------------------------------+
| TRUST BOUNDARY MODEL                                                                    |
+-----------------------------------------------------------------------------------------+
| LOCAL HOST BOUNDARY (Windows Workstation)                                               |
|                                                                                         |
|  [Threat: Bit-rot / Hardware Errors] --------> MITIGATED (SHA-256 + SQLite WAL)         |
|  [Threat: Unprivileged Local User] ---------> MITIGATED (NTFS ACLs + DPAPI key)         |
|  [Threat: Remote Injection / SQLi] ---------> MITIGATED (Loopback binding + ORM param) |
|                                                                                         |
|  [Threat: Host Administrator / SYSTEM] -----> RESIDUAL RISK: A root/admin attacker      |
|                                               can call CryptUnprotectData, alter the    |
|                                               database, edit archives, and re-sign.     |
+-----------------------------------------------------------------------------------------+
| EXTERNAL TRUST ANCHOR (Optional Enterprise Extension)                                    |
|                                                                                         |
|  [Remote WORM / External Syslog Ledger] ----> Eliminates local admin tampering risk     |
|                                               by anchoring checkpoint digests off-host. |
+-----------------------------------------------------------------------------------------+
```

---

## 5. Implementation Authorization Notice

> [!CAUTION]
> **GOVERNANCE STATUS: PROPOSED — PENDING EXPLICIT USER APPROVAL**  
> This ADR does **NOT** authorize code changes, database migrations, key generation, or audit pruning. Physical audit-event pruning remains **STRICTLY BLOCKED** in the application codebase until the project owner explicitly records approval in `specs/DECISIONS.md`.
