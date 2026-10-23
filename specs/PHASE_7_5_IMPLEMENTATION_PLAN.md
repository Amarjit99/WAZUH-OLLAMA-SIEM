# Implementation Plan — Phase 7.5 / 7.5A (Future Phased Rollout)
## Audit Checkpoint Engine, DPAPI Signing, Verifiable Archival & Suffix Pruning

**Document ID:** `specs/PHASE_7_5_IMPLEMENTATION_PLAN.md`  
**Status:** PROPOSED IMPLEMENTATION BLUEPRINT (Implementation Authorization Withheld)  
**Target Phase:** Phase 7.6 (Subject to Project Owner Authorization)  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Date:** October 20, 2026 (Updated in Phase 7.5A)  

---

## 1. Governance & Execution Safeguards

> [!IMPORTANT]
> **Implementation Authorization Requirement:**
> No tasks in this implementation plan may be executed without explicit written authorization from the project owner recorded in `specs/DECISIONS.md`. In Phase 7.5 / 7.5A, all activities are strictly limited to documentation, architecture analysis, and threat modeling. Destructive audit pruning remains **strictly blocked**.

Each stage below specifies:
- **Prerequisites:** What must be completed and approved before starting.
- **Deliverables:** The exact source files, migration scripts, or configurations to be created.
- **Verification Gates:** Mandatory automated checks or tests that must pass before advancing.
- **Stop Conditions:** Specific failure modes that mandate immediate halt and rollback.

---

## 2. Twelve-Stage Implementation Plan

```
Stage 1: Governance & ADR-013 Formal Approval
   |
Stage 2: Windows DPAPI Key Management & Trust-Anchor Design
   |
Stage 3: Checkpoint Schema & Alembic Migration Design
   |
Stage 4: Key Management & Cryptographic Utilities
   |
Stage 5: Dual Chain Verifier (Genesis & Suffix with Fail-Closed Policy)
   |
Stage 6: Checkpoint Generation Engine
   |
Stage 7: Compressed Archival Export Engine (Configurable AUDIT_ARCHIVE_DIR)
   |
Stage 8: Dry-Run Reporting & Operator Visibility
   |
Stage 9: Atomic Pruning Sweep & Interrupted Crash Recovery
   |
Stage 10: Isolated Destructive Test Suite Execution (20 Test Cases)
   |
Stage 11: End-to-End Regression & Security Review
   |
Stage 12: Documentation Hardening & Release Closeout
```

---

### Stage 1: Governance & ADR-013 Formal Approval
- **Prerequisites:** Phase 7.5 / 7.5A documentation suite (`PRD`, `TRD`, `CHECKPOINT_PROTOCOL`, `THREAT_MODEL`, `ADR-013`, `DECISION_REGISTER`, `TEST_PLAN`) reviewed by project owner.
- **Deliverables:** Project owner formal approval record recorded in `specs/DECISIONS.md`.
- **Verification Gates:** Confirmed approval signature in `specs/DECISIONS.md` specifically authorizing implementation of ADR-013 and creation of Phase 7.6.
- **Stop Conditions:** Stop if the project owner chooses Option 1 (Indefinite Retention) or requests alterations to the trust model.

---

### Stage 2: Windows DPAPI Key Management & Trust-Anchor Design
- **Prerequisites:** Stage 1 approval.
- **Deliverables:**
  - Technical design for Windows DPAPI key container management (`win32crypt` / `ctypes` bindings for `CryptProtectData` / `CryptUnprotectData`).
  - Key lifecycle specifications: generation of HMAC-SHA256 or Ed25519 signing key, rotation scheme via `signing_key_id`, encrypted key backup, and recovery procedure.
  - Documented trust-boundary analysis confirming that DPAPI protects against unprivileged users and cold extraction, but does **not** protect against a local administrator or SYSTEM user.
- **Verification Gates:** Python module verification testing DPAPI availability, encryption/decryption round-trip, and graceful fail-closed behavior if DPAPI is unavailable.
- **Stop Conditions:** Stop if DPAPI integration introduces unstable binary dependencies or breaks Linux/WSL2 execution without a clean fallback.

---

### Stage 3: Checkpoint Schema & Alembic Migration Design
- **Prerequisites:** Stage 2 complete.
- **Deliverables:**
  - `backend/app/models/audit_checkpoint.py`: SQLAlchemy 2.0 ORM model for `AuditCheckpoint`.
  - `backend/alembic/versions/*_create_audit_checkpoints_table.py`: Versioned Alembic migration script creating `audit_checkpoints` and indexes (`idx_checkpoints_seq`, `idx_checkpoints_hash`, `idx_checkpoints_last_event`).
- **Verification Gates:** Migration upgrade and downgrade tests pass on an isolated temporary SQLite database.
- **Stop Conditions:** Stop if migration introduces syntax errors, locks the database, or alters existing `audit_events` or `investigations` tables.

---

### Stage 4: Key Management & Cryptographic Utilities
- **Prerequisites:** Stage 3 complete.
- **Deliverables:**
  - `backend/app/core/audit_crypto.py`: Canonical JSON serialization (RFC 8785), SHA-256 rolling digest calculation, Merkle root generation, DPAPI key storage wrapper, and signature generation/verification (`HMAC-SHA256` / `ED25519`).
- **Verification Gates:** Unit tests verifying byte-for-byte deterministic output across key orders, whitespace variations, and microsecond timestamps.
- **Stop Conditions:** Stop if canonical serialization fails RFC 8785 compliance checks.

---

### Stage 5: Dual Chain Verifier (Fail-Closed Policy)
- **Prerequisites:** Stage 4 complete.
- **Deliverables:**
  - Refactor `AuditRepository.verify_chain_integrity()` to support:
    - Suffix verification against the active checkpoint anchor (`last_included_event_hash`).
    - Full-chain verification from genesis if no checkpoints exist.
    - Checkpoint meta-chain verification (`previous_checkpoint_hash`).
  - Enforce strict **Fail-Closed Policy**: any missing event, tampered hash, invalid signature, or missing DPAPI trust anchor returns `is_valid=False` with a structured error code.
- **Verification Gates:** Passes `TC-CP-01`, `TC-CP-02`, `TC-CP-03`, `TC-CP-04`, `TC-CP-05`, `TC-CP-06`, `TC-CP-07`, and `TC-CP-08` on isolated test fixtures.
- **Stop Conditions:** Stop if verifier reports false positives on clean chains, fails to detect boundary gaps, or silently falls back to unsigned mode.

---

### Stage 6: Checkpoint Generation Engine
- **Prerequisites:** Stage 5 complete.
- **Deliverables:**
  - `AuditRepository.create_checkpoint()`: Queries expired candidate range ($> 365$ days old), computes boundary hashes and rolling digest, signs digest via DPAPI, and stages `AuditCheckpoint` row.
- **Verification Gates:** Unit tests confirming generated checkpoint header matches canonical digest and valid signature.
- **Stop Conditions:** Stop if checkpoint calculation locks the SQLite database for $> 50\text{ ms}$.

---

### Stage 7: Compressed Archival Export Engine (Configurable Destination)
- **Prerequisites:** Stage 6 complete.
- **Deliverables:**
  - Add `AUDIT_ARCHIVE_DIR: str = "data/archives/"` to `backend/app/core/config.py`.
  - `backend/app/services/audit_archival_service.py`: Streams candidate audit events to compressed JSON archive (`audit_archive_{sequence}_{start}_{end}.json.gz`).
  - Strict path traversal guard: validates that resolved destination is within allowed directories and rejects dangerous characters.
  - Pre-flight disk space assertion: verifies $\ge 1\text{ GB}$ free space before streaming.
  - Computes physical SHA-256 of the archive file and validates content before returning.
- **Verification Gates:** Offline archive verification test (`TC-CP-16`) passes 100%. Path traversal attempts rejected with validation errors.
- **Stop Conditions:** Stop if archive write encounters permission errors or disk space exhaustion.

---

### Stage 8: Dry-Run Reporting & Operator Visibility
- **Prerequisites:** Stage 7 complete.
- **Deliverables:**
  - Update `RetentionService.prune_expired_audit_events(dry_run=True)` to report:
    - Number of candidate events $> 365$ days old.
    - Projected checkpoint boundary and sequence number.
    - Configured archive destination (`AUDIT_ARCHIVE_DIR`).
    - Active suffix verification status.
- **Verification Gates:** Dry-run tests confirm zero database mutations and zero file creations.
- **Stop Conditions:** Stop if dry-run executes any write transaction or alters table rows.

---

### Stage 9: Atomic Pruning Sweep & Interrupted Crash Recovery
- **Prerequisites:** Stage 8 complete.
- **Deliverables:**
  - Update `RetentionService.prune_expired_audit_events(dry_run=False)`:
    - Unblock destructive execution.
    - Execute archive export, checkpoint insert, and event deletion in a single atomic write transaction (`BEGIN IMMEDIATE ... COMMIT`).
    - Record `AUDIT_EXPIRED_PRUNED` audit event.
    - Execute WAL passive checkpointing (`PRAGMA wal_checkpoint(PASSIVE)`).
- **Verification Gates:** Passes crash recovery tests (`TC-CP-11` and `TC-CP-12`).
- **Stop Conditions:** Stop if any batch failure reports false success or leaves orphaned records.

---

### Stage 10: Isolated Destructive Test Suite Execution
- **Prerequisites:** Stage 9 complete.
- **Deliverables:**
  - Full execution of all 20 test cases defined in `specs/PHASE_7_5_TEST_PLAN.md` on isolated temporary database fixtures.
- **Verification Gates:** 20/20 test cases pass with zero failures. Zero production database rows affected.
- **Stop Conditions:** Stop if any test fails, is skipped, or reveals an unhandled exception.

---

### Stage 11: End-to-End Regression & Security Review
- **Prerequisites:** Stage 10 complete.
- **Deliverables:**
  - Full backend pytest suite execution (`pytest -v`).
  - Frontend lint and contract validation checks.
  - Audit log immutability inspection.
- **Verification Gates:** 100% pass rate across all legacy Phase 1–7.4 test suites. Zero regressions.
- **Stop Conditions:** Stop if any existing investigation persistence, history, or correlation test fails.

---

### Stage 12: Documentation Hardening & Release Closeout
- **Prerequisites:** Stage 11 complete.
- **Deliverables:**
  - Update `specs/PHASE_7_SECURITY_AND_RETENTION.md` with final checkpoint operational procedures.
  - Create `PHASE_7_6_IMPLEMENTATION_REPORT.md`.
- **Verification Gates:** Working tree verified clean; deployment repository untouched; zero Git commits or pushes without explicit authorization.
- **Stop Conditions:** None.
