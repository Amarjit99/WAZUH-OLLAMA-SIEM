# Test Plan — Phase 7.5
## Audit Retention Checkpoint Architecture & Integrity Verification

**Document ID:** `specs/PHASE_7_5_TEST_PLAN.md`  
**Status:** PROPOSED TEST PLAN (Implementation Authorization Withheld)  
**Phase:** 7.5  
**Target Platform:** pytest, pytest-asyncio, aiosqlite, SQLite WAL  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Date:** October 20, 2026  

---

## 1. Test Strategy & Mandatory Safety Invariants

This document establishes the test specification for future implementation of the audit checkpointing and verification system.

> [!CAUTION]
> **Mandatory Execution Invariants:**
> 1. **Zero Production Data Usage:** All future tests must execute exclusively against isolated, temporary SQLite databases generated dynamically via pytest fixtures (`tmp_path`). Never run tests against `data/siem_history.db`.
> 2. **Ephemeral Key Fixtures:** Signing and HMAC tests must use temporary, in-memory or ephemeral test keys. Never use production machine keys.
> 3. **Non-Implementation in Phase 7.5:** These tests are **NOT** to be implemented or executed in Phase 7.5. This document is a technical blueprint for a future authorized implementation phase.

---

## 2. Test Suite Specification (20 Test Cases)

---

### TC-CP-01: Empty-Chain Verification
- **Test ID:** `TC-CP-01`
- **Scope:** Base verification behavior when zero audit events and zero checkpoints exist.
- **Fixture:** Isolated temporary SQLite database.
- **Setup:** Database initialized with empty `audit_events` and `audit_checkpoints` tables.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(True, 0, "SUCCESS", None)`. No error logged; handles empty state gracefully.
- **Security Property Validated:** Boundary condition stability; zero false alarms on clean initialized databases.

---

### TC-CP-02: Valid Full-Chain Verification (Genesis Mode)
- **Test ID:** `TC-CP-02`
- **Scope:** Verifies that in the absence of checkpoints, existing Phase 7.1–7.4 hash chaining works seamlessly.
- **Fixture:** Isolated temporary SQLite database.
- **Setup:** Seed 10 sequential audit events using `AuditRepository.log_event()`. No checkpoints in `audit_checkpoints`.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(True, 10, "SUCCESS", None)`. All records recompute hashes correctly matching `GENESIS_HASH`.
- **Security Property Validated:** Backward compatibility with ADR-012.

---

### TC-CP-03: Valid Checkpoint Plus Retained Suffix
- **Test ID:** `TC-CP-03`
- **Scope:** Core operational test verifying active suffix anchored to a committed checkpoint.
- **Fixture:** Isolated temporary database.
- **Setup:**
  1. Seed 20 audit events ($e_1 \dots e_{20}$).
  2. Create valid Checkpoint #1 covering events $e_1 \dots e_{10}$, recording $e_{10}.\text{event\_hash}$ as `last_included_event_hash`.
  3. Delete events $e_1 \dots e_{10}$ from `audit_events`.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(True, 10, "SUCCESS", None)`. Verifier recognizes Checkpoint #1, confirms $e_{11}.\text{previous\_hash} == \text{Checkpoint}_1.\text{last\_included\_event\_hash}$, and verifies $e_{11} \dots e_{20}$.
- **Security Property Validated:** Continuity of cryptographic integrity across pruned boundaries.

---

### TC-CP-04: Tampered Checkpoint Header
- **Test ID:** `TC-CP-04`
- **Scope:** Detects modification of checkpoint metadata in the database.
- **Fixture:** Isolated temporary database.
- **Setup:** Create valid Checkpoint #1 and retained suffix as in `TC-CP-03`. Manually modify `checkpoint_sequence` or `last_included_event_hash` in the `audit_checkpoints` row.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(False, 0, "CHECKPOINT_INVALID", details)`. Verification fails closed immediately without trusting the modified anchor.
- **Security Property Validated:** Tamper-evidence of checkpoint headers via canonical digest recalculation.

---

### TC-CP-05: Tampered Checkpoint Signature
- **Test ID:** `TC-CP-05`
- **Scope:** Detects signature tampering when cryptographic signatures are enabled.
- **Fixture:** Isolated temporary database with ephemeral HMAC/Ed25519 key.
- **Setup:** Create signed Checkpoint #1 (`signature_algorithm='HMAC-SHA256'`). Alter one byte of `signature_value`.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(False, 0, "CHECKPOINT_SIGNATURE_INVALID", details)`.
- **Security Property Validated:** Authenticity verification of external trust anchors.

---

### TC-CP-06: Unavailable Trust Anchor / Invalid Signing Key
- **Test ID:** `TC-CP-06`
- **Scope:** Fail-closed behavior when signature verification is required but key is missing.
- **Fixture:** Isolated temporary database.
- **Setup:** Checkpoint specifies `signing_key_id='key-prod-01'`, but environment lacks the key.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(False, 0, "TRUST_ANCHOR_UNAVAILABLE", details)`. Does **NOT** silently fall back to unsigned verification.
- **Security Property Validated:** Fail-closed defense-in-depth against silent downgrade attacks.

---

### TC-CP-07: Missing or Overlapping Checkpoints in Meta-Chain
- **Test ID:** `TC-CP-07`
- **Scope:** Detects sequence gaps or hash breaks across multiple checkpoints.
- **Fixture:** Isolated temporary database.
- **Setup:** Create Checkpoint #1 (seq 1) and Checkpoint #3 (seq 3, omitting seq 2).
- **Action:** Call `verify_checkpoint_meta_chain(session)`.
- **Expected Result:** Returns `(False, 1, "CHECKPOINT_SEQUENCE_GAP", "Expected seq 2, got 3")`.
- **Security Property Validated:** Prevention of silent historical checkpoint excision.

---

### TC-CP-08: Missing Event at Retention Boundary (Anchor Gap)
- **Test ID:** `TC-CP-08`
- **Scope:** Detects unauthorized deletion of the first retained event after pruning.
- **Fixture:** Isolated temporary database.
- **Setup:**
  1. Checkpoint #1 covers $e_1 \dots e_{10}$ ($h_{10}$ is anchor).
  2. Live table contains $e_{12} \dots e_{20}$ (event $e_{11}$ was deleted maliciously).
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(False, 0, "UNVERIFIED_GAP_DETECTED", details)`. Detects that $e_{12}.\text{previous\_hash}$ does not equal $h_{10}$.
- **Security Property Validated:** Complete protection against boundary truncation.

---

### TC-CP-09: Event Alteration Before and After Checkpoint Creation
- **Test ID:** `TC-CP-09`
- **Scope:** Verifies that modifying any event in the active suffix breaks verification.
- **Fixture:** Isolated temporary database.
- **Setup:** Valid checkpoint plus retained suffix ($e_{11} \dots e_{20}$). Alter `outcome` in event $e_{15}$.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(False, 4, "TAMPER_DETECTED", details)`.
- **Security Property Validated:** Retained event payload integrity.

---

### TC-CP-10: Checkpoint Rollback to an Older Checkpoint
- **Test ID:** `TC-CP-10`
- **Scope:** Detects attempt to replace active Checkpoint #2 with historical Checkpoint #1.
- **Fixture:** Isolated temporary database.
- **Setup:** System has pruned up to event $e_{20}$ (Checkpoint #2). Attacker updates database to mark Checkpoint #1 as active.
- **Action:** Call `verify_chain_integrity(session)`.
- **Expected Result:** Returns `(False, 0, "UNVERIFIED_GAP_DETECTED", details)`. Live events start at $e_{21}$ (previous_hash = $h_{20}$), which does not match Checkpoint #1 anchor ($h_{10}$).
- **Security Property Validated:** Rollback resistance.

---

### TC-CP-11: Crash Before Database Commit (Archive Staged)
- **Test ID:** `TC-CP-11`
- **Scope:** Simulates power failure after writing archive file but before committing SQLite transaction.
- **Fixture:** Isolated temporary filesystem and database.
- **Setup:** Retention service writes `audit_archive_seq1.json.gz.tmp`, then process is killed before executing `session.commit()`.
- **Action:** Restart retention service; run `verify_chain_integrity()` and inspect table.
- **Expected Result:** All audit events remain in `audit_events`. Zero checkpoints committed in database. Uncommitted `.tmp` archive is ignored or cleaned up.
- **Security Property Validated:** Zero data loss under mid-cycle power failure.

---

### TC-CP-12: Crash During Retention Deletion Transaction
- **Test ID:** `TC-CP-12`
- **Scope:** Simulates exception during atomic SQLite transaction.
- **Fixture:** Isolated temporary database.
- **Setup:** Inject database I/O error during the `DELETE FROM audit_events` phase.
- **Action:** Verify transaction rollback.
- **Expected Result:** Transaction rolls back completely; checkpoint is not inserted; audit events are not deleted; `status="FAILED"` returned.
- **Security Property Validated:** Atomicity of checkpoint creation and event pruning.

---

### TC-CP-13: SQLite WAL Recovery with Checkpoints
- **Test ID:** `TC-CP-13`
- **Scope:** Verifies that checkpoints and retained events recover cleanly through SQLite WAL recovery.
- **Fixture:** Isolated temporary database.
- **Setup:** Commit a checkpoint and suffix events; simulate uncheckpointed WAL file; reopen database engine.
- **Action:** Call `PRAGMA integrity_check` and `verify_chain_integrity(session)`.
- **Expected Result:** WAL replays successfully; chain verification passes with 100% integrity.
- **Security Property Validated:** SQLite WAL compatibility and crash durability.

---

### TC-CP-14: Concurrent Audit Writes During Checkpoint Computation
- **Test ID:** `TC-CP-14`
- **Scope:** Verifies that logging new audit events while a checkpoint is being calculated does not cause lock timeouts or chain branching.
- **Fixture:** Isolated temporary database.
- **Setup:** Launch concurrent tasks: Task A reads candidate events for checkpointing; Task B calls `AuditRepository.log_event()`.
- **Action:** Await both tasks; verify chain integrity.
- **Expected Result:** Both tasks succeed within SQLite WAL `busy_timeout` (5000ms). Chain remains linear and unbroken.
- **Security Property Validated:** Read-write concurrency and transaction serialization.

---

### TC-CP-15: Canonicalization Edge Cases & Microsecond Timestamps
- **Test ID:** `TC-CP-15`
- **Scope:** Verifies deterministic hashing across JSON key permutations, whitespace, and microsecond timestamps.
- **Fixture:** Python test fixture.
- **Setup:** Construct payloads with randomized key orders, UTF-8 strings, and varying microsecond precisions (`.123000Z` vs `.123Z`).
- **Action:** Compute canonical hashes.
- **Expected Result:** Output hashes are 100% byte-for-byte identical across runs.
- **Security Property Validated:** Deterministic RFC 8785 canonicalization.

---

### TC-CP-16: Offline Archive File Verification
- **Test ID:** `TC-CP-16`
- **Scope:** Verifies offline verification of compressed archive files against checkpoint records.
- **Fixture:** Isolated temporary filesystem.
- **Setup:** Prune and archive 50 events to `data/archives/audit_archive_seq1.json.gz`.
- **Action:** Call `verify_archive_file(archive_path, checkpoint_id)`.
- **Expected Result:** Returns `(True, 50, "ARCHIVE_VERIFIED_SUCCESS")`.
- **Security Property Validated:** Independent auditability of cold compliance archives.

---

### TC-CP-17: Retention Dry-Run Accuracy
- **Test ID:** `TC-CP-17`
- **Scope:** Verifies dry-run returns exact candidate counts without deleting or mutating records.
- **Fixture:** Isolated temporary database.
- **Setup:** Seed 25 events older than 365 days, 15 events younger than 365 days.
- **Action:** Call `retention_service.prune_expired_audit_events(dry_run=True)`.
- **Expected Result:** Returns `eligible_count=25, deleted_count=0, status="DRY_RUN"`. Table count remains exactly 40.
- **Security Property Validated:** Non-destructive dry-run predictability.

---

### TC-CP-18: Fail-Closed Enforcement on Unverifiable History
- **Test ID:** `TC-CP-18`
- **Scope:** Asserts that verifier never outputs `VALID` when an error or ambiguity occurs.
- **Fixture:** Isolated temporary database.
- **Setup:** Simulate unhandled parsing exception inside event payload.
- **Action:** Call verifier.
- **Expected Result:** Returns `(False, idx, "UNVERIFIED_CORRUPT_PAYLOAD", exc)`.
- **Security Property Validated:** Fail-closed security posture.

---

### TC-CP-19: Zero Deletion Prior to Integrity Check Success
- **Test ID:** `TC-CP-19`
- **Scope:** Ensures pruning aborts without deleting rows if pre-flight verification fails.
- **Fixture:** Isolated temporary database.
- **Setup:** Deliberately tamper with one event in the candidate block prior to pruning.
- **Action:** Trigger pruning sweep.
- **Expected Result:** Pre-flight check detects tampering; sweep aborts; **zero rows deleted**; error logged.
- **Security Property Validated:** Pre-condition validation safety.

---

### TC-CP-20: Full Regression Coverage for Investigation & Audit Repositories
- **Test ID:** `TC-CP-20`
- **Scope:** Verifies that introducing checkpointing does not regress any Phase 7.1–7.4 investigation or audit features.
- **Fixture:** Isolated temporary database.
- **Setup:** Execute full test suite including investigation persistence, history pagination, and 90-day investigation retention.
- **Action:** Run `pytest tests/`.
- **Expected Result:** 100% of existing tests pass with zero regressions.
- **Security Property Validated:** System-wide architectural stability.
