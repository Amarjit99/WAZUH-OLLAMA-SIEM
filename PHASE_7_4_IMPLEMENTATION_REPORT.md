# PHASE 7.4 IMPLEMENTATION REPORT
## Retention & Cleanup Automation

**Project:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Phase:** 7.4  
**Date:** October 20, 2026  
**Status:** COMPLETE (Investigation Retention Implemented; Audit Pruning Safely Blocked to Preserve ADR-012 Hash-Chain Integrity)  
**Git Commit/Push:** NONE (Unauthorized)  
**Deployment Repository:** Strictly Untouched  
**Phase 7.5 Status:** NOT STARTED  

---

## 1. Executive Summary

Phase 7.4 delivers the automated retention, pruning, and storage maintenance engine for the local persistence layer established in Phases 7.1–7.3. It implements:

1. **Investigation Retention (90 Days):**
   - Deterministic UTC cutoff calculation: `now_utc - timedelta(days=90)`.
   - Bounded batch deletion ($\le 100$ records per batch) with inter-batch yield delays (`asyncio.sleep(0.01)`) to avoid locking the SQLite WAL database.
   - Deep cascade verification: physical deletion of parent `investigations` automatically cleans child records across all 5 dependent tables (`investigation_results`, `investigation_facts`, `investigation_hypotheses`, `investigation_checks`, `investigation_evidence_snapshots`) via database-level `ON DELETE CASCADE` and SQLite foreign keys.
   - Complete audit trail preservation: investigation deletions leave `audit_events` intact and record an `INVESTIGATION_EXPIRED_PRUNED` audit event capturing pruned counts and actor context.

2. **Audit Retention Analysis & Safe Blocking (365 Days):**
   - In accordance with Section 5 of Phase 7.4 instructions, the existing `AuditRepository` and `ADR-012` design were evaluated prior to implementing physical audit deletion.
   - **Architectural Blocker Identified:** ADR-012 defines a strictly sequential cryptographic SHA-256 hash chain starting from `GENESIS_HASH` (`0000000000000000000000000000000000000000000000000000000000000000`). Physical deletion of expired prefix events without an approved checkpoint or anchor table would permanently break `verify_chain_integrity()` for all subsequent active audit events.
   - **Safe Behavior:** The `AuditRepository` and `RetentionService` identify and report expired candidate counts during dry-runs, but destructive physical deletion of audit records is **safely blocked** (`status="BLOCKED"`, `deleted_count=0`) with an explicit rationale until a formal checkpointing ADR/migration is approved.

3. **Dry-Run Engine & Safe Execution Safeguards:**
   - Dry-run capability (`dry_run=True` by default) estimates candidates and calculates cutoffs without mutating data.
   - No automatic deletion on application startup; background sweep is callable on demand by authorized maintenance services.
   - Zero public or unauthenticated cleanup API endpoints exposed.

4. **SQLite WAL & Operational Safety:**
   - Explicit WAL checkpoint invocation (`PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA wal_checkpoint(PASSIVE)`) to reclaim WAL journal pages safely without deleting or corrupting WAL files.
   - Atomic transaction management per batch: if any batch encounters a database or I/O failure, the transaction rolls back cleanly, recording an accurate error status without false success.

---

## 2. Exact Files Created and Modified

### Created Files
- `backend/app/services/retention_service.py`: Service implementing retention cutoffs, dry-run candidate estimation, bounded batch investigation pruning, audit retention safety blocking, WAL checkpointing, and comprehensive maintenance sweeps.
- `backend/tests/test_persistence_retention.py`: Pytest suite (10 test cases) verifying cutoffs, boundary comparisons, dry-runs, cascading deletions, audit preservation, bounded batching, idempotency, audit hash-chain blocking, WAL checkpoints, and simulated database failure rollbacks.

### Modified Files
- `backend/app/repositories/investigation_repository.py`:
  - Added `count_expired_investigations(session, cutoff)`
  - Added `get_expired_investigation_ids(session, cutoff, limit)`
  - Added `delete_investigations_by_ids(session, investigation_ids)`
- `backend/app/repositories/audit_repository.py`:
  - Added `count_expired_audit_events(session, cutoff)`
  - Added `get_expired_audit_ids(session, cutoff, limit)`
  - Added `await session.flush()` in `log_event()` to ensure sequential hashing within a single transaction
- `backend/app/services/__init__.py`:
  - Exported `RetentionService`, `RetentionCutoffs`, `RetentionCandidatesSummary`, `InvestigationPruneResult`, `AuditPruneResult`, `RetentionSweepSummary`
- `backend/app/api/deps.py`:
  - Added `get_retention_service(request: Request) -> RetentionService` dependency provider
- `backend/app/main.py`:
  - Initialized `app.state.retention_service` using the application's engine and sessionmaker during lifespan startup

---

## 3. Retention Cutoff Definitions and Timezone Behavior

### Cutoff Specification
- **Timezone Standard:** Strict UTC (`datetime.now(timezone.utc)`). If an input `now` is naive, it is coerced to UTC; if it has another timezone, it is converted to UTC.
- **Investigation Retention:** Exactly 90 days (`now - timedelta(days=90)`).
- **Audit Event Retention:** Exactly 365 days (`now - timedelta(days=365)`).
- **Boundary Comparison Rule:** Strict `<` comparison (`created_at < cutoff` / `timestamp < cutoff`).
  - Records created at `cutoff - 1 microsecond` are **eligible** for pruning.
  - Records created at `cutoff` or later (`created_at >= cutoff`) are **strictly preserved**.
  - Verified by `test_investigation_boundary_comparison`.

---

## 4. Investigation Cleanup Algorithm & Cascade Verification

### Execution Logic
```text
1. Compute cutoff: cutoff = now_utc - 90 days.
2. Initialize deleted_total = 0, batches_run = 0.
3. While batches_run < max_batches:
     a. Begin transaction on AsyncSession.
     b. Query batch of expired IDs: SELECT investigation_id FROM investigations 
        WHERE created_at < :cutoff ORDER BY created_at ASC LIMIT :batch_size.
     c. If empty: break loop.
     d. DELETE FROM investigations WHERE investigation_id IN (:batch_ids).
     e. Commit transaction.
     f. Increment deleted_total += len(batch_ids).
     g. Log batch completion and yield event loop (await asyncio.sleep(0.01)).
4. If deleted_total > 0 and not dry_run:
     Record AuditEvent(action="INVESTIGATION_EXPIRED_PRUNED", outcome="SUCCESS").
5. Return InvestigationPruneResult(status="COMPLETED", deleted_count=deleted_total).
```

### Cascade Verification
With SQLite PRAGMA `foreign_keys = ON`, deleting the parent `Investigation` record automatically triggers cascading deletions defined in the ORM and schema:
- `investigation_results` (`ondelete="CASCADE"`)
- `investigation_facts` (`ondelete="CASCADE"`)
- `investigation_hypotheses` (`ondelete="CASCADE"`)
- `investigation_checks` (`ondelete="CASCADE"`)
- `investigation_evidence_snapshots` (`ondelete="CASCADE"`)
- `audit_events` has **NO** foreign key to `investigations` and is **100% preserved**.
- Verified by `test_investigation_retention_cascades_children_and_preserves_audit`.

---

## 5. Audit Pruning & Hash-Chain Boundary Design

### Evaluation of ADR-012 Hash Chain
ADR-012 defines a sequential cryptographic hash chain:
$$h_i = \text{SHA256}(\text{CanonicalJSON}(e_i) \,\|\, h_{i-1})$$
where $h_0 = \text{GENESIS\_HASH} = \text{"0"}\times 64$.

Verification traverses from $i=0$ to $N$. If an expired prefix ($e_0, \dots, e_k$) is deleted from the table:
- The earliest surviving event $e_{k+1}$ has `previous_hash` $= h_k$.
- Because $e_k$ is deleted, $h_k$ cannot be recomputed or verified against genesis.
- Any invocation of `verify_chain_integrity()` would fail at index 0 of the surviving set.

### Implemented Decision
Per Section 5 of Phase 7.4 instructions ("If safe pruning cannot be implemented without a new architectural decision, stop audit-event deletion, document the precise blocker, and complete only the independent work that remains safe"):
- Destructive deletion of audit records is **intentionally blocked** in `RetentionService.prune_expired_audit_events()`.
- Dry-run candidate counts are reported for observability (`candidates_count`).
- Calling destructive pruning returns:
  ```python
  AuditPruneResult(
      status="BLOCKED",
      deleted_count=0,
      candidates_count=candidates,
      cutoff=cutoff,
      error_message="Audit pruning blocked: ADR-012 SHA-256 hash-chain integrity requires an approved checkpoint/anchoring schema migration."
  )
  ```
- Verified by `test_audit_retention_pruning_safely_blocked_to_protect_hash_chain`.

---

## 6. Dry-Run & Deletion Safeguards

- **Default Execution Mode:** Dry-run is the default parameter (`dry_run: bool = True`). Destructive execution requires explicit `dry_run=False`.
- **Zero Data Modification:** Dry-run queries only use `SELECT COUNT(*)` and `SELECT id ... LIMIT`. No `DELETE` statements or transactions are executed.
- **No Production Automation:** The FastAPI lifespan initializes the service object on `app.state.retention_service` for dependency injection and administrative scripting, but does **not** trigger cleanup jobs on startup.
- **No Unauthenticated Routes:** Cleanup logic is encapsulated in the service layer and not exposed via any public HTTP routes.

---

## 7. SQLite WAL & Failure-Handling Behavior

- **Checkpoint Execution:** `RetentionService.execute_wal_checkpoint(mode="TRUNCATE")` runs `PRAGMA wal_checkpoint(TRUNCATE)` inside a direct connection context, reclaiming WAL space after large deletion batches.
- **Atomic Batch Rollback:** Each deletion batch runs within its own transaction context (`async with session.begin():`). If an unexpected database error occurs:
  - The transaction rolls back automatically.
  - The service catches the exception, logs structured failure details, and returns `status="FAILED"` with the exact error message.
  - No false success is reported.
- **Retry Safety:** Deletion queries sort by `created_at ASC` and delete in idempotent batches. An interrupted sweep can be retried immediately without corruption or data loss.

---

## 8. Test Execution & Verification

All tests were executed against isolated temporary SQLite databases.

### Retention Test Suite (`test_persistence_retention.py`)
```bash
.\.venv\Scripts\python.exe -m pytest tests/test_persistence_retention.py -v
```
**Results:** 10 passed, 0 failed, 1 warning (Starlette testclient deprecation) in 1.25s:
1. `test_retention_cutoffs_calculation`: PASSED
2. `test_dry_run_identifies_candidates_without_modifications`: PASSED
3. `test_investigation_boundary_comparison`: PASSED
4. `test_investigation_retention_cascades_children_and_preserves_audit`: PASSED
5. `test_investigation_retention_bounded_batches`: PASSED
6. `test_investigation_retention_idempotent_and_safe`: PASSED
7. `test_audit_retention_pruning_safely_blocked_to_protect_hash_chain`: PASSED
8. `test_wal_checkpoint_execution`: PASSED
9. `test_full_retention_sweep_end_to_end`: PASSED
10. `test_simulated_db_failure_returns_failed_status_and_rolls_back`: PASSED

### Full Backend Pytest Suite
```bash
.\.venv\Scripts\python.exe -m pytest -v
```
**Results:** 137 passed, 4 deselected (live external containers), 0 failed in 25.95s.

### Frontend Quality & Contract Verification
```bash
# In frontend/
npm run lint
node tests/validate_client.js
```
**Results:**
- `oxlint`: 0 errors, 2 informational warnings.
- `validate_client.js`: 13/13 contract, security, and immutability checks passed.

---

## 9. Safety & Invariant Confirmations

| Requirement | Confirmation |
|---|---|
| Isolated Test Data Only | Confirmed: All retention tests used isolated SQLite databases created in temporary directories with `ignore_cleanup_errors=True`. |
| Production DB Untouched | Confirmed: `backend/data/siem_history.db` does not exist (`Test-Path` returned `False`). Zero production records touched. |
| Cascade Safety | Confirmed: `investigations` deletion cascaded to child tables without deleting `audit_events`. |
| Audit Hash-Chain Integrity | Confirmed: Destructive audit deletion is blocked; cryptographic hash chain remains 100% verifiable. |
| Git Commits / Pushes | Confirmed: 0 commits, 0 pushes. Working tree preserves all untracked/modified files. |
| Git HEAD | `793e4c4a9e9133e69db5e8462ef3063ef3f0e86b` on branch `main`. |
| Deployment Repository | Confirmed: `F:\MY Project\wazuh-docker` remains strictly untouched. |
| Phase 7.5 Status | Confirmed: Phase 7.5 has not started. |

---

## 10. Summary & Next Steps

Phase 7.4 is complete. The 90-day investigation retention policy is fully implemented and tested with safe bounded batches and cascading child deletion. Audit history is independently preserved, with destructive audit pruning safely blocked to maintain ADR-012 cryptographic hash-chain integrity. The repository is ready for Phase 7.5 (Documentation Hardening & Audit Completion) upon project owner authorization.
