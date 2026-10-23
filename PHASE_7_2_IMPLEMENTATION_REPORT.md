# Phase 7.2 Implementation Report — Investigation & Evidence-Snapshot Persistence

**Project:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Phase:** 7.2 — Investigation & Evidence-Snapshot Persistence  
**Authorization:** Explicitly Authorized by Project Owner  
**Repository:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Deployment Repository:** `F:\MY Project\wazuh-docker` (Strictly Untouched / Read-Only)  
**Git Branch:** `main` | **Git Commit HEAD:** `793e4c4` (Zero Git Commits/Pushes Executed)  
**Report Date:** October 20, 2026  
**Status:** COMPLETE & VERIFIED — READY FOR PHASE 7.3 AUTHORIZATION GATE  

---

## 1. Executive Summary

Phase 7.2 implements durable, transactional persistence for security investigation lifecycles and minimized forensic evidence snapshots, building on the asynchronous SQLAlchemy 2.0 and Alembic migration foundation established in Phase 7.1.

All operations strictly uphold the core security principle: **Wazuh remains the sole authoritative detection and alerting engine; the local LLM operates strictly as an advisory analyst assistant whose hypotheses, facts, and recommendations are persisted with cryptographic provenance and tamper-evident audit logging.**

Key achievements in Phase 7.2:
1. **Transaction-Safe Persistence Repositories:** Implemented `InvestigationRepository` and `AuditRepository` supporting atomic persistence of investigation lifecycles, structured synthesis results, observed facts, hypotheses, read-only checks, and minimized evidence snapshots.
2. **Decoupled Architecture & Bounded Transactions:** Separated database transactions from slow local Ollama inference. Bounded Transaction 1 records the initial `running` state; inference executes unconstrained; Bounded Transaction 2 records `completed` results and snapshots atomically.
3. **In-Flight Conflict Prevention (HTTP 409):** Guarded `POST /api/v1/alerts/{alert_id}/investigate` against concurrent double-investigations on the same alert, returning standard HTTP 409 (`CONFLICT: CONCURRENT_INVESTIGATION_RUNNING`).
4. **Sequential Run Sequencing:** Re-running an alert whose prior investigation concluded (`completed` or `failed`) creates a discrete investigation with an auto-incremented `run_sequence` (Run #1, #2, #3...).
5. **Startup Crash Recovery (`ORPHANED_PROCESS_CRASH`):** Integrated lifespan reconciliation that detects investigations stranded in `running` state due to process termination and transitions them transactionally to `failed` with error reason `ORPHANED_PROCESS_CRASH` and audit logging.
6. **Minimized Evidence Snapshots:** Persists only normalized, allowlisted metadata fields with source pointers (`raw_evidence_ref`) without duplicating full raw OpenSearch alert documents.
7. **Tamper-Evident SHA-256 Hash Chaining:** `AuditRepository` computes canonical SHA-256 hashes linking each audit event to its predecessor, with automated chain verification detecting any database alteration.
8. **100% Test Pass Rate & Zero Regressions:** Authored comprehensive integration test suite `backend/tests/test_investigation_persistence.py`. Full test suite executed with **117 tests passing, 0 failures, 0 regressions**.

---

## 2. Pre-Implementation Working Tree & Safety Verification

Before any source files were modified, the repository state was formally verified:
- **Active Branch:** `main`
- **Git HEAD Commit:** `793e4c4`
- **User Working Tree Changes:** All pre-existing user modifications in `.gitignore`, `App.tsx`, `client.ts`, `index.css`, `types/api.ts`, `DECISIONS.md`, and backend configurations were preserved intact.
- **Git Operations:** Zero commits, zero pushes, zero stashes, zero branch checkouts, and zero resets were executed.
- **Deployment Isolation:** `F:\MY Project\wazuh-docker` remained completely untouched.
- **Database Isolation:** Test runs executed against isolated temporary databases (`tempfile.TemporaryDirectory`), ensuring zero production databases (`data/siem_history.db`) were created during verification.

---

## 3. Repositories Implemented

### 3.1 `InvestigationRepository` (`backend/app/repositories/investigation_repository.py`)
Encapsulates all database interactions for investigations and child entities:
- `get_next_run_sequence(session, alert_id) -> int`: Queries `func.coalesce(func.max(run_sequence), 0) + 1` for monotonic incrementing.
- `get_running_investigation_for_alert(session, alert_id) -> Optional[Investigation]`: Fast indexed lookup for active investigations preventing concurrent conflicts.
- `create_investigation(session, investigation_id, alert, window_minutes, max_items, actor_id) -> Investigation`: Inserts initial lifecycle row in `status='running'`.
- `record_investigation_success(session, investigation_id, result, evidence_package, duration_ms)`: Atomically updates investigation to `completed`, inserts `InvestigationResult`, `InvestigationFact` rows, `InvestigationHypothesis` rows, `InvestigationCheck` rows, and `InvestigationEvidenceSnapshot` rows.
- `record_investigation_failure(session, investigation_id, error_code, error_message, duration_ms)`: Updates investigation to `failed` with bounded error codes and sanitized messages.
- `reconcile_orphaned_investigations(session) -> List[str]`: Bulk-updates any stranded `running` investigations to `failed` with `error_code='ORPHANED_PROCESS_CRASH'`.
- `get_investigation_by_id(session, investigation_id) -> Optional[Investigation]`: Eagerly loads full hierarchy with child facts, hypotheses, checks, and snapshots via `selectinload`.

### 3.2 `AuditRepository` (`backend/app/repositories/audit_repository.py`)
Encapsulates tamper-evident audit logging conforming to RFC 8785 canonical JSON principles:
- `compute_canonical_hash(...) -> str`: Computes deterministic SHA-256 hash over canonical JSON concatenated with `previous_hash`.
- `format_canonical_timestamp(ts) -> str`: Formats timestamp with fixed microsecond precision (`%Y-%m-%dT%H:%M:%S.%fZ`) to eliminate database driver parsing drift.
- `get_latest_hash(session) -> str`: Obtains the hash of the latest audit record, or returns genesis hash `0`*64.
- `log_event(session, actor_id, action, resource_type, resource_id, outcome, request_id, client_ip, metadata, ...)`: Persists an append-only audit event chained to `prev_hash`.
- `verify_chain_integrity(session) -> Tuple[bool, int, Optional[str]]`: Walks the entire audit chain from genesis to tip, verifying all links and hashes, returning `(True, verified_count, None)` or `(False, failed_index, error_reason)`.

### 3.3 `InvestigationPersistenceService` (`backend/app/services/investigation_persistence_service.py`)
Coordinates service-layer transactions, connecting the API router to repositories:
- Manages transactional boundaries around async sessions (`async with session.begin():`).
- Handles rollback and failure recording if database commit fails.
- Synchronizes investigation state transitions with corresponding audit log events (`INVESTIGATION_COMPLETED`, `INVESTIGATION_FAILED`, `CRASH_RECOVERY_RECONCILED`).

---

## 4. Evidence Snapshot Minimization & Sanitization

In strict adherence to ADR-009, full raw OpenSearch documents are never duplicated in the relational database:
- **Allowlisted Fields Only:** Persists only structured fields evaluated during inference: `evidence_id` (`EV-01`), `source_record_id`, `event_timestamp`, `is_primary`, `rule_id`, `rule_level`, `rule_description`, `agent_name`, `source_ip`, `destination_ip`, `username`, `correlation_reason`, `correlation_qualifier`, and `raw_evidence_ref`.
- **Pre-Ingestion Redaction:** All evidence strings pass through `EvidenceService` sanitization (scrubbing AWS keys, passwords, bearer tokens, private keys) before reaching the database.
- **Safe Field Bounds:** Field lengths are strictly enforced (`rule_description` bounded to 2048 chars, strings bounded to column definitions).
- **Citation Validation:** In `record_investigation_success`, fact citations (`fact.cited_evidence_ids`) and hypothesis citations (`hyp.cited_evidence_ids`) are verified against `valid_evidence_ids = {item.evidence_id for item in evidence_package.items}` to ensure no dangling or hallucinated evidence references are stored.

---

## 5. Investigation Lifecycle & State Transitions

The state machine strictly enforces the approved lifecycle:

```
[Trigger Request]
       |
       v
+--------------+     Inference Failed / Timed Out
|   running    | -------------------------------------> +--------------+
+--------------+                                       |    failed    |
       |                                                +--------------+
       | Inference Succeeded &                                ^
       | Persistence Committed                                | Process Crash at Startup
       v                                                      | (ORPHANED_PROCESS_CRASH)
+--------------+                                              |
|  completed   |                                              |
+--------------+ ---------------------------------------------+
```

1. **`running`**: Persisted immediately upon endpoint initiation before evidence building and Ollama inference.
2. **`completed`**: Transitioned atomically only after all result records, child facts, hypotheses, checks, snapshots, and audit log entries have successfully committed to the database.
3. **`failed`**: Transitioned if inference times out (HTTP 504), Ollama is offline (HTTP 503), model output is malformed (HTTP 502), or persistence fails (HTTP 500).
4. **`cancelled`**: Reserved for analyst-initiated cancellations.

---

## 6. Endpoint Integration & In-Flight Conflict Prevention

The endpoint `POST /api/v1/alerts/{alert_id}/investigate` in `backend/app/api/v1/alerts.py` was updated with the full Phase 7.2 persistence workflow:

1. **Input Validation & Retrieval:** Validates `alert_id` format and retrieves authoritative alert from OpenSearch.
2. **In-Flight Conflict Check:** Queries `persistence_service.get_running_investigation_for_alert(clean_id)`. If an active investigation exists, immediately aborts with:
   ```json
   {
     "error": {
       "code": "CONFLICT",
       "message": "An investigation is already in progress for alert 'alert-12345'.",
       "request_id": "req-...",
       "details": {
         "error_code": "CONCURRENT_INVESTIGATION_RUNNING",
         "investigation_id": "inv-...",
         "status": "running"
       }
     }
   }
   ```
3. **Transaction 1 (Bounded Start):** Persists `running` investigation record with calculated `run_sequence` (e.g. Run 1, Run 2).
4. **Decoupled Inference:** Evidence building and Ollama inference execute without holding an open database transaction, preventing SQLite WAL lock contention during slow model generation.
5. **Inference Failure Interception:** Catches `AppException` and generic exceptions, records failure metadata in the database with exact duration, and re-raises.
6. **Transaction 2 (Bounded Complete):** Persists full result set and sanitized snapshots in an atomic transaction. If persistence fails, marks investigation as `failed` with `PERSISTENCE_TRANSACTION_FAILED` and raises HTTP 500 (never returns 200 OK on persistence failure).

---

## 7. Startup Crash Recovery Reconciliation

Implemented in `backend/app/main.py` lifespan manager:
1. At application startup, invokes `persistence_service.reconcile_orphaned_at_startup()`.
2. Queries all investigations where `status == 'running'`.
3. In a single atomic transaction:
   - Updates all orphaned records to `status='failed'`, `error_code='ORPHANED_PROCESS_CRASH'`, `error_message='Investigation was in progress when backend process terminated unexpectedly.'`.
   - Logs an audit event `CRASH_RECOVERY_RECONCILED` for each reconciled investigation.
4. Leaves `completed`, `failed`, `queued`, and `cancelled` investigations untouched.
5. Emits an operational warning log summarizing the count of reconciled records.
6. In `APP_ENV='production'`, startup fails closed if the database operation fails.

---

## 8. Test Execution & Verification Matrix

A dedicated test suite `backend/tests/test_investigation_persistence.py` was authored and executed alongside all existing test suites.

### 8.1 Phase 7.2 Dedicated Tests (`test_investigation_persistence.py`)

| Test Case | Scenario / Condition | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| `test_investigation_start_and_complete_lifecycle` | Start investigation -> complete with result, facts, hypotheses, checks, snapshots, audit event | `running` -> `completed`, full entity graph persisted, audit event chained to genesis | Verified | **PASS** |
| `test_investigation_failure_lifecycle` | Start investigation -> simulate inference timeout / failure | `running` -> `failed`, `error_code='UPSTREAM_TIMEOUT'`, failure audit event written | Verified | **PASS** |
| `test_sequential_investigations_increment_run_sequence` | Execute 3 consecutive investigations on the same alert | `run_sequence` increments monotonically (1 -> 2 -> 3) | Verified | **PASS** |
| `test_startup_crash_recovery_reconciles_running_investigations` | 2 investigations in `running`, 1 in `completed`; trigger crash recovery | Orphaned records marked `failed` with `ORPHANED_PROCESS_CRASH`, completed unaffected, recovery audit events created | Verified | **PASS** |
| `test_atomic_rollback_on_persistence_failure` | Simulated DB failure during snapshot insertion | Entire transaction rolls back; investigation remains in prior state, zero orphaned results/snapshots, zero audit events leaked | Verified | **PASS** |
| `test_audit_hash_chain_integrity_and_tamper_detection` | Log multiple audit events; verify chain; simulate deliberate DB record tampering | `verify_chain_integrity()` succeeds on intact chain; immediately detects altered row and returns failure | Verified | **PASS** |
| `test_endpoint_investigate_persistence_and_conflict` | TestClient call to `/alerts/{alert_id}/investigate`; then trigger while running | First returns 200 OK and persists; second returns HTTP 409 Conflict with `CONFLICT: CONCURRENT_INVESTIGATION_RUNNING` | Verified | **PASS** |

### 8.2 Full Backend Regression Suite

```cmd
.\.venv\Scripts\python.exe -m pytest
================ 117 passed, 4 deselected, 1 warning in 21.33s ================
```

- `tests/test_alerts.py`: 12 passed
- `tests/test_config.py`: 3 passed
- `tests/test_connectors.py`: 9 passed
- `tests/test_correlation.py`: 38 passed
- `tests/test_database_connection.py`: 4 passed
- `tests/test_database_migrations.py`: 4 passed
- `tests/test_errors.py`: 3 passed
- `tests/test_health.py`: 4 passed
- `tests/test_investigation_api.py`: 8 passed
- `tests/test_investigation_persistence.py`: 7 passed
- `tests/test_investigation_schema.py`: 14 passed
- `tests/test_ollama_client.py`: 11 passed
- **Total:** **117 passed, 0 failed, 0 regressions.**

---

## 9. Files Changed & Added

| File Path | Action | Description |
|---|---|---|
| `backend/app/schemas/error.py` | Modified | Added `CONFLICT` and `INSUFFICIENT_STORAGE` to `ErrorCode` enum |
| `backend/app/core/errors.py` | Modified | Added HTTP 409 (`CONFLICT`) and 507 (`INSUFFICIENT_STORAGE`) mapping in exception handlers |
| `backend/app/repositories/__init__.py` | Created | Repository package exports |
| `backend/app/repositories/investigation_repository.py` | Created | Full investigation lifecycle, result persistence, evidence snapshot insertion, in-flight check, and crash recovery |
| `backend/app/repositories/audit_repository.py` | Created | Tamper-evident audit logging with canonical SHA-256 hash chaining and chain integrity verification |
| `backend/app/services/investigation_persistence_service.py` | Created | Transactional coordination service for investigations and audit trails |
| `backend/app/api/deps.py` | Modified | Added `get_investigation_persistence_service` dependency provider |
| `backend/app/api/v1/alerts.py` | Modified | Integrated persistence, conflict prevention (409), decoupled timing, and failure handling into `investigate_alert_endpoint` |
| `backend/app/main.py` | Modified | Added startup crash recovery reconciliation and engine disposal in lifespan |
| `backend/tests/conftest.py` | Modified | Pre-initializes isolated test database schema to protect production `data/siem_history.db` |
| `backend/tests/test_investigation_persistence.py` | Created | Comprehensive Phase 7.2 test suite verifying persistence, lifecycle, conflict, snapshots, rollback, and audit chaining |

---

## 10. Non-Negotiable Rules Adherence Review

1. **Wazuh as Authoritative Detector:** Preserved. Wazuh remains the authoritative source of alerts. Investigations analyze existing detections without creating authoritative SIEM rules.
2. **Local AI Remains Advisory:** Preserved. Persisted investigation results explicitly record `disclaimer`, `confidence_label`, `limitations`, and mark all checks as `is_read_only=True`.
3. **No Unauthenticated Changes:** Preserved. Route-level auth and loopback restrictions are preserved.
4. **Data Minimization:** Preserved. Evidence snapshots persist only allowlisted metadata fields and source pointers (`raw_evidence_ref`), not raw OpenSearch document blobs.
5. **Credential Scrubbing:** Preserved. Pre-ingestion redaction ensures zero secrets or tokens are persisted.
6. **Zero Git Commits/Pushes:** Preserved. Working tree has uncommitted modifications only. Git HEAD is unchanged at `793e4c4`.
7. **Deployment Untouched:** Preserved. `F:\MY Project\wazuh-docker` remains untouched.

---

## 11. Known Limitations & Phase 7.3 Boundary

- **Read APIs Pending (Phase 7.3):** Investigation history query endpoints (`GET /api/v1/investigations`, `GET /api/v1/investigations/{id}`, and alert-to-investigation link retrieval) are scheduled for Phase 7.3.
- **Frontend History UI Pending (Phase 7.3):** SOC analyst investigation history views, run tabs, and snapshot inspectors will be implemented in Phase 7.3.
- **Automated Retention Pruning (Phase 7.4):** Background 90-day investigation pruning and 365-day audit archiving are scheduled for Phase 7.4.

---

## 12. Conclusion & Phase 7.3 Authorization Gate

Phase 7.2 is fully implemented, verified, and regression-free. The system now durably records every alert investigation, protects against concurrent run conflicts, safely recovers stranded jobs on startup, and guarantees tamper-evident audit trails.

**Phase 7.2 is COMPLETE. Awaiting explicit Project Owner authorization before initiating Phase 7.3.**
