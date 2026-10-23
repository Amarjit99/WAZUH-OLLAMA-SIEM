# Implementation Plan — Phase 7: Secure Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_IMPLEMENTATION_PLAN.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** Staged Execution Roadmap from Infrastructure Setup to Production Hardening  
**Authors:** SOC Engineering Lead & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. Stage Overview & Delivery Cadence

To preserve the validated Phase 6B baseline and avoid broad, unverified changes, Phase 7 implementation is strictly partitioned into seven distinct, reviewable stages:

```
[Phase 7.0: Design Review & Decisions]
        |
        v
[Phase 7.1: Persistence Foundation & Alembic Migrations]
        |
        v
[Phase 7.2: Investigation & Evidence-Snapshot Persistence]
        |
        v
[Phase 7.3: Authenticated History & Detail REST APIs]
        |
        v
[Phase 7.4: Frontend Investigation History Drawer & Navigation]
        |
        v
[Phase 7.5: Retention Pruning, Soft-Purge, & Sanitized Exports]
        |
        v
[Phase 7.6: Security Hardening, Tamper Integrity, & Recovery Drills]
```

> [!NOTE]
> These stages represent the implementation roadmap for subsequent coding tasks. No code changes or migrations are executed during this documentation-only phase.

---

## 2. Stage-by-Stage Specifications

### Stage 7.0: Architecture Alignment & Design Sign-off
- **Dependencies:** Completion and approval of Phase 7 documentation package (`PHASE_7_*.md`).
- **Files Expected to Change:** `specs/DECISIONS.md` (recording formal acceptance of ADR-007 implementation approach).
- **Implementation Tasks:**
  - Review proposed SQLite WAL vs. PostgreSQL tradeoffs with stakeholders.
  - Confirm retention duration (`INVESTIGATION_RETENTION_DAYS=90`).
  - Resolve pending design items identified in Section 5 of Phase 7 requirements.
- **Tests:** None (Specification sign-off).
- **Security Review Points:** Confirm loopback-only binding, absence of exposed database network ports, and NTFS ACL strategy.
- **Acceptance Criteria:** Written stakeholder consensus on engine selection and schema normalization.
- **Rollback Considerations:** Zero risk; documentation only.
- **Explicit Exclusions:** No database creation or dependency installation.

---

### Stage 7.1: Persistence Foundation & Migration Framework
- **Dependencies:** Stage 7.0 sign-off.
- **Files Expected to Change:**
  - `backend/pyproject.toml` (add `sqlalchemy>=2.0.0`, `aiosqlite>=0.20.0`, `alembic>=1.13.0`)
  - `backend/app/core/config.py` (add `DATABASE_URL`, `DATABASE_ECHO`, `INVESTIGATION_RETENTION_DAYS`)
  - `backend/app/db/session.py` (async engine, connection event listeners for `PRAGMA foreign_keys=ON;`, `journal_mode=WAL;`, `busy_timeout=5000;`)
  - `backend/app/db/base.py` (SQLAlchemy declarative base)
  - `backend/alembic.ini` and `backend/alembic/env.py` (configured with `render_as_batch=True`)
  - `backend/alembic/versions/20261021_0001_initial_tables.py`
- **Implementation Tasks:**
  - Configure async SQLAlchemy 2.0 connection manager for SQLite WAL mode (`sqlite+aiosqlite:///data/siem_history.db`).
  - Register SQLite connection hooks enforcing foreign keys, WAL mode, normal synchronous writes, and busy timeout.
  - Establish Alembic async migration environment with batch mode support.
  - Author initial migration script defining tables (`investigations` with denormalized `primary_rule_id` and `primary_agent_name`, `investigation_results`, `investigation_facts`, `investigation_hypotheses`, `investigation_checks`, `investigation_evidence_snapshots`, `audit_events` with hash chain columns).
- **Tests:**
  - `backend/tests/test_database_migrations.py`: Test migration `upgrade` and `downgrade` lifecycle.
  - `backend/tests/test_database_connection.py`: Test async session creation, rollback, connection pooling, and PRAGMA enforcement.
- **Security Review Points:** Verify database file is created inside restricted directory with appropriate host ACLs. Verify no passwords in connection URL.
- **Acceptance Criteria:** `alembic upgrade head` creates all normalized tables with constraints, indexes, and foreign keys active.
- **Rollback Considerations:** Revert `pyproject.toml`, run `alembic downgrade base`, remove `data/` directory.
- **Explicit Exclusions:** No route handler integration or frontend modifications.

---

### Stage 7.2: Investigation & Evidence-Snapshot Persistence
- **Dependencies:** Stage 7.1 complete.
- **Files Expected to Change:**
  - `backend/app/repositories/investigation_repository.py`
  - `backend/app/repositories/audit_repository.py`
  - `backend/app/services/investigation_persistence_service.py`
  - `backend/app/main.py` (lifespan startup reconciliation hook for stale `running` jobs)
  - `backend/app/api/v1/alerts.py` (update `/investigate` endpoint to persist results)
- **Implementation Tasks:**
  - Implement `InvestigationRepository` with atomic transaction boundaries.
  - Implement `AuditRepository` with canonical JSON serialization and SHA-256 hash chaining.
  - Implement startup reconciliation hook marking any stale `running` investigations as `failed` (`ORPHANED_PROCESS_CRASH`).
  - Hook persistence into `/alerts/{alert_id}/investigate` so completed, failed, and cancelled investigations are recorded atomically without blocking inference.
- **Tests:**
  - `backend/tests/test_investigation_repository.py`: CRUD operations, multi-run sequence numbering, foreign key cascade checks.
  - `backend/tests/test_investigation_atomic_persistence.py`: Simulated failure during snapshot creation verifying clean transaction rollback.
  - `backend/tests/test_crash_recovery.py`: Startup reconciliation for interrupted jobs.
- **Security Review Points:** Verify evidence snapshots undergo regex redaction before SQL insertion.
- **Acceptance Criteria:** Running an AI investigation writes valid, queryable rows to `investigations`, `investigation_results`, and `investigation_evidence_snapshots`.
- **Rollback Considerations:** Comment out persistence service call in `/investigate` endpoint; existing Phase 6B ephemeral behavior resumes immediately.
- **Explicit Exclusions:** No history retrieval API routes yet.

---

### Stage 7.3: Authenticated History & Detail REST APIs
- **Dependencies:** Stage 7.2 complete.
- **Files Expected to Change:**
  - `backend/app/api/v1/investigations.py` (new router)
  - `backend/app/schemas/history.py` (request/response models)
  - `backend/app/main.py` (mount `/api/v1/investigations` router)
- **Implementation Tasks:**
  - Implement `GET /api/v1/investigations` (paginated list with rule, host, alert, time filters).
  - Implement `GET /api/v1/investigations/{investigation_id}` (full detail and evidence snapshots).
  - Enforce `verify_api_auth` on all endpoints.
- **Tests:**
  - `backend/tests/test_investigations_api.py`: Filter validation, pagination bounds ($\le 100$), 401 unauthenticated checks, 404 missing ID checks.
- **Security Review Points:** Verify SQL injection impossibility through parameterized queries. Verify constant-time Bearer token check.
- **Acceptance Criteria:** Authenticated API client can list past investigations and retrieve full investigation details in $< 50\text{ ms}$.
- **Rollback Considerations:** Unmount `/investigations` router in `backend/app/main.py`.
- **Explicit Exclusions:** Frontend UI integration.

---

### Stage 7.4: Frontend Investigation History
- **Dependencies:** Stage 7.3 complete.
- **Files Expected to Change:**
  - `frontend/src/api/client.ts` (add `listInvestigations`, `getInvestigationById`)
  - `frontend/src/types/api.ts` (add history types)
  - `frontend/src/components/InvestigationHistoryDrawer.tsx` (new component)
  - `frontend/src/components/InvestigationModal.tsx` (detect and load previous runs)
  - `frontend/src/App.tsx` (history navigation button in header)
  - `frontend/src/index.css` (history drawer styling)
- **Implementation Tasks:**
  - Build responsive History Drawer displaying past investigations with status pills, timestamps, rule IDs, and confidence levels.
  - In `InvestigationModal`, if prior investigations exist for the selected alert, provide options to view prior runs or execute a new investigation.
- **Tests:**
  - `frontend/tests/validate_client.js`: Verify new endpoints adhere to contract.
  - Frontend build and lint checks (`npm run lint`, `npm run build`).
- **Security Review Points:** Verify 100% avoidance of `dangerouslySetInnerHTML`. Ensure safe escaping of stored strings.
- **Acceptance Criteria:** Analyst can view, filter, and inspect past investigations directly in the UI without re-running Ollama.
- **Rollback Considerations:** Revert frontend components; revert to Phase 6B modal UI.
- **Explicit Exclusions:** Bulk export and deletion utilities.

---

### Stage 7.5: Retention Pruning, Soft-Purge, & Sanitized Exports
- **Dependencies:** Stage 7.4 complete.
- **Files Expected to Change:**
  - `backend/app/services/retention_service.py`
  - `backend/app/api/v1/investigations.py` (add `DELETE` and `/export` routes)
  - `backend/app/cli/maintenance.py` (CLI command for retention cleanup)
- **Implementation Tasks:**
  - Implement `GET /api/v1/investigations/{id}/export` streaming sanitized Markdown and JSON reports.
  - Implement `DELETE /api/v1/investigations/{id}` with soft-delete flag and immutable audit logging.
  - Implement automated retention pruner deleting records older than `INVESTIGATION_RETENTION_DAYS`.
- **Tests:**
  - `backend/tests/test_retention_and_export.py`: Expiration pruning verification, export sanitization checks, audit log creation.
- **Security Review Points:** Verify exports do not contain unredacted secrets or formula injection characters (`=`, `+`, `-`, `@`).
- **Acceptance Criteria:** Analyst can export reports and delete records; retention cleanup successfully purges expired records.
- **Rollback Considerations:** Disable deletion endpoint and retention task.
- **Explicit Exclusions:** Advanced recovery and chaos testing.

---

### Stage 7.6: Security Hardening, Tamper Integrity & Recovery Drills
- **Dependencies:** Stages 7.1–7.5 complete.
- **Files Expected to Change:**
  - `backend/app/services/integrity_service.py`
  - `backend/tests/test_security_persistence.py`
  - `backend/tests/test_disaster_recovery.py`
- **Implementation Tasks:**
  - Implement audit hash-chain verification routine.
  - Implement automated disk-space guard ($< 500\text{ MB}$ quota tripwire).
  - Execute database corruption drill (`PRAGMA integrity_check`) and vacuum backup recovery.
- **Tests:**
  - Full non-live and live test regression suites.
  - Tamper injection test verifying that modifying an audit row breaks chain validation.
- **Security Review Points:** Verify NTFS file permissions and lack of open network ports via port audit.
- **Acceptance Criteria:** 100% passing test suite across all suites with documented disaster recovery drill.
- **Rollback Considerations:** Operational safeguards; zero disruption.
