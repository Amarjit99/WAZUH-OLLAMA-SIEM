# Comprehensive Test Plan — Phase 7: Secure Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_TEST_PLAN.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** Verification Strategy, Test Fixtures, Integrity & Security Assurance  
**Target Platform:** Pytest (AsyncIO, AnyIO), SQLite In-Memory / File Engine, Playwright / Node Validation  
**Authors:** SOC QA & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. Test Strategy Overview

Testing Phase 7 persistence demands a rigorous, multi-tiered verification approach. Because security investigations involve forensic evidence and audit accountability, tests must guarantee:
1. **Zero Data Loss:** Transactions either commit completely or roll back cleanly.
2. **Fail-Safe Operation:** Database locks or outages never crash the core live SIEM.
3. **Immutability of Audit Trails:** Audit events cannot be silently altered or deleted.
4. **Leak-Free Persistence:** Secrets, tokens, and unredacted PII never reach database disk pages.

```
+-------------------------------------------------------------------+
|                        Test Strategy Pyramid                      |
|                                                                   |
|   [E2E / Live Drills]      Backup restore, recovery, live Ollama  |
|   [Security / Chaos]       SQLi, tampering, disk-full, locking    |
|   [API Contract / Auth]    Routes, pagination, filters, Bearer    |
|   [Integration / Schema]   Alembic upgrade/downgrade, cascades    |
|   [Unit / Repository]      CRUD, serialization, redaction tests   |
+-------------------------------------------------------------------+
```

---

## 2. Test Fixtures & Environment Matrix

### 2.1 Pytest Database Fixtures
- `@pytest.fixture(scope="function") async def test_db_session()`:
  Creates an isolated in-memory or temporary SQLite database (`sqlite+aiosqlite:///:memory:` or temporary directory), applies `alembic upgrade head`, yields an active async session, and drops all objects upon teardown.
- `@pytest.fixture def sample_investigation_result()`:
  Returns a validated `InvestigationResult` with 1 fact (`F-1`), 1 hypothesis (`H-1`), 1 check (`C-1`), and 2 evidence items (`EV-01`, `EV-02`).
- `@pytest.fixture def sample_evidence_package()`:
  Returns a bounded `EvidencePackage` conforming to `DATA_SCHEMA.md`.

---

## 3. Test Suites & Verification Criteria

### 3.1 Migration & Schema Integrity Tests (`tests/test_persistence_migrations.py`)
- **T-MIG-1 (Forward & Backward Migration):**
  - *Action:* Execute `alembic upgrade head` followed by `alembic downgrade base`.
  - *Expected Outcome:* All tables created successfully, and subsequently dropped cleanly without foreign key lockups or dangling constraints.
- **T-MIG-2 (Foreign Key Enforcement):**
  - *Action:* Attempt inserting an `investigation_results` row with a non-existent `investigation_id`.
  - *Expected Outcome:* Database raises `IntegrityError` (foreign key constraint violated).
- **T-MIG-3 (Cascade Deletion):**
  - *Action:* Delete an investigation row from `investigations`.
  - *Expected Outcome:* Associated rows in `investigation_results`, `investigation_facts`, `investigation_hypotheses`, `investigation_checks`, and `investigation_evidence_snapshots` are deleted automatically. `audit_events` remains untouched.
- **T-MIG-4 (SQLite Connection PRAGMA Verification):**
  - *Action:* Open connection via SQLAlchemy pool and query `PRAGMA foreign_keys;`, `PRAGMA journal_mode;`, `PRAGMA busy_timeout;`.
  - *Expected Outcome:* Returns `foreign_keys=1`, `journal_mode=wal`, `busy_timeout=5000`.

### 3.2 Repository & Atomic Transaction Tests (`tests/test_persistence_repository.py`)
- **T-REPO-1 (Atomic Finalization Success):**
  - *Action:* Finalize an investigation with 5 facts, 3 hypotheses, and 10 evidence items.
  - *Expected Outcome:* Single atomic transaction commits; querying by ID returns exact match for all nested entities.
- **T-REPO-2 (Rollback on Mid-Transaction Failure):**
  - *Action:* Simulate an error while inserting evidence snapshots (e.g., duplicate snapshot ID).
  - *Expected Outcome:* Entire transaction rolls back; no orphaned investigation results or partial evidence rows exist.
- **T-REPO-3 (Multi-Run Sequence Increment):**
  - *Action:* Record 3 successive investigations for alert `alert-001`.
  - *Expected Outcome:* `run_sequence` automatically assigns 1, 2, and 3 respectively.

### 3.3 API Contract, Filtering & Pagination Tests (`tests/test_investigations_api.py`)
- **T-API-1 (List Pagination Bounds):**
  - *Action:* Seed 150 investigations; query `GET /api/v1/investigations?page=1&page_size=50`.
  - *Expected Outcome:* Returns first 50 items with `total_items=150`, `total_pages=3`, `has_next=true`.
- **T-API-2 (Page Size Clamping):**
  - *Action:* Query with `page_size=200`.
  - *Expected Outcome:* HTTP 422 or clamped to maximum allowable 100 per API contract.
- **T-API-3 (Multi-Parameter Filtering):**
  - *Action:* Filter by `rule_id=5710` AND `confidence_label=medium` AND date range.
  - *Expected Outcome:* Returns strictly matching records; query uses index and completes in $< 50\text{ ms}$.
- **T-API-4 (Missing / Soft-Deleted Record):**
  - *Action:* Query `GET /api/v1/investigations/{deleted_id}`.
  - *Expected Outcome:* Returns HTTP 404 with standard error envelope.

### 3.4 Concurrency, Idempotency & Conflict Tests (`tests/test_persistence_concurrency.py`)
- **T-CONC-1 (Concurrent Execution Lockout):**
  - *Action:* Trigger two simultaneous `/investigate` POST requests for the same `alert_id`.
  - *Expected Outcome:* One request proceeds to inference; the second receives HTTP 409 (`CONFLICT: CONCURRENT_INVESTIGATION_RUNNING`).
- **T-CONC-2 (Concurrent Readers and Writers in WAL Mode):**
  - *Action:* Execute 50 concurrent history read requests while a write transaction commits an investigation.
  - *Expected Outcome:* Zero deadlocks; zero `OperationalError: database is locked`.

### 3.5 Negative Security & Injection Tests (`tests/test_persistence_security.py`)
- **T-SEC-1 (SQL Injection in Filters):**
  - *Action:* Send `rule_id="5710' OR '1'='1"` and `alert_id="'; DROP TABLE investigations; --"`.
  - *Expected Outcome:* Queries parameterized safely; no SQL syntax error; no unauthorized data disclosure; tables intact.
- **T-SEC-2 (Unauthenticated Request Rejection):**
  - *Action:* Issue `GET /api/v1/investigations` with no Bearer token or invalid token.
  - *Expected Outcome:* HTTP 401 with standard error envelope.
- **T-SEC-3 (Secret Sanitization Verification):**
  - *Action:* Pass evidence containing `password="SuperSecret123!"` and `Authorization: Bearer test_token`.
  - *Expected Outcome:* Database stores `[REDACTED]`; plaintext secret never appears in database rows or raw file strings.

### 3.6 Chaos & Failure Recovery Drills (`tests/test_persistence_chaos.py`)
- **T-CHAOS-1 (Database Offline Graceful Degradation):**
  - *Action:* Point backend to non-existent database file or simulate read-only permissions.
  - *Expected Outcome:* Live alert browsing continues normally. Investigation endpoint returns advisory warning or explicit 503 without crashing Uvicorn process.
- **T-CHAOS-2 (Simulated Disk-Full Condition):**
  - *Action:* Mock filesystem reporting free space $< 500\text{ MB}$.
  - *Expected Outcome:* Write operations rejected with HTTP 507 (`INSUFFICIENT_STORAGE`); existing database file not corrupted.
- **T-CHAOS-3 (Integrity Verification on Startup):**
  - *Action:* Introduce corrupted byte into SQLite database header.
  - *Expected Outcome:* Startup health check detects failure, isolates file, and alerts administrator.
- **T-CHAOS-4 (Startup Crash Recovery for Stale Jobs):**
  - *Action:* Seed database with an investigation in `status='running'`; trigger application lifespan startup.
  - *Expected Outcome:* Startup reconciliation sweep updates record to `status='failed'`, `error_code='ORPHANED_PROCESS_CRASH'`, and writes an audit event.

### 3.7 Retention, Export & Audit Tests (`tests/test_persistence_retention.py`)
- **T-RET-1 (Expiration Pruning via Bounded Batches):**
  - *Action:* Seed 250 records with `created_at` older than 90 days; execute bounded retention cleanup (batch size 100).
  - *Expected Outcome:* Expired investigations and evidence snapshots deleted in batches; `PRAGMA wal_checkpoint(TRUNCATE)` executed.
- **T-RET-2 (Audit Log Immutability & Independence):**
  - *Action:* Verify that deletion of an investigation produces an audit log record and does NOT delete prior audit records.
- **T-RET-3 (Export Sanitization):**
  - *Action:* Export investigation to Markdown and JSON.
  - *Expected Outcome:* Valid formatted document returned; zero token leakage; advisory banner included.
- **T-RET-4 (Audit Hash Chain Tamper Detection):**
  - *Action:* Seed 10 audit events with valid hash chain; maliciously modify `action` in row 5 directly via raw SQL; run audit integrity checker.
  - *Expected Outcome:* Integrity checker detects hash mismatch at row 5, logs security alert, and identifies exact tampered record.

---

## 4. Expected Acceptance Gates

```
+--------------------------------------------------------------+
| Phase 7 Acceptance Gate: All suites must pass with exit code 0 |
|  - Unit & Repository:      100% pass                         |
|  - Migrations:             100% pass (upgrade + downgrade)   |
|  - API Contract & Auth:    100% pass                         |
|  - Security & Injection:   100% pass                         |
|  - Concurrency & Chaos:    100% pass                         |
|  - Full Regression Suite:  Zero regressions against Phase 6B |
+--------------------------------------------------------------+
```
