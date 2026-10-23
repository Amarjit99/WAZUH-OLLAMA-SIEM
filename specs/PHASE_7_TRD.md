# Technical Requirements Document (TRD) — Phase 7: Secure Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_TRD.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** Phase 7 Documentation & Architecture Planning  
**Target Platform:** FastAPI, SQLAlchemy 2.0 (Async), Alembic, Pydantic v2  
**Authors:** SOC Architecture & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. Architectural Overview & Component Boundaries

The persistence layer for Phase 7 integrates cleanly with the existing hexagonal architecture established in Phases 1–6B.

```
       +--------------------------------------------------------+
       |             Browser / React Analyst UI                |
       +--------------------------------------------------------+
                                   |
                             HTTP / JSON
                 (Loopback 127.0.0.1:5174 -> 127.0.0.1:8001)
                    Bearer Token Auth: verify_api_auth
                                   v
+----------------------------------------------------------------------+
|                     FastAPI Application Core                        |
|                                                                      |
|  [Routers]                                                          |
|    - /api/v1/alerts (Live OpenSearch / Wazuh alerts)                 |
|    - /api/v1/investigations (History, Details, Exports)              |
|                                                                      |
|  [Service & Orchestration Layer]                                     |
|    - EvidenceService (Sanitization, Bounding, Correlation)          |
|    - OllamaClient (Structured Local Inference via 127.0.0.1:11434)   |
|    - InvestigationPersistenceService (Atomic lifecycle & snapshots)  |
|                                                                      |
|  [Repository & Data Access Layer]                                    |
|    - InvestigationRepository (CRUD & Filtered Pagination)           |
|    - AuditRepository (Immutable Audit Event Logging)                |
|    - DatabaseSessionManager (SQLAlchemy 2.0 Async Session Factory)   |
+----------------------------------------------------------------------+
                                   |
                       Async Connection Pool (Loopback)
                                   v
+----------------------------------------------------------------------+
|                       Relational Database Layer                      |
|           Default Local Driver: SQLite via aiosqlite / WAL Mode      |
|       (Production Evolution Path: PostgreSQL via asyncpg per ADR-007)|
+----------------------------------------------------------------------+
```

### 1.1 Strict Boundary Invariants
1. **Frontend Isolation:** The frontend React application interacts exclusively with the backend via `/api/v1` authenticated JSON REST endpoints. No direct SQL or database socket communication occurs from the browser.
2. **SIEM Non-Interference:** The database engine is strictly decoupled from the live detection pipeline. If the persistence store fails or becomes locked, Wazuh alert ingestion and live OpenSearch querying continue unimpeded.
3. **Repository Abstraction:** Route handlers never execute inline SQL queries or touch the raw database session directly; they interact through typed Repository interfaces (`InvestigationRepository`, `AuditRepository`).

---

## 2. Backend Persistence Service & Repository Layer

### 2.1 Repository Pattern Design
The persistence implementation introduces clean, testable repository interfaces:

```python
# Conceptual Interface: app/repositories/investigation_repository.py

class InvestigationRepository(Protocol):
    async def create_investigation(
        self, session: AsyncSession, record: InvestigationRecordCreate
    ) -> InvestigationRecord: ...

    async def finalize_investigation(
        self,
        session: AsyncSession,
        investigation_id: str,
        result: InvestigationResult,
        evidence_items: List[EvidenceItem],
    ) -> InvestigationRecord: ...

    async def fail_investigation(
        self,
        session: AsyncSession,
        investigation_id: str,
        error_code: str,
        error_message: str,
    ) -> InvestigationRecord: ...

    async def get_by_id(
        self, session: AsyncSession, investigation_id: str
    ) -> Optional[InvestigationDetail]: ...

    async def list_investigations(
        self,
        session: AsyncSession,
        filters: InvestigationFilterParams,
        pagination: PaginationParams,
    ) -> PagedResult[InvestigationSummary]: ...

    async def soft_delete(
        self, session: AsyncSession, investigation_id: str
    ) -> bool: ...
```

### 2.2 Lifecycle & Atomic Transaction Boundaries
Every investigation operation follows strict transactional guarantees:

1. **Phase 1: Initiation (`POST /api/v1/alerts/{alert_id}/investigate`):**
   - Transaction begins.
   - Initial record inserted into `investigations` with `status='running'`, target `alert_id`, denormalized `primary_rule_id`, `primary_agent_name`, timestamp, and query parameters.
   - Transaction commits immediately so that concurrent monitoring can observe the active job.
2. **Phase 2: Evidence Gathering & Local AI Inference:**
   - Executed outside of database transactions to prevent holding database locks during LLM inference (which may take 5–25 seconds).
3. **Phase 3: Finalization & Snapshot Insertion:**
   - Single atomic transaction begins:
     - `investigations` status updated to `'completed'`, `execution_duration_ms` recorded.
     - `investigation_results` record inserted with summary, calibrated confidence, limitations, and grounding warnings.
     - `investigation_facts` inserted with foreign keys.
     - `investigation_hypotheses` inserted with uncertainty ratings.
     - `investigation_checks` inserted with read-only flags.
     - `investigation_evidence_snapshots` inserted for each evaluated `EvidenceItem`.
     - `audit_events` entry written with SHA-256 hash chaining.
   - Transaction commits atomically. If any constraint fails, the entire snapshot rolls back, and the investigation status is updated to `'failed'` with error details.

### 2.3 Mandatory SQLite Connection Listener & PRAGMA Hooks
> [!CRITICAL]
> SQLite disables foreign key constraint checking by default on every new database connection.
The session factory (`app/db/session.py`) MUST register a `connect` event listener on `engine.sync_engine`:
- `PRAGMA foreign_keys = ON;` (Mandatory for cascade deletes and foreign key integrity)
- `PRAGMA journal_mode = WAL;` (Enables non-blocking concurrent readers)
- `PRAGMA synchronous = NORMAL;` (Safe fsync durability in WAL mode)
- `PRAGMA busy_timeout = 5000;` (5-second lock timeout before SQLITE_BUSY)

### 2.4 Startup Crash Recovery & Stale State Reconciliation
If the backend process terminates unexpectedly (SIGKILL, power failure, OS restart) during Phase 2 inference:
- The investigation record remains frozen in `status='running'`.
- On application startup (FastAPI lifespan hook), a startup reconciliation query runs:
  ```sql
  UPDATE investigations
  SET status = 'failed',
      error_code = 'ORPHANED_PROCESS_CRASH',
      error_message = 'Process terminated unexpectedly during active inference.',
      updated_at = :now_utc
  WHERE status = 'running';
  ```
- For each recovered row, an audit event (`action='CRASH_RECOVERY_RECONCILED'`, `outcome='FAILURE'`) is appended to `audit_events`.

---

## 3. Schema Versioning & Migration Strategy

### 3.1 Migration Framework (Alembic)
- **Tooling:** Schema evolution MUST be managed using Alembic.
- **Directory Structure:**
  - `backend/alembic.ini`
  - `backend/alembic/env.py` (configured for async SQLAlchemy engine)
  - `backend/alembic/versions/*.py` (explicitly versioned migration scripts)
- **Convention:** Migration scripts must be versioned with sequential identifiers and descriptive slugs:
  `20261021_0001_phase7_initial_investigation_tables.py`

### 3.2 Automated Startup & Rollback Controls
- **Startup Check:** On application startup, the backend verifies that the database schema matches the expected head revision.
- **Fail-Safe Startup:** If unapplied migrations exist, the backend fails to boot in production mode with a descriptive configuration error (`DATABASE_MIGRATION_REQUIRED`), preventing schema drift.
- **Reversible Migrations:** Every migration file MUST provide both `upgrade()` and `downgrade()` methods. Downward migrations must be tested to ensure clean rollback capability.

### 3.3 SQLite vs. PostgreSQL Migration Caveats
> [!WARNING]
> While SQLAlchemy models are largely portable, migrations for SQLite require `render_as_batch=True` in `alembic/env.py` because SQLite does not natively support `ALTER TABLE ... DROP/MODIFY COLUMN`. When migrating to PostgreSQL in future phases, batch mode must be disabled or conditionally configured based on the dialect.

---

## 4. Error Handling & Service-Unavailable Behavior

| Error Scenario | Root Cause | System Response |
|---|---|---|
| **Database Disk Full** | Available host disk space $< 500\text{ MB}$ | Rejects write requests with HTTP 507 (`INSUFFICIENT_STORAGE`). Logs critical alert. Read-only live alert browsing remains operational. |
| **Database Locked / Busy** | Concurrency timeout ($> 5\text{ s}$) in SQLite WAL | Returns HTTP 503 (`DEPENDENCY_UNAVAILABLE`) with retry-after header ($2\text{ s}$). Does not corrupt data. |
| **Schema Inconsistency** | Out-of-sync migration revision | Fails backend startup visibly with error code `DATABASE_SCHEMA_MISMATCH`. |
| **Database File Corruption** | Host power loss / ungraceful crash | Automatic startup integrity check (`PRAGMA integrity_check`). If corrupt, moves file to `.corrupt.<timestamp>` and refuses to launch without administrative recovery drill. |

---

## 5. Integration with Current API Authentication

- All investigation persistence routes `/api/v1/investigations` MUST enforce the existing `verify_api_auth` dependency.
- **Authorization Flow:**
  - Evaluates Bearer token via constant-time comparison (`secrets.compare_digest`).
  - When authenticated, assigns `actor_id='local_analyst'` to the request context.
  - In future multi-user phases, `verify_api_auth` will be extended to decode signed JWT claims without altering the underlying repository layer.

---

## 6. Frontend / API Interaction Model

### 6.1 State Synchronization
- When the analyst navigates to an alert or opens the Investigation Modal, the frontend checks for existing investigations:
  `GET /api/v1/investigations?alert_id={alert_id}&status=completed`
- If an existing completed investigation exists, the frontend displays:
  *"Existing investigation found from 2026-10-20 18:32:00 UTC (Run #1). [View Stored Investigation] or [Run New Investigation]"*
- This prevents redundant LLM execution and allows instant retrieval of prior analysis.

### 6.2 Stale-Request & Cancellation Protection
- If an analyst closes the modal while inference is running, the frontend aborts its `AbortController`.
- The backend detects client disconnection or explicit cancellation request and transitions the record to `status='cancelled'`, writing a corresponding audit event.

---

## 7. Logging, Observability, Backups, and Recovery

### 7.1 Structured Observability
- All database queries and transactions are instrumented under logger `siem.persistence`.
- Execution durations $> 100\text{ ms}$ emit a warning log with `request_id`, operation name, and bounded query metrics.
- Database operational metrics surfaced on `/health/ready`:
  `{"database": {"status": "connected", "engine": "sqlite_wal", "version": "20261021_0001", "total_investigations": 42}}`

### 7.2 Database Backups & Disaster Recovery
- **Hot Backups:**
  - For SQLite in WAL mode: `VACUUM INTO 'backups/siem_investigations_backup_<date>.db'` allows online, non-blocking snapshot creation without stopping services.
- **Backup Verification:**
  - Weekly automated restore drill verifying schema integrity and sample record retrieval.
- **Encryption of Backups:**
  - Backup archives must be encrypted using AES-256 (GPG or OpenSSL) before cold storage.

---

## 8. Testing Strategy & Rollback Procedure

1. **Unit Tests:** Mock repository methods to test service-level error handling, retry logic, and validation.
2. **Integration Tests with Test Engine:** Test real SQLite in-memory or temporary file instances using `aiosqlite`.
3. **Migration Tests:** Test forward migration (`upgrade`) followed immediately by reverse migration (`downgrade`), verifying clean table creation and teardown.
4. **Idempotency & Concurrent Writes:** Concurrent asyncio tasks triggering simultaneous investigations on the same alert ID to verify row locking and unique sequence constraints.
