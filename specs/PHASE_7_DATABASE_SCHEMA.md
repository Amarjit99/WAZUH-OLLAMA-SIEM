# Relational Database Schema Specification — Phase 7: Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_DATABASE_SCHEMA.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** Entity-Relationship Modeling, Normalization, Constraints & Indexing  
**Target Platform:** SQLAlchemy 2.0 Declarative Models (SQLite WAL / PostgreSQL)  
**Authors:** SOC Database Architect & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. Engine Evaluation & Recommendation: SQLite vs PostgreSQL

In accordance with `AGENTS.md` and `specs/DECISIONS.md` (ADR-007: *"Do not introduce PostgreSQL/Redis until case persistence, audit durability, or job recovery requirements justify them"*), we evaluate the target relational database engine:

| Evaluation Criteria | SQLite (WAL Mode via `aiosqlite`) | PostgreSQL (via `asyncpg`) | Evaluation Verdict |
|---|---|---|---|
| **Deployment Footprint** | Zero additional containers, daemon-less, single file on host filesystem. | Requires dedicated container in `docker-compose.yml`, credentials, volume mounts. | **SQLite:** Ideal for current single-node loopback workstation. **PostgreSQL:** Adds infrastructure overhead not yet justified. |
| **Concurrency Model** | Multiple readers, single writer. WAL mode eliminates reader-writer blocking. | Full MVCC, multi-writer, row-level locks. | **SQLite:** Exceeds requirements for single-user local SOC analyst ($\le 10$ writes/minute). |
| **Data Integrity & ACID** | Full ACID compliant in WAL mode. Atomic transactions. | Full ACID compliant with enterprise durability guarantees. | **Tie:** Both guarantee transaction atomicity and rollbacks. |
| **Network Attack Surface** | Zero network ports. No socket listening on loopback or LAN. | Listens on port 5432 (requires loopback binding, password auth, TLS). | **SQLite:** Superior security posture for local-only threat model (zero network footprint). |
| **Multi-User RBAC & Cases** | No native database user roles. Security relies on OS file permissions. | Granular table/row level security, native role management. | **PostgreSQL:** Necessary for future Phase 8 multi-tenant enterprise deployment. |

### Recommendation
1. **Initial Phase 7 Implementation:** Standardize on **SQLite in WAL mode** (`sqlite+aiosqlite:///data/siem_history.db`) for the local single-user release.
2. **Abstracted Data Access:** Define all models using standard SQLAlchemy 2.0 types (`Mapped`, `mapped_column`, `String`, `DateTime`, `ForeignKey`, `Index`) ensuring a 100% compatible zero-code-change migration to **PostgreSQL** when multi-user case management or cloud deployment is authorized under ADR-007.

---

## 2. Entity-Relationship Model (ERD)

```
+-----------------------------------+
|          investigations           |
|-----------------------------------|
| PK  investigation_id   UUID/TEXT  |
|     alert_id           TEXT       |
|     run_sequence       INTEGER    |
|     status             TEXT       |
|     created_at         TIMESTAMPTZ|
|     updated_at         TIMESTAMPTZ|
|     duration_ms        INTEGER    |
|     actor_id           TEXT       |
+-----------------------------------+
          | 1             | 1
          |               |
          | 1             | 0..*
+-----------------------+ +-----------------------------------+
| investigation_results | | investigation_evidence_snapshots  |
|-----------------------| |-----------------------------------|
| PK  result_id UUID/TXT| | PK  snapshot_id     UUID/TEXT     |
| FK  investigation_id  | | FK  investigation_id UUID/TEXT    |
|     model_name  TEXT  | |     evidence_id     TEXT (EV-01)  |
|     model_tag   TEXT  | |     source_record_id TEXT         |
|     summary     TEXT  | |     event_timestamp TIMESTAMPTZ   |
|     confidence  TEXT  | |     is_primary      BOOLEAN       |
|     disclaimer  TEXT  | |     rule_id         TEXT          |
+-----------------------+ |     rule_level      INTEGER       |
    | 1       | 1         |     agent_name      TEXT          |
    |         |           |     source_ip       TEXT          |
    | 0..*    | 0..*      |     destination_ip  TEXT          |
+-------+ +-------------+ |     username        TEXT          |
| facts | | hypotheses  | |     correlation_sig TEXT          |
+-------+ +-------------+ +-----------------------------------+
    | 1
    | 0..*
+-----------------------+
|  recommended_checks   |
+-----------------------+

+-----------------------------------+
|           audit_events            |
|-----------------------------------|
| PK  audit_id           UUID/TEXT  |
|     timestamp          TIMESTAMPTZ|
|     actor_id           TEXT       |
|     action             TEXT       |
|     resource_type      TEXT       |
|     resource_id        TEXT       |
|     outcome            TEXT       |
|     request_id         TEXT       |
|     metadata_json      TEXT       |
+-----------------------------------+
```

---

## 3. Entity Specifications

### 3.1 Table: `investigations`
Tracks the lifecycle, execution metadata, and ownership of each investigation attempt.
- **Authority:** Authoritative orchestration record.
- **Columns:**
  - `investigation_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `alert_id` (`TEXT(128)`, NOT NULL): Source Wazuh/OpenSearch alert document ID.
  - `run_sequence` (`INTEGER`, NOT NULL, DEFAULT 1): Sequential attempt number for this `alert_id`.
  - `status` (`TEXT(32)`, NOT NULL): Enum: `queued`, `running`, `completed`, `failed`, `cancelled`.
  - `primary_rule_id` (`TEXT(64)`, NOT NULL): Denormalized primary alert rule ID for fast indexed filtering.
  - `primary_rule_level` (`INTEGER`, NULLABLE): Wazuh rule severity level (1–16).
  - `primary_agent_name` (`TEXT(255)`, NULLABLE): Monitored endpoint hostname.
  - `query_window_minutes` (`INTEGER`, NOT NULL, DEFAULT 30): Configured correlation window.
  - `max_evidence_items` (`INTEGER`, NOT NULL, DEFAULT 10): Configured evidence limit.
  - `error_code` (`TEXT(64)`, NULLABLE): Error code on failure (`DEPENDENCY_UNAVAILABLE`, `UPSTREAM_TIMEOUT`, `ORPHANED_PROCESS_CRASH`, etc.).
  - `error_message` (`TEXT(512)`, NULLABLE): Safe user-facing error message (no secrets).
  - `execution_duration_ms` (`INTEGER`, NULLABLE): Time taken for evidence retrieval + LLM inference.
  - `actor_id` (`TEXT(64)`, NOT NULL, DEFAULT `'local_analyst'`): Initiator identifier.
  - `created_at` (`TIMESTAMPTZ`, NOT NULL): Investigation creation time in UTC.
  - `updated_at` (`TIMESTAMPTZ`, NOT NULL): Last state transition in UTC.
  - `deleted_at` (`TIMESTAMPTZ`, NULLABLE): Soft-delete timestamp in UTC.
- **Constraints & Indexes:**
  - `CONSTRAINT uq_alert_run UNIQUE (alert_id, run_sequence)`
  - `INDEX idx_investigations_alert_id (alert_id)`
  - `INDEX idx_investigations_created_at (created_at DESC)`
  - `INDEX idx_investigations_status (status)`
  - `INDEX idx_investigations_rule (primary_rule_id)`
  - `INDEX idx_investigations_agent (primary_agent_name)`
  - `INDEX idx_investigations_actor (actor_id)`

### 3.2 Table: `investigation_results`
Stores the validated AI-generated synthesis for completed investigations.
- **Authority:** Advisory AI output.
- **Columns:**
  - `result_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `investigation_id` (`TEXT(36)`, NOT NULL, FK -> `investigations.investigation_id` ON DELETE CASCADE): Parent investigation.
  - `model_name` (`TEXT(64)`, NOT NULL): e.g. `'ollama'`.
  - `model_tag` (`TEXT(64)`, NOT NULL): e.g. `'llama3.2:3b'`.
  - `prompt_version` (`TEXT(32)`, NOT NULL): Hash or version tag of system prompt.
  - `summary` (`TEXT`, NOT NULL): High-level narrative summary.
  - `confidence_label` (`TEXT(16)`, NOT NULL): Enum: `low`, `medium`, `high`.
  - `disclaimer` (`TEXT`, NOT NULL): Standard advisory disclaimer text.
  - `limitations_json` (`TEXT`, NOT NULL): JSON-serialized array of limitation strings.
  - `warnings_json` (`TEXT`, NOT NULL): JSON-serialized array of grounding/citation warnings.
  - `correlation_status` (`TEXT(32)`, NOT NULL): Status enum (`enriched`, `partial`, `no_related_events_found`, etc.).
  - `created_at` (`TIMESTAMPTZ`, NOT NULL): Output generation timestamp in UTC.
- **Constraints & Indexes:**
  - `CONSTRAINT uq_result_investigation UNIQUE (investigation_id)`
  - `INDEX idx_results_confidence (confidence_label)`

### 3.3 Table: `investigation_facts`
Stores discrete factual statements extracted from evidence.
- **Authority:** Corroborated facts citing specific evidence.
- **Columns:**
  - `fact_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `result_id` (`TEXT(36)`, NOT NULL, FK -> `investigation_results.result_id` ON DELETE CASCADE): Parent result.
  - `fact_identifier` (`TEXT(16)`, NOT NULL): e.g. `'F-1'`, `'F-2'`.
  - `statement` (`TEXT`, NOT NULL): Factual claim.
  - `cited_evidence_ids_json` (`TEXT`, NOT NULL): JSON array of cited IDs, e.g. `["EV-01"]`.
- **Constraints & Indexes:**
  - `INDEX idx_facts_result (result_id)`

### 3.4 Table: `investigation_hypotheses`
Stores plausible investigative inferences and uncertainty labels.
- **Authority:** Advisory hypothesis; non-authoritative.
- **Columns:**
  - `hypothesis_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `result_id` (`TEXT(36)`, NOT NULL, FK -> `investigation_results.result_id` ON DELETE CASCADE): Parent result.
  - `hypothesis_identifier` (`TEXT(16)`, NOT NULL): e.g. `'H-1'`, `'H-2'`.
  - `statement` (`TEXT`, NOT NULL): Inferred hypothesis.
  - `uncertainty` (`TEXT(16)`, NOT NULL): Enum: `low`, `medium`, `high`.
  - `cited_evidence_ids_json` (`TEXT`, NOT NULL): JSON array of cited IDs.
- **Constraints & Indexes:**
  - `INDEX idx_hypotheses_result (result_id)`

### 3.5 Table: `investigation_checks`
Stores recommended verification actions for human analysts.
- **Authority:** Advisory read-only check.
- **Columns:**
  - `check_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `result_id` (`TEXT(36)`, NOT NULL, FK -> `investigation_results.result_id` ON DELETE CASCADE): Parent result.
  - `check_identifier` (`TEXT(16)`, NOT NULL): e.g. `'C-1'`, `'C-2'`.
  - `description` (`TEXT`, NOT NULL): Recommended action description.
  - `rationale` (`TEXT`, NULLABLE): Rationale for check.
  - `priority` (`TEXT(16)`, NOT NULL): Enum: `low`, `medium`, `high`.
  - `is_read_only` (`BOOLEAN`, NOT NULL, DEFAULT TRUE): Must strictly be `TRUE`.
- **Constraints & Indexes:**
  - `INDEX idx_checks_result (result_id)`

### 3.6 Table: `investigation_evidence_snapshots`
Stores the exact minimized, sanitized evidence items evaluated during this investigation.
- **Authority:** Forensic snapshot of evidence at the time of inference.
- **Columns:**
  - `snapshot_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `investigation_id` (`TEXT(36)`, NOT NULL, FK -> `investigations.investigation_id` ON DELETE CASCADE): Parent investigation.
  - `evidence_id` (`TEXT(16)`, NOT NULL): Stable package ID, e.g. `'EV-01'`, `'EV-02'`.
  - `source_record_id` (`TEXT(128)`, NOT NULL): Original OpenSearch `_id`.
  - `event_timestamp` (`TIMESTAMPTZ`, NOT NULL): Original event time in UTC.
  - `is_primary` (`BOOLEAN`, NOT NULL): `TRUE` for primary alert target, `FALSE` for related event.
  - `rule_id` (`TEXT(64)`, NOT NULL): Source rule ID.
  - `rule_level` (`INTEGER`, NULLABLE): Wazuh rule level (1-16).
  - `rule_description` (`TEXT`, NULLABLE): Sanitized rule description.
  - `agent_name` (`TEXT(255)`, NULLABLE): Monitored endpoint hostname.
  - `source_ip` (`TEXT(45)`, NULLABLE): Sanitized IPv4/IPv6 source.
  - `destination_ip` (`TEXT(45)`, NULLABLE): Sanitized IPv4/IPv6 destination.
  - `username` (`TEXT(128)`, NULLABLE): Sanitized user/account.
  - `correlation_reason` (`TEXT(64)`, NULLABLE): Reason for inclusion.
  - `correlation_qualifier` (`TEXT(128)`, NULLABLE): Specific domain qualifier.
  - `raw_evidence_ref` (`TEXT(255)`, NOT NULL): Index/document URI reference.
- **Constraints & Indexes:**
  - `CONSTRAINT uq_investigation_evidence UNIQUE (investigation_id, evidence_id)`
  - `INDEX idx_snapshots_investigation (investigation_id)`
  - `INDEX idx_snapshots_source_record (source_record_id)`

### 3.7 Table: `audit_events`
Immutable security and administrative log for all persistence operations.
- **Authority:** Authoritative audit log.
- **Columns:**
  - `audit_id` (`TEXT(36)`, PK): UUIDv4 string.
  - `timestamp` (`TIMESTAMPTZ`, NOT NULL): Event creation time in UTC.
  - `actor_id` (`TEXT(64)`, NOT NULL): Acting user or service.
  - `action` (`TEXT(64)`, NOT NULL): e.g. `INVESTIGATION_CREATED`, `INVESTIGATION_VIEWED`, `INVESTIGATION_EXPORTED`, `INVESTIGATION_DELETED`, `CRASH_RECOVERY_RECONCILED`.
  - `resource_type` (`TEXT(32)`, NOT NULL): e.g. `investigation`.
  - `resource_id` (`TEXT(64)`, NOT NULL): Target ID.
  - `outcome` (`TEXT(16)`, NOT NULL): `SUCCESS` or `FAILURE`.
  - `request_id` (`TEXT(64)`, NOT NULL): Request correlation ID.
  - `client_ip` (`TEXT(45)`, NOT NULL): Caller IP (`127.0.0.1`).
  - `metadata_json` (`TEXT`, NULLABLE): Minimized non-sensitive context (e.g. export format).
  - `previous_hash` (`TEXT(64)`, NOT NULL): SHA-256 hash of the immediately preceding audit event row (genesis hash: 64 zeros).
  - `event_hash` (`TEXT(64)`, NOT NULL): SHA-256 hash computed over canonical serialization of current row fields concatenated with `previous_hash`.
- **Constraints & Indexes:**
  - `INDEX idx_audit_timestamp (timestamp DESC)`
  - `INDEX idx_audit_action (action)`
  - `INDEX idx_audit_resource (resource_type, resource_id)`
  - `INDEX idx_audit_event_hash (event_hash)`

---

## 4. Timezone & Timestamp Contract
- All timestamps (`created_at`, `updated_at`, `event_timestamp`, `timestamp`) MUST be stored in **timezone-aware UTC**.
- SQLite stores UTC timestamps in ISO-8601 string format (`YYYY-MM-DDTHH:MM:SS.mmmmmm+00:00`).
- Database retrieval converts all timestamp fields to Python `datetime.datetime` objects with `tzinfo=timezone.utc`.

---

## 5. Retention & Deletion Contract
- **Cascade Deletion:** When an investigation record is purged, child records in `investigation_results`, `investigation_facts`, `investigation_hypotheses`, `investigation_checks`, and `investigation_evidence_snapshots` are deleted via database `ON DELETE CASCADE`.
- **Audit Event Independence:** `audit_events` records are **never** cascaded or deleted when an investigation is purged. They retain an independent 365-day retention lifecycle to ensure forensic accountability.

---

## 6. SQLite Engine Specifics & Mandatory Connection PRAGMAs

> [!CRITICAL]
> By default, SQLite **disables** foreign key enforcement on every newly opened connection. If foreign keys are not explicitly enabled via connection hooks, `ON DELETE CASCADE` and all relational integrity constraints are silently ignored by the engine.

When utilizing SQLite via `aiosqlite` and SQLAlchemy 2.0, the connection pool MUST register a `connect` event listener enforcing the following PRAGMAs on every connection checkout:
```python
# app/db/session.py listener
from sqlalchemy import event
from sqlite3 import Connection as SQLiteConnection

@event.listens_for(engine.sync_engine, "connect")
def configure_sqlite_connection(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLiteConnection):
        cursor = dbapi_connection.cursor()
        # 1. Enforce Foreign Key Integrity and Cascades
        cursor.execute("PRAGMA foreign_keys = ON;")
        # 2. Enforce Write-Ahead Logging for non-blocking concurrent reads
        cursor.execute("PRAGMA journal_mode = WAL;")
        # 3. Synchronous NORMAL provides safe durability in WAL mode
        cursor.execute("PRAGMA synchronous = NORMAL;")
        # 4. Set busy timeout to 5000ms to allow concurrent write retries
        cursor.execute("PRAGMA busy_timeout = 5000;")
        cursor.close()
```

---

## 7. Startup Crash Recovery & Stale State Reconciliation

If the backend process crashes or is killed while an investigation is in `status='running'`, the record remains stalled in `running` indefinitely. To ensure lifecycle consistency:
1. **Startup Reconciliation Hook:** On application boot (in FastAPI lifespan startup), the backend executes a reconciliation query:
   ```sql
   UPDATE investigations
   SET status = 'failed',
       error_code = 'ORPHANED_PROCESS_CRASH',
       error_message = 'Investigation was in progress when backend process terminated unexpectedly.',
       updated_at = :now_utc
   WHERE status = 'running';
   ```
2. **Audit Event Generation:** For each reconciled record, an audit event (`action='CRASH_RECOVERY_RECONCILED'`, `outcome='FAILURE'`) is written with the recovered investigation ID.

