# PHASE 7 — CRITICAL ARCHITECTURE REVIEW & DOCUMENTATION HARDENING REPORT
## Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform

**Target Workspace:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Deployment Infrastructure:** `F:\MY Project\wazuh-docker` (strictly read-only, untouched)  
**Date:** October 20, 2026  
**Auditor:** Antigravity Senior Security & Reliability Agent  
**Review Mode:** Documentation Review and Remediation Only  
**Implementation Authorization:** NOT AUTHORIZED  
**Readiness Determination:** **READY FOR PHASE 7.0 REVIEW**  

---

## 1. Executive Summary

A critical, evidence-based architectural review of the Phase 7 persistence specifications was conducted. The review evaluated ADR governance, transaction integrity, database lifecycle handling, audit-chain tamper resistance, dual retention lifecycles, loopback security boundaries, and cross-document consistency.

Prior to remediation, several high-impact contradictions and missing requirements were identified:
1. **Critical Schema vs. API Filter Contradiction:** `specs/PHASE_7_DATABASE_SCHEMA.md` omitted denormalized `primary_rule_id` and `primary_agent_name` columns on the `investigations` table, which would have forced expensive full-table scans and multi-table joins across evidence snapshots for basic history queries.
2. **Critical Audit Schema Mismatch:** `specs/PHASE_7_SECURITY_AND_RETENTION.md` specified a cryptographic hash chain for `audit_events`, but `specs/PHASE_7_DATABASE_SCHEMA.md` omitted the required `previous_hash` and `event_hash` columns.
3. **Critical SQLite Foreign Key Blindspot:** SQLite disables foreign key constraint checking by default on every new database connection. Without an explicit connection hook executing `PRAGMA foreign_keys = ON;`, all relational integrity and `ON DELETE CASCADE` actions are silently ignored by SQLite.
4. **Unhandled Process Crash Lifecycle:** Stalled investigations in `status='running'` had no documented recovery mechanism if the backend process crashed or was killed mid-inference.
5. **Tamper-Evidence Overclaim:** Local hash chaining was qualified to make clear that without an external trust anchor (HSM, DPAPI key, or remote append-only syslog), a hash chain in the same writable SQLite file detects accidental corruption and uncoordinated tampering, but cannot mathematically prevent a privileged local attacker from recomputing hashes.

All five core documents ([specs/PHASE_7_DATABASE_SCHEMA.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_DATABASE_SCHEMA.md), [specs/PHASE_7_SECURITY_AND_RETENTION.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_SECURITY_AND_RETENTION.md), [specs/PHASE_7_TRD.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_TRD.md), [specs/PHASE_7_API_CONTRACT.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_API_CONTRACT.md), [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md), and [specs/PHASE_7_TEST_PLAN.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_TEST_PLAN.md)) were surgically updated and hardened. Zero application code, zero database tables, zero packages, and zero deployment files were modified.

---

## 2. Exact Files Inspected

### Phase 7 Specifications Inspected
1. `specs/PHASE_7_ADR.md`
2. `specs/PHASE_7_DATABASE_SCHEMA.md`
3. `specs/PHASE_7_SECURITY_AND_RETENTION.md`
4. `specs/PHASE_7_PRD.md`
5. `specs/PHASE_7_TRD.md`
6. `specs/PHASE_7_API_CONTRACT.md`
7. `specs/PHASE_7_IMPLEMENTATION_PLAN.md`
8. `specs/PHASE_7_TEST_PLAN.md`

### Core Project Source of Truth Inspected
1. `AGENTS.md`
2. `specs/DECISIONS.md`
3. `specs/ARCHITECTURE.md`
4. `specs/API_CONTRACT.md`
5. `specs/DATA_SCHEMA.md`
6. `specs/AI_SAFETY_RULES.md`
7. `specs/SECURITY_THREAT_MODEL.md`
8. Phase audit reports: `PHASE_6_RELATED_EVENT_CORRELATION_AUDIT_REPORT.md`, `PHASE_6A_CORRELATION_QUALITY_AUDIT_REPORT.md`, `PHASE_6A_1_CORRELATION_RELIABILITY_AUDIT_REPORT.md`, `PHASE_6A_2_FINAL_RELIABILITY_SECURITY_AUDIT_REPORT.md`, `PHASE_6A_3_API_AUTH_RELEASE_READINESS_REPORT.md`, and `PHASE_6B_SOC_ANALYST_WORKFLOW_AUDIT_REPORT.md`.
9. Existing code: `backend/app/api/v1/alerts.py`, `backend/app/api/deps.py`, `backend/app/schemas/investigation.py`, `backend/app/services/evidence_service.py`, `backend/app/services/ollama_client.py`.

### Missing or Inaccessible Files
- None. All requested files exist and were directly inspected.

---

## 3. ADR Governance Review (ADR-007 through ADR-012)

| ADR ID & Title | Documented Status | Evidence & Source Location | Identified Contradiction / Gap | Recommended Action & Approval Status |
|---|---|---|---|---|
| **ADR-007: Optional database and queue** | `proposed` | `specs/DECISIONS.md:L40-44` | Earlier Phase 7 text stated condition was "formally satisfied", which could be misinterpreted as accepted. | **UNRESOLVED — APPROVAL REQUIRED.** Remains formally proposed in `specs/DECISIONS.md`. Requires explicit human sign-off before Phase 7.1. |
| **ADR-008: Relational Database Engine Selection** | `proposed` | `specs/PHASE_7_ADR.md:L26-44` | Claimed "seamless zero-code-change migration to PostgreSQL" without documenting FK pragma, WAL locking, Alembic batch mode, or JSON type differences. | **UNRESOLVED — APPROVAL REQUIRED.** Fully qualified with dialect differences. Awaits stakeholder sign-off. |
| **ADR-009: Minimized Evidence Snapshot Persistence** | `proposed` | `specs/PHASE_7_ADR.md:L46-60` | None. Clean architectural rationale separating sanitized snapshots from raw OpenSearch documents. | **PROPOSED — APPROVAL REQUIRED.** Solid design; recommend acceptance during Phase 7.0 review. |
| **ADR-010: Lifecycle Tracking for Failed and Cancelled Jobs** | `proposed` | `specs/PHASE_7_ADR.md:L63-76` | Did not specify startup crash recovery for jobs frozen in `status='running'` when Uvicorn is killed. | **PROPOSED — APPROVAL REQUIRED.** Remediated by adding startup reconciliation hook. Recommend acceptance. |
| **ADR-011: Dual-Lifecycle Retention & Soft-Purge** | `proposed` | `specs/PHASE_7_ADR.md:L79-95` | Did not specify bounded batching for cleanup, risking SQLite table lockups and WAL explosion. | **PROPOSED — APPROVAL REQUIRED.** Remediated with 100-row batching specification. Recommend acceptance. |
| **ADR-012: Tamper-Evident Hash Chain Reality & Scope** | `proposed` | `specs/PHASE_7_ADR.md:L106-121` | Originally unrecorded in ADR log; needed to prevent false claims of local immutability against privileged OS attackers. | **PROPOSED — APPROVAL REQUIRED.** Formally added as ADR-012. Recommend acceptance. |

---

## 4. Database Schema & Transaction Review (Review B)

### Entity Structure & Foreign Key Integrity
- **Relational Integrity:** Child records (`investigation_results`, `investigation_facts`, `investigation_hypotheses`, `investigation_checks`, `investigation_evidence_snapshots`) strictly link to `investigations.investigation_id` with `ON DELETE CASCADE`.
- **Audit Decoupling:** `audit_events.resource_id` deliberately avoids a foreign key constraint to `investigations.investigation_id`. This guarantees that purging an expired investigation does not cascade-delete or corrupt historical audit entries.
- **Denormalized Primary Alert Fields:** Added `primary_rule_id` (`TEXT(64)`), `primary_rule_level` (`INTEGER`), and `primary_agent_name` (`TEXT(255)`) to `investigations` with dedicated B-tree indexes (`idx_investigations_rule`, `idx_investigations_agent`), eliminating multi-table joins during paginated list queries.

### SQLite WAL Mode & Connection Hooks
SQLite connection lifecycle requirements were codified in `specs/PHASE_7_TRD.md` Section 2.3 and `specs/PHASE_7_DATABASE_SCHEMA.md` Section 6:
```python
@event.listens_for(engine.sync_engine, "connect")
def configure_sqlite_connection(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")       # Enforces FK constraints & cascades
    cursor.execute("PRAGMA journal_mode = WAL;")        # Non-blocking concurrent readers
    cursor.execute("PRAGMA synchronous = NORMAL;")      # Safe fsync policy in WAL mode
    cursor.execute("PRAGMA busy_timeout = 5000;")       # 5s lock timeout for busy writers
    cursor.close()
```

### Process Crash Recovery & Lifecycle States
- **Crash Scenario:** If the FastAPI backend is terminated (SIGKILL, power failure, OS reboot) while Ollama inference is executing, the investigation record would remain frozen in `status='running'`.
- **Remediation Specification:** Added startup reconciliation in FastAPI lifespan:
  ```sql
  UPDATE investigations
  SET status = 'failed',
      error_code = 'ORPHANED_PROCESS_CRASH',
      error_message = 'Process terminated unexpectedly during active inference.',
      updated_at = :now_utc
  WHERE status = 'running';
  ```
  An audit event (`action='CRASH_RECOVERY_RECONCILED'`) is appended for every recovered job.

---

## 5. Audit Event Integrity Assessment (Review C)

### Hash-Chain Specification Hardening
`specs/PHASE_7_DATABASE_SCHEMA.md` Section 3.7 was updated to include:
- `previous_hash` (`TEXT(64)`, NOT NULL)
- `event_hash` (`TEXT(64)`, NOT NULL)
- `INDEX idx_audit_event_hash (event_hash)`

### Mathematical Formula & Canonicalization
$$\text{Hash}_n = \text{SHA-256}(\text{CanonicalJSON}(\text{AuditID}_n, \text{Timestamp}_n, \text{Actor}_n, \text{Action}_n, \text{ResourceType}_n, \text{ResourceID}_n, \text{Outcome}_n, \text{RequestID}_n, \text{Metadata}_n) \,\|\, \text{Hash}_{n-1})$$
- **Genesis Hash:** Fixed at 64 zeros (`'000...000'`).
- **Canonical Serialization:** Requires RFC 8785 canonical JSON or strict deterministic Python serialization (`json.dumps(obj, sort_keys=True, separators=(',', ':'))`).

### Threat Boundary Limitation
The documentation explicitly differentiates:
1. **Accidental Corruption Detection:** Verified by recomputing the chain.
2. **Uncoordinated Tampering Detection:** Detects manual SQL edits by unprivileged users.
3. **Privileged Attacker Limitation:** A local process or attacker with write access to `siem_history.db` can modify an audit row and mathematically recompute the SHA-256 chain forward. True non-repudiation requires an external trust anchor (Windows DPAPI/TPM-backed HMAC or remote syslog). This is recorded as an unresolved decision pending enterprise review.

---

## 6. Retention & Deletion Analysis (Review D)

### Coexistence of Dual Lifecycles
- **Investigation Lifecycle:** 90 days (`INVESTIGATION_RETENTION_DAYS=90`).
- **Audit Log Lifecycle:** 365 days.
- **Cascading Isolation:** Investigation purging cascades to results, facts, hypotheses, checks, and evidence snapshots, but leaves `audit_events` intact.

### Bounded Batch Pruning
Unconstrained `DELETE` statements on thousands of rows cause SQLite lock timeouts and WAL file bloat. `specs/PHASE_7_SECURITY_AND_RETENTION.md` Section 4.1 was updated to mandate:
1. Batch deletion using subquery limits of 100 rows per transaction.
2. 100ms pause between batches to yield writer locks to live inference jobs.
3. Post-cleanup execution of `PRAGMA wal_checkpoint(TRUNCATE);` to reclaim physical disk space.

---

## 7. Security & Privacy Assessment (Review E)

| Security Control | Baseline Status | Review Assessment |
|---|---|---|
| **Loopback Binding** | Preserved | FastAPI (`127.0.0.1:8001`) and Ollama (`127.0.0.1:11434`). SQLite opens zero network ports. |
| **API Authentication** | Preserved | `verify_api_auth` enforced on all `/api/v1/investigations` routes via constant-time token comparison. |
| **SQL Injection Defense** | Preserved | 100% parameterized queries via SQLAlchemy 2.0 ORM/Core. Raw concatenated SQL prohibited. |
| **Filesystem ACLs** | Hardened | Documented `icacls` command for native Windows execution. Explicitly documented WSL2 DrvFs metadata requirement when run in Linux subsystem. |
| **Secret Redaction** | Preserved | All evidence snapshots and model outputs pass through regex scrubbers before database insertion. |
| **AI Advisory Invariant** | Preserved | Detections originate exclusively from Wazuh/OpenSearch. Stored AI hypotheses never alter detection state. |

---

## 8. API & Cross-Document Consistency (Review F)

- **Model Mapping:** The response schema in `specs/PHASE_7_API_CONTRACT.md` matches the database models in `specs/PHASE_7_DATABASE_SCHEMA.md` and the domain models in `backend/app/schemas/investigation.py`.
- **List Item Fields:** Denormalized fields (`primary_rule_id`, `primary_rule_level`, `primary_agent_name`) were added to the list item schema in `specs/PHASE_7_API_CONTRACT.md`, perfectly aligning with the updated database schema.
- **Frontend Isolation:** Verified that no specification allows or implies direct browser connections to SQLite, OpenSearch, Wazuh, or Ollama. All interactions flow through `/api/v1`.

---

## 9. Classified Findings Matrix

| Finding ID | Severity | Category | Summary of Finding | Remediated In Document |
|---|:---:|---|---|---|
| **F-01** | **Critical** | Data Integrity | SQLite disables foreign key checks by default; `ON DELETE CASCADE` would have been ignored. | `specs/PHASE_7_DATABASE_SCHEMA.md` Sec 6; `specs/PHASE_7_TRD.md` Sec 2.3 |
| **F-02** | **Critical** | Schema Mismatch | `audit_events` schema lacked `previous_hash` and `event_hash` columns required for hash chaining. | `specs/PHASE_7_DATABASE_SCHEMA.md` Sec 3.7 |
| **F-03** | **High** | Performance & API | `investigations` table lacked `primary_rule_id` and `primary_agent_name`, breaking indexed API filtering. | `specs/PHASE_7_DATABASE_SCHEMA.md` Sec 3.1; `specs/PHASE_7_API_CONTRACT.md` Sec 2.1 |
| **F-04** | **High** | Lifecycle Integrity | Stalled `running` investigations had no recovery path on process crash/kill. | `specs/PHASE_7_TRD.md` Sec 2.4; `specs/PHASE_7_DATABASE_SCHEMA.md` Sec 7 |
| **F-05** | **High** | Security Threat Model | Hash-chaining overclaimed immutability against privileged local OS attacker. | `specs/PHASE_7_SECURITY_AND_RETENTION.md` Sec 3.1; `specs/PHASE_7_ADR.md` ADR-012 |
| **F-06** | **Medium** | Governance | ADR-007 was described as "condition satisfied" without making clear that formal human approval is still required. | `specs/PHASE_7_ADR.md` Sec 1; Status table |
| **F-07** | **Medium** | Operational Stability | Retention pruning lacked bounded batching, risking SQLite table lockups on large datasets. | `specs/PHASE_7_SECURITY_AND_RETENTION.md` Sec 4.1 |
| **F-08** | **Medium** | Platform Portability | Oversimplified claim of "seamless zero-code-change migration to PostgreSQL". | `specs/PHASE_7_ADR.md` ADR-008; `specs/PHASE_7_TRD.md` Sec 3.3 |
| **F-09** | **Low** | OS Environment | Windows NTFS ACLs were assumed to apply identically in WSL2 environments without DrvFs metadata flags. | `specs/PHASE_7_SECURITY_AND_RETENTION.md` Sec 1.2 |

---

## 10. Documentation Files Remediated

| File Path | Nature and Rationale of Remediation |
|---|---|
| [specs/PHASE_7_DATABASE_SCHEMA.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_DATABASE_SCHEMA.md) | Added `primary_rule_id`, `primary_rule_level`, `primary_agent_name` to `investigations`; added `previous_hash` and `event_hash` to `audit_events`; added Section 6 on mandatory SQLite PRAGMAs (`foreign_keys=ON`); added Section 7 on startup crash recovery. |
| [specs/PHASE_7_SECURITY_AND_RETENTION.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_SECURITY_AND_RETENTION.md) | Qualified tamper-evidence limitations against privileged attackers; defined canonical JSON serialization and genesis hash; added bounded batch retention pruning (100 rows/batch); added Section 1.2 distinguishing Windows NTFS ACLs from WSL2 mount behaviors. |
| [specs/PHASE_7_TRD.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_TRD.md) | Added Section 2.3 specifying mandatory SQLite connection event listener; added Section 2.4 specifying startup crash reconciliation (`ORPHANED_PROCESS_CRASH`); added Section 3.3 documenting PostgreSQL portability constraints and Alembic batch mode. |
| [specs/PHASE_7_API_CONTRACT.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_API_CONTRACT.md) | Updated Section 2.1 response model to include denormalized `primary_rule_id`, `primary_rule_level`, and `primary_agent_name`. |
| [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md) | Clarified ADR-007 through ADR-011 as `PROPOSED — HUMAN APPROVAL REQUIRED`; qualified PostgreSQL portability in ADR-008; added ADR-012 documenting tamper-evident hash chain scope and limitations. |
| [specs/PHASE_7_TEST_PLAN.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_TEST_PLAN.md) | Added tests: `T-MIG-4` (SQLite connection PRAGMA verification), `T-CHAOS-4` (startup crash recovery for stale jobs), and `T-RET-4` (audit hash chain tamper detection). |

---

## 11. Unresolved Decisions Requiring Human Approval

The following four architecture decisions are documented as proposed and require explicit human stakeholder sign-off prior to authorizing Phase 7.1 implementation:

1. **Formal Acceptance of ADR-007:** Approval to introduce persistent relational storage to the platform.
2. **Approval of ADR-008:** Adoption of SQLite in WAL mode (`aiosqlite`) as the default local persistence driver with SQLAlchemy 2.0 async models.
3. **Approval of ADR-009 & ADR-010:** Acceptance of minimized evidence snapshots (avoiding full OpenSearch document duplication) and full lifecycle tracking (including failed/cancelled attempts).
4. **Approval of ADR-011 & ADR-012:** Acceptance of the dual 90-day/365-day retention lifecycle and the local hash-chained audit logging model with its documented trust boundaries.

---

## 12. Phase 7.0 Readiness Decision

### **READINESS OUTCOME: READY FOR PHASE 7.0 REVIEW**

**Justification:**  
All internal architectural contradictions, schema mismatches, and connection PRAGMA gaps have been resolved across the specification suite. The documentation is now completely coherent, self-consistent, and secure. It is ready for human stakeholder review in Phase 7.0 to formally approve the ADRs before implementation begins in Phase 7.1.

Implementation remains **STRICTLY NOT AUTHORIZED** until Phase 7.0 review is formally concluded.

---

## 13. Git State & Infrastructure Verification

- **Current Git Branch:** `main`
- **Current HEAD Commit:** `793e4c4` (Zero commits created)
- **Source Code Changed:** 0 lines
- **Database Tables Created:** 0
- **Migrations Executed:** 0
- **Deployment Repository (`F:\MY Project\wazuh-docker`):** 100% untouched
- **Runtime Services:** All existing services remain running on loopback without restart
