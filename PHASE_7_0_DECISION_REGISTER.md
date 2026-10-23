# PHASE 7.0 — FORMAL ARCHITECTURAL DECISION REGISTER
## Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform

**Document ID:** `PHASE_7_0_DECISION_REGISTER.md`  
**Governance Gate:** Phase 7.0 Formal Decision Approval & Implementation Readiness Gate  
**Reference Source:** [specs/DECISIONS.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/DECISIONS.md), [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md), and [PHASE_7_0_IMPLEMENTATION_READINESS_REPORT.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_IMPLEMENTATION_READINESS_REPORT.md)  
**Date:** October 20, 2026  
**Auditor:** Antigravity Senior Security & Reliability Agent  
**Approval Source:** Explicit Project Owner Decision provided in current conversation  
**Implementation Authorization:** STRICTLY WITHHELD (Phase 7.1 implementation authorization: NOT AUTHORIZED)  
**Governance Rule Enforced:** Strict preservation of historical decision records; unambiguous separation between architectural decision approval and implementation authorization.

---

## 1. Executive Summary & Decision State Overview

In accordance with `AGENTS.md` and repository governance rules, the project owner has reviewed the Phase 7 architectural specifications and recorded explicit approval for **ADR-007 through ADR-012**. 

All six architectural decisions are formally **`APPROVED`** for documented architectural scope. Simultaneously, **Phase 7.1 implementation authorization remains strictly WITHHELD**. No source code, database tables, migrations, or dependencies may be created until a separate, explicit implementation authorization is granted.

| Decision ID | Title | Prior Status | Approved Scope | Governance State | Implementation Status |
|---|---|:---:|---|:---:|:---:|
| **[ADR-007](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md#adr-007-authorization-to-introduce-persistent-relational-storage)** | Authorization to Introduce Persistent Relational Storage | `proposed` | Introduction of persistent relational storage | `APPROVED` | **NOT AUTHORIZED** |
| **[ADR-008](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md#adr-008-sqlite-wal-aiosqlite-and-sqlalchemy-20-async-architecture)** | SQLite WAL, aiosqlite & SQLAlchemy 2.0 Async Architecture | `proposed` | SQLite WAL, aiosqlite, and SQLAlchemy 2.0 async architecture | `APPROVED` | **NOT AUTHORIZED** |
| **[ADR-009](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md#adr-009-minimized-sanitized-evidence-snapshots-vs-raw-logs)** | Minimized, Sanitized Evidence Snapshots vs. Raw Logs | `proposed` | Minimized, sanitized evidence snapshots rather than raw OpenSearch document duplication | `APPROVED` | **NOT AUTHORIZED** |
| **[ADR-010](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md#adr-010-full-investigation-lifecycle-failedcancelledcrash-recovery)** | Full Investigation Lifecycle (Failed/Cancelled/Crash Recovery) | `proposed` | Full investigation lifecycle, including failed, cancelled, and crash-recovery handling | `APPROVED` | **NOT AUTHORIZED** |
| **[ADR-011](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md#adr-011-90-day-investigation-retention-and-365-day-audit-retention)** | Dual Retention (90d Investigations, 365d Audit Events) | `proposed` | 90-day investigation retention and 365-day audit-event retention | `APPROVED` | **NOT AUTHORIZED** |
| **[ADR-012](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md#adr-012-local-hash-chained-audit-logging--documented-trust-limitations)** | Local Hash-Chained Audit Logging & Trust Boundaries | `proposed` | Local hash-chained audit logging with explicitly documented trust limitations | `APPROVED` | **NOT AUTHORIZED** |

---

## 2. Detailed Decision Register

### ADR-007: Authorization to Introduce Persistent Relational Storage
- **Current Status from Source:** `accepted (Approved by Project Owner; implementation authorization withheld)` in [specs/DECISIONS.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/DECISIONS.md).
- **Prior Status:** `proposed` (as "Optional database and queue").
- **Approved Scope:** Introduction of persistent relational storage.
- **Approval Source:** Explicit Project Owner Decision provided in current conversation.
- **Decision:** Introduce a persistent relational storage layer to transition AI investigation results, evidence packages, and analyst audit events from ephemeral browser state to durable on-disk storage.
- **Consequences:**
  - *Positive:* Enables persistent investigation history, citation traceability after OpenSearch log rollover, and compliance auditing.
  - *Negative:* Adds schema migration maintenance (Alembic), disk I/O, database backup management, and file permission security requirements.
- **Security & Operational Risks:**
  - Data-at-rest confidentiality risk: unencrypted storage of sanitized logs and analyst findings on the host.
  - Disk exhaustion risk: unconstrained investigation volume could consume host disk capacity.
- **Dependencies & Affected Specifications:**
  - Core dependency for all Phase 7 specifications ([PRD](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_PRD.md), [TRD](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_TRD.md), [Schema](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_DATABASE_SCHEMA.md), [API](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_API_CONTRACT.md), [Security](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_SECURITY_AND_RETENTION.md), [Plan](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_IMPLEMENTATION_PLAN.md)).
- **Governance State:** **`APPROVED`**
- **Implementation Status:** **`NOT AUTHORIZED`** (Requires separate explicit authorization to start Phase 7.1).

---

### ADR-008: SQLite WAL, aiosqlite, and SQLAlchemy 2.0 Async Architecture
- **Current Status from Source:** `APPROVED (Implementation Authorization Withheld)` in [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md).
- **Prior Status:** `proposed (Human Approval Required)`.
- **Approved Scope:** SQLite WAL, aiosqlite, and SQLAlchemy 2.0 async architecture.
- **Approval Source:** Explicit Project Owner Decision provided in current conversation.
- **Decision:** Adopt **SQLite in Write-Ahead Logging (WAL) mode** (`sqlite+aiosqlite:///data/siem_history.db`) as the default engine for the local single-user release, abstracting models via **SQLAlchemy 2.0 Async** to preserve a future migration path to PostgreSQL (`asyncpg`).
- **Consequences:**
  - *Positive:* Zero additional Docker containers, zero open network ports, daemon-less operation, zero RAM footprint when idle.
  - *Negative:* Single-writer constraint (mitigated by WAL mode for concurrent readers); requires explicit connection event listener for `PRAGMA foreign_keys = ON;`.
- **Security & Operational Risks:**
  - File-level permissions depend entirely on host OS NTFS ACLs (`icacls`) or Linux permissions.
  - Concurrent writes are serialized; heavy bursts could encounter `SQLITE_BUSY` if operations exceed the 5000ms timeout.
- **Dependencies & Affected Specifications:**
  - `specs/PHASE_7_DATABASE_SCHEMA.md`, `specs/PHASE_7_TRD.md`, `backend/pyproject.toml`.
- **Governance State:** **`APPROVED`**
- **Implementation Status:** **`NOT AUTHORIZED`** (Requires separate explicit authorization to start Phase 7.1).

---

### ADR-009: Minimized, Sanitized Evidence Snapshots vs. Raw Logs
- **Current Status from Source:** `APPROVED (Implementation Authorization Withheld)` in [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md).
- **Prior Status:** `proposed`.
- **Approved Scope:** Minimized, sanitized evidence snapshots rather than raw OpenSearch document duplication.
- **Approval Source:** Explicit Project Owner Decision provided in current conversation.
- **Decision:** Persist an immutable, normalized snapshot of the evaluated evidence package (`investigation_evidence_snapshots`), storing only sanitized allowlisted fields (`rule_id`, `agent_name`, `source_ip`, `username`, correlation signals). Prohibit copying full raw OpenSearch JSON blobs.
- **Consequences:**
  - *Positive:* Evidence citations (`EV-01`) remain verifiable even after source OpenSearch alert indices rotate or are purged. Average footprint is kept $< 35\text{ KB}$ per investigation.
  - *Negative:* Snapshots reflect evidence at the time of inference and do not capture retroactive log alterations.
- **Security & Operational Risks:**
  - Potential secret leakage if sanitization regex misses novel credential formats. Mitigated by multiple regex scrubbers in `EvidenceService`.
- **Dependencies & Affected Specifications:**
  - `specs/PHASE_7_DATABASE_SCHEMA.md`, `specs/DATA_SCHEMA.md`, `backend/app/services/evidence_service.py`.
- **Governance State:** **`APPROVED`**
- **Implementation Status:** **`NOT AUTHORIZED`** (Requires separate explicit authorization to start Phase 7.1).

---

### ADR-010: Full Investigation Lifecycle (Failed/Cancelled/Crash Recovery)
- **Current Status from Source:** `APPROVED (Implementation Authorization Withheld)` in [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md).
- **Prior Status:** `proposed`.
- **Approved Scope:** Full investigation lifecycle, including failed, cancelled, and crash-recovery handling.
- **Approval Source:** Explicit Project Owner Decision provided in current conversation.
- **Decision:** Track and persist the full lifecycle of an investigation (`queued`, `running`, `completed`, `failed`, `cancelled`), including upstream Ollama timeouts and a startup crash recovery sweep reconciling orphaned `running` jobs with `ORPHANED_PROCESS_CRASH`.
- **Consequences:**
  - *Positive:* Provides 100% forensic visibility into model availability, denial-of-service attempts, and application restarts.
  - *Negative:* Slightly higher database row count (managed via retention pruning).
- **Security & Operational Risks:**
  - Stale `running` records could mislead analysts if startup reconciliation is not executed reliably.
- **Dependencies & Affected Specifications:**
  - `specs/PHASE_7_TRD.md`, `specs/PHASE_7_DATABASE_SCHEMA.md`, `backend/app/main.py`.
- **Governance State:** **`APPROVED`**
- **Implementation Status:** **`NOT AUTHORIZED`** (Requires separate explicit authorization to start Phase 7.1).

---

### ADR-011: 90-Day Investigation Retention and 365-Day Audit Retention
- **Current Status from Source:** `APPROVED (Implementation Authorization Withheld)` in [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md).
- **Prior Status:** `proposed`.
- **Approved Scope:** 90-day investigation retention and 365-day audit-event retention.
- **Approval Source:** Explicit Project Owner Decision provided in current conversation.
- **Decision:** Implement a dual-lifecycle retention policy: 90-day retention with bounded batch cascade deletion for investigation records and evidence snapshots; independent 365-day non-cascading retention for `audit_events`.
- **Consequences:**
  - *Positive:* Enforces privacy data minimization and disk bounding while preserving forensic audit trails.
  - *Negative:* Requires a dedicated periodic maintenance job executing bounded deletions (`LIMIT 100`).
- **Security & Operational Risks:**
  - Unbounded deletions could lock the SQLite database. Mitigated by bounded batching and `PRAGMA wal_checkpoint(TRUNCATE)`.
- **Dependencies & Affected Specifications:**
  - `specs/PHASE_7_SECURITY_AND_RETENTION.md`, `specs/PHASE_7_DATABASE_SCHEMA.md`.
- **Governance State:** **`APPROVED`**
- **Implementation Status:** **`NOT AUTHORIZED`** (Requires separate explicit authorization to start Phase 7.1).

---

### ADR-012: Local Hash-Chained Audit Logging & Documented Trust Limitations
- **Current Status from Source:** `APPROVED (Implementation Authorization Withheld)` in [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md).
- **Prior Status:** `proposed (Human Approval Required)`.
- **Approved Scope:** Local hash-chained audit logging with explicitly documented trust limitations.
- **Approval Source:** Explicit Project Owner Decision provided in current conversation.
- **Decision:** Implement sequential SHA-256 hash chaining on `audit_events` with canonical JSON serialization. Explicitly document that local hash chaining detects **accidental corruption** and **uncoordinated local file tampering**, but **cannot** resist a privileged attacker with local OS write access to the database file without an external trust anchor (HSM/WORM/syslog).
- **Consequences:**
  - *Positive:* Provides deterministic integrity verification without adding external network dependencies.
  - *Negative:* Requires serialized transaction writes for audit entries; cannot claim true non-repudiation against local root/admin attackers.
- **Security & Operational Risks:**
  - Overconfidence in local security posture if analysts assume local hash chains equal hardware immutability. Mitigated by prominent warnings in security documentation.
- **Dependencies & Affected Specifications:**
  - `specs/PHASE_7_SECURITY_AND_RETENTION.md`, `specs/PHASE_7_DATABASE_SCHEMA.md`.
- **Governance State:** **`APPROVED`**
- **Implementation Status:** **`NOT AUTHORIZED`** (Requires separate explicit authorization to start Phase 7.1).

---

## 3. Recorded Project Owner Sign-off Block

```text
================================================================================
FORMAL PHASE 7.0 PROJECT OWNER APPROVAL RECORD
================================================================================
Approval Source: Explicit Project Owner Decision provided in current conversation
Approval Date:   2026-10-20

[X] ADR-007: Approved — Introduction of persistent relational storage
[X] ADR-008: Approved — SQLite WAL, aiosqlite, and SQLAlchemy 2.0 async architecture
[X] ADR-009: Approved — Minimized, sanitized evidence snapshots vs raw OpenSearch duplication
[X] ADR-010: Approved — Full investigation lifecycle (failed, cancelled, crash recovery)
[X] ADR-011: Approved — 90-day investigation retention and 365-day audit retention
[X] ADR-012: Approved — Local hash-chained audit logging with documented trust limitations

Phase 7.1 implementation authorization: [ ] YES  [X] NOT AUTHORIZED (STRICTLY WITHHELD)

Scope Limitation Note:
Approval applies strictly to the documented architecture, schemas, and specifications.
Implementation authorization is strictly withheld. No application code, database tables,
migrations, dependencies, or infrastructure may be created or modified.
================================================================================
```
