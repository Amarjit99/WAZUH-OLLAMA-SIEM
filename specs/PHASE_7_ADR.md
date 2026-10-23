# Architecture Decision Record (ADR) Log — Phase 7: Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_ADR.md`  
**Reference Document:** Linked to primary log at [specs/DECISIONS.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/DECISIONS.md), register at [PHASE_7_0_DECISION_REGISTER.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md), and report at [PHASE_7_0_IMPLEMENTATION_READINESS_REPORT.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_IMPLEMENTATION_READINESS_REPORT.md)  
**Status:** APPROVED ARCHITECTURAL DECISIONS (Implementation Authorization Withheld)  
**Authors:** SOC Architecture Board & Antigravity Security Agent  
**Approval Source:** Explicit Project Owner Decision recorded in Phase 7.0 governance review  
**Approval Scope:** Applies strictly to documented architecture, schemas, and specifications; does NOT authorize code implementation or migration execution  
**Last Updated:** October 20, 2026  

---

## 1. Review of Existing ADR-007

In [specs/DECISIONS.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/DECISIONS.md), **ADR-007** was originally recorded as:
> **ADR-007: Optional database and queue**  
> - **Status:** proposed  
> - **Decision:** do not introduce PostgreSQL/Redis until case persistence, audit durability, or job recovery requirements justify them.  
> - **Consequence:** early implementation remains simpler; the choice must be revisited before production if durability requirements demand it.

### Evaluation & Current Governance Status
- **Current Status:** `APPROVED (Implementation Authorization Withheld)`
- **Prior Status:** `proposed`
- **Approval Date:** 2026-10-20
- **Approval Source:** Explicit project-owner decision recorded in Phase 7.0 review.
- **Assessment:** Investigation history, evidence snapshots, and audit requirements now formally justify transitioning from ephemeral state to persistent relational storage.
- **Implementation Status:** NOT AUTHORIZED. While the architectural decision to introduce persistent relational storage is approved, physical coding, package installation, and database creation remain strictly unauthorized until explicit Phase 7.1 implementation authorization is granted.

---

## 2. Phase 7 Architecture Decision Records

### ADR-008: Relational Database Engine Selection for Local Single-User Scope
- **Date:** 2026-10-20
- **Status:** APPROVED (Implementation Authorization Withheld)
- **Prior Status:** proposed (Human Approval Required)
- **Approval Source:** Explicit project-owner decision recorded in Phase 7.0 review.
- **Decision Owner:** Project Owner Approved
- **Context:**  
  Phase 7 requires persisting structured investigation results, facts, hypotheses, evidence snapshots, and audit events. The current deployment baseline is a local workstation running single-node Wazuh/OpenSearch in Docker, local Ollama on loopback, and FastAPI on loopback (`127.0.0.1`). Adding PostgreSQL requires provisioning and maintaining an additional Docker container in `wazuh-docker`, configuring secrets, and opening network ports.
- **Decision:**  
  Adopt **SQLite in Write-Ahead Logging (WAL) mode** (`sqlite+aiosqlite:///data/siem_history.db`) as the default database engine for the local single-user release. Abstract all models and queries via **SQLAlchemy 2.0 (Async)** to facilitate a future migration to PostgreSQL when multi-user requirements justify it.
- **Alternatives Considered:**  
  1. *PostgreSQL in Docker:* Highly robust, MVCC multi-writer, but introduces container orchestration overhead, credential management, and unnecessary complexity for a single-analyst loopback environment.
  2. *Flat JSON files on disk:* Zero dependencies, but lacks atomic transaction guarantees, foreign key cascades, secondary indexing, concurrent read safety, and standard query filtering.
  3. *In-Memory Caching (Redis):* Volatile on restarts; lacks relational query semantics and durability needed for audit records.
- **Consequences:**  
  - *Positive:* Zero infrastructure overhead; zero exposed network ports; daemon-less operation; atomic ACID transactions; full SQLAlchemy 2.0 portability.
  - *Negative:* Single-writer constraint (mitigated by WAL mode for concurrent readers); lacks native row-level security; security boundary relies on OS-level NTFS file ACLs.
- **Security Impact:** Minimizes attack surface by not listening on any network socket. Relies on host-level NTFS ACLs and BitLocker for data-at-rest protection.
- **Operational Cost:** Minimal. No background daemon or memory overhead.
- **PostgreSQL Portability Qualification & Caveats:**  
  > [!WARNING]
  > SQLite and PostgreSQL are **not** 100% interchangeable without code considerations:
  > 1. *Foreign Keys:* SQLite disables FKs by default on every connection (`PRAGMA foreign_keys = ON;` is required); PostgreSQL enforces FKs automatically.
  > 2. *Concurrency:* SQLite serializes all write transactions using a single file lock; PostgreSQL uses multi-version concurrency control (MVCC) with row-level locks.
  > 3. *Schema Migrations:* Alembic migrations targeting SQLite require `render_as_batch=True` to alter columns/tables; PostgreSQL natively supports DDL transactions.
  > 4. *Data Types:* SQLite stores JSON and Datetime as text strings; PostgreSQL provides native `JSONB` and `TIMESTAMPTZ` types.
  > Therefore, claiming "zero-code-change portability" is an oversimplification: driver configuration, Alembic batch mode, and dialect-specific connection listeners must be maintained.

---

### ADR-009: Minimized Evidence Snapshot Persistence vs Raw Log Duplication
- **Date:** 2026-10-20
- **Status:** APPROVED (Implementation Authorization Withheld)
- **Prior Status:** proposed
- **Approval Source:** Explicit project-owner decision recorded in Phase 7.0 review.
- **Context:**  
  AI investigations cite specific evidence items (`EV-01`, `EV-02`). Historical alerts in OpenSearch are subject to index rotation, rollover, or deletion under SIEM retention policies (ILM). If an investigation is retrieved after its source alert index has expired, citations would break unless evidence is preserved. Conversely, copying entire raw OpenSearch JSON documents creates massive data bloat and stores unredacted, unnecessary PII.
- **Decision:**  
  Persist a **minimized, sanitized evidence snapshot** (`investigation_evidence_snapshots`) for each evidence item evaluated during an investigation. Do not copy full raw OpenSearch documents. Link citations directly to these snapshots.
- **Alternatives Considered:**  
  1. *Reference-Only (store alert ID only):* Breaks citation provenance when OpenSearch indices rotate or alerts are purged.
  2. *Full Raw Document Mirroring:* Stores multi-kilobyte raw JSON blobs per event, duplicating OpenSearch storage and increasing data leakage risk.
- **Consequences:**  
  - *Positive:* Investigations remain forensically verifiable and self-contained forever, even if OpenSearch indices are pruned. Storage footprint is tiny ($< 35\text{ KB}$ per investigation).
  - *Negative:* Snapshots reflect evidence at the time of investigation, not retroactive log alterations (which is forensically desirable).
- **Security Impact:** Only pre-sanitized, redacted fields are persisted. Secrets and tokens are stripped before database insertion.

---

### ADR-010: Lifecycle Tracking for Failed and Cancelled Investigations
- **Date:** 2026-10-20
- **Status:** APPROVED (Implementation Authorization Withheld)
- **Prior Status:** proposed
- **Approval Source:** Explicit project-owner decision recorded in Phase 7.0 review.
- **Context:**  
  Inference can fail due to upstream Ollama timeouts, model unavailability, prompt injection rejection, or analyst cancellation. If persistence only stores successful investigations, operational failures and potential security denial-of-service attempts become invisible in the audit trail.
- **Decision:**  
  Persist an initial record in `investigations` with `status='running'` immediately upon request receipt. If inference succeeds, update to `'completed'` and attach results. If inference fails or is aborted, update to `'failed'` or `'cancelled'` with standard error codes (`UPSTREAM_TIMEOUT`, `DEPENDENCY_UNAVAILABLE`), duration, and audit events.
- **Alternatives Considered:**  
  1. *Only persist completed investigations:* Leaves gaps in operational audit logs; fails to record resource consumption or attack patterns.
- **Consequences:**  
  - *Positive:* Full operational visibility; tracking of model failure rates and timeouts; detection of repeated failing prompts.
  - *Negative:* Slightly higher row volume in `investigations` table (cleaned up via standard retention pruning).
- **Security Impact:** Enhances audit integrity and forensic accountability.

---

### ADR-011: Retention vs Audit Integrity (Soft-Purge & Independent Audit Lifecycle)
- **Date:** 2026-10-20
- **Status:** APPROVED (Implementation Authorization Withheld)
- **Prior Status:** proposed
- **Approval Source:** Explicit project-owner decision recorded in Phase 7.0 review.
- **Context:**  
  Privacy compliance and disk management require pruning old investigations (e.g. after 90 days), while security auditing mandates that administrative actions (who deleted what, when) remain immutable.
- **Decision:**  
  Implement a dual-lifecycle policy:
  1. **Investigations Lifecycle:** Retention period defaults to 90 days (`INVESTIGATION_RETENTION_DAYS=90`). When an investigation is deleted (manually or via retention pruning), its child tables (results, facts, hypotheses, evidence snapshots) are purged via database `ON DELETE CASCADE`.
  2. **Audit Events Lifecycle:** The `audit_events` table operates on an independent 365-day retention lifecycle and is **never** cascaded or deleted during investigation cleanup.
- **Alternatives Considered:**  
  1. *Hard-delete audit events with investigations:* Destroys forensic audit trail.
  2. *Never delete anything:* Causes unbounded disk growth on long-running deployments.
- **Consequences:**  
  - *Positive:* Satisfies privacy data minimization and disk bounding while preserving forensic non-repudiation.
  - *Negative:* Requires a dedicated retention cleanup utility.
- **Security Impact:** Ensures audit trails outlive transient investigation artifacts.

---

### ADR-012: Tamper-Evident Hash Chain Reality & Scope Limitations
- **Date:** 2026-10-20
- **Status:** APPROVED (Implementation Authorization Withheld)
- **Prior Status:** proposed (Human Approval Required)
- **Approval Source:** Explicit project-owner decision recorded in Phase 7.0 review.
- **Decision Owner:** Project Owner Approved
- **Context:**  
  Security compliance requires audit trails to be tamper-evident. On a local single-user system without an external HSM, WORM drive, or remote syslog server, all audit records reside within the local SQLite file (`siem_history.db`).
- **Decision:**  
  Implement a sequential SHA-256 hash chain linking each audit event to its predecessor. Acknowledge and document that this mechanism detects **accidental corruption** and **uncoordinated local file tampering**, but **cannot** prevent an attacker with local OS write access from altering a record and recomputing the SHA-256 chain forward.
- **Alternatives Considered:**  
  1. *Plain unhashed audit logging:* Provides zero integrity or tampering detection.
  2. *Mandatory Remote Append-Only Syslog / Cloud WORM:* Highly secure, but introduces external network dependencies and infrastructure complexity prohibited in a loopback-only local environment.
- **Consequences:**  
  - *Positive:* Provides deterministic integrity verification for accidental corruption without network dependencies.
  - *Negative:* Must not be advertised or relied upon as absolute immutability against privileged local compromise.
- **Security Impact:** Clearly articulates the trust boundary and avoids false security claims.

---

## 3. Unresolved & Pending Decisions

| Decision Topic | Status | Impact & Trigger for Resolution |
|---|---|---|
| **Phase 7.1 Implementation Authorization** | **WITHHELD / PENDING** | Authorizing execution of Python code, ORM models, and database creation. Trigger: Explicit Project Owner command. |
| **Multi-User RBAC & Authentication Provider** | **PENDING** | Current implementation uses shared local Bearer token (`API_KEY`). Transitioning to multi-user RBAC requires selecting an auth mechanism (e.g., local SQLite users + bcrypt vs external OIDC/SAML). Trigger: Authorization of Phase 8 multi-analyst deployment. |
| **SQLCipher vs Platform Encryption** | **PENDING** | Standard SQLite relies on host BitLocker/NTFS ACLs. Adopting SQLCipher for cryptographic file-level encryption requires compiling native C binaries on Windows. Trigger: High-security compliance mandate requiring software-level database encryption at rest. |
| **Remote Append-Only Syslog Export** | **PENDING** | Forwarding audit events in real-time to a remote, write-only syslog server for hardware-level immutability. Trigger: Enterprise SOC compliance review. |
