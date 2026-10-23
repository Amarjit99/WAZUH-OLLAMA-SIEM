# Product Requirements Document (PRD) — Phase 7: Secure Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_PRD.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** Phase 7 Documentation & Architecture Planning  
**Target Platform:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Authors:** SOC Engineering & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. Executive Summary & Problem Statement

### 1.1 Context
In Phases 1 through 6B, the Wazuh + Ollama SIEM platform established:
1. Authoritative alert ingestion and indexing from Wazuh and OpenSearch.
2. Evidence-grounded local AI investigation via Ollama (`llama3.2:3b`) with bounded evidence extraction, deterministic correlation, and strict citation verification.
3. SOC analyst workflow enhancements including segregated facts/hypotheses, interactive citation navigation, and markdown export.

### 1.2 The Problem
Currently, all investigation results are **ephemeral**, living exclusively in frontend React component state (`investigationResult`). 
- When an analyst closes the browser tab, refreshes the page, or navigates to another alert, the entire investigation context—including generated findings, cited evidence packages, grounding warnings, and recommended read-only checks—is discarded.
- Comparing subsequent investigations of the same alert or host is impossible without re-invoking the LLM, causing redundant compute overhead and inconsistent analysis.
- Operational security oversight lacks an audit trail of which alerts were analyzed, which model parameters were used, when investigations occurred, and what validation warnings were triggered.
- OpenSearch index lifecycle management (ILM) periodically rotates or deletes historical alert indexes, meaning that without a persistent record of the evaluated evidence snapshot, historical investigations cannot be substantiated.

### 1.3 Goals
1. **Durable Investigation Records:** Persist completed, failed, and cancelled investigations with their model configurations and execution timings.
2. **Forensic Evidence Snapshots:** Store the minimized, sanitized evidence items evaluated during an investigation to ensure citations remain verifiable even if the underlying OpenSearch alert expires.
3. **Structured Audit Trail:** Log security-relevant analyst actions (creation, viewing, export, deletion) in a structured audit log.
4. **Preserved Security Baseline:** Enforce loopback-only binding, API authentication, strict read-only guarantees, and zero leakage of raw credentials or secrets.

---

## 2. User Personas & System Scope

### 2.1 Supported Persona (Current Single-User Scope)
- **SOC Tier 1 / Tier 2 Analyst (Local Operator):**
  - Operates on a dedicated, local loopback workstation (`127.0.0.1`).
  - Triages incoming Wazuh alerts, executes AI-assisted investigations, reviews cited evidence provenance, and exports sanitized findings into ticketing systems.
  - Requires quick retrieval of recent investigations, searching by alert ID, rule ID, host name, or time range.
  - Operates under a shared, local API Bearer token (`API_KEY`) configured in environment settings.

### 2.2 Future Multi-User Persona (Out of Scope for Phase 7.x Initial Release)
- **SOC Lead / Incident Response Manager / Multi-Tenant Teams:**
  - Requires individual user accounts, role-based access control (RBAC), team-segregated investigation queues, and cryptographic non-repudiation.
  - *Distinction:* Phase 7 design introduces relational database schemas and data models that accommodate an `actor_id` or `created_by` field, but does **not** implement full identity federation (LDAP/SAML/OIDC) or multi-user RBAC in this phase.

---

## 3. Functional Requirements

### 3.1 Investigation Lifecycle & Persistence
- **FR-1.1 (State Tracking):** The system MUST track and persist investigation lifecycle states: `queued`, `running`, `completed`, `failed`, and `cancelled`.
- **FR-1.2 (Automatic Persistence):** When an analyst triggers `/api/v1/alerts/{alert_id}/investigate`, the backend MUST record an initial investigation entry with timestamps, target alert metadata, and request parameters.
- **FR-1.3 (Finalization):** Upon inference completion and schema validation, the system MUST persist the structured result (summary, observed facts, hypotheses, read-only checks, limitations, confidence label, and grounding warnings).
- **FR-1.4 (Failure & Cancellation Logging):** If inference fails (HTTP 502/503/504) or is cancelled by the analyst, the system MUST persist the failure state with standard error codes (e.g. `UPSTREAM_TIMEOUT`, `DEPENDENCY_UNAVAILABLE`), avoiding silent drops.
- **FR-1.5 (Multi-Run Versioning):** The system MUST allow multiple investigations for the same alert (e.g., investigating with different correlation windows or different model tags). Each run receives a distinct, globally unique `investigation_id` (UUIDv4) and a sequential run index for that alert.

### 3.2 Evidence Snapshot Persistence
- **FR-2.1 (Evidence Packaging):** The system MUST persist the exact normalized, sanitized evidence package evaluated during the investigation (`items: List[EvidenceItem]`).
- **FR-2.2 (Data Minimization):** Stored evidence items MUST be restricted to allowlisted fields: `evidence_id`, `source_record_id`, `event_timestamp`, `is_primary`, `rule_id`, `rule_level`, `rule_description`, `agent_name`, `source_ip`, `destination_ip`, `username`, `correlation_reason`, `correlation_qualifier`, and `raw_evidence_ref`.
- **FR-2.3 (No Raw OpenSearch Duplication):** The database MUST NOT store full raw Elasticsearch/OpenSearch JSON documents or unredacted log blobs.
- **FR-2.4 (Citation Preservation):** Foreign key or relational linkage MUST ensure that citations in observed facts (`cited_evidence_ids`) resolve directly to persisted evidence items.

### 3.3 Search, Filtering, Sorting, and Pagination
- **FR-3.1 (History Listing):** The API MUST provide a bounded history query endpoint (`GET /api/v1/investigations`).
- **FR-3.2 (Filters):** The endpoint MUST support filtering by:
  - `alert_id` (exact match)
  - `status` (`completed`, `failed`, `cancelled`)
  - `start_time` and `end_time` (ISO 8601 UTC window)
  - `rule_id` (source alert rule identifier)
  - `agent_name` (source agent/host)
  - `confidence_label` (`low`, `medium`, `high`)
- **FR-3.3 (Pagination):** Pagination MUST be enforced server-side (default 25 records, hard upper bound 100 records per page).
- **FR-3.4 (Deterministic Sorting):** Results MUST be sortable by `created_at` (descending by default) or `execution_duration_ms`.

### 3.4 Report Export & Sanitization
- **FR-4.1 (Standard Formats):** The system MUST support exporting persisted investigations in structured JSON and sanitized Markdown formats.
- **FR-4.2 (Credential Redaction):** Exports MUST undergo strict automated redaction; no tokens, passwords, internal endpoints, or private keys may appear in export output.
- **FR-4.3 (Advisory Banner Inclusion):** All exports MUST prominently include the advisory disclaimer: *"Wazuh alert logs remain the authoritative detection and forensic record. AI output is advisory."*

### 3.5 Retention, Deletion, and Soft-Purge
- **FR-5.1 (Configurable Retention):** The system MUST support a configurable retention duration (default: 90 days, configurable via `INVESTIGATION_RETENTION_DAYS`).
- **FR-5.2 (Automated Expiration Cleanup):** A maintenance routine MUST be definable to prune expired investigation records and their associated evidence snapshots once retention expires.
- **FR-5.3 (Manual Deletion / Soft-Purge):** If an analyst deletes an investigation via the API, the system MUST soft-delete the record (`deleted_at` timestamp) or purge it in accordance with policy, while recording an immutable audit event.

### 3.6 Audit Trail
- **FR-6.1 (Security Audit Logging):** An audit event MUST be written whenever an investigation is:
  - Created (`INVESTIGATION_CREATED`)
  - Viewed / read (`INVESTIGATION_VIEWED`)
  - Exported (`INVESTIGATION_EXPORTED`)
  - Deleted (`INVESTIGATION_DELETED`)
- **FR-6.2 (Audit Metadata):** Audit events MUST record: `audit_id`, `timestamp` (UTC), `actor_id` (or `local_analyst`), `action`, `resource_type`, `resource_id`, `outcome` (`SUCCESS`/`FAILURE`), `request_id`, and `client_ip`.

---

## 4. Non-Functional Requirements

### 4.1 Security & Threat Mitigation
- **NFR-1.1 (Loopback Confinement):** Database access MUST be restricted to the backend application running on `127.0.0.1`. No database ports or direct connections may be exposed to the external network or browser.
- **NFR-1.2 (SQL Injection Defense):** All database operations MUST use parameterized queries via an approved ORM/query builder (SQLAlchemy Core/ORM 2.0). Raw concatenated SQL queries are strictly prohibited.
- **NFR-1.3 (Zero Secret Persistence):** The database MUST NOT store API keys, Wazuh JWTs, OpenSearch passwords, or TLS private keys.
- **NFR-1.4 (Filesystem Permissions):** On Windows hosts, the database file or data directory MUST be restricted via NTFS ACLs to the user executing the backend process and the SYSTEM account.

### 4.2 Performance & Resource Bounds
- **NFR-2.1 (Query Latency):** Querying an individual investigation by ID with evidence items MUST complete in $< 50\text{ ms}$ under local single-user load.
- **NFR-2.2 (History Listing Latency):** Paged list queries (page size 50) with standard filters MUST complete in $< 100\text{ ms}$.
- **NFR-2.3 (Storage Footprint):** Storing one complete investigation (with summary, facts, hypotheses, checks, and 10 sanitized evidence items) MUST consume $< 35\text{ KB}$ of disk space on average.
- **NFR-2.4 (Disk Bounds):** The system MUST monitor free disk space and fail safely with HTTP 507 (`INSUFFICIENT_STORAGE`) rather than corrupting database files when available disk space drops below 500 MB.

### 4.3 Reliability & Failure Isolation
- **NFR-3.1 (SIEM Independence):** Database unavailability MUST NOT prevent Wazuh alerting, OpenSearch log ingestion, or live alert browsing.
- **NFR-3.2 (Graceful Degradation):** If the database is offline or in read-only mode, live alert investigation MAY proceed in an explicit ephemeral mode, returning a visible warning: *"Persistence unavailable: Investigation executed in ephemeral memory only."*
- **NFR-3.3 (Atomic Transactions):** Storing an investigation and its associated evidence items, facts, and hypotheses MUST occur within an atomic database transaction. Partial writes resulting in orphaned facts or missing evidence items are strictly prohibited.

---

## 5. Privacy & Sensitive Evidence Minimization

1. **Untrusted Input Treatment:** All log strings, user fields, and agent names stored in the database remain classified as untrusted external data.
2. **PII and Secret Redaction:** Evidence packages must pass through `EvidenceService` sanitization prior to database insertion.
3. **Prompt Minimization:** The system MUST NOT persist full multi-thousand-token LLM system prompts in the relational database for every run; instead, it records a deterministic `prompt_version` hash and stores only the user-specific evidence context.

---

## 6. Out of Scope for Phase 7

The following capabilities are explicitly deferred to future phases:
- Automated threat remediation, active response, or firewall modification.
- Multi-tenant enterprise identity providers (SAML 2.0, Okta, Active Directory LDAP).
- External cloud database hosting (AWS RDS, Google Cloud SQL).
- Distributed message streaming architectures (Kafka, RabbitMQ) prior to high-volume distributed ingestion requirements.
- Collaborative multi-analyst live editing or commenting threads.

---

## 7. Acceptance Criteria

| ID | Criterion | Verification Method |
|---|---|---|
| **AC-PRD-1** | All investigation states (`completed`, `failed`, `cancelled`) persist reliably. | Integration test verifying database state transitions. |
| **AC-PRD-2** | Sanitized evidence snapshots are preserved and linkable to citations. | Contract test asserting `cited_evidence_ids` match stored `evidence_items`. |
| **AC-PRD-3** | Bounded history API returns paginated records with filtering. | API test validating `page_size`, rule, host, and time window filters. |
| **AC-PRD-4** | Expired alerts in OpenSearch do not break stored investigation viewing. | Integration test deleting source alert from mock OpenSearch and retrieving investigation. |
| **AC-PRD-5** | Audit events are recorded for every state change, export, and deletion. | Audit table inspection confirming corresponding event records. |
| **AC-PRD-6** | Database failure degrades gracefully without crashing core SIEM. | Chaos test simulating database lock/disconnect while testing alert endpoints. |
