# Architecture Decision Log

Record decisions with date, status, context, decision, alternatives, and consequences. Proposed decisions below should be confirmed during environment discovery.

## ADR-001: Wazuh remains authoritative for detection
- Status: accepted
- Context: AI output is probabilistic and can be wrong.
- Decision: Wazuh rules and source evidence remain the authority for alerts. Ollama assists investigation only.
- Consequence: AI summaries cannot create a confirmed alert status on their own.

## ADR-002: Local inference via Ollama
- Status: accepted for initial design
- Context: the project prioritizes keeping evidence inside the internal environment.
- Decision: Ollama is the local inference endpoint; only the backend calls it.
- Consequence: model tag, hardware, resource limits, and outbound-network policy must be documented. Local inference alone does not make every other integration local.

## ADR-003: Read-only first release
- Status: accepted
- Context: automated response is high impact.
- Decision: v1 has no automated remediation.
- Consequence: future response actions require separate authorization, audit, and safety review.

## ADR-004: Indexer for indexed alert search
- Status: proposed/confirm in environment
- Context: searchable alert evidence is needed.
- Decision: use documented OpenSearch/Wazuh Indexer search with verified mappings and restricted credentials; use Wazuh API for supported manager/agent operations.
- Consequence: actual indexes and fields must be discovered for the deployed version.

## ADR-005: Start with checkpointed polling
- Status: accepted for initial milestone
- Context: polling is simpler to validate than an event streaming pipeline.
- Decision: start with bounded polling, stable IDs, overlap, deduplication, and checkpoint persistence.
- Consequence: latency is measured and not advertised as instantaneous. Introduce a queue/stream only when justified.

## ADR-006: Keep frontend away from infrastructure credentials
- Status: accepted
- Decision: browser talks only to the authenticated backend.
- Consequence: all authorization and query validation occur server-side.

## ADR-007: Introduction of persistent relational storage
- Status: accepted (Approved by Project Owner in conversation; implementation authorization withheld)
- Prior Status: proposed (as "Optional database and queue")
- Context: investigation history, citation traceability after OpenSearch rollover, and audit requirements justify transitioning from ephemeral state to persistent relational storage.
- Decision: introduce persistent relational storage layer for investigation history, evidence snapshots, and audit events.
- Consequence: enables durable investigation records and audit trails; requires migration framework, disk management, and backup procedures.
- Implementation Status: NOT AUTHORIZED (Architectural decision approved; implementation requires separate explicit authorization).

## ADR-008 through ADR-012: Phase 7 Architecture Decisions
Detailed records are maintained in [specs/PHASE_7_ADR.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md) and [PHASE_7_0_DECISION_REGISTER.md](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_0_DECISION_REGISTER.md):
- **ADR-008:** SQLite WAL, aiosqlite, and SQLAlchemy 2.0 async architecture — **APPROVED** (implementation withheld)
- **ADR-009:** Minimized, sanitized evidence snapshots vs. raw OpenSearch logs — **APPROVED** (implementation withheld)
- **ADR-010:** Full investigation lifecycle (failed, cancelled, crash recovery) — **APPROVED** (implementation withheld)
- **ADR-011:** 90-day investigation retention and 365-day audit retention — **APPROVED** (implementation withheld)
- **ADR-012:** Local hash-chained audit logging and documented trust limitations — **APPROVED** (implementation withheld)

## ADR-013: Audit Retention Checkpoint Architecture & Verifiable Archival
- Status: **APPROVED** (Explicitly Approved by Project Owner)
- Date: 2026-10-20
- Context: Pruning audit events older than 365 days breaks sequential SHA-256 hash chains from genesis.
- Decision: Adopt Segmented Checkpoint & Verifiable Archival Architecture with Windows DPAPI-backed signing, configurable archive directory (`AUDIT_ARCHIVE_DIR`), and strict fail-closed verification. Physical audit pruning remains bounded and gated on verified checkpoints and archives.
- Consequence: Enables cryptographic verification across retained suffixes and offline archives; bounds long-term database storage growth.

## Decision template
### ADR-XXX: Title
- Date:
- Status: proposed / accepted / superseded
- Context:
- Decision:
- Alternatives:
- Consequences:
- Verification:

