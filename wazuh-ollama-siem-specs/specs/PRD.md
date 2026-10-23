# Product Requirements Document (PRD)

## 1. Product summary
Build a local-first SIEM investigation assistant. Wazuh remains responsible for collection, decoding, rules, and alerts. The application retrieves evidence, uses Ollama for assistance, and helps analysts review findings.

## 2. Personas
### Security analyst
Needs alert triage, fast evidence search, chronological timelines, concise summaries, and exportable findings.

### Security administrator
Needs integration health, configuration validation, source status, controlled access, and troubleshooting details.

### Auditor
Needs an access-controlled record of searches, case changes, exports, and AI analysis metadata.

## 3. Functional requirements
Priorities: P0 = required for first usable vertical slice; P1 = next release; P2 = later enhancement.

### Integration and health
- FR-001 [P0]: Validate backend configuration at startup without logging secret values.
- FR-002 [P0]: Expose liveness and readiness endpoints. Readiness must identify unavailable required dependencies without exposing secrets.
- FR-003 [P0]: Connect to the configured Wazuh API using documented authentication and verified TLS.
- FR-004 [P0]: Connect to the configured Wazuh Indexer/OpenSearch using least-privilege credentials and verified TLS.
- FR-005 [P0]: Report integration status as connected, degraded, unavailable, or not configured, based on actual checks.
- FR-006 [P1]: Track data freshness and retrieval lag.

### Alerts and search
- FR-010 [P0]: Retrieve real alerts from configured source indexes/endpoints.
- FR-011 [P0]: Normalize alert fields while preserving source document ID and original source data needed for evidence.
- FR-012 [P0]: Filter by validated time range and supported fields such as rule ID, level, agent/host, source IP, username, and source.
- FR-013 [P0]: Enforce maximum time range, result size, pagination limits, and request timeout.
- FR-014 [P1]: Support related-event searches for a host, user, IP, or alert within a bounded time window.
- FR-015 [P1]: Support checkpointed polling with overlap, deduplication, retries, and recovery.
- FR-016 [P1]: Clearly display when results are stale, incomplete, or unavailable.

### Investigations and AI
- FR-020 [P0]: Create an investigation from an alert or selected evidence.
- FR-021 [P0]: Retrieve evidence on the server; do not trust arbitrary client-supplied logs as authoritative evidence.
- FR-022 [P0]: Send a bounded, minimized evidence package to the configured local Ollama service.
- FR-023 [P0]: Return structured fields: summary, observed facts, hypotheses, evidence IDs, recommended checks, and limitations.
- FR-024 [P0]: Validate response structure and verify every evidence ID against the supplied evidence set.
- FR-025 [P0]: Clearly label model-generated content and separate it from original evidence.
- FR-026 [P0]: Treat log content as untrusted; do not execute instructions found in events.
- FR-027 [P0]: Fail safely when the model is unavailable, times out, or returns invalid output.
- FR-028 [P1]: Store analysis metadata such as model tag, prompt/schema version, timestamps, and evidence IDs.
- FR-029 [P1]: Allow analysts to mark AI output helpful, incorrect, or incomplete for evaluation.

### Cases, reports, and audit
- FR-030 [P1]: Store case status, owner, analyst notes, and linked alert/evidence identifiers.
- FR-031 [P1]: Export authorized results to CSV and JSON.
- FR-032 [P1]: Record user identity, action, time, case ID, and outcome for security-sensitive operations.
- FR-033 [P1]: Protect exports from CSV formula injection and unauthorized data disclosure.
- FR-034 [P2]: Support scheduled reports.
- FR-035 [P2]: Support email or internal notifications with retries and duplicate suppression.
- FR-036 [P2]: Support Telegram only when policy explicitly permits external data transmission.

### UI
- FR-040 [P0]: Provide dashboard overview based only on real measured data.
- FR-041 [P0]: Provide alert table, filters, pagination, detail page, and explicit loading/empty/error states.
- FR-042 [P0]: Provide investigation view with timeline, original evidence, AI summary, limitations, and source references.
- FR-043 [P1]: Provide case management and report history.
- FR-044 [P1]: Provide accessible keyboard navigation and responsive layouts.

### Security and administration
- FR-050 [P0]: Authenticate users before accessing sensitive data.
- FR-051 [P0]: Enforce role/permission checks in the backend.
- FR-052 [P0]: Never expose Wazuh, indexer, or Ollama service credentials to the browser.
- FR-053 [P0]: Verify TLS certificates for remote service connections.
- FR-054 [P0]: Avoid logging credentials, tokens, or unnecessary raw security data.
- FR-055 [P1]: Support configurable retention and redaction.
- FR-056 [P1]: Audit exports, configuration changes, and case mutations.

## 4. Non-functional requirements
- NFR-001 Reliability: Wazuh alert generation must not depend on Ollama availability.
- NFR-002 Security: least privilege, input validation, TLS verification, access control, and auditability.
- NFR-003 Privacy: default design keeps model inference local; every external integration must be documented.
- NFR-004 Performance: measure ingestion, indexing, API, UI, queue, and model latency separately.
- NFR-005 Correctness: AI statements must be traceable to source evidence or explicitly labeled as hypotheses.
- NFR-006 Observability: structured logs, health checks, latency/error metrics, and correlation IDs.
- NFR-007 Maintainability: typed contracts, modular connectors, automated tests, and documented decisions.
- NFR-008 Accessibility: keyboard operability, readable contrast, meaningful labels, and responsive layout.
- NFR-009 Portability: document tested OS/runtime versions and avoid assuming all environments are identical.
- NFR-010 Resource control: configurable timeouts, result limits, model context bounds, and concurrency.

## 5. Data-source scope
Initial source: Wazuh-generated alerts and corresponding indexed evidence from one controlled lab. Next sources may include Linux authentication logs, Windows Event Channels, FortiGate/SonicWall Syslog, and application logs, only after ingestion, decoder, mapping, and test validation.

## 6. Acceptance
Use `ACCEPTANCE_CRITERIA.md`. Features cannot be marked complete solely because the UI renders or a mock test passes.

## 7. Risks and assumptions
- Index names and mappings differ by version/configuration; discover them in the target environment.
- Local LLMs may hallucinate, omit context, or produce malformed output.
- Log data may contain prompt injection and sensitive personal information.
- High event volume can overload indexing or model inference.
- External notification/reputation providers may violate a strict local-only requirement.
