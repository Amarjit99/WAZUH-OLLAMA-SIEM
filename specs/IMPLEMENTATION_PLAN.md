# Implementation Plan

## Phase 0 — Environment discovery and specification
Tasks:
- Inspect repository and current code.
- Confirm OS, hardware, Wazuh version/topology, indexer TLS/auth, Ollama availability, model tag.
- Complete and review specs.
Exit: requirements and dependencies are clear; unknowns are recorded.

## Phase 1 — Runnable skeleton
Tasks:
- Create backend and frontend.
- Central configuration, health endpoints, lint/test/build commands.
- Establish API client and typed errors.
Exit: both apps run; checks pass; no fabricated production data.

## Phase 2 — Real Wazuh connector
Tasks:
- Implement authenticated API and/or indexer connector.
- Discover real mappings and index patterns.
- Add alert normalization, bounded filters, pagination, error handling.
Exit: actual test alert is retrieved from the target environment.

## Phase 3 — Evidence retrieval
Tasks:
- Retrieve related events by bounded time window and allowlisted filters.
- Preserve source IDs and retrieval metadata.
- Add field minimization/redaction.
Exit: investigation evidence can be reproduced and traced.

## Phase 4 — Ollama integration
Tasks:
- Validate model/service health.
- Implement bounded local inference, versioned prompt, response schema, validator.
- Add timeouts, concurrency controls, error handling, audit metadata.
Exit: real retrieved evidence yields a validated result or a clear failure.

## Phase 5 — Dashboard vertical slice
Tasks:
- Alert explorer, filters, detail page, investigation state, evidence and AI display.
- Implement all loading/empty/stale/error states.
Exit: full path works through the UI.

## Phase 6 — Polling and reliability
Tasks:
- Checkpointed polling with stable IDs, overlap, deduplication, retries, late-arrival handling.
- Add observability and lag metrics.
Exit: restart/retry tests show no known loss/duplication in tested scenarios.

## Phase 7 — Cases and reports
Tasks:
- Add persistence only for required application metadata.
- Cases, notes, status, CSV/JSON export, authorization and audit.
Exit: exports are correct and access-controlled.

## Phase 8 — Notifications
Tasks:
- Add durable notification job state, idempotency, bounded retry.
- Use approved internal email/notification route.
- Enable external channels only after privacy review.
Exit: tested delivery and failure recovery.

## Phase 9 — Security hardening
Tasks:
- RBAC, secret management, TLS, network restrictions, redaction, retention.
- Security tests and threat-model review.
Exit: release security criteria pass.

## Phase 10 — Performance and release
Tasks:
- Load/latency tests, model factuality evaluation, backup/recovery tests, operational runbook.
- Document deployment topology and supported versions.
Exit: acceptance criteria are evidenced, known limitations are published.

## Phase 11 — Endpoint fleet telemetry (Completed)
Tasks:
- Implement `/api/v1/agents` connector and summary endpoint.
- Add frontend monitored fleet table with status filters (active, disconnected, never_connected) and search.
- Verified live with Wazuh Manager cluster telemetry.
Exit: verified live agent table with real heartbeats and auto-refresh.

## Phase 12 — Automated alert webhook dispatcher (Completed)
Tasks:
- Add `NotificationService` with high-severity alert filtering.
- Implement `/api/v1/notifications/test-webhook` endpoint with credential masking.
- Format structured payloads for Slack, Discord, and generic JSON webhooks.
Exit: verified interactive webhook delivery test from UI.

## Phase 13 — Analyst-approved active response & containment (Completed)
Tasks:
- Implement `/api/v1/containment/propose` multi-platform rule generator (Linux iptables/nftables, Windows netsh, Wazuh Active Response).
- Enforce loopback lockout prevention (`127.0.0.1`, `::1` rejected).
- Implement human-in-the-loop approval gate in `/api/v1/containment/execute` (`analyst_approval=true` mandatory).
- Record containment approvals into SQLite audit ledger with SHA-256 cryptographic hash chaining.
- Build glassmorphic analyst containment modal in UI with playbook copy buttons.
Exit: verified end-to-end containment approval and cryptographic audit recording in browser.

## Work rules
- Complete one vertical slice at a time.
- Avoid parallel implementation of dependent contracts.
- Update tests and docs with every behavior change.
- Keep commits small and reversible.
- Do not add advanced response automation before the read-only system is reliable.
