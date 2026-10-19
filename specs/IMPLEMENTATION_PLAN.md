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

## Work rules
- Complete one vertical slice at a time.
- Avoid parallel implementation of dependent contracts.
- Update tests and docs with every behavior change.
- Keep commits small and reversible.
- Do not add advanced response automation before the read-only system is reliable.
