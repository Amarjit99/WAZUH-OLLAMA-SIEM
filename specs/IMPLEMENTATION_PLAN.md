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

## Phase 14 — Automated Threat Intelligence (TI) & IOC Enrichment
Tasks:
- Implement `ThreatIntelService` supporting pluggable providers:
  - AbuseIPDB (IP abuse score, domain, ISP, country code)
  - AlienVault OTX (Pulse indicators, threat adversary tags)
  - VirusTotal / MalwareBazaar (File hash reputation: MD5, SHA-1, SHA-256)
  - CISA KEV (Known Exploited Vulnerabilities catalog lookup)
- Add local SQLite / in-memory LRU caching to eliminate external API latency, respect rate limits, and support air-gapped corporate deployments.
- Build `/api/v1/threat-intel/lookup/{ioc_type}/{ioc_value}` and batch enrichment endpoints.
- Auto-enrich alert evidence with color-coded threat badges (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN`) in the Alert Explorer and Alert Detail Modal.
- Provide full attribution details: Confidence score (0-100), threat categories, and geographic origin.
Exit: verified live/cached IOC enrichment with automated fallback when external feeds are unreachable.

## Phase 15 — Direct Active Response (1-Click Agent Isolation & Rollback)
Tasks:
- Integrate directly with Wazuh Manager REST API `/active-response` endpoint over authenticated TLS session.
- Expand `ContainmentService` with live dispatch capabilities for:
  - `host-isolation`: Disconnects all network interfaces on the endpoint except SIEM keep-alive port (1514/1515).
  - `firewall-drop`: Instantly injects blocking rules on Linux (`iptables`/`nftables`) or Windows (`netsh`).
  - `kill-process`: Terminates identified malicious PID across the target agent.
- Build a safe Rollback / Restore mechanism (`unblock` / `reconnect-host`) to instantly revert containment if an alert is deemed a false positive.
- Enforce loopback (`127.0.0.1`), gateway, and SIEM server IP protection against self-lockout.
- Log every direct dispatch and rollback event into the tamper-evident SQLite audit ledger with SHA-256 hash chaining.
Exit: verified live agent command dispatch and rollback with sub-2-second execution confirmation.

## Phase 16 — Automated Executive & Compliance Reporting Engine (PCI-DSS, ISO 27001, SOC 2, HIPAA)
Tasks:
- Correlate ingested Wazuh alerts and system events against international compliance standards:
  - PCI-DSS 4.0 (Requirement 10: Log Monitoring, Requirement 11: File Integrity)
  - ISO/IEC 27001:2022 (A.8.15 Logging, A.8.16 Monitoring Activities)
  - SOC 2 Type II (Common Criteria 6.1, 6.8: Incident Response & Audit Trails)
  - HIPAA Security Rule (45 CFR § 164.312: Audit Controls)
- Implement `ComplianceReportService` with `/api/v1/compliance/summary` and `/api/v1/compliance/export/pdf` endpoints.
- Build dedicated "Compliance & Audit" dashboard in frontend featuring:
  - Real-time Compliance Readiness Gauges (% Passing vs Failing controls)
  - Top 10 Attack Vectors and Compromised Entities
  - 1-Click Executive PDF and HTML report generation with tamper-evident cryptographic signoff.
Exit: complete, auditor-ready compliance report generation with CSV formula sanitization.

## Phase 17 — Enterprise SSO & Role-Based Access Control (RBAC)
Tasks:
- Implement OAuth2 / OIDC authentication layer compatible with enterprise identity providers:
  - Microsoft Entra ID (Azure Active Directory)
  - Okta Identity Cloud
  - Keycloak / FreeIPA on-premise IAM
  - Standard Local Database fallback with Argon2id password hashing
- Define granular role permissions:
  - `SOC_ANALYST_TIER_1`: View alerts, perform AI threat hunting, open cases (Read-Only).
  - `SOC_ANALYST_TIER_2`: Update cases, approve containment playbooks, add IOCs.
  - `SOC_ADMIN`: Manage API keys, configure threat feeds, trigger direct active response, inspect audit ledger.
- Add backend endpoint permission decorators (`@require_permission(...)`) and frontend dynamic UI gating.
Exit: security test verification proving unauthorized role escalation is rejected with 403 Forbidden.

## Phase 18 — User & Entity Behavior Analytics (UEBA) & Anomaly Detection
Tasks:
- Implement statistical and heuristic anomaly detection modules over indexed OpenSearch telemetry:
  - **Impossible Travel:** Detects concurrent or near-concurrent logins from geographically disparate IP locations within impossible flight times.
  - **After-Hours Anomaly:** Flags employee or service accounts accessing critical assets outside baseline operational hours.
  - **Privilege Escalation Spikes:** Detects sudden bursts of administrative actions, `sudo` elevation, or group modifications.
- Assign an aggregate User Risk Score (0-100) per employee and host entity.
- Render UEBA Risk Timeline and Top Risky Users widget in the SIEM dashboard.
Exit: test suite verifying synthetic baseline deviations trigger high-fidelity UEBA alerts.

## Phase 19 — Multi-Cloud & SaaS Security Telemetry Connectors
Tasks:
- Build specialized log ingestion and normalization pipelines for modern enterprise cloud environments:
  - **AWS CloudTrail & VPC Flow Logs:** S3-bucket based ingestion detecting root login, IAM privilege modifications, and open Security Groups.
  - **Microsoft 365 / Entra ID Audit Logs:** Detects mass mail forwarding rules, consent grant abuse, and external sharing anomalies.
  - **GitHub / GitLab Enterprise Audit Logs:** Detects hardcoded secrets, mass repository exports, and branch protection bypasses.
- Normalize cloud telemetry into Wazuh/ECS unified schema.
- Display multi-cloud threat origin map in the SIEM dashboard.
Exit: end-to-end cloud event normalization and threat alerting verified without data drop.

## Work rules
- Complete one vertical slice at a time.
- Avoid parallel implementation of dependent contracts.
- Update tests and docs with every behavior change.
- Keep commits small and reversible.
- Do not add advanced response automation before the read-only system is reliable.
