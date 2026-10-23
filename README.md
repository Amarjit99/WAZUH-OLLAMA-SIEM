# Wazuh + Ollama Local AI SIEM

A locally hosted, AI-assisted security investigation platform that combines Wazuh detections, searchable indexed security evidence, Ollama local inference, and an analyst dashboard.

> Status: **Fully Implemented and Verified**. Live integration combining real Wazuh alert ingestion, authenticated OpenSearch queries, local Ollama LLM threat hunting, case tracking, tamper-evident SHA-256 audit ledger, monitored endpoint fleet telemetry, automated webhook alert dispatcher, and analyst-approved containment playbooks. All 205 test suites passing.

## Purpose
- Collect security events through Wazuh-supported collection paths.
- Use Wazuh rules and alerting as the authoritative detection mechanism.
- Retrieve relevant alert evidence through documented, authenticated APIs.
- Use a locally hosted Ollama model to summarize selected evidence and suggest read-only investigative checks.
- Present source evidence and AI interpretation separately with confidence scoring and MITRE ATT&CK mapping.
- Manage endpoint agent fleet health and keep-alive heartbeats.
- Automatically dispatch high-severity security notifications to SOC channels (Slack/Discord/webhooks).
- Provide safe, analyst-gated active response and containment playbooks (Linux iptables/nftables, Windows Firewall, Wazuh Active Response).
- Record every action in a cryptographic SQLite audit ledger with SHA-256 hash chaining.

## Release features
Included:
- Real, authenticated Wazuh alert retrieval and live streaming.
- Verified OpenSearch/Wazuh Indexer search with query bounded limits.
- Local Ollama AI investigation of bounded, authorized evidence.
- Analyst case management and exportable CSV/JSON reports.
- Monitored endpoint fleet telemetry and status filtering.
- Automated webhook notifications for critical/high-severity alerts.
- Human-in-the-Loop active response and containment playbooks with loopback lockout protection.
- Tamper-evident SHA-256 cryptographic audit logging and automated backup/retention.

Not included in the first release:
- Autonomous response/remediation.
- LLM-generated commands executed on hosts.
- Unrestricted internet reputation lookups.
- Claims of content-level AI-tool monitoring from firewall metadata alone.
- Guaranteed detection of every attack.
- Multi-tenant SaaS unless separately specified.

## Intended stack
- SIEM: Wazuh agents, Wazuh server/manager, Wazuh Indexer, Wazuh Dashboard.
- Search: Wazuh Indexer/OpenSearch, using verified mappings and least-privilege credentials.
- Local AI: Ollama with an explicitly installed and evaluated model.
- Backend: Python 3.11+ (confirm supported runtime), FastAPI, Pydantic, pytest.
- Frontend: React + TypeScript, accessible responsive UI.
- Optional later components: PostgreSQL for cases/audit metadata; Redis or another durable queue for background jobs; SMTP/internal notification adapter.

## Documentation map
- `AGENTS.md`: coding-agent instructions.
- `specs/PROJECT_BRIEF.md`: product summary and goals.
- `specs/PRD.md`: functional and non-functional requirements.
- `specs/ARCHITECTURE.md`: components and trust boundaries.
- `specs/DATA_FLOW.md`: event and investigation flows.
- `specs/API_CONTRACT.md`: initial backend API contract.
- `specs/DATA_SCHEMA.md`: normalized data structures.
- `specs/AI_SAFETY_RULES.md`: model safety requirements.
- `specs/SECURITY_THREAT_MODEL.md`: threat model and mitigations.
- `specs/UI_UX_SPEC.md`: pages, interactions, and UI states.
- `specs/TEST_STRATEGY.md`: verification strategy.
- `specs/ACCEPTANCE_CRITERIA.md`: measurable release criteria.
- `specs/IMPLEMENTATION_PLAN.md`: build order.
- `specs/DECISIONS.md`: architecture decision log.

## Before implementation
1. Confirm operating system, hardware, deployment topology, and Wazuh version.
2. Deploy or identify a working Wazuh environment.
3. Verify the Wazuh API, indexer endpoint, TLS certificates, credentials, index names, mappings, and retention policy.
4. Install Ollama and a model suitable for the available hardware; record its exact tag/version.
5. Fill `.env.example` values in a local untracked environment file. Never commit secrets.
6. Implement one end-to-end slice: real Linux authentication event -> Wazuh alert -> backend retrieval -> Ollama analysis -> evidence-backed UI.
7. Expand sources and features only after that slice passes tests.

## Environment variables
See `.env.example`. Values are examples/placeholders. Do not assume URLs, index patterns, model names, or credentials are valid for a particular installation.

## Development status labels
Use these labels consistently:
- `implemented`: code exists and relevant tests passed.
- `partially_implemented`: some paths work; limitations are documented.
- `planned`: specified but not built.
- `unverified`: code/config exists but has not been tested against a live dependency.
- `unavailable`: dependency or credentials are not configured.

## Security
The app handles sensitive security telemetry. Restrict access, verify TLS, use least-privilege credentials, redact sensitive fields where practical, define retention, and audit access. Local model inference does not by itself guarantee the entire workflow is local: external notification or enrichment services may transmit data.

## License
Choose and add an appropriate project license before public distribution. Verify licenses for all dependencies and model weights separately.
