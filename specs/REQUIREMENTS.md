# Requirements Traceability

Use this table to connect product requirements to implementation and tests. Update file/module names after implementation; do not invent passing results.

| Requirement | Description | Likely implementation area | Verification |
|---|---|---|---|
| FR-001–006 | Configuration, health, Wazuh/indexer connection | `backend/app/config.py`, `connectors/`, `api/v1/health.py` | Connector and health integration tests |
| FR-010–016 | Alert retrieval/search/normalization | `connectors/opensearch.py`, `services/alert_service.py` | Search contract and integration tests |
| FR-020–029 | Evidence-backed investigation and Ollama | `ai/`, `services/investigation_service.py` | Grounding, schema, outage, prompt-injection tests |
| FR-030–036 | Cases, reports, audit, notifications | `services/`, `repositories/`, `workers/` | Authorization, export, idempotency tests |
| FR-040–044 | Dashboard and UI states | `frontend/src/features/` | UI and end-to-end tests |
| FR-050–056 | Security and admin | `security/`, `api/`, deployment config | Security tests and configuration review |

## Status values
- `not_started`
- `in_progress`
- `implemented_unverified`
- `verified`
- `blocked`

Every requirement should have an owner, implementation reference, test reference, status, and notes once coding begins.
