# API Contract — Initial Version

Status: proposed contract. Implementations must preserve this contract or update it with a recorded decision. All routes are under `/api/v1` unless stated otherwise.

## General conventions
- JSON request/response.
- UTC ISO-8601 timestamps.
- Authenticated access for sensitive endpoints.
- Request/correlation ID included in responses and logs.
- Pagination is bounded. Suggested defaults: page size 25, maximum 100; tune through configuration.
- Maximum query window and request size are configurable and enforced server-side.
- Never accept arbitrary OpenSearch DSL or unrestricted query strings from the browser.
- Error bodies must not contain credentials, stack traces, internal host secrets, or raw sensitive log dumps.

## Health
### GET `/health/live`
Checks whether the API process is alive.
Response: `{"status":"ok"}`

### GET `/health/ready`
Checks configured required dependencies. Response includes safe dependency statuses such as `connected`, `degraded`, `unavailable`, or `not_configured`. Do not expose URLs containing secrets or detailed credentials.

## Alerts
### GET `/alerts`
Query parameters:
- `start_time` required/validated according to policy
- `end_time` required/validated
- `severity_min` optional
- `rule_id` optional
- `host_id` or `host_name` optional
- `source_ip` optional
- `username` optional
- `source` optional
- `cursor` or `page`/`page_size` according to the selected pagination strategy

Response:
- `items`: normalized alert records
- `next_cursor` or pagination metadata
- `query_window`
- `retrieved_at`
- `data_status`: `fresh`, `stale`, `partial`, or `unavailable`

### GET `/alerts/{alert_id}`
Returns one alert by stable source ID. Validate ID format and authorization. Return 404 when absent; do not substitute a mock record.

## Search
### POST `/search`
Request contains a typed, allowlisted search plan: time range, allowed filters, sort direction, and bounded page size. It must not accept arbitrary backend query DSL from untrusted clients.
Response includes results, query summary, source, retrieval time, and completeness/freshness metadata.

## Investigations
### POST `/investigations`
Creates an investigation from a real alert ID and optional bounded investigation settings. The backend retrieves authoritative evidence itself. Return an investigation ID and state such as `queued`, `running`, or `completed`.

### GET `/investigations/{investigation_id}`
Returns state, evidence references, analysis status, and validated result if available.

### POST `/investigations/{investigation_id}/analyze`
Starts or retries analysis for the authorized investigation. Use idempotency where appropriate. No remediation action is performed.

### GET `/investigations/{investigation_id}/evidence`
Returns the evidence records permitted for the requesting user. Apply field-level redaction where configured.

## Cases (P1)
- `GET /cases`: bounded search/filter.
- `POST /cases`: create case linked to alert/investigation IDs.
- `GET /cases/{case_id}`: read case and authorized references.
- `PATCH /cases/{case_id}`: update permitted fields such as status, assignee, and notes; audit every change.

## Reports
### POST `/reports`
Create an export from an authorized query, investigation, or case. Enforce size/time limits.
### GET `/reports/{report_id}`
Return status and a safe download link or streamed file. Reauthorize at download time.
Formats: CSV and JSON. Escape CSV formula injection and avoid exposing data outside the user's authorization.

## Endpoint Fleet Management
### GET `/agents`
Returns list and summary of monitored Wazuh endpoint agents.
- Query parameters: `limit` (int, default 50), `offset` (int, default 0), `status` (optional: `active`, `disconnected`, `never_connected`).
- Response: `items` (list of agent items with id, name, ip, status, os, version, node_name), `total` count, `summary` (total, active, disconnected, never_connected counts), `source` (`wazuh-api` or `simulated`).

## Automated Notifications
### POST `/notifications/test-webhook`
Sends a test security alert payload to the configured or provided webhook URL (Slack / Discord / Generic HTTP JSON).
- Request body: `{"webhook_url": "optional string URL"}`
- Response: `status` (`delivered`, `disabled`, `failed`), `message`, `dispatched_at`, `target_masked`.

## Active Response & Containment (Human-in-the-Loop)
### POST `/containment/propose`
Formulates platform mitigation playbooks for an offending IP or host entity. No commands are executed.
- Request body: `{"source_ip": "optional IP", "agent_name": "optional string", "agent_id": "optional string"}`
- Rejects loopback (`127.0.0.1`, `::1`) with 400 Bad Request to prevent self-lockout.
- Response: `target`, `entity_type`, `proposed_actions` (list of playbooks with `action_type`, `platform`, `risk_level`, `rationale`, and `commands` for Linux iptables, nftables, Windows Firewall, and Wazuh Active Response).

### POST `/containment/execute`
Approves and cryptographically logs a containment action. Requires analyst authorization.
- Request body: `{"action_type": "BLOCK_IP" | "ISOLATE_HOST", "target": "string", "rationale": "string", "analyst_id": "string", "analyst_approval": true, "alert_id": "optional string"}`
- Requires `analyst_approval: true`; returns 400 if false.
- Commits audit event to SQLite audit ledger with tamper-evident SHA-256 hash chaining.
- Response: `execution_id`, `action_type`, `target`, `status` (`APPROVED_LOGGED`), `commands`, `audit_event_id`, `audit_event_hash`, `timestamp`.

### GET `/containment/history`
Returns paginated list of analyst-approved containment actions and their cryptographic audit metadata.
- Query parameters: `limit` (default 50), `offset` (default 0).
- Response: `items`, `total`.

## Settings (admin only)
Only expose safe, validated settings. Never return secrets. Configuration changes require explicit authorization and audit logging. Secret rotation should use deployment/secret-management mechanisms rather than returning secret values through the UI.

## Error model
Example:
`{"error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Search service is unavailable","request_id":"..."}}`

Suggested codes: `VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `RATE_LIMITED`, `DEPENDENCY_UNAVAILABLE`, `UPSTREAM_TIMEOUT`, `ANALYSIS_INVALID`, `INTERNAL_ERROR`.

## Status codes
- 200 successful read/update
- 201 created resource
- 202 accepted asynchronous task
- 400 invalid request
- 401 unauthenticated
- 403 unauthorized
- 404 absent resource
- 409 conflicting state/idempotency conflict
- 422 schema/semantic validation error
- 429 rate limit
- 502 upstream invalid response
- 503 dependency unavailable
- 504 upstream timeout

## Contract testing
Use schema/contract tests for request validation, response shape, pagination, authorization, error responses, and backward-compatible changes. Generate OpenAPI from FastAPI, but treat this document as the intended product contract.
