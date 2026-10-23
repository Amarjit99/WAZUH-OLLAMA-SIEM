# Test Strategy

## Test layers
### Unit
Test normalization, time-range validation, IP validation, policy checks, pagination, evidence minimization, output validation, CSV escaping, idempotency, and error mapping.

### Connector integration
Against a configured disposable/test Wazuh and OpenSearch environment:
- valid authentication
- invalid credentials
- TLS validation failure
- no matching alerts
- matching alert
- pagination
- unavailable service and timeout
- mapping/field absence

### Ollama integration
- model available
- model missing
- malformed output
- timeout
- oversized evidence rejected
- invalid evidence IDs rejected
- prompt injection inside event text does not alter policy
- model unavailable does not affect alert search

### API contract
Validate request/response schemas, error envelopes, auth requirements, pagination limits, and backward compatibility.

### Frontend
Test loading, empty, stale, error, unauthorized, filters, pagination, evidence links, and export behavior. Ensure fixtures cannot be enabled in production accidentally.

### End-to-end
1. Generate a controlled event on a monitored lab endpoint.
2. Confirm expected Wazuh alert.
3. Retrieve the actual alert through the application connector.
4. Retrieve bounded evidence.
5. Run Ollama analysis.
6. Validate returned evidence references.
7. Display source evidence and AI result in the UI.
8. Export the result and verify content/authorization.

### Security
Test authorization bypass, IDOR, injection in search parameters, prompt injection in logs, secret leakage, rate limiting, CSV formula injection, oversized payloads, TLS failure behavior, and exposed internal endpoints.

## Performance testing
Measure source-to-alert, indexing, API, queue wait, model inference, UI refresh, and notification latency independently. Use representative sanitized event volume. Establish targets from measured baselines and hardware constraints.

## Test data
Use synthetic/sanitized fixtures with clearly fake identities and reserved example IP ranges. Never put real sensitive production logs in source control.

## CI
Run formatter, linter, type checker, unit tests, frontend tests, dependency/security checks as appropriate, and build. Live integration tests may run in a dedicated environment and must report when skipped due to missing dependencies.

## Reporting
A test result must distinguish `passed`, `failed`, and `not run`. Never report a skipped live integration test as proof of real integration.
