# Security Threat Model

## Assets
- Security logs, alerts, evidence, and case notes.
- Wazuh and OpenSearch credentials.
- Ollama model/service availability.
- User accounts, roles, and session data.
- Reports and exports.
- Audit records and configuration.
- Integrity of detections and investigation results.

## Trust boundaries
1. Endpoint/network sources -> Wazuh collection.
2. Wazuh manager/indexer -> application backend.
3. Backend -> Ollama.
4. Browser -> authenticated backend.
5. Backend -> optional database/queue.
6. Application -> external email/Telegram/threat intelligence if enabled.

## Threats and required mitigations
### Credential theft
Use environment/secret-manager injection, least-privilege accounts, rotation, redaction, and never return secrets in API responses or logs.

### Unauthorized data access
Authenticate users, enforce backend RBAC and resource-level authorization, restrict index patterns, limit exports, and test horizontal privilege escalation.

### Prompt injection through logs
Treat log text as untrusted. Do not expose tools/credentials to the model. Validate output and require human review.

### Hallucinated investigation findings
Require evidence references, validate IDs, separate facts from hypotheses, test against labeled cases, and show original records.

### Search/query abuse
Use allowlisted filters, validated IP/date inputs, bounded time windows and result counts, timeouts, rate limits, and read-only indexer permissions.

### TLS/network exposure
Verify certificates, restrict network ports, bind local services to loopback where possible, use private segments/firewall rules, and do not expose Ollama or indexer APIs publicly.

### Sensitive data leakage
Minimize evidence, redact secrets/PII where appropriate, restrict logs and exports, define retention, encrypt backups, and document any external transmission.

### Denial of service / resource exhaustion
Limit request size, model context, concurrency, queue depth, search ranges, and retry rates. Apply backpressure and health checks.

### Replay/duplicate processing
Use stable IDs, idempotency keys, durable checkpoints, and duplicate-suppression tests.

### Supply-chain risk
Pin and review dependencies, scan packages/images, use trusted model sources, record model tags, and document licenses.

### Audit tampering
Restrict audit-write permissions, protect retention/backups, and consider append-only or integrity-protected storage for higher assurance.

## Initial security posture
- Read-only connectors.
- No automatic remediation.
- No public exposure of Ollama/indexer.
- Verified TLS.
- Authentication and backend authorization before access to sensitive data.
- Explicit development-only fixture mode.
- Security tests required before release.

## Residual risks
Local models can still be wrong; compromised endpoints can emit misleading logs; incomplete telemetry can miss attacks; and local hosting does not eliminate insider risk. Document these limitations.


## Review checklist
- [ ] Publicly exposed ports reviewed.
- [ ] Credentials are scoped and rotatable.
- [ ] TLS verification tested, including failure path.
- [ ] User authorization tested on every sensitive endpoint.
- [ ] Logs and model context checked for secret/PII leakage.
- [ ] Prompt injection tested with hostile event text.
- [ ] Query ranges, pagination, and payload limits tested.
- [ ] Export authorization and CSV injection tested.
- [ ] Ollama outage and overload behavior tested.
- [ ] Backup and retention policy documented.
