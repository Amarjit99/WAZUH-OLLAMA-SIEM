# Acceptance Criteria

A feature is not complete because a screen renders or a mock returns a plausible result. Evidence must be collected from actual test execution.

## AC-001: Startup/configuration
- Missing required production configuration causes a clear startup/readiness error.
- Secrets are not printed.
- Liveness and readiness are distinct.

## AC-002: Wazuh connectivity
- Authenticated connection works against the documented target.
- TLS certificate verification is enabled.
- Invalid credentials and unavailable services produce safe errors.
- Integration status reflects real checks.

## AC-003: Real alert retrieval
- A controlled test event generates a Wazuh alert.
- Backend returns the actual alert and stable source identifier.
- No hardcoded record is returned when the source is unavailable.
- Field mapping is documented and tested against the target environment.

## AC-004: Search safety
- Invalid IP/time range/filter is rejected.
- Maximum time range/result size is enforced server-side.
- Arbitrary backend query DSL is not accepted from the client.
- Pagination does not duplicate or silently omit records under the tested conditions.

## AC-005: AI grounding
- Ollama receives only authorized bounded evidence.
- Response conforms to the schema.
- All cited evidence IDs exist in the exact input package.
- Unsupported claims are flagged or omitted.
- Facts and hypotheses are separate.
- Model failure does not break alert search or Wazuh detection.

## AC-006: Dashboard
- Displays actual backend data and truthful freshness status.
- Loading, empty, partial, error, and unauthorized states work.
- Every visible action has a real implementation or is explicitly disabled/labeled planned.
- No mock metrics appear in production mode.

## AC-007: Reports
- CSV and JSON contain the correct authorized scope and source references.
- CSV formula injection is mitigated.
- Unauthorized downloads are denied.
- Exports are auditable if audit feature is enabled.

## AC-008: Security
- Backend authorization is tested.
- Secrets are absent from repository and logs.
- TLS verification is enabled.
- Prompt-injection test strings in logs cannot invoke tools or change permissions.
- LLM cannot trigger remediation in v1.

## AC-009: Reliability
- Ollama outage leaves alert retrieval available.
- Connector timeout is bounded.
- Retries do not create duplicate records/cases/notifications.
- Checkpoint restart recovery is tested when polling is enabled.

## AC-010: Documentation
- Setup prerequisites and actual run commands are documented.
- Version/configuration assumptions are explicit.
- Known limitations and unverified integrations are listed.
- Test report distinguishes passed, failed, and not run.

## AC-011: Endpoint fleet monitoring
- Backend retrieves agent statuses (active, disconnected, never_connected) from Wazuh Manager API or authorized fallback.
- Fleet metrics and summary statistics accurately represent monitored endpoints.
- Hostname, IP, and status query filters function correctly and safely.

## AC-012: Automated alert notifications
- High-severity alerts trigger structured notification dispatch to configured webhooks.
- Payloads format correctly for Slack, Discord, and generic JSON webhooks.
- Masking prevents leaking internal tokens or private credentials in outbound webhook logs.

## AC-013: Active response & containment playbooks
- Multi-platform containment commands (iptables, nftables, Windows Firewall, Wazuh Active Response) are generated without autonomous execution.
- Human analyst explicit authorization (`analyst_approval=true`) is enforced before any containment action is approved or logged.
- Blocking self-loopback addresses (`127.0.0.1`, `::1`) is rejected with a validation error to prevent self-lockout.
- Every approved containment action is committed to the tamper-evident SQLite audit ledger with SHA-256 hash chaining.

## Release gate
No release claim of “real-time,” “local-only,” or “production-ready” unless the corresponding latency, outbound-traffic, security, and acceptance tests have been run and recorded.
