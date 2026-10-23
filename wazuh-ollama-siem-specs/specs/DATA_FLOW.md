# Data Flow and Real-Time Processing

## 1. Normal event-to-alert path
1. A monitored source writes an event.
2. Wazuh agent or configured Syslog collection path receives the event.
3. Wazuh manager decodes and evaluates it against configured rules.
4. Matching rules generate alert records.
5. Alert data becomes searchable in the configured indexer.
6. Backend retrieves the record through an authenticated connector.
7. Frontend displays it with source ID, event timestamp, ingestion/observation time when available, and current freshness.

## 2. AI investigation path
1. Analyst opens a real alert.
2. Backend checks authentication and authorization.
3. Backend loads the alert by stable source identifier.
4. Backend retrieves related evidence within a bounded time window and allowed sources.
5. Backend minimizes/redacts evidence where practical and enforces byte/event limits.
6. Backend sends evidence and a versioned prompt/schema to local Ollama.
7. Model returns structured analysis.
8. Validator checks schema, output size, and that every cited event ID exists in the supplied evidence.
9. Backend persists analysis metadata and an audit event if configured.
10. UI shows source evidence, facts, hypotheses, recommended checks, and limitations separately.

## 3. Polling/checkpoint design
- Use a configurable polling interval, not a hardcoded promise of one-second delivery.
- Use a stable source document ID or supported composite cursor.
- Use a small overlap window to handle indexing delay and boundary races.
- Deduplicate using stable IDs.
- Advance checkpoints only after successful processing.
- Make processing idempotent so retries do not create duplicate cases/notifications.
- Detect late-arriving records and provide a reconciliation window.
- Bound query range and result size; paginate safely.
- Record last successful poll, last source timestamp, last indexed timestamp if available, and last error.
- Alert on excessive lag or repeated failures.

## 4. Real-time UI
The initial version can refresh via polling. SSE/WebSockets can be introduced when there is a backend event stream. UI freshness must be visible. Browser streaming does not guarantee source ingestion latency.

## 5. Latency metrics
Measure separately:
- source event to Wazuh receipt (if measurable)
- Wazuh processing to alert generation
- alert generation to index visibility
- index query and backend response
- backend queue wait
- Ollama inference
- UI delivery
- notification delivery

Define service targets only after baseline measurement on the target hardware and data volume.

## 6. Data integrity and timestamps
- Store normalized timestamps as timezone-aware UTC.
- Preserve original timestamp text and source timezone where needed.
- Handle missing, malformed, and future timestamps explicitly.
- Never treat a timestamp alone as unique.
- Preserve source index, source document ID, rule ID, agent/host ID, and retrieval time where available.

## 7. Example investigation record
A case contains an alert reference, selected event references, query window, evidence retrieval timestamp, model tag, prompt/schema version, AI result status, and analyst decision. It should not copy all raw logs by default.
