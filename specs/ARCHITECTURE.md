# System Architecture

## 1. Architecture principles
- Wazuh is the detection authority.
- The application is an investigation and analyst-assistance layer.
- The LLM is not trusted as a source of facts.
- Real evidence retrieval is separate from AI inference.
- Failures in AI must not interrupt primary SIEM collection/detection.
- The initial release is read-only.
- All external connections, credentials, and trust boundaries are explicit.

## 2. Logical components
### Sources
Monitored endpoints and services produce logs: Linux, Windows, firewalls, VPN, network devices, and applications.

### Collection and detection
Wazuh agents and configured Syslog/other supported collection paths deliver events to the Wazuh server/manager. Decoders and rules evaluate events. Wazuh generates alerts according to configured rules and integrations.

### Search/indexing
The Wazuh Indexer/OpenSearch stores searchable alert data. Exact indexes, fields, retention, authentication, and TLS settings must be discovered and verified in the deployed environment.

### Backend API
FastAPI provides authenticated application endpoints. It validates filters, authorizes users, retrieves data through connectors, builds evidence packages, calls Ollama, validates output, and records audit events.

### AI service
Ollama runs a selected local model. Only the backend communicates with it. The model receives a bounded evidence package, not indexer credentials or unrestricted access to data/tools.

### Persistence
The indexer remains the primary search store for alert evidence. An application database such as PostgreSQL may later store cases, analyst notes, audit metadata, and report metadata. Avoid duplicating all raw logs unless justified by a retention and governance design.

### Queue/workers
The first version may use bounded background execution for investigations. Add a durable queue when retries, concurrency, backlog recovery, or multiple workers require it. Do not add Redis solely for appearance.

### Frontend
React/TypeScript calls only the authenticated backend. It never connects directly to the Wazuh API, indexer, or Ollama.

## 3. Data flow
1. Source generates an event.
2. Wazuh collection receives it.
3. Wazuh decodes and evaluates rules.
4. Alert is emitted and indexed.
5. Backend retrieves alert using a documented, authenticated interface.
6. Backend retrieves related records with bounded filters.
7. Backend creates a minimized evidence package and records correlation metadata.
8. Ollama returns structured analysis.
9. Backend validates schema, evidence IDs, size, and policy.
10. Frontend shows evidence separately from generated interpretation.
11. Optional case/report/notification workflows operate through controlled services.

## 4. Integration choice
- Wazuh API: agent/manager status and operations documented by the deployed Wazuh API.
- Indexer/OpenSearch: searching indexed alert evidence using verified mappings and restricted credentials.
- Use both only where their responsibilities are distinct. Do not assume the Wazuh API is a replacement for arbitrary raw event search.
- Do not read internal queues or internal files as a substitute for documented interfaces without a reviewed design.

## 5. Real-time strategy
Start with checkpointed polling. Use a stable source ID or deterministic composite cursor, bounded overlap, deduplication, and safe checkpoint advancement. Late-arriving events must be considered. Do not use timestamp alone as a unique cursor.

If low latency or higher throughput later requires event forwarding, use a supported integration or durable queue and prove delivery/retry behavior. SSE or WebSockets are UI delivery mechanisms; they do not themselves make upstream log ingestion real-time.

## 6. Deployment options
### Local lab
Single machine or VMs may host Wazuh, indexer, Ollama, backend, and frontend if resources permit. Keep service ports bound/restricted and document that this is not automatically high availability.

### Distributed lab/production
Separate Wazuh/indexer from model inference where possible. Use restricted network segments, dedicated service identities, verified TLS, monitoring, backups, and recovery testing.

## 7. Failure behavior
- Wazuh unavailable: alert/search endpoints report degraded/unavailable; do not show fabricated data.
- Indexer unavailable: search fails safely; keep error IDs and sanitized diagnostics.
- Ollama unavailable: evidence search remains available; AI analysis becomes unavailable/retryable.
- Malformed model output: reject it and mark analysis failed/invalid.
- Notification failure: retry from durable state if notification feature is enabled.
- Frontend disconnected: show stale-data state and last successful refresh time.

## 8. Observability
Use request/correlation IDs; record source retrieval time, event timestamp, indexing/query time, model start/end, result status, and errors. Never log secrets or unnecessary raw logs.

## 9. Scaling
Measure event rate, indexer capacity, storage retention, concurrent investigations, model inference duration, and queue backlog before scaling. Add worker pools, durable queues, and separate model hosts based on measured bottlenecks.
