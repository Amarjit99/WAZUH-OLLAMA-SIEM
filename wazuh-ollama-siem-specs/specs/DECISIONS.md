# Architecture Decision Log

Record decisions with date, status, context, decision, alternatives, and consequences. Proposed decisions below should be confirmed during environment discovery.

## ADR-001: Wazuh remains authoritative for detection
- Status: accepted
- Context: AI output is probabilistic and can be wrong.
- Decision: Wazuh rules and source evidence remain the authority for alerts. Ollama assists investigation only.
- Consequence: AI summaries cannot create a confirmed alert status on their own.

## ADR-002: Local inference via Ollama
- Status: accepted for initial design
- Context: the project prioritizes keeping evidence inside the internal environment.
- Decision: Ollama is the local inference endpoint; only the backend calls it.
- Consequence: model tag, hardware, resource limits, and outbound-network policy must be documented. Local inference alone does not make every other integration local.

## ADR-003: Read-only first release
- Status: accepted
- Context: automated response is high impact.
- Decision: v1 has no automated remediation.
- Consequence: future response actions require separate authorization, audit, and safety review.

## ADR-004: Indexer for indexed alert search
- Status: proposed/confirm in environment
- Context: searchable alert evidence is needed.
- Decision: use documented OpenSearch/Wazuh Indexer search with verified mappings and restricted credentials; use Wazuh API for supported manager/agent operations.
- Consequence: actual indexes and fields must be discovered for the deployed version.

## ADR-005: Start with checkpointed polling
- Status: accepted for initial milestone
- Context: polling is simpler to validate than an event streaming pipeline.
- Decision: start with bounded polling, stable IDs, overlap, deduplication, and checkpoint persistence.
- Consequence: latency is measured and not advertised as instantaneous. Introduce a queue/stream only when justified.

## ADR-006: Keep frontend away from infrastructure credentials
- Status: accepted
- Decision: browser talks only to the authenticated backend.
- Consequence: all authorization and query validation occur server-side.

## ADR-007: Optional database and queue
- Status: proposed
- Decision: do not introduce PostgreSQL/Redis until case persistence, audit durability, or job recovery requirements justify them.
- Consequence: early implementation remains simpler; the choice must be revisited before production if durability requirements demand it.

## Decision template
### ADR-XXX: Title
- Date:
- Status: proposed / accepted / superseded
- Context:
- Decision:
- Alternatives:
- Consequences:
- Verification:
