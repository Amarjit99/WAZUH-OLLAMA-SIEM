# UI/UX Specification

## Design goals
- Professional SOC-style interface, responsive for desktop and tablet.
- Clear hierarchy and fast investigation workflow.
- Evidence and AI interpretation are visually distinct.
- No fabricated counts, health indicators, or charts.
- Accessible keyboard navigation, labels, contrast, and focus states.

## Navigation
1. Overview
2. Alerts
3. Investigations
4. Cases (P1)
5. Reports (P1)
6. System health / settings (role-restricted)

## Overview
Show only metrics computed from actual backend responses:
- alert count for a clearly labeled time window
- severity distribution based on source fields and documented mapping
- data freshness/last successful refresh
- connected/degraded/unavailable integrations
- investigation queue/model health if implemented
- processing and AI latency metrics when measured

Every card must have loading, empty, stale, and error states. Do not display placeholder values as live values.

## Alert explorer
- Search/filter by time window, rule ID/level, host/agent, source IP, username, source.
- Server-side pagination and bounded filters.
- Sort by supported fields only.
- Display source alert ID, event timestamp, rule description, host, severity/level, and AI analysis status.
- Detail action opens original evidence and source references.
- Preserve filters in URL when safe and useful.
- Clearly show when fields are unavailable.

## Alert detail
Sections:
1. Summary of source alert fields.
2. Original source evidence/selected fields.
3. Related event timeline if implemented.
4. Start investigation action.
5. Source identifiers and retrieval time.

## Investigation page
- State: queued/running/completed/failed.
- Evidence list with timestamp, source ID, host, event type.
- AI summary prominently labeled as generated.
- Separate observed facts, hypotheses, recommended read-only checks, limitations.
- Each claim's evidence references link to matching records.
- Show model tag, generation time, and validation status.
- If invalid/unavailable, show a safe error and preserve the original evidence.

## Search
- Natural-language input is optional and must resolve into a constrained query plan.
- Show interpreted filters/time range before broad or ambiguous searches.
- Never send raw natural-language text as arbitrary OpenSearch DSL.
- Provide a conventional filter builder as a reliable alternative.

## Cases and reports
- Case status, assignee, notes, linked alert IDs, audit trail.
- CSV/JSON export with clear scope and timestamp.
- Reauthorize report download.
- Protect sensitive content and CSV formula injection.

## UI states
All API-backed components must handle:
- loading
- successful data
- empty result
- stale data
- partial result
- unauthorized/forbidden
- dependency unavailable
- timeout/retry
- malformed response

## Visual language
Use severity labels based on actual configured source data; avoid treating Wazuh rule level as a calibrated probability. Use consistent typography, spacing, table density, readable dark/light themes if supported, and avoid decorative motion that impedes SOC work.

## Frontend security
- No Wazuh/OpenSearch/Ollama credentials in browser bundles.
- Do not trust client-side role checks.
- Render log content as text, not executable HTML.
- Sanitize/escape user-generated notes and event strings.
- Avoid storing sensitive logs in local storage.
