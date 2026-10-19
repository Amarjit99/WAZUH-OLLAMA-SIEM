# Data Schema and Normalization

This is the canonical internal model. Actual Wazuh/OpenSearch fields must be mapped from verified source mappings; do not assume every field exists for every source.

## 1. Normalized Alert
Required when available:
- `alert_id`: stable source document/alert identifier.
- `source_system`: e.g. Wazuh.
- `source_index`: index or collection identifier.
- `timestamp`: normalized UTC timestamp.
- `retrieved_at`: backend retrieval timestamp.
- `rule_id`: source rule identifier, represented as string to preserve formats.
- `rule_description`: source description.
- `rule_level`: source numeric level when available; do not confuse with a universal risk score.
- `agent_id`, `agent_name`, `host_name`.
- `source_ip`, `destination_ip`, `username`.
- `event_type`, `location`, `decoder_name` where available.
- `raw_evidence_ref`: reference to source record, not necessarily a copy of the entire raw record.
- `normalization_warnings`: missing or malformed fields.

Unknown values should be null/omitted, not fabricated.

## 2. Evidence Event
- `event_id`: stable source ID.
- `source_system`, `source_index`.
- `timestamp`, `retrieved_at`.
- `host_id`, `host_name`.
- `event_type`.
- `selected_fields`: allowlisted relevant fields.
- `redaction_applied`: boolean and/or redaction metadata.
- `source_reference`: pointer to the original record.

## 3. Investigation
- `investigation_id`: application-generated unique ID.
- `created_at`, `updated_at`.
- `created_by`.
- `alert_ids`: references to authoritative alert records.
- `query_window`: start/end timestamps.
- `status`: `queued`, `running`, `completed`, `failed`, `cancelled`.
- `evidence_ids`: references included in the model context.
- `model_name`, `model_tag`, `prompt_version`, `schema_version`.
- `analysis_status`: `pending`, `valid`, `invalid`, `unavailable`, `timed_out`.
- `result_ref`: validated analysis record reference.
- `error_code`: safe machine-readable code, not secret details.

## 4. AI Analysis Result
- `analysis_id`.
- `investigation_id`.
- `generated_at`.
- `model_name` and exact configured tag.
- `summary`.
- `observed_facts`: list of `{text, evidence_ids}`.
- `hypotheses`: list of `{text, evidence_ids, uncertainty}`.
- `recommended_checks`: list of `{text, evidence_ids, priority}`; recommendations must be read-only in v1.
- `limitations`: list of strings.
- `confidence_label`: optional qualitative value with documented rubric. Do not invent calibrated probabilities.
- `validation_status`.
- `prompt_version`, `schema_version`.
- `review_status`: optional analyst feedback.

Every cited evidence ID must exist in the exact evidence package supplied to the model. Claims without support must be labeled as hypotheses or omitted.

## 5. Case
- `case_id`, `title`, `status`, `severity_label` if separately justified.
- `created_at`, `updated_at`, `created_by`, `assignee`.
- `alert_ids`, `investigation_ids`, `evidence_ids`.
- `analyst_notes`.
- `closure_reason`.
- `audit_event_ids`.

## 6. Audit Event
- `audit_id`, `timestamp`, `actor_id`, `action`, `resource_type`, `resource_id`, `outcome`, `request_id`.
- `metadata`: minimized, non-secret metadata.
- Do not include passwords, tokens, full credentials, or unnecessary raw logs.

## 7. API envelope
For list results:
- `items`
- `page_size` and `next_cursor` or equivalent pagination metadata
- `query_window`
- `retrieved_at`
- `data_status`
- `request_id`

## 8. Data quality rules
- Preserve source IDs and original field names in a controlled evidence reference.
- Normalize timestamps to timezone-aware UTC.
- Preserve source time and timezone if available.
- Validate IP addresses with a proper parser.
- Do not parse arbitrary strings as trusted instructions.
- Cap field lengths and collection sizes.
- Apply redaction according to policy.
- Keep severity, confidence, and incident status as distinct concepts.
