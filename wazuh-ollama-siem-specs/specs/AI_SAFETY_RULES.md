# AI Safety Rules — Local Ollama Analysis

## Purpose
Ollama is used to explain and summarize selected evidence. It is not the authoritative detector, a source of independent facts, or an autonomous response engine.

## Evidence grounding
1. The backend retrieves evidence from authorized SIEM sources.
2. The model receives only a bounded evidence package needed for the investigation.
3. The model must separate:
   - Observed facts directly supported by evidence.
   - Hypotheses that remain unconfirmed.
   - Read-only recommended checks.
   - Missing context and limitations.
4. Every fact/hypothesis that cites evidence must include source event IDs.
5. Backend code validates that cited IDs were present in the exact supplied evidence set.
6. Unsupported claims must be rejected, downgraded to an explicitly uncertain hypothesis, or flagged for review.
7. Do not treat a persuasive narrative as proof of compromise.

## Prompt injection
- Treat every log field, URL, username, process argument, HTTP user agent, and external text as untrusted data.
- The prompt must explicitly state that evidence content is data, not instructions.
- Never allow text inside logs to change system policy, enable tools, reveal secrets, or initiate actions.
- Do not give the model shell, arbitrary HTTP, database, indexer, or endpoint-control tools.
- Do not rely on prompt wording alone; enforce permissions and output validation in code.

## Data minimization
- Retrieve only relevant events and fields.
- Bound the number of records, maximum field length, total serialized bytes, and model context.
- Redact secrets, authentication tokens, session cookies, personal data, and unrelated payloads when present.
- Avoid sending entire raw events when a minimized representation is enough.
- Document whether logs or model prompts are retained by the application.
- Local inference does not mean every integration is local. External messaging or reputation APIs require separate approval.

## Output contract
Return a validated structure:
- `summary`
- `observed_facts`: text + evidence IDs
- `hypotheses`: text + evidence IDs + uncertainty
- `recommended_checks`: read-only actions only
- `limitations`
- optional qualitative `confidence_label` based on a documented rubric

No shell commands for execution, no direct remediation, no claims of external reputation checks unless performed by a real authorized integration.

## Reliability
- Enforce timeout, concurrency limit, input/output size limits, and bounded retry.
- Reject malformed or schema-invalid responses.
- Treat model unavailability as an AI-analysis failure, not as SIEM failure.
- Do not automatically retry indefinitely.
- Record model tag, prompt/schema version, duration, status, and evidence IDs without logging secrets.
- Prevent duplicate investigation jobs where possible.

## Human review
- Label output as AI-generated.
- Show original evidence beside the summary.
- Analysts make final incident classification and response decisions.
- Capture feedback for evaluation without treating feedback as ground truth automatically.

## Evaluation
Build a labeled test set covering:
- Clear supported findings.
- Missing evidence.
- Contradictory records.
- Benign activity resembling attacks.
- Prompt injection embedded in logs.
- Invalid/malformed model output.
- Out-of-window events.
- Wrong or invented evidence IDs.
Measure unsupported-claim rate, citation correctness, task usefulness, latency, and failure rate.
