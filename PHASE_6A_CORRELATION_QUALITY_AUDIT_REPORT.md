# PHASE 6A — CORRELATION QUALITY & FALSE-ASSOCIATION VALIDATION AUDIT REPORT

**Project:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Workspace:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Deployment Repository:** `F:\MY Project\wazuh-docker`  
**Evaluation Target:** Related-Event Correlation Hardening, Semantic Validation, Signal Classification, and Grounding Calibration  
**Date:** October 20, 2026  
**Auditor:** Senior Security Automation & AI Grounding Auditor (Lazy Senior Dev / Ponytail Mode)

---

## 1. Executive Verdict

### **Verdict: PASS**

The Phase 6 related-event correlation pipeline has been rigorously audited, semantically constrained, and hardened against false associations and unsubstantiated causal inference:

1. **Signal Grounding & Placeholder Rejection:** Correlation fields (`source_ip`, `destination_ip`, `username`, `agent_id`, `agent_name`, `host_name`) are strictly validated against empty strings, unparsed placeholders (`"unknown"`, `"none"`, `"-"`, `"null"`), loopback (`"127.0.0.1"`, `"::1"`, `"localhost"`), and unspecified (`"0.0.0.0"`, `"::"`) addresses. Matching cannot occur on placeholder values.
2. **Explicit Weak Proximity Semantics:** Temporal-only proximity is labeled as weak non-causal context (`temporal_proximity_only (weak correlation; temporal proximity does not prove causation or attacker intent)`) and cannot trigger `enriched` status alone.
3. **Inclusive Boundary Enforcement & Out-of-Window Rejection:** Time windows are computed around the anchor alert using UTC normalization. Events exactly on window boundaries ($t_{\text{anchor}} \pm \frac{\text{window}}{2}$) are included; events even 1 second outside are strictly rejected. Timezone-naive timestamps are normalized to UTC.
4. **Unsupported Telemetry Disclosed, Never Fabricated:** Because the Wazuh alert document schema does not provide normalized process lineage or process trees, process correlation is explicitly flagged as unsupported via `unsupported_signals: ["process_lineage", "command_line"]` in both the API contract and frontend display. Hypotheses asserting process injection or lateral movement without corroborating telemetry are flagged with validation warnings.
5. **Confidence Calibration Guardrail:** When an investigation is conducted on an isolated alert or when correlation context consists exclusively of weak temporal proximity, the investigation confidence label cannot be `HIGH` and is automatically calibrated to `MEDIUM`.
6. **Zero Commit & Infrastructure Invariance:** Zero git commits were made, all user files were preserved, and Wazuh, Docker, OpenSearch, Ollama, certificates, and secrets were kept strictly unchanged.

---

## 2. Exact Files Inspected and Modified

### Inspected Files
- `specs/DATA_SCHEMA.md`
- `specs/API_CONTRACT.md`
- `specs/AI_SAFETY_RULES.md`
- `specs/SECURITY_THREAT_MODEL.md`
- `AGENTS.md`
- `PHASE_6_RELATED_EVENT_CORRELATION_AUDIT_REPORT.md`
- `backend/app/core/config.py`
- `backend/app/schemas/alert.py`
- `backend/app/services/opensearch_client.py`
- `backend/app/services/wazuh_client.py`

### Modified Files
- [`backend/app/schemas/investigation.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/schemas/investigation.py)
  - Added `unsupported_signals: List[str]` to `RelatedEventsSummary` (`["process_lineage", "command_line"]`).
  - Added regex patterns: `PROCESS_CORRELATION_PATTERN`, `LATERAL_MOVEMENT_PATTERN`, `CAUSAL_TEMPORAL_PATTERN`.
  - Added guardrails flagging unsupported process claims, lateral movement without network flow telemetry, and unwarranted causal claims in `validate_evidence_citations`.
  - Added confidence calibration downgrade from `HIGH` to `MEDIUM` when evidence has $\le 1$ event or only weak temporal signals.
- [`backend/app/services/evidence_service.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/services/evidence_service.py)
  - Added helper validators: `is_valid_ip`, `is_valid_username`, `is_valid_agent` with rejection of `INVALID_PLACEHOLDERS` (`""`, `"unknown"`, `"none"`, `"null"`, `"-"`, `"0.0.0.0"`, `"127.0.0.1"`, `"::1"`).
  - Hardened `classify_correlation()`: returns standardized reasons `shared_source_ip`, `shared_destination_ip`, `shared_username`, `same_agent`, and `temporal_proximity_only (weak correlation; temporal proximity does not prove causation or attacker intent)`.
  - Hardened `build_evidence_package()`: strict inclusive boundary filtering ($start \le t \le end$), timezone-aware UTC normalization, out-of-window rejection, and distinction between `enriched`, `partial`, `no_related_events_found`, `failed_fallback_single_alert`, and `skipped_not_requested`.
  - Hardened `_fetch_candidate_alerts()`: validated host, source IP, and username search dimensions against placeholder values before executing OpenSearch queries.
- [`backend/app/services/ollama_client.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/services/ollama_client.py)
  - Added Rules 11 and 12 to `_build_system_prompt()` prohibiting fabricated process lineage and reiterating temporal non-causality.
  - Added automatic injection of unsupported telemetry disclosures and weak temporal context disclosures into `InvestigationResult.limitations`.
- [`backend/tests/test_correlation.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/tests/test_correlation.py)
  - Updated `test_classify_shared_user` to assert standardized `shared_username`.
  - Added 7 dedicated Phase 6A test functions covering boundary inclusion/exclusion, placeholder rejection, UTC normalization, stable evidence IDs, unsupported telemetry disclosure, lateral movement flagging, and confidence calibration.
- [`frontend/src/types/api.ts`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/types/api.ts)
  - Extended `RelatedEventsSummary` interface with optional `unsupported_signals?: string[]`.
- [`frontend/src/components/InvestigationModal.tsx`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/components/InvestigationModal.tsx)
  - Rendered `PARTIAL (TRUNCATED / WEAK)` and `NO MATCHES` status pills.
  - Added explicit unsupported telemetry disclosure box when `unsupported_signals` are reported.
- [`frontend/src/index.css`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/index.css)
  - Added `.status-partial` and `.status-no_matches` styling.

---

## 3. Existing Behavior and Root Causes Found

| Component | Pre-6A State | Root Cause & Failure Mode | Hardened Behavior in 6A |
| :--- | :--- | :--- | :--- |
| **Entity Classification** | Checked `if primary.username and rel.username:` | Empty string or `"unknown"` present on both records would match as `shared_user` (false association). | Validated with `is_valid_username()` / `is_valid_ip()` / `is_valid_agent()`. Placeholders are rejected. |
| **Loopback / Unspecified IPs** | IP check did not parse standard IP semantics | Two separate machines reporting `0.0.0.0` or `127.0.0.1` would correlate as `shared_source_ip`. | `ipaddress` parsing excludes loopback and unspecified addresses from network correlation. |
| **Time Window Boundaries** | OpenSearch query range filtering only | Candidates returned by mock or loose index ranges outside $\pm \frac{\text{window}}{2}$ were not filtered post-query. | Strict client-side check enforces $start \le t_{\text{cand}} \le end$ (inclusive) in UTC; out-of-bounds rejected. |
| **Process Lineage** | Schema lacked process fields | Model might hallucinate process trees or lateral movement without telemetry to corroborate it. | Declared unsupported in `unsupported_signals`; citation validator flags process lineage and lateral movement without IP flow. |
| **Confidence Scoring** | Model could output `HIGH` confidence on weak temporal correlation | LLM mistook temporal proximity as confirmation of attack activity. | Confidence calibration automatically downgrades `HIGH` to `MEDIUM` when evidence is isolated or temporal-only. |

---

## 4. Confirmed Correlation Fields and Their Actual Source Provenance

Wazuh alerts normalized into `NormalizedAlert` originate from the OpenSearch index `wazuh-alerts-4.x-*`. The following table maps supported correlation dimensions to their source fields:

| Correlation Signal | Source Record Field(s) | Normalization Mapping | Supported in Alert Schema |
| :--- | :--- | :--- | :--- |
| **Source IP** | `data.srcip` | `NormalizedAlert.source_ip` | **Yes** |
| **Destination IP** | `data.dstip` | `NormalizedAlert.destination_ip` | **Yes** |
| **Username** | `data.srcuser` | `NormalizedAlert.username` | **Yes** |
| **Agent Identifier** | `agent.id` | `NormalizedAlert.agent_id` | **Yes** |
| **Agent / Host Name** | `agent.name` | `NormalizedAlert.agent_name` / `host_name` | **Yes** |
| **Process Identifier** | None (top-level) | N/A | **No (Disclosed as Unsupported)** |
| **Parent Process** | None (top-level) | N/A | **No (Disclosed as Unsupported)** |
| **Command Line** | None (top-level) | N/A | **No (Disclosed as Unsupported)** |

---

## 5. Definition of the Correlation Window and Verified Boundary Behavior

### 5.1 Window Calculation
- Parameter: `correlation_window_minutes: int` (clamped between 5 and 60 minutes, default `30`).
- Definition: The **total window duration** centered symmetrically around the primary alert timestamp ($t_{\text{anchor}}$).
- Half-Window: $\Delta = \frac{\text{window\_minutes}}{2.0}$ minutes. For default `30m`, $\Delta = 15.0$ minutes ($\pm 15$ minutes).
- Window Bounds:
  $$\text{start} = t_{\text{anchor}} - \Delta, \quad \text{end} = t_{\text{anchor}} + \Delta$$

### 5.2 Boundary Verification
Deterministic unit tests in `test_exact_window_boundaries_and_out_of_window_rejection` verified:
- Event at $t = t_{\text{anchor}} - 15\text{m}$ (exact lower bound) $\rightarrow$ **INCLUDED**.
- Event at $t = t_{\text{anchor}} + 15\text{m}$ (exact upper bound) $\rightarrow$ **INCLUDED**.
- Event at $t = t_{\text{anchor}} - 15\text{m} - 1\text{s}$ (outside lower bound) $\rightarrow$ **REJECTED**.
- Event at $t = t_{\text{anchor}} + 15\text{m} + 1\text{s}$ (outside upper bound) $\rightarrow$ **REJECTED**.

---

## 6. Correlation Reason Semantics and Ranking Behavior

### 6.1 Priority Ladder
Candidates within the correlation window are ranked using a deterministic 3-tuple key:
1. **Signal Rank Ascending:**
   - **Rank 1 (Strongest):** Shared exact entity identifiers (`shared_source_ip`, `shared_destination_ip`, `shared_username`).
   - **Rank 2 (Medium):** Same reporting endpoint context (`same_agent`). Identifies the same agent, does **not** prove causation or shared attack chain.
   - **Rank 3 (Weak Context):** Temporal proximity only (`temporal_proximity_only`).
2. **Absolute Time Delta Ascending:** $|t_{\text{cand}} - t_{\text{anchor}}|$.
3. **Alert ID Ascending (Tie-Breaker):** Deterministic tie-breaker ensuring repeatable ordering across multiple runs.

### 6.2 Standardized Reason Identifiers
- `shared_source_ip`: Verified valid source IP exists in both events.
- `shared_destination_ip`: Verified valid destination IP exists in both events.
- `shared_username`: Normalized username matches case-insensitively in both events.
- `same_agent`: Verified `agent_id` or non-placeholder `agent_name` matches in both events.
- `temporal_proximity_only (temporal_only weak correlation; temporal proximity does not prove causation or attacker intent)`: Only time proximity exists.

---

## 7. Test Commands and Exact Pass / Fail / Skip Counts

### Backend Non-Live Test Suite (Unit & Contract Tests)
- **Command:** `.\.venv\Scripts\python.exe -m pytest -m "not live" -v`
- **Result:** **84 PASSED**, 0 FAILED, 4 deselected in 11.70s.
- **Breakdown of Correlation Tests (`tests/test_correlation.py`):**
  - `test_classify_shared_source_ip`: PASSED
  - `test_classify_shared_destination_ip`: PASSED
  - `test_classify_shared_user`: PASSED
  - `test_classify_same_agent`: PASSED
  - `test_classify_temporal_only_weak_link`: PASSED
  - `test_deterministic_ranking_and_primary_preservation`: PASSED
  - `test_candidate_deduplication`: PASSED
  - `test_max_related_events_and_evidence_capping`: PASSED
  - `test_byte_limit_truncation`: PASSED
  - `test_missing_or_invalid_timestamp_fallbacks_to_single_alert`: PASSED
  - `test_opensearch_failure_resilience`: PASSED
  - `test_no_related_events_found`: PASSED
  - `test_api_investigate_with_correlation`: PASSED
  - `test_api_parameter_bounds_enforced`: PASSED
  - `test_placeholder_entity_rejection`: PASSED
  - `test_exact_window_boundaries_and_out_of_window_rejection`: PASSED
  - `test_naive_timestamp_utc_normalization`: PASSED
  - `test_stable_unique_evidence_ids`: PASSED
  - `test_unsupported_process_telemetry_disclosed_and_flagged`: PASSED
  - `test_lateral_movement_hypothesis_without_network_flagged`: PASSED
  - `test_temporal_only_package_calibrates_confidence_from_high`: PASSED

### Backend Live Connector Tests
- **Command:** `.\.venv\Scripts\python.exe -m pytest -m live -v`
- **Result:** **4 PASSED**, 0 FAILED, 84 deselected in 23.55s.
  - `test_live_wazuh_client_authentication`: PASSED (JWT token acquired from Wazuh Manager port 55000).
  - `test_live_opensearch_client_alerts_search`: PASSED (Retrieved genuine alerts from OpenSearch port 9200).
  - `test_live_api_alerts_endpoint`: PASSED (GET `/api/v1/alerts` returned 200 with genuine alert records).
  - `test_live_api_investigate_endpoint`: PASSED (POST `/api/v1/alerts/{id}/investigate` completed genuine inference with local Ollama `llama3.2:3b` on port 11434).

### Frontend Verification
- **Linter:** `npm run lint` (`oxlint`): **0 warnings, 0 errors** across 10 files.
- **Typecheck & Production Build:** `npm run build` (`tsc -b && vite build`): **Clean build** in 283ms (`dist/index.html`, `dist/assets/index-B0-dctVG.css`, `dist/assets/index-C7glqdMc.js`).
- **Contract & Security Suite:** `node tests/validate_client.js`: **All 9 checks PASSED**.

---

## 8. Results of Existing Live Integration Tests

All four live integration tests ran against active local infrastructure without issues:

| Live Test | Target Service | Port | TLS / Auth Status | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| `test_live_wazuh_client_authentication` | Wazuh Manager | 55000 | TLS Verified (Self-signed cert bundle), Basic Auth | **PASSED** |
| `test_live_opensearch_client_alerts_search` | Wazuh Indexer | 9200 | TLS Verified (Self-signed root CA), Basic Auth | **PASSED** |
| `test_live_api_alerts_endpoint` | FastAPI App | 8001 | Internal in-process TestClient with live connectors | **PASSED** |
| `test_live_api_investigate_endpoint` | Ollama Daemon | 11434 | Loopback HTTP, `llama3.2:3b` structured generation | **PASSED** |

---

## 9. Before / After Comparison Using Synthetic Test Fixtures

*(Note: The following examples use synthetic test fixtures strictly labeled as test fixtures; no mock alerts were injected into the live production SIEM).*

### Example 1: Placeholder IP & Username Matching

**Synthetic Input Alerts (Test Fixture):**
- Primary Alert: `rule_id="1001", source_ip="0.0.0.0", username="unknown", agent_name="unknown"`
- Candidate Alert: `rule_id="1002", source_ip="0.0.0.0", username="unknown", agent_name="unknown"`

**Before Phase 6A:**
- Evaluated `primary.source_ip == rel.source_ip` as `True`.
- Correlation reason assigned: `"shared_source_ip"` (Rank 1).
- **False Association:** The events were presented as sharing a verified source IP.

**After Phase 6A:**
- `is_valid_ip("0.0.0.0")` $\rightarrow$ `False`.
- `is_valid_username("unknown")` $\rightarrow$ `False`.
- `is_valid_agent("unknown")` $\rightarrow$ `False`.
- Correlation reason assigned: `"temporal_proximity_only (weak correlation; temporal proximity does not prove causation or attacker intent)"` (Rank 3).
- **Accurate Outcome:** No entity correlation is claimed; only weak temporal proximity is noted.

---

### Example 2: Confidence Calibration on Temporal-Only Package

**Synthetic Investigation Result (Test Fixture):**
- Target: Primary alert + 1 candidate matching only by temporal proximity.
- Ollama generated: `confidence_label="high"`.

**Before Phase 6A:**
- `result.confidence_label` remained `HIGH`.
- The UI displayed `HIGH` confidence despite having zero corroborating entity evidence.

**After Phase 6A:**
- `validate_evidence_citations` detected that all related items were temporal-only.
- `result.confidence_label` was calibrated from `HIGH` to `MEDIUM`.
- Warning recorded: `"Confidence calibrated from HIGH to MEDIUM: correlation relies exclusively on an isolated alert or weak temporal proximity without corroborating entity or host telemetry."`

---

## 10. Ollama Grounding and Frontend Transparency Findings

1. **System Prompt Hardening:**
   - System rules 11 and 12 explicitly prohibit Ollama from assuming process injection or lateral movement without explicit network and process telemetry.
   - Ollama is instructed that nearby timestamps alone are temporal correlation, not proof of causation.
2. **Server-Side Limitations Disclosure:**
   - When correlation is partial or truncated, `InvestigationResult.limitations` automatically includes a disclosure notice.
   - When process correlation is unsupported by the schema, `InvestigationResult.limitations` discloses that process telemetry is unavailable.
3. **Frontend Presentation:**
   - The investigation modal cleanly displays the correlation status (`ENRICHED`, `PARTIAL (TRUNCATED / WEAK)`, `NO RELATED EVENTS FOUND`, `SINGLE-ALERT FALLBACK`, or `NOT REQUESTED`).
   - If unsupported signals are present, a distinct yellow warning banner clarifies:
     `⚠️ Unsupported Telemetry: [process_lineage, command_line] are not supported by the alert schema (process correlation is unsupported).`
   - The disclaimer confirms: `ℹ️ Correlation context provides observational proximity. Correlation does not prove causation, attacker progression, or compromise.`

---

## 11. Remaining Limitations and False-Positive Risks

1. **Shared DHCP / NAT Infrastructure:**
   - Multiple separate endpoints behind the same egress NAT or receiving the same dynamically reassigned IP address within the 30-minute window will produce a `shared_source_ip` signal. This is an inherent property of IP-level telemetry. SOC analysts must verify internal host identities.
2. **Generic System User Accounts:**
   - Usernames like `root` or `admin` on Linux or Windows hosts may match across distinct physical servers if multiple machines experience administrative logins around the same time. The correlation reason is factually `shared_username`, but analysts must verify whether the account was operated by the same identity.
3. **Regex Grounding Ceilings:**
   - The citation validator uses deterministic regular expressions to catch explicit phrases (e.g. `process injection`, `lateral movement`, `insider threat`, `compromised host`). While effective and deterministic, regex does not perform full natural language entailment. Highly paraphrased speculative language may bypass heuristic checks.
4. **Single-Node Detection Schema:**
   - Wazuh rootcheck and syscheck alerts do not capture process trees or parent PID hierarchies in their top-level fields. Detailed process lineage requires Sysmon or auditd rule sets.

---

## 12. Confirmation of Repository Safety

- **No Git Commits Created:** Confirmed via `git status` that branch `main` remains cleanly uncommitted.
- **User Changes Preserved:** All existing user modifications and untracked report files remain intact.
- **No Git History / Branch Alterations:** No `git reset`, `stash`, `clean`, `commit`, or branch modifications were executed.

---

## 13. Confirmation of Infrastructure Safety

- **Wazuh Unchanged:** Wazuh Manager configuration, rule files, decoders, and certificates were not modified.
- **Docker Containers Untouched:** Docker containers (`wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`) were not stopped, restarted, or altered.
- **OpenSearch Data Untouched:** No index mappings, documents, or data were created, modified, or deleted.
- **Secrets & Credentials Protected:** No passwords, JWT tokens, private keys, or environment files were logged or committed.
- **Read-Only Operation Maintained:** All live interactions with OpenSearch, Wazuh Manager, and Ollama remain strictly read-only.
