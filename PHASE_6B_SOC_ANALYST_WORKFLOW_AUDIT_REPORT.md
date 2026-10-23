# PHASE 6B — SOC ANALYST WORKFLOW & INVESTIGATION QUALITY AUDIT REPORT

**Project:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Target Workspace:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Deployment Infrastructure:** `F:\MY Project\wazuh-docker` (read-only, untouched)  
**Date:** October 20, 2026  
**Auditor / Mode:** Antigravity Senior Security & Reliability Agent (Lazy Senior Dev Mode)  
**Status:** Complete — All Workstreams Implemented & Verified

---

## 1. Executive Verdict

### **VERDICT: PASS**

Phase 6B successfully elevated the SOC analyst investigation experience, evidence provenance tracking, and alert triage usability while preserving 100% of the Phase 6A security, reliability, and architectural boundaries.

Key achievements:
1. **Advisory Authority & Fact-Hypothesis Segregation (Workstream A):** Established explicit visual and conceptual boundaries between authoritative Wazuh detection records (`DETECTION OF RECORD: WAZUH / OPENSEARCH`) and advisory AI analysis (`🤖 ADVISORY AI INVESTIGATION`). Observed facts are strictly segregated from investigative hypotheses, with uncertainty levels clearly designated.
2. **First-Class Evidence Provenance (Workstream B):** Real evidence records (`evidence_items`) are now surfaced from the backend evidence builder through the API schema to the UI. Analysts inspect stable evidence identifiers (`EV-01`, `EV-02`), primary vs. related role tags, UTC event timestamps, rule IDs/descriptions, agent context, network attributes, correlation signals, and explicit qualification banners (e.g., NAT/DHCP disclaimers).
3. **Interactive Citation Navigation & Markdown Export (Workstream A & B):** Analysts can click any evidence pill in observed facts or hypotheses to smoothly scroll and highlight the supporting evidence record. A one-click "Copy Markdown Report" feature exports clean, formatted, unredacted-safe Markdown reports for ticketing systems without inventing data or leaking tokens.
4. **Alert Triage Usability (Workstream C):** Preserved real-time alert severity badges, rule-level indicators, UTC timestamps, agent tags, and direct transitions from alert details to AI investigations, while maintaining request cancellation and stale-data protection.
5. **Investigation History Persistence Assessment (Workstream D):** Completed a comprehensive architectural assessment. Verified that investigation results are currently ephemeral (in-memory React state). Documented privacy, retention, access control, and integrity risks of improvised local file caching, formally deferring persistent audit logging to Phase 7 in accordance with ADR-007.
6. **Zero Regression Baseline (Workstream E):** All 101 non-live pytest tests, all 38 correlation tests, 14 schema tests, 4 live end-to-end connector tests against real Wazuh/OpenSearch/Ollama, frontend linter (0 errors), build (clean bundle), and client contract tests passed with zero failures. Zero Git commits were created, and deployment infrastructure was completely untouched.

---

## 2. Existing Behavior Inspected Before Changes

Prior to Phase 6B implementation, inspection of the codebase revealed:
- **Backend Schema (`backend/app/schemas/investigation.py`):** The `InvestigationResult` model contained structured summary, facts, hypotheses, checks, limitations, and `related_events_summary`, but did **not** expose the underlying `EvidenceItem` records that constituted the evidence package.
- **Backend Inference (`backend/app/services/ollama_client.py`):** `EvidenceService.build_evidence_package()` built and sanitized an `EvidencePackage` containing `items: List[EvidenceItem]`, but discarded this item list when constructing the returned `InvestigationResult`.
- **Frontend Presentation (`frontend/src/components/InvestigationModal.tsx`):**
  - Rendered `cited_evidence_ids` as static inline pills (`EV-01`), but there was no corresponding evidence card list to inspect the actual raw rule, timestamp, agent, or IP behind that citation.
  - The modal lacked an easy, standardized mechanism for SOC analysts to export the full structured investigation to an external ticketing/case-management system (e.g., Jira, TheHive).
  - While advisory disclaimers existed, the distinction between Wazuh as the detection authority of record vs. Ollama as an advisory assistant needed clearer visual anchoring.
- **Frontend Types (`frontend/src/types/api.ts`):** Lacked typed definitions for `EvidenceItem`.

---

## 3. Workstream A — Investigation Report Quality Improvements

### Distinct Conceptual Hierarchy
The investigation report in [InvestigationModal.tsx](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/components/InvestigationModal.tsx) now presents a crystal-clear, structured investigation hierarchy:
1. **Detection Authority Header:** Displays an immutable badge `DETECTION OF RECORD: WAZUH / OPENSEARCH` alongside `🤖 ADVISORY AI INVESTIGATION` and the active model identifier (`llama3.2:3b`).
2. **Mandatory Advisory Disclaimer:** Reinforces that Wazuh alert logs remain the authoritative detection and forensic record.
3. **Correlation Context Card:** Shows the correlation status (`ENRICHED`, `PARTIAL`, `NO_RELATED_EVENTS_FOUND`, `FAILED_FALLBACK_SINGLE_ALERT`, or `SKIPPED`), time window boundaries (±15m), retrieved vs. included counts, truncation warnings, and unsupported telemetry notices (e.g., process correlation unavailable).
4. **Executive Findings Summary:** Concise high-level synthesis with calibrated confidence tags (`CONFIDENCE: LOW`, `CONFIDENCE: MEDIUM`).
5. **Observed Facts:** Factual statements corroborating evidence records. Each fact displays its ID (`F-1`) and interactive evidence citation pills (`EV-01`).
6. **Investigative Hypotheses:** Plausible inferences with explicit uncertainty labels (`LOW`, `MEDIUM`, `HIGH` uncertainty) and cited evidence IDs.
7. **Authoritative Evidence Package:** Fully rendered provenance cards for every evidence record (detailed in Workstream B).
8. **Recommended Read-Only Checks:** Human-in-the-loop verification steps labeled with `READ-ONLY CHECK` and priority badges (`LOW`, `MEDIUM`, `HIGH`).
9. **Investigation Bounds & Context Gaps:** Deterministic grounding warnings, citation validation warnings, and model-declared limitations.

### One-Click Structured Markdown Export
Analysts can copy a standardized, audit-ready Markdown report via the "📄 Copy Markdown Report" button. The exporter:
- Includes Target Alert ID, Model Tag, Authority Disclaimer, Summary, Facts with citations, Hypotheses with uncertainty ratings, Authoritative Evidence records with timestamps/rules/hosts/IPs, and Recommended Read-Only Checks.
- Never fabricates missing fields or leaks internal tokens/credentials.

---

## 4. Workstream B — Evidence Provenance Improvements

### Provenance Exposure in Backend & API Contract
- Updated `backend/app/schemas/investigation.py` to include `evidence_items: Optional[List[EvidenceItem]] = Field(default=None, description="Authoritative evidence records evaluated during this investigation")`.
- Updated `backend/app/services/ollama_client.py` to attach `evidence_items=package.items` directly onto the instantiated `InvestigationResult`.
- Updated `frontend/src/types/api.ts` to define the typed `EvidenceItem` interface and attach `evidence_items?: EvidenceItem[] | null` to `InvestigationResult`.

### Evidence Provenance Presentation
Every evidence item rendered in [InvestigationModal.tsx](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/components/InvestigationModal.tsx) features:
- **Stable ID & Primary Status:** Stable tag (`EV-01`, `EV-02`) with a distinct role pill: `PRIMARY ALERT` (cyan accent) vs. `RELATED EVENT` (indigo accent). Primary alert `EV-01` always remains first.
- **UTC Timestamp:** Preserves original event time formatted in ISO UTC.
- **Rule Metadata:** Wazuh rule ID, severity level badge (`LVL 5`), and rule description.
- **Agent / Host Context:** Explicit host name or `Unavailable` if omitted.
- **Network & Account Context:** Source IP, Destination IP, and Username (marked `None` if absent, never fabricated).
- **Correlation Signals:** Displays the exact correlation reason (e.g., `same_source_ip_and_destination_ip`, `same_agent_id_and_destination_ip`).
- **Correlation Qualifier Warnings:** Displays explicit domain qualifiers:
  - `network_association_subject_to_nat_dhcp_or_shared_egress`: "⚠️ Shared IP address is subject to NAT, DHCP pools, or proxies; does not prove a shared host or attacker."
  - `generic_account_name_unverified_identity`: "⚠️ Matching generic username across hosts does not verify human identity or lateral movement."
  - `temporal_proximity_only_non_causal`: "ℹ️ Temporal proximity only; non-causal association."
  - `reporting_endpoint_context_only`: "ℹ️ Activity co-located on the same monitored endpoint."

### Interactive Citation Jump Navigation
- Clicking an `EV-XX` citation button in Observed Facts or Hypotheses triggers smooth scrolling to `evidence-card-EV-XX`.
- The target evidence card receives an active glowing highlight (`active-highlight`) for 2.5 seconds, allowing immediate visual cross-examination.

---

## 5. Workstream C — Alert Triage Usability Improvements

1. **Detection Authority Anchoring:** Clear segregation between Wazuh detections and AI inferences prevents analysts from assuming AI-generated hypotheses represent confirmed breaches.
2. **Alert Detail Modal Direct Path:** Preserved one-click transition from Alert Detail modal (`View Detail`) to AI Investigation modal (`🤖 Investigate with AI`) without page reloading.
3. **Data Integrity & Filter State:** Preserved fast, client-side filtering by rule level, agent name, rule ID, and text search, bound to validated pagination limits (max 100 alerts per page).
4. **State Machine Clarity:** Loading spinners, detailed progress descriptions, explicit error recovery actions (`Retry Investigation`), and prompt cancellation safeguards remain active and responsive.

---

## 6. Workstream D — Investigation History Persistence: Scope Assessment

An exhaustive code and architecture inspection was conducted to assess existing investigation persistence:

| Dimension | Current State | Findings & Architectural Risk |
|---|---|---|
| **Storage Mechanism** | Strictly Ephemeral | Investigation results exist only in React component memory (`investigationResult` state). Closing the modal or refreshing the page clears the result. |
| **Backend Persistence** | None | No database (PostgreSQL, SQLite), persistent key-value store (Redis), or on-disk JSON log files are configured or written to for investigations. |
| **Privacy & Secret Exposure** | Low (Ephemeral) | Because results are ephemeral, sanitized logs and model outputs are not accumulated on disk. An improvised local JSON/SQLite cache would risk storing sensitive log parameters without encryption at rest. |
| **Access Control & RBAC** | Single-user loopback | Backend currently operates in local single-user mode. Any local persistence mechanism without cryptographic file permissions or authenticated multi-tenant isolation would violate ADR-007. |
| **Disk Growth & DOS** | Controlled | Storing unconstrained investigation payloads on disk on a high-throughput SIEM could cause local disk exhaustion or unmanaged file sprawl. |
| **Integrity & Tamper Evidence** | Unverified if improvised | Improvised text file logging lacks cryptographic hashing, tamper evidence, or immutable audit log guarantees required for forensic compliance. |

### Architectural Conclusion
Introducing an ad-hoc local SQLite or JSON file cache in Phase 6B would violate `AGENTS.md` ("Add PostgreSQL/Redis only when the case-management, audit, or background-processing requirements justify them") and ADR-007. **Investigation history persistence is properly deferred to Phase 7**, where a durable, schema-migrated database with encryption at rest, retention cleanup policies, and access controls will be formally introduced.

---

## 7. Files Changed and Purpose

| File Path | Purpose of Changes |
|---|---|
| [backend/app/schemas/investigation.py](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/schemas/investigation.py) | Added `evidence_items: Optional[List[EvidenceItem]]` to `InvestigationResult` schema to carry authoritative evidence records. |
| [backend/app/services/ollama_client.py](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/services/ollama_client.py) | Populated `evidence_items=package.items` upon instantiating `InvestigationResult` in `investigate_alert()`. |
| [backend/tests/test_investigation_schema.py](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/tests/test_investigation_schema.py) | Added unit test `test_investigation_result_carries_evidence_items_provenance` verifying serialization and deserialization of evidence items. |
| [frontend/src/types/api.ts](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/types/api.ts) | Added `EvidenceItem` TypeScript interface and updated `InvestigationResult` with optional `evidence_items`. |
| [frontend/src/components/InvestigationModal.tsx](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/components/InvestigationModal.tsx) | Implemented interactive citation navigation (`scrollToEvidence`), Authoritative Evidence Package section, authority badges, and Markdown export. |
| [frontend/src/index.css](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/frontend/src/index.css) | Added CSS styling for evidence cards, role badges, active citation highlights, qualification disclaimers, and Markdown export actions. |

---

## 8. Exact Tests, Exit Codes, Counts, and Warnings

### Test 1: Backend Correlation Tests
- **Command:** `.\.venv\Scripts\python.exe -m pytest tests/test_correlation.py -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Test Counts:** 38 passed
- **Warnings:** 1 (FastAPI/Starlette `httpx` deprecation warning)
- **Duration:** 4.76s

### Test 2: Backend Investigation Schema Suite
- **Command:** `.\.venv\Scripts\python.exe -m pytest tests/test_investigation_schema.py -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Test Counts:** 14 passed (including newly added `test_investigation_result_carries_evidence_items_provenance`)
- **Warnings:** 1 (FastAPI/Starlette `httpx` deprecation warning)
- **Duration:** 0.06s

### Test 3: Backend Non-Live Regression Suite
- **Command:** `.\.venv\Scripts\python.exe -m pytest -m "not live" -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Test Counts:** 101 passed, 4 deselected
- **Warnings:** 1 (FastAPI/Starlette `httpx` deprecation warning)
- **Duration:** 19.97s

### Test 4: Live End-to-End Connector Tests
- **Command:** `.\.venv\Scripts\python.exe -m pytest -m live -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Test Counts:** 4 passed (`test_live_wazuh_client_authentication`, `test_live_opensearch_client_alerts_search`, `test_live_api_alerts_endpoint`, `test_live_api_investigate_endpoint`), 101 deselected
- **Warnings:** 1 (FastAPI/Starlette `httpx` deprecation warning)
- **Duration:** 22.08s (executed live against local Wazuh API, Wazuh Indexer, and Ollama `llama3.2:3b`)

### Test 5: Frontend Linter
- **Command:** `npm run lint`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\frontend`
- **Exit Code:** `0`
- **Output:** Found 0 warnings and 0 errors across 10 files.

### Test 6: Frontend Production Build
- **Command:** `npm run build` (`tsc -b && vite build`)
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\frontend`
- **Exit Code:** `0`
- **Output:** Built bundle cleanly (`dist/assets/index-BpbVdtdN.js` 265.29 kB │ gzip: 79.45 kB) in 104ms.

### Test 7: Frontend Security & Contract Validation
- **Command:** `node tests/validate_client.js`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\frontend`
- **Exit Code:** `0`
- **Output:** 
  - Verified 0 leaked ports or backend credentials in bundle.
  - Verified standard query params formatting and page_size <= 100 clamping.
  - Verified investigateAlert payload clamping <= 20 and URL path encoding.
  - Verified 100% avoidance of `dangerouslySetInnerHTML`.
  - Verified immutable alert severity and rule metadata.
  - Verified safe error envelopes for HTTP 400, 404, 502, 503, 504.

---

## 9. Security-Boundary Regression Results

| Security Control | Validated Status | Verification Evidence |
|---|---|---|
| **Loopback Binding** | Preserved | Uvicorn running on `127.0.0.1:8001`, Vite on `127.0.0.1:5174`, Ollama on `127.0.0.1:11434`. |
| **API Authentication** | Preserved | `test_api_auth_all_sensitive_routes_enforce_bearer_token` passed; fail-closed on invalid key. |
| **CORS Policy** | Preserved | `test_cors_loopback_origins_restricted` passed; only configured loopback ports allowed. |
| **TLS & Hostname Verification** | Preserved | `test_opensearch_client_auth_failure_401` and live test passed with strict custom CA verification. |
| **Read-Only Invariant** | Preserved | No shell execution, active response, firewall modification, or account locking introduced. `test_remediation_action_in_recommended_checks_flagged_and_forced_readonly` passed. |
| **Evidence Sanitization** | Preserved | Passwords, tokens, and raw credentials redacted; payload capped at 20 items / 32,768 bytes. |
| **XSS Prevention** | Preserved | Zero instances of `dangerouslySetInnerHTML`; all user/log strings rendered via React DOM escaping. |

---

## 10. Before / After Behavior Supported by Evidence

| Behavior Area | Before Phase 6B | After Phase 6B |
|---|---|---|
| **Evidence Item Provenance** | Evidence items were dropped after backend validation; frontend only saw citation IDs (`EV-01`) without knowing the underlying event, host, or rule. | `evidence_items` are returned in `InvestigationResult`. Each item is presented with full provenance: rule ID/desc, agent name, IPs, username, and qualification disclaimers. |
| **Citation Traceability** | Citations were static text buttons with no interactive behavior. | Clicking any `EV-XX` citation smoothly navigates the viewport to the evidence card and pulses it with a glowing highlight. |
| **Report Export** | Analysts could only copy raw summary text. No mechanism existed to export facts, hypotheses, evidence, and checks. | Analysts can click "Copy Markdown Report" to obtain a full, beautifully formatted Markdown document ready for ticket pastes. |
| **Authoritative Distinction** | Detections and AI hypotheses were visually close, risking confusion over alert authority. | Prominent header badges (`DETECTION OF RECORD: WAZUH / OPENSEARCH` vs `🤖 ADVISORY AI INVESTIGATION`) and explicit disclaimers clarify that Wazuh is the detector of record. |
| **Investigation Persistence** | Undocumented / unspecified. | Rigorously assessed and documented; verified strictly ephemeral to prevent unencrypted disk leaks prior to Phase 7. |

---

## 11. Git Status Before and After

### Working Tree Status
```text
 M .gitignore
 M backend/app/api/v1/__init__.py
 M backend/app/core/config.py
 M backend/app/core/errors.py
 M backend/app/main.py
 D backend/app/middleware/__init__.py
 D backend/app/middleware/correlation.py
 M backend/app/schemas/__init__.py
 M backend/app/services/__init__.py
 M backend/app/services/health_service.py
 M backend/pyproject.toml
 M frontend/src/App.tsx
 M frontend/src/api/client.ts
 M frontend/src/index.css
 M frontend/src/types/api.ts
?? backend/app/api/deps.py
?? backend/app/api/v1/alerts.py
?? backend/app/core/tls.py
?? backend/app/schemas/alert.py
?? backend/app/schemas/investigation.py
?? backend/app/services/evidence_service.py
?? backend/app/services/ollama_client.py
?? backend/app/services/opensearch_client.py
?? backend/app/services/wazuh_client.py
?? backend/tests/test_alerts.py
?? backend/tests/test_connectors.py
?? backend/tests/test_correlation.py
?? backend/tests/test_investigation_api.py
?? backend/tests/test_investigation_schema.py
?? backend/tests/test_live_connectors.py
?? backend/tests/test_ollama_client.py
?? frontend/src/components/
?? frontend/tests/
```

---

## 12. Confirmation of Zero Commits

- **Current Git Branch:** `main`
- **Latest Commit Hash:** `793e4c4` (`feat(phase1): implement FastAPI backend skeleton, health endpoints, and React SOC dashboard frontend`)
- **Total New Commits Created:** `0`
- **Compliance:** 100% adherence to Rule 5 ("Do not commit, push, amend commits, stage unrelated files, or switch branches").

---

## 13. Confirmation That Deployment Infrastructure Was Untouched

- **Repository Inspected:** `F:\MY Project\wazuh-docker`
- **Status:** Unmodified during Phase 6B. No containers restarted, no Docker compose files changed, no certificates modified, and no OpenSearch indices altered.
- **Compliance:** 100% adherence to Rule 6 & Rule 7.

---

## 14. Remaining Limitations and Prioritized Next Steps

### Remaining Limitations
1. **Single-User Local Boundary:** API authentication protects endpoints with a static Bearer token suitable for single-analyst loopback operation, but does not provide multi-tenant RBAC or per-user audit trails.
2. **Ephemeral Investigation State:** Navigating away from or closing an active investigation modal discards the generated report; results cannot currently be recalled across browser sessions without re-running inference.
3. **Absence of Host Process Telemetry:** Because the normalized Wazuh alert schema prioritizes rule, network, agent, and user fields, deep process-tree lineage (Sysmon/auditd process trees) is not yet extracted into the evidence package and is explicitly reported in `unsupported_signals`.

### Prioritized Next Steps (Phase 7 Preparation)
1. **Durable Investigation & Audit Store (ADR-007):** Design and provision a local relational store (e.g., PostgreSQL with SQLAlchemy/Alembic) to persist investigations, analyst notes, and audit trails with encrypted sensitive fields and retention cleanup policies.
2. **Case Management Integration:** Support saving investigations as persistent "Cases" with analyst status updates (`in_progress`, `false_positive`, `escalated`).
3. **Deep Telemetry Extractors:** Expand `EvidenceService` to parse Sysmon Event IDs (Event ID 1 process creation, Event ID 3 network connection) from `data.win.eventdata` when available.
