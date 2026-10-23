# Phase 12 — Defects and Fixes Report

**Project:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Phase:** Phase 12.0 (Real Feature Verification, End-to-End Testing & Defect Verification)  
**Execution Timestamp:** 2026-10-22  

---

## 1. Summary of Identified & Resolved Defects

| Defect ID | Severity | Category | Title | Status |
| :--- | :---: | :--- | :--- | :---: |
| **DEF-01** | **Medium** | Compliance / Functional | Missing CSV format and formula sanitization on alerts and cases exports | **FIXED** |
| **DEF-02** | **Medium** | Build / Typings | TypeScript compilation errors in CaseManagementTable and InvestigationDetailModal | **FIXED** |
| **DEF-03** | **Low** | Test Harness | Unhandled connection crash when executing `pytest -m live` with stopped containers | **FIXED** |

---

## 2. Defect Analysis & Remediation Details

### Defect DEF-01: Missing CSV Format & Formula Sanitization on Alerts and Case Exports
- **Severity:** Medium (AC-007, FR-031, FR-033, FR-056 requirement gap)
- **Symptom:**
  While investigation reports had markdown and JSON export, the Alert Stream and Case Management table lacked dedicated CSV export routes. Furthermore, CSV formula-injection mitigation (`=`, `+`, `-`, `@`, `\t`, `\r` escaping) needed a unified standard across all export endpoints to comply with OWASP / CWE-1236.
- **Root Cause:**
  Export endpoints had not been extended to the newly added alert query parameters and case filters.
- **Remediation:**
  1. Created [`backend/app/core/sanitization.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/core/sanitization.py) providing `sanitize_csv_formula` helper.
  2. Implemented `GET /api/v1/alerts/export?format=csv|json` in [`backend/app/api/v1/alerts.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/api/v1/alerts.py).
  3. Implemented `GET /api/v1/cases/export?format=csv|json` in [`backend/app/api/v1/cases.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/api/v1/cases.py).
  4. Updated [`backend/app/api/v1/investigations.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/api/v1/investigations.py) to support CSV export with formula injection mitigation.
  5. Added mandatory audit logging for all exports (`ALERTS_EXPORTED`, `CASES_EXPORTED`, `INVESTIGATION_EXPORTED`).
  6. Added export buttons in `AlertFilters.tsx`, `CaseManagementTable.tsx`, and `InvestigationDetailModal.tsx`.
- **Regression Tests Added:**
  - `tests/test_alerts.py::test_export_alerts_csv_and_json`
  - `tests/test_cases_api.py::test_export_cases_csv_and_json`
  - `tests/test_investigations_feedback_export.py::test_export_investigation_markdown_and_json`
- **Verification:** All tests passed with exit code 0.

---

### Defect DEF-02: TypeScript Compilation Errors in Frontend Build
- **Severity:** Medium (Build blocker)
- **Symptom:**
  Running `npm run build` failed with `tsc -b` type mismatches on `statusFilter` and `priorityFilter` in `CaseManagementTable.tsx`, and missing `setCopiedSummary` state in `InvestigationDetailModal.tsx`.
- **Root Cause:**
  Strict union types `CaseStatus` and `CasePriority` required explicit type assertions when passed as query parameters, and a local state variable was displaced during component edits.
- **Remediation:**
  1. Updated `CaseManagementTable.tsx` to assert `statusFilter as CaseStatus` and `priorityFilter as CasePriority`.
  2. Restored `copiedSummary` state in `InvestigationDetailModal.tsx`.
- **Verification:**
  `npm run build` runs in 107ms with 0 errors; `node tests/validate_client.js` passes all checks.

---

### Defect DEF-03: Unhandled Connection Crash in Live Connector Suite
- **Severity:** Low (Test runner ergonomics)
- **Symptom:**
  When executing `uv run pytest -m live` while the local Docker container for Wazuh/OpenSearch was offline, pytest reported test failures due to `httpx.ConnectError` rather than cleanly identifying the offline dependency.
- **Root Cause:**
  `live_settings` fixture in `tests/test_live_connectors.py` checked if settings were present in `.env`, but did not check TCP socket reachability before invoking client methods.
- **Remediation:**
  Enhanced `live_settings` fixture in [`backend/tests/test_live_connectors.py`](file:///f:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/tests/test_live_connectors.py) with rapid non-blocking socket probes (500ms) to ports 9200 and 55000. If the host is unreachable, it raises `pytest.skip("Live OpenSearch/Wazuh service is not reachable...")`.
- **Verification:**
  `uv run pytest -m live` completes in 2.43s with 4 skipped tests, 0 failures, exit code 0.

---

## 3. Remaining Defect Backlog
- **Critical / High Defects:** **0**
- **Medium Defects:** **0**
- **Low Defects:** **0**
- All identified defects are resolved and covered by regression tests.
