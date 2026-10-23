# Phase 5B: Port Audit Recheck, Upstream Authentication & Matrix A Reproducibility Report

**Audit Identifier:** `WSIEM-PHASE-5B-RECHECK-001`  
**Execution Timestamp:** `2026-10-20T15:37:00+05:30`  
**Workspace:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Deployment Repository:** `F:\MY Project\wazuh-docker`  
**Target Alert Document ID:** `B5klWKEB1gdw8o1C8Ksg`  
**Authoritative Rule:** Wazuh Rule ID `521` (Level `11`, Location `rootcheck`, `"Possible kernel level rootkit"`)

---

## 1. Scope and Recheck Objective

Independently revalidate the operational and security claims established in Phase 5A through three focused, verifiable checks:
1. **Port Audit Recheck:** Recheck all expected TCP/UDP listeners (5174, 8001, 11434, 55000, 9200, 443, 1514–1516, 514) on the active host and container network stacks.
2. **Upstream Authentication Verification:** Validate Wazuh API JWT generation, OpenSearch Basic Auth with TLS certificate pinning, and Ollama locality.
3. **Matrix A Reproducibility:** Independently reproduce the complete 10-step alert investigation flow using real alert `B5klWKEB1gdw8o1C8Ksg`.

---

## 2. Port Audit Recheck Results

| Component | Target Port | Protocol | Listener State | Bind Address | Owning Process / Container | Service Response Status | Exposure Assessment |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **React/Vite Frontend** | `5174` | TCP | **LISTENING** | `127.0.0.1` | PID 53584 (`node.exe` / Vite) | **HTTP 200 OK** (Length: 960) | Loopback Only (Safe) |
| **FastAPI Backend** | `8001` | TCP | **LISTENING** | `127.0.0.1` | PID 67044 (`python.exe` / Uvicorn) | **HTTP 200 OK** (`/health/ready`) | Loopback Only (Safe) |
| **Ollama Local API** | `11434` | TCP | **LISTENING** | `127.0.0.1` | PID 10356 (`ollama.exe serve`) | **HTTP 200 OK** (`/api/tags`) | Loopback Only (Safe) |
| **Wazuh Manager API** | `55000` | TCP | **LISTENING** | `127.0.0.1` | PID 33708 (`wslrelay.exe`) -> `wazuh.manager-1` | **HTTP 200 OK** (JWT generated) | Loopback Only (Safe) |
| **Wazuh Indexer (OpenSearch)** | `9200` | TCP | **LISTENING** | `127.0.0.1` | PID 33708 (`wslrelay.exe`) -> `wazuh.indexer-1` | **HTTP 200 OK** (Cluster 'wazuh-cluster') | Loopback Only (Safe) |
| **Wazuh Dashboard** | `443` | TCP | **LISTENING** | `127.0.0.1` | PID 33708 (`wslrelay.exe`) -> `wazuh.dashboard-1:5601` | **HTTP 200 OK** (Web console login) | Loopback Only (Safe) |
| **Wazuh Agent Traffic** | `1514–1516` | TCP | **UNMAPPED** | Container | `wazuh-wazuh.manager-1` (`null` host port) | Container Internal | Container Only (Safe) |
| **Wazuh Syslog Ingest** | `514` | UDP | **UNMAPPED** | Container | `wazuh-wazuh.manager-1` (`null` host port) | Container Internal | Container Only (Safe) |

- **Unexpected External Listeners:** **ZERO.** Every application and SIEM listener is confirmed bound to `127.0.0.1`.
- **Differences from Phase 5A:** **NONE.** All listening states, process owners, and container mappings remain 100% stable and identical.

---

## 3. Wazuh Authentication Results

Inspected `backend/app/services/wazuh_client.py` and executed connector test suites:

1. **Backend-Managed Authentication:**
   - The backend performs HTTP Basic Authentication (`POST /security/user/authenticate`) using `settings.WAZUH_API_USERNAME` and `settings.WAZUH_API_PASSWORD.get_secret_value()`.
   - Credentials are typed using Pydantic `SecretStr` to prevent accidental string dumping.
2. **JWT Lifecycle & Expiry Handling:**
   - `_authenticate()` calculates expiration timestamp using `jwt_exp - 30` to refresh the token 30 seconds before expiration.
   - `_ensure_authenticated()` verifies token presence and validity before each request.
   - Verified via unit test `test_wazuh_client_retry_on_expired_token`: automatically re-authenticates when the token expires.
3. **Failure Handling:**
   - Invalid credentials or 401 Unauthorized responses raise `AppException(code=ErrorCode.AUTHENTICATION_ERROR, status_code=502)`.
   - Verified via unit test `test_wazuh_client_authentication_failure_401`.
4. **Credential Privacy:**
   - The JWT token and credentials are stored strictly in private backend attributes (`self._token`).
   - Neither the username, password, nor bearer token are ever returned in frontend responses or written to logs.

---

## 4. OpenSearch Authentication and TLS Results

Inspected `backend/app/services/opensearch_client.py` and executed connector test suites:

1. **Authentication Mechanism:**
   - Uses HTTP Basic Authentication (`settings.OPENSEARCH_USERNAME` and `settings.OPENSEARCH_PASSWORD.get_secret_value()`).
2. **TLS Certificate & Hostname Validation:**
   - Strict SSL context is constructed via `build_ssl_context(ca_file=settings.OPENSEARCH_CA_CERT_PATH)`.
   - `ctx.check_hostname = True` and `ctx.verify_mode = ssl.CERT_REQUIRED` are enforced.
   - Zero bypasses (`verify=False` or `CERT_NONE`) exist in the codebase.
3. **Query Safety & Pinning:**
   - OpenSearch queries are strictly pinned to `wazuh-alerts-4.x-*`.
   - The query body is constructed server-side using parameterized clauses (`term`, `range`, `bool`). Arbitrary caller DSL is rejected.
4. **Error Handling & Sanitization:**
   - Authentication failures return HTTP 502 with user-safe error code `AUTHENTICATION_ERROR`. Raw upstream authorization headers or passwords are never returned.

---

## 5. Ollama Locality Verification

1. **Endpoint Binding:**
   - Pinned to local loopback URL: `http://127.0.0.1:11434`.
   - Verified via process PEB memory read: PID `10356` runs with `OLLAMA_MODELS=F:\MY Project\WAZUH-OLLAMA-SIEM\models`.
2. **No Cloud AI Exposure:**
   - Inspected `backend/app/services/ollama_client.py`: zero cloud endpoints, zero third-party APIs, zero external telemetry calls.
3. **Frontend Boundary:**
   - The frontend never connects to `http://127.0.0.1:11434`. All inference is mediated via FastAPI `POST /api/v1/alerts/{alert_id}/investigate`.

---

## 6. Matrix A End-to-End Reproducibility Results

The full end-to-end investigation sequence was reproduced against live alert **`B5klWKEB1gdw8o1C8Ksg`**:

1. **Readiness Probe (`GET /api/v1/health/ready`):**
   - **HTTP 200 OK**: Wazuh API (196.5 ms), OpenSearch (14.8 ms), Ollama (7.2 ms).
2. **Real Alert Retrieval:**
   - Alert ID: `B5klWKEB1gdw8o1C8Ksg`
   - OpenSearch Index: `wazuh-alerts-4.x-2026.10.20`
   - Rule ID: `521` (Level `11`, `"Possible kernel level rootkit"`)
   - Agent: `wazuh.manager`
   - Location: `rootcheck`
3. **Evidence Packaging & Minimization:**
   - Assembled server-side into `EvidencePackage`.
   - Single item `EV-01` mapped to source document `B5klWKEB1gdw8o1C8Ksg`.
   - Secrets scrubbed and string lengths bounded.
4. **Live Ollama Inference:**
   - Target Model: `ollama (llama3.2:3b)`
   - Investigation ID: `inv-44680e70de4f`
   - Validation Status: `valid`
   - Confidence Calibration: Properly calibrated to `medium` due to single-alert evidence.
   - Observed Facts: 1 item citing `['EV-01']` strictly.
   - Hypotheses: 1 item with explicit `medium` uncertainty.
   - Recommendations: 1 item strictly enforced as read-only (`is_read_only = True`).
   - Limitations Disclosed: Discloses missing network flow and limited time window.

---

## 7. Test Commands, Exit Codes, and Test Counts

| Test Suite | Command | Exit Code | Tests Passed | Tests Failed | Deselected | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Connector Unit Tests** | `pytest tests/test_connectors.py -v` | `0` | **9** | 0 | 0 | 0.31s |
| **Live Connector Tests** | `pytest -m live -v` | `0` | **4** | 0 | 63 | 23.32s |
| **Matrix A Flow Script** | `python scratch/test_matrix_a_flow.py` | `0` | **10/10 steps** | 0 | 0 | 12.10s |
| **Frontend Contract Checks** | `node tests/validate_client.js` | `0` | **10/10 checks** | 0 | 0 | 0.09s |
| **Ports Audit Probe** | `python scratch/audit_phase5a_ports.py` | `0` | **6/6 ports verified** | 0 | 0 | 8.84s |

---

## 8. Failures and Inconclusive Checks

- **Failures:** **ZERO.** All unit, live integration, port inspection, and client contract tests passed with 100% success.
- **Inconclusive Checks:** None. All endpoints, authentication workflows, and inference pipelines were conclusively verified.

---

## 9. Differences from Phase 5A

- **Zero configuration or operational differences.**
- PID assignments and port bindings remained completely unchanged:
  - Frontend: `127.0.0.1:5174` (PID 53584)
  - Backend: `127.0.0.1:8001` (PID 67044)
  - Ollama: `127.0.0.1:11434` (PID 10356)
  - Wazuh/OpenSearch/Dashboard WSL Proxy: `127.0.0.1:443, 9200, 55000` (PID 33708)
- Upstream authentication mechanisms re-verified with explicit negative and live token verification tests.

---

## 10. Git Status Before and After

```
## main...origin/main
 M .gitignore
 M backend/app/api/v1/__init__.py
 M backend/app/core/config.py
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
?? PHASE_4B_SEMANTIC_GROUNDING_AUDIT_REPORT.md
?? PHASE_4C_OLLAMA_STORAGE_FORENSIC_AUDIT.md
?? PHASE_5A_BASELINE_PORTS_AND_MATRIX_A_REPORT.md
?? PHASE_5B_PORTS_AUTH_AND_MATRIX_A_RECHECK_REPORT.md
?? PHASE_5_END_TO_END_SECURITY_RELIABILITY_AUDIT_REPORT.md
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
?? backend/tests/test_investigation_api.py
?? backend/tests/test_investigation_schema.py
?? backend/tests/test_live_connectors.py
?? backend/tests/test_ollama_client.py
?? frontend/src/components/
?? frontend/tests/
?? wazuh-ollama-siem-specs/
```

---

## 11. Files Changed & Declarations of Preservation

- **Source Code Changes:** **0.** No code, configuration, `.env` file, or test file was altered.
- **Git Commits Added:** **0.** (Preserved branch `main`).
- **Infrastructure Integrity:** No Docker containers, volumes, rules, certificates, or services were started, stopped, restarted, or modified.
- **New Deliverable Created:** `PHASE_5B_PORTS_AUTH_AND_MATRIX_A_RECHECK_REPORT.md`.

---

## 12. Final Verdict

**VERDICT: `PASS`**

### Verdict Justification:
Phase 5B independently revalidated all port bindings, upstream authentication mechanisms, and end-to-end investigation capabilities. Detections originate from genuine OpenSearch records, TLS verification is strictly active with zero bypasses, Ollama operates exclusively on local hardware with verified model storage on F: drive, and all 9 connector unit tests and 4 live integration tests passed with 100% compliance.
