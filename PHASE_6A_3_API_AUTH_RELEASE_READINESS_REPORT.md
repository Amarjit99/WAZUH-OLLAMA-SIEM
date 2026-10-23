# PHASE 6A.3 — API AUTHENTICATION COVERAGE & RELEASE READINESS REPORT

**Project:** Wazuh + Ollama Local AI-Powered SIEM & Threat Hunting Platform  
**Workspace:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Deployment Repository:** `F:\MY Project\wazuh-docker` (Untouched, read-only)  
**Execution Date:** 2026-10-20  
**Phase:** 6A.3 (Route-Level Authentication Audit, Constant-Time Verification, Configuration Behavior & Release Readiness)  
**Branch:** `main` (0 commits created, working tree preserved)

---

## 1. Executive Verdict

### **VERDICT: PASS WITH LIMITATIONS**

A comprehensive, route-by-route audit of the FastAPI application has verified that all sensitive endpoints (`GET /api/v1/alerts`, `GET /api/v1/alerts/{alert_id}`, and `POST /api/v1/alerts/{alert_id}/investigate`) enforce the configurable `verify_api_auth` dependency. Authentication has been hardened with constant-time comparison (`secrets.compare_digest`), whitespace/empty token sanitization, and fail-closed error handling under secure mode. Health endpoints follow a deliberate public policy for probe reliability. CORS is strictly restricted to local loopback origins.

The application is deemed **RELEASE-READY FOR SINGLE-USER LOCAL LOOPBACK DEPLOYMENT**, but remains subject to architectural limitations that require explicit user decisions before exposure to a shared network or multi-tenant environment.

**Key Achievements:**
- **Complete Route Inventory:** 100% of routes mapped across FastAPI routers. All alert and investigation routes strictly enforce `verify_api_auth`. Health and service descriptor routes follow an explicitly documented public policy.
- **Constant-Time Verification:** Token comparison employs `secrets.compare_digest` to eliminate timing side-channel vulnerabilities.
- **Fail-Closed Secure Mode:** When `API_AUTH_REQUIRED=True` and `API_KEY` is missing or whitespace, the application fails closed (HTTP 500) and emits an alert log at startup.
- **CORS Restriced:** Wildcard `*` removed; strictly bound to loopback frontend origins (`127.0.0.1:5174`, `localhost:5174`, etc.).
- **100% Pass Across All Verification Suites:**
  - Backend Unit Suite: **101 passed**, 4 deselected, 0 failed, 1 dependency warning.
  - Correlation & Security Suite: **38 passed**, 0 failed.
  - Live Connectors: **4 passed**, 0 failed (live Wazuh Manager, OpenSearch Indexer, and Ollama `llama3.2:3b` execution).
  - Frontend Lint (`oxlint`): **0 errors, 0 warnings**.
  - Frontend Build (`tsc -b && vite build`): **0 errors, clean build**.
  - Frontend Contract & Security Validation: **All 9 checks passed**.

---

## 2. Complete Route Inventory and Authentication Matrix

The effective FastAPI dependency graph was extracted and verified directly from `app.router`.

| HTTP Method | Route Path | Handler Name | Sensitivity | Auth Required? | Access Control Mechanism | Policy / Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/alerts` | `list_alerts` | **High** (Security Alert Records) | **Yes** (Configurable) | `verify_api_auth` | Enforces Bearer token if `API_KEY` or `API_AUTH_REQUIRED=True`; permitted on loopback in default dev mode. |
| `GET` | `/api/v1/alerts/{alert_id}` | `get_alert` | **High** (Detailed Alert & Raw Log) | **Yes** (Configurable) | `verify_api_auth` | Enforces Bearer token if `API_KEY` or `API_AUTH_REQUIRED=True`; permitted on loopback in default dev mode. |
| `POST` | `/api/v1/alerts/{alert_id}/investigate` | `investigate_alert_endpoint` | **Critical** (AI Inference & Evidence Packaging) | **Yes** (Configurable) | `verify_api_auth` | Enforces Bearer token if `API_KEY` or `API_AUTH_REQUIRED=True`; bounded concurrency semaphore (max 1 concurrent inference). |
| `GET` | `/api/v1/health/live` | `health_live` | **Low** (Process Liveness) | **No** (Public by design) | None | Kubernetes / container runtime liveness probe. Returns `{"status":"ok"}`. |
| `GET` | `/api/v1/health/ready` | `health_ready` | **Medium** (Upstream Dependency Status) | **No** (Public by design) | None | Kubernetes / load balancer readiness probe. Returns dependency connectivity states (Wazuh, OpenSearch, Ollama). |
| `GET` | `/health/live` | `health_live` | **Low** (Root Liveness) | **No** (Public by design) | None | Root-level liveness probe alias. |
| `GET` | `/health/ready` | `health_ready` | **Medium** (Root Readiness) | **No** (Public by design) | None | Root-level readiness probe alias. |
| `GET` | `/` | `root` | **Low** (Service Metadata) | **No** (Public by design) | None | Returns service name and version (`{"service":"Wazuh + Ollama SIEM API","version":"0.1.0"}`). |
| `GET` | `/openapi.json` | `openapi` | **Low** (API Documentation Schema) | **No** (Public by design) | None | OpenAPI JSON schema for client generation. |
| `GET` | `/docs` | `swagger_ui_html` | **Low** (Interactive Swagger UI) | **No** (Public by design) | None | Local interactive API documentation. |
| `GET` | `/redoc` | `redoc_html` | **Low** (ReDoc UI) | **No** (Public by design) | None | Alternative API documentation format. |

---

## 3. Configuration Behavior Across Authentication Modes

Configuration is governed by `backend/app/core/config.py` and validated by `verify_api_auth` in `backend/app/api/deps.py`:

| Mode | `API_AUTH_REQUIRED` | `API_KEY` Value | Effective Behavior | Rationale / Target Environment |
| :--- | :--- | :--- | :--- | :--- |
| **Default Local Dev** | `False` | `None` or unset | Access permitted without credentials on loopback (`127.0.0.1`). | Preserves developer workflow, zero-configuration startup, and seamless browser UI operation. |
| **Secure Token Mode** | `False` or `True` | Non-empty secret string (e.g. `SecretStr(...)`) | Callers must supply `Authorization: Bearer <API_KEY>`. Missing or invalid tokens return HTTP 401. | Protected single-user deployment; script and external client integrations. |
| **Fail-Closed Mode** | `True` | `None` or empty/whitespace (`"   "`) | Requests fail closed with HTTP 500 error (`ErrorCode.INTERNAL_ERROR`). Startup emits error log. | Prevents accidental unauthenticated exposure when secure mode is explicitly requested. |

### Secret Comparison Implementation:
```python
# Constant-time comparison prevents timing side-channel attacks:
if not secrets.compare_digest(credentials.credentials.strip(), expected_key):
    raise AppException(
        code=ErrorCode.VALIDATION_ERROR,
        message="Unauthorized: valid API token required",
        status_code=401,
    )
```

---

## 4. Route-Level Security Test Results

The full test matrix was exercised via automated tests in `backend/tests/test_correlation.py`:

| Test Function | Mode | Credential | Route Tested | Expected Status | Observed Status | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Missing header | `GET /api/v1/alerts` | `401 Unauthorized` | `401 Unauthorized` | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Invalid token | `GET /api/v1/alerts` | `401 Unauthorized` | `401 Unauthorized` | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Valid token | `GET /api/v1/alerts` | `!= 401` (Allowed) | `200 OK` / fresh | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Missing header | `GET /api/v1/alerts/{id}` | `401 Unauthorized` | `401 Unauthorized` | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Invalid token | `GET /api/v1/alerts/{id}` | `401 Unauthorized` | `401 Unauthorized` | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Valid token | `GET /api/v1/alerts/{id}` | `!= 401` (Allowed) | `404` (ID not found) | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Missing header | `POST /alerts/{id}/investigate` | `401 Unauthorized` | `401 Unauthorized` | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Invalid token | `POST /alerts/{id}/investigate` | `401 Unauthorized` | `401 Unauthorized` | **PASS** |
| `test_api_auth_all_sensitive_routes_enforce_bearer_token` | Auth Required | Valid token | `POST /alerts/{id}/investigate` | `!= 401` (Allowed) | `404` (ID not found) | **PASS** |
| `test_api_auth_required_fails_closed_when_key_missing_or_whitespace` | Auth Required | Key = `None` | `GET /api/v1/alerts` | `500 Server Error` | `500 Server Error` | **PASS** |
| `test_api_auth_required_fails_closed_when_key_missing_or_whitespace` | Auth Required | Key = `"   "` | `GET /api/v1/alerts` | `500 Server Error` | `500 Server Error` | **PASS** |
| `test_api_auth_unauthenticated_allowed_in_default_dev_mode` | Auth Disabled | Missing header | `GET /api/v1/alerts` | `!= 401` (Allowed) | `200 OK` | **PASS** |
| `test_health_endpoints_remain_public_under_auth_mode` | Auth Required | Missing header | `/health/live`, `/health/ready`, `/api/v1/health/*` | `!= 401` (Public) | `200 OK` | **PASS** |
| `test_cors_loopback_origins_restricted` | Any | Untrusted Origin | `OPTIONS /api/v1/alerts` | No Allow-Origin header | Header absent | **PASS** |

---

## 5. Health Endpoint Access Policy

### Explicit Policy Definition
1. **Liveness Probe (`/health/live`, `/api/v1/health/live`):**
   - **Access:** Unauthenticated (Public).
   - **Rationale:** Container orchestrators (Docker, Kubernetes, systemd) execute lightweight HTTP GET requests on interval to verify the Python event loop is unblocked. Requiring credentials on liveness probes introduces authentication-coupling failures where expired secrets cause the orchestrator to repeatedly restart healthy processes.
   - **Information Disclosed:** None. Returns static `{"status":"ok"}`.
2. **Readiness Probe (`/health/ready`, `/api/v1/health/ready`):**
   - **Access:** Unauthenticated (Public).
   - **Rationale:** Load balancers and orchestration ingress controllers probe readiness to determine whether to route traffic to the instance. Returns boolean connectivity status for Wazuh, OpenSearch, and Ollama.
   - **Information Disclosed:** Qualitative status strings (`"ok"`, `"degraded"`, `"unavailable"`). No passwords, URLs with credentials, TLS private keys, or raw query results are exposed.

---

## 6. CORS, Binding, and Network Exposure

### Verified Findings:
1. **CORS Allowed Origins:**
   - Evaluates `CORS_ALLOWED_ORIGINS` setting, defaulting to:
     `"http://127.0.0.1:5174,http://localhost:5174,http://127.0.0.1:5173,http://localhost:5173"`
   - Untrusted origins (e.g. `https://malicious-attacker.com`) are rejected: the backend emits no `Access-Control-Allow-Origin` header for unlisted origins.
   - Permitted methods restricted to `["GET", "POST", "OPTIONS"]`.
2. **Network Listener Bindings:**
   - Backend command line verified running on loopback: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8001`.
   - Frontend Vite development server verified on loopback: `http://127.0.0.1:5174/`.
   - OpenSearch Indexer verified on loopback: `https://127.0.0.1:9200`.
   - Wazuh Manager verified on loopback: `https://127.0.0.1:55000`.
   - Ollama Daemon verified on loopback: `http://127.0.0.1:11434`.
3. **No Direct External Connections:**
   - Browser client communicates exclusively with the backend (via Vite `/api` proxy or direct loopback CORS).
   - The browser never establishes direct connections to Wazuh Manager, OpenSearch Indexer, or Ollama.
   - All upstream credentials and TLS certificates reside solely within the backend filesystem.

---

## 7. Frontend Token-Mode Authentication Status

### Architectural Finding:
- **Current State:** The React analyst UI is designed as a local single-user console. It does not contain a login modal, session management state, or persistent token storage.
- **Safe Evaluation:**
  - Hardcoding a shared API key into frontend source code or the Vite production bundle (`dist/assets/*.js`) would constitute a security vulnerability (leaking the secret to any user inspecting browser devtools).
  - Therefore, in the current release, frontend authentication is **deliberately not hardcoded in the client bundle**.
  - In default development mode, loopback access is unauthenticated.
  - If token mode is enabled in production, analysts accessing the API via scripts or API clients pass `Authorization: Bearer <token>`.
  - Adding a secure analyst login screen with HTTP-only cookies or OIDC/OAuth2 flow is scheduled as an explicit user decision for Phase 7.

---

## 8. Role-Based Access Control (RBAC) Status

- **Status:** **UNIMPLEMENTED IN V1.**
- **Clarification:** The platform currently treats any authorized caller as a full-access analyst. There is no role distinction between:
  - Read-only Tier 1 SOC Analyst (alert viewing only).
  - Senior Incident Responder (triggering AI investigations and viewing full sanitized logs).
  - SIEM Administrator (configuring models and connectors).
- **Consequence:** The platform must **NOT** be described as multi-tenant or multi-user secure. It is strictly a single-analyst local investigation tool.

---

## 9. Remaining Dependency Warnings

| Warning | Category | Origin | Risk Assessment & Remediation |
| :--- | :--- | :--- | :--- |
| `StarletteDeprecationWarning: Using 'httpx' with 'starlette.testclient' is deprecated; install 'httpx2' instead.` | Dependency Internal | `fastapi/testclient.py:1` importing `starlette.testclient` | **Risk: None.** This is an informational deprecation notice emitted by Starlette to library maintainers regarding future test-client plumbing. It does not affect production application runtime, security, or API behavior. Safe to leave until FastAPI releases an updated testclient package. |

---

## 10. Exact Verification Commands, Exit Codes, and Counts

### 1. Correlation, Security & Route-Level Auth Suite
- **Command:** `.\.venv\Scripts\python.exe -m pytest tests/test_correlation.py -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Observed Counts:** **38 passed, 0 failed, 1 warning** (in 2.99s)

### 2. Full Non-Live Backend Unit & Regression Suite
- **Command:** `.\.venv\Scripts\python.exe -m pytest -m "not live" -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Observed Counts:** **101 passed, 4 deselected, 0 failed, 1 warning** (in 14.01s)

### 3. Live SIEM Connectors Suite
- **Command:** `.\.venv\Scripts\python.exe -m pytest -m live -v`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\backend`
- **Exit Code:** `0`
- **Observed Counts:** **4 passed, 101 deselected, 0 failed, 1 warning** (in 18.89s)
  - `test_live_wazuh_client_authentication`: PASSED
  - `test_live_opensearch_client_alerts_search`: PASSED
  - `test_live_api_alerts_endpoint`: PASSED
  - `test_live_api_investigate_endpoint`: PASSED (live local Ollama `llama3.2:3b` execution)

### 4. Frontend Code Quality (`oxlint`)
- **Command:** `npm run lint`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\frontend`
- **Exit Code:** `0`
- **Result:** **0 errors, 0 warnings** (10 files inspected)

### 5. Frontend Production Bundle Build
- **Command:** `npm run build` (`tsc -b && vite build`)
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\frontend`
- **Exit Code:** `0`
- **Result:** Built successfully: `dist/index.html` (0.78 kB), `dist/assets/index-3dLGZSgM.js` (258.01 kB gzip: 77.72 kB).

### 6. Frontend Client & Security Contract Checks
- **Command:** `node tests/validate_client.js`
- **Working Directory:** `F:\MY Project\WAZUH-OLLAMA-SIEM\frontend`
- **Exit Code:** `0`
- **Result:** **All 9 contract and security checks passed.**

---

## 11. Files Changed and Purpose

| File | Type | Changes & Purpose |
| :--- | :--- | :--- |
| `backend/app/api/deps.py` | Python Dependencies | Added `secrets.compare_digest` for constant-time comparison in `verify_api_auth`. Added whitespace trimming and fail-closed handling for empty/whitespace tokens. |
| `backend/app/core/config.py` | Python Config | Added `is_api_auth_configured()` helper to `Settings`. |
| `backend/app/main.py` | Python Entrypoint | Added startup error log in `lifespan` when `API_AUTH_REQUIRED=True` but no valid `API_KEY` is configured. |
| `backend/tests/test_correlation.py` | Python Tests | Updated and expanded route-level auth tests to cover all sensitive endpoints (`GET /alerts`, `GET /alerts/{id}`, `POST /alerts/{id}/investigate`), whitespace key fail-closed behavior, and public health probe persistence. |

---

## 12. Git Before/After State and User Data Safety

### Git Status (`git status --short`):
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
?? PHASE_4B_SEMANTIC_GROUNDING_AUDIT_REPORT.md
?? PHASE_4C_OLLAMA_STORAGE_FORENSIC_AUDIT.md
?? PHASE_5A_BASELINE_PORTS_AND_MATRIX_A_REPORT.md
?? PHASE_5B_PORTS_AUTH_AND_MATRIX_A_RECHECK_REPORT.md
?? PHASE_5_END_TO_END_SECURITY_RELIABILITY_AUDIT_REPORT.md
?? PHASE_6A_1_CORRELATION_RELIABILITY_AUDIT_REPORT.md
?? PHASE_6A_2_FINAL_RELIABILITY_SECURITY_AUDIT_REPORT.md
?? PHASE_6A_3_API_AUTH_RELEASE_READINESS_REPORT.md
?? PHASE_6A_CORRELATION_QUALITY_AUDIT_REPORT.md
?? PHASE_6_RELATED_EVENT_CORRELATION_AUDIT_REPORT.md
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
?? wazuh-ollama-siem-specs/
```

### Safety Confirmations:
- **Zero Commits Created:** Working tree preserved on `main`.
- **Infrastructure Preserved:** `F:\MY Project\wazuh-docker` remains untouched.
- **No Data Deletion or Stashing:** All user files, prior audit reports, and untracked artifacts remain intact.

---

## 13. Remaining Risks and Release Recommendations

### Remaining Risks
1. **Unauthenticated Local Access in Default Mode:** If another user or unprivileged process has access to the local workstation, they can access `http://127.0.0.1:8001/api/v1/alerts` when running in default development mode.
2. **Absence of RBAC:** Any caller with the Bearer token has equal authority to query all alerts and invoke LLM investigations.

### Release Recommendations
1. **Local Deployment Approval:** The application is cleared for local single-user deployment on loopback (`127.0.0.1`).
2. **Phase 7 Architectural Decision:** Before exposing the platform beyond loopback, implement an authentication gateway:
   - *Option A:* OIDC / OAuth2 proxy (e.g. Keycloak / Authentik) with HTTP-only session cookies.
   - *Option B:* Reverse proxy with mutual TLS (mTLS) or HTTP Basic Authentication.
   - *Option C:* Dedicated analyst login UI with backend session token issuance and role-based permissions (Tier 1 vs Lead Analyst).
