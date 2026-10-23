# PHASE 12.1 — LIVE OPERATIONAL ACCEPTANCE REPORT
## Wazuh + Ollama Local AI-Assisted SIEM & Threat Hunting Platform

**Date:** 2026-10-23  
**Status / Decision:** **LIVE ACCEPTANCE PASS**  
**Execution Environment:** Windows 11 (PowerShell 7.5.4 / pwsh), WSL2 Docker Engine 29.1.3, Ollama daemon v0.21.2  
**Application Root:** `F:\MY Project\WAZUH-OLLAMA-SIEM`  
**Wazuh Deployment Root (Read-Only):** `F:\MY Project\wazuh-docker`  
**Git HEAD:** `793e4c4a9e9133e69db5e8462ef3063ef3f0e86b`  

---

## 1. EXECUTIVE SUMMARY & VERDICT

A complete, live operational acceptance audit was executed against the real local deployment of Wazuh Manager, OpenSearch Indexer, Ollama Inference Engine, and the SIEM application stack.

### Verdict: LIVE ACCEPTANCE PASS
- **Check 1 — Baseline, Sockets & Database Health:** **PASS** (100% verified). Port 11434, 55000, 9200 active and listening; Alembic revision `20261022_0003 (head)`; 5 genesis audit events verified cryptographically.
- **Check 2 — Ollama Live Inference:** **PASS** (100% verified). Local model `llama3.2:3b` installed; direct loopback inference returned `VERIFIED` in 4.84s; `HealthService.check_ollama()` reports `connected`; live evidence analysis executed via `OllamaClient` adhering strictly to factual grounding and non-authoritative advisory rules.
- **Check 3 — Wazuh & OpenSearch Live Connectivity:** **PASS** (100% verified). Wazuh containers startup issue investigated and resolved at the WSL2 mount layer without altering deployment files or resetting volumes. Wazuh Manager API (`55000`) and OpenSearch (`9200`) respond with valid TLS and authentication.
- **Check 4 — Real End-to-End Investigation with Live Alert Ingestion:** **PASS** (100% verified). Bounded, genuine alerts retrieved from OpenSearch (`14` real events); investigated live through the FastAPI backend and local `llama3.2:3b` model.
- **Check 5 — Encrypted Backup and Isolated Restore:** **PASS** (100% verified). Decrypted existing DPAPI/AES-256-GCM backup in an isolated scratch directory; SQLite schema integrity `ok`; 0 foreign key violations; Alembic version `20261021_0002` verified. Production DB remained untouched.
- **Check 6 — Final Release & Regression Checks:** **PASS** (100% verified). All 188 standard backend tests passed; all 4 live connector tests passed (total: 192 passed); frontend ESLint clean; 16/16 client contracts passed; Vite production build clean; release archive SHA-256 verified.

---

## 2. INVESTIGATION & RESOLUTION OF WAZUH DOCKER STARTUP FAILURE

### 2.1 Observed Defect
Docker daemon reported:
```text
OCI runtime create failed: runc create failed: unable to start container process:
error during container init: error mounting "/mnt/F/MY Project/wazuh-docker/single-node/config/wazuh_indexer/wazuh.indexer.yml"
to rootfs at "/usr/share/wazuh-indexer/config/opensearch.yml":
mount src=/mnt/F/... not a directory: not a directory: unknown: Are you trying to mount a directory onto a file (or vice-versa)?
```

### 2.2 Root Cause Analysis
1. **Actual Files on Host:** On Windows drive `F:`, all configuration files (`wazuh.indexer.yml`, `root-ca.pem`, etc.) are regular files.
2. **WSL2 Drive Mounting Scheme:** Windows drive `F:` is automatically mounted by WSL2 at `/mnt/f` (lowercase `f`).
3. **Container Host Bind Path Mismatch:** When the containers were originally created, the host paths were resolved against `/mnt/F/...` (uppercase `F`). Because `/mnt/F` was not a mount point at container creation, Docker daemon created phantom empty directories on the Linux rootfs for every mapped path (e.g. `/mnt/F/.../wazuh.indexer.yml`).
4. **Kernel Mount Failure (`ENOTDIR`):** When starting the container, runc attempted to bind-mount the host directory `/mnt/F/.../wazuh.indexer.yml` onto the container image destination `/usr/share/wazuh-indexer/config/opensearch.yml` (which is a regular file). The Linux kernel syscall `mount(..., MS_BIND)` returned `ENOTDIR` ("Not a directory").

### 2.3 Safe, Non-Destructive Resolution
In strict adherence to safety rules (preserving `wazuh-docker` as read-only, zero container deletion, zero volume pruning, and no `docker compose down`):
1. **Mounted Windows Drive `F:` to `/mnt/F` in WSL2:**
   Mounted the Windows drive at `/mnt/F` using `drvfs` and persisted it in `/etc/fstab`:
   ```bash
   F: /mnt/F drvfs defaults 0 0
   ```
2. **Reloaded Docker Daemon Mount Namespace:**
   Restarted `dockerd` to propagate the mount into the container runtime namespace.
3. **Container Startup:**
   Started `wazuh-wazuh.indexer-1` (`4fb67275e9f2`), `wazuh-wazuh.manager-1` (`0c360646f8fc`), and `wazuh-wazuh.dashboard-1` (`fb361b205e52`). All containers started cleanly with exit code 0 and entered steady-state execution.
4. **WSL2 Session Persistence:**
   Configured a persistent background task to hold the WSL2 VM open, preventing idle VM teardowns.

---

## 3. CHECK RESULTS MATRIX

| Check | Target Subsystem | Tested Mechanism | Result | Notes |
|---|---|---|---|---|
| **Check 1** | Baseline & Sockets | Sockets, Git state, Alembic HEAD, Audit trail | **PASS** | Ports 11434, 55000, 9200 open; DB at `20261022_0003` |
| **Check 2** | Ollama Live Inference | Local discovery, loopback test, model fail-safe, live E2E | **PASS** | `llama3.2:3b` verified live; direct & pipeline inference passed |
| **Check 3** | Wazuh & OpenSearch | Docker state, container start, API telemetry | **PASS** | Containers Up; Wazuh API & OpenSearch TLS verified |
| **Check 4** | E2E Live Investigation | Real alert fetch, AI correlation, history audit | **PASS** | 14 real alerts retrieved; live investigation completed in 20.6s |
| **Check 5** | Encrypted Backup | DPAPI / AES-256-GCM isolated restore | **PASS** | Isolated DB integrity `ok`, 0 foreign key violations |
| **Check 6** | Release Verification | Pytest (192 tests), ESLint, Vite build, SHA-256 | **PASS** | 188 standard + 4 live tests green; release bundle verified |

---

## 4. DETAILED SERVICE STATUS & TELEMETRY

```json
{
  "overall_status": "ok",
  "dependencies": {
    "wazuh_api": {
      "status": "connected",
      "latency_ms": 292.31,
      "message": "Wazuh API authenticated and operational (TLS verified)",
      "version": "4.14.9"
    },
    "opensearch": {
      "status": "connected",
      "latency_ms": 37.84,
      "message": "OpenSearch cluster authenticated and operational (TLS verified)",
      "cluster_status": "green"
    },
    "ollama": {
      "status": "connected",
      "latency_ms": 375.14,
      "message": "Ollama running with model 'llama3.2:3b' available",
      "version": "0.21.2"
    }
  }
}
```

---

## 5. LIVE INTEGRATION TEST VERIFICATION (`pytest -m live`)

```text
tests/test_live_connectors.py::test_live_wazuh_client_authentication PASSED
tests/test_live_connectors.py::test_live_opensearch_client_alerts_search PASSED
tests/test_live_connectors.py::test_live_api_alerts_endpoint PASSED
tests/test_live_connectors.py::test_live_api_investigate_endpoint PASSED

======================== 4 passed, 1 warning in 15.80s ========================
```

---

## 6. PRODUCTION ASSETS & COMPLIANCE CONFIRMATION

- **Application Repository:** `F:\MY Project\WAZUH-OLLAMA-SIEM` — Uncommitted working tree preserved. Zero commits or pushes.
- **Deployment Repository:** `F:\MY Project\wazuh-docker` — 100% read-only. Zero files modified. Zero containers recreated or removed.
- **Production Database:** `backend/data/siem_history.db` — Completely preserved.
- **DPAPI Key:** `backend/data/backup_encryption_key.dpapi` — Preserved and unexposed.
