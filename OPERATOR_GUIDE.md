# Wazuh + Ollama Local AI SIEM — Operator Guide

**Version:** 1.0 (Phase 11.0 Controlled Local Release)  
**Classification:** Internal Security Operations Manual  
**Target Platform:** Microsoft Windows (x64) with native CNG/DPAPI  

---

## 1. Overview

### 1.1 Purpose and Scope
The **Wazuh + Ollama SIEM Platform** is a real, locally hosted, AI-assisted security investigation and threat hunting platform. It integrates:
- **Wazuh Manager:** Authoritative endpoint detection and security monitoring.
- **Wazuh Indexer / OpenSearch:** High-throughput security alert indexing and query retrieval.
- **Ollama:** Local, private Large Language Model inference (e.g. `llama3.2:3b`) without external SaaS telemetry leakage.
- **FastAPI Backend (Python 3.11+):** Business logic, query bounds, cryptographic audit logging, and DPAPI-protected backup management.
- **React / TypeScript Analyst UI:** Responsive, single-pane SOC dashboard for telemetry monitoring, alert filtering, and advisory investigation review.

### 1.2 Read-Only SIEM Security Posture
In accordance with **ADR-003**, this initial release operates in a **strictly read-only posture**. The platform performs zero automated remediation actions:
- No automated firewall or IP blocking.
- No automated account suspension or active response command execution.
- No remote shell execution.
- Any future active containment workflow requires explicit secondary authorization and manual analyst confirmation.

### 1.3 Detection Authority vs. AI Advisory Role
In accordance with **ADR-001**:
- **Wazuh is the sole authoritative detector of record.** Alert severity levels, rule IDs, rule descriptions, timestamps, and agent identifiers originate from Wazuh and are strictly immutable.
- **Ollama operates strictly as an analyst assistant.** Model output is probabilistic and advisory. AI summaries cannot alter alert severity or mark alerts as false positives without human verification.

### 1.4 Supported Platform & Native Cryptography
- **Supported OS:** Microsoft Windows 10/11 (64-bit) or Windows Server 2022+.
- **Cryptographic Engine:** Uses native Windows Cryptography Next Generation (**CNG** via `bcrypt.dll`) for hardware-accelerated **AES-256-GCM** authenticated encryption.
- **Key Protection:** Uses Windows Data Protection API (**DPAPI** via `crypt32.dll`) bound to the local Windows user security context.
- **Non-Windows Environments:** Linux and macOS environments are **not supported** for encrypted backup operations. The platform strictly fails closed rather than falling back to unauthenticated or plaintext key storage.

### 1.5 Architecture & Network Boundaries
```
+-------------------------------------------------------------+
|                     Analyst Browser                         |
|               (http://127.0.0.1:5174)                       |
+------------------------------+------------------------------+
                               | Local Loopback CORS
                               v
+-------------------------------------------------------------+
|                 FastAPI Backend Server                      |
|               (http://127.0.0.1:8001)                       |
+--------+--------------------+--------------------+----------+
         | Strict TLS         | Strict TLS         | HTTP
         v                    v                    v
+------------------+ +------------------+ +------------------+
|  Wazuh Manager   | |  Wazuh Indexer   | |  Ollama Service  |
|  (Port 55000)    | |  OpenSearch:9200 | |  (Port 11434)    |
+------------------+ +------------------+ +------------------+
```
All platform services bind exclusively to loopback (`127.0.0.1`). No ports are exposed to external network interfaces.

---

## 2. Installation & Prerequisites

### 2.1 Software Prerequisites
Verify the following runtime software is installed on the host machine:
1. **Windows PowerShell 5.1+** or **PowerShell 7+**
2. **Python 3.11+** (managed via `uv`)
3. **uv (Astral)** package manager:
   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```
4. **Node.js (LTS >= 18.0.0)** and **npm (>= 9.0.0)**:
   ```powershell
   node --version
   npm --version
   ```
5. **Wazuh Infrastructure:** Running Wazuh Manager (55000) and Indexer (9200).
6. **Ollama:** Installed and serving locally on port 11434.

### 2.2 Reproducible Dependency Installation

#### Backend Setup
From the repository root, install backend dependencies using the frozen lockfile (`uv.lock`):
```powershell
cd backend
uv sync --frozen
cd ..
```

#### Frontend Setup
From the repository root, install frontend dependencies using the frozen lockfile (`package-lock.json`):
```powershell
cd frontend
npm ci
npm run build
cd ..
```

### 2.3 Configuration Setup
1. Copy the example configuration template to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
2. Open `.env` with a secure text editor and configure real operational parameters:
   - `WAZUH_API_URL`: Base URL (default `https://127.0.0.1:55000`).
   - `WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD`: Dedicated read-only API credentials.
   - `WAZUH_CA_CERT_PATH`: Absolute path to Wazuh Manager Root CA certificate (PEM format).
   - `OPENSEARCH_URL`: Base URL (default `https://127.0.0.1:9200`).
   - `OPENSEARCH_USERNAME` / `OPENSEARCH_PASSWORD`: Indexer read-only search credentials.
   - `OPENSEARCH_CA_CERT_PATH`: Absolute path to OpenSearch Root CA certificate.
   - `OLLAMA_MODEL`: Target model tag (e.g. `llama3.2:3b`).
   - `BACKUP_SCHEDULE_ENABLED`: Must remain `false` by default.

### 2.4 Certificate and TLS Setup
Strict TLS certificate verification is enforced across all upstream connectors.
- Never set TLS verification to false.
- Ensure the root certificates referenced in `WAZUH_CA_CERT_PATH` and `OPENSEARCH_CA_CERT_PATH` are valid and readable by the running Windows user account.

### 2.5 Ollama Model Verification
Confirm Ollama is running and the desired model is pulled locally:
```powershell
ollama list
```
If the configured model (e.g. `llama3.2:3b`) is missing:
```powershell
ollama pull llama3.2:3b
```

### 2.6 Database Initialization & Migrations
Initialize or verify the SQLite database schema using Alembic:
```powershell
cd backend
uv run alembic upgrade head
uv run alembic current
cd ..
```
Expected output:
```
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
20261021_0002 (head)
```

---

## 3. Daily Operation

### 3.1 Starting the Application
Launch all platform services using the controlled startup script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-local.ps1
```
The script will:
1. Verify Python, Node.js, and npm prerequisites.
2. Confirm port 8001 (Backend) and port 5174 (Frontend) are available.
3. Validate database migration state.
4. Launch backend and frontend with output logging to `logs/`.
5. Record process IDs to `run/*.pid` for reliable tracking.
6. Verify liveness via `http://127.0.0.1:8001/health/live`.

### 3.2 Stopping the Application
Gracefully terminate the application using the controlled shutdown script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/stop-local.ps1
```
The script stops *only* the processes recorded in `run/backend.pid` and `run/frontend.pid`. It never kills unrelated applications, Docker containers, or system processes.

### 3.3 Dashboard Navigation
Once started, navigate to:
```
http://127.0.0.1:5174
```
Key UI Components:
- **Telemetry Bar:** Displays real-time live probe status for Wazuh Manager API, OpenSearch Indexer, Ollama Inference Engine, Database Backups, and Audit Chain Integrity.
- **Alert Filtering:** Filter by time window (past 1h to 24h), minimum severity level (0–15), Rule ID, Hostname, and Source IP.
- **Alert Details Modal:** Click any alert row to view raw and normalized metadata without modifying state.
- **Investigate with AI:** Trigger bounded analysis on a selected alert.
- **Investigation History Tab:** View chronological records of completed, failed, or cancelled investigations.

### 3.4 Health Telemetry Endpoints
Operators can query backend health programmatically:
- **Liveness:** `GET http://127.0.0.1:8001/health/live` (returns HTTP 200 `{"status": "ok"}`).
- **Readiness:** `GET http://127.0.0.1:8001/health/ready` (evaluates live upstream dependencies).
- **Backup Subsystem:** `GET http://127.0.0.1:8001/api/v1/health/backup` (verifies DPAPI key accessibility and backup directory writeability).
- **Audit Chain Integrity:** `GET http://127.0.0.1:8001/api/v1/health/audit-chain` (verifies SHA-256 sequential hash chain from genesis).

---

## 4. Backup, Cryptography, and Disaster Recovery

### 4.1 AES-256-GCM Encrypted Backup Behavior
Backups use native Windows CNG `BCryptEncrypt` / `BCryptDecrypt` with:
- **Cipher:** Authenticated AES-256-GCM.
- **Nonce:** Unique 96-bit cryptographically secure random nonce (`os.urandom(12)`) per backup. Nonces are never reused.
- **Tag:** 128-bit authentication tag protecting both ciphertext and authenticated header metadata (AAD).
- **Integrity Digest:** Plaintext SHA-256 digest embedded in the authenticated header.
- **Container Format:** Custom versioned container header (`SIEM_ENC`, uint16 version 1, uint16 cipher ID 1).

### 4.2 Windows DPAPI Key Protection
The 256-bit Data Encryption Key (DEK) is protected using `CryptProtectData` (Windows DPAPI) with custom entropy.
- **Security Boundary:** The key file (`backend/data/keys/backup_encryption_key.dpapi`) is tied to the **local Windows user profile**.
- **Fail-Closed Policy:** If the key file is missing, corrupted, or cannot be decrypted by DPAPI, the system **strictly fails closed** with `BackupKeyUnavailableError`.
- **CRITICAL:** The application **never regenerates a missing key automatically**. Regenerating a key would permanently strand and make all existing backups unrecoverable.

### 4.3 Creating an Encrypted Backup Snapshot
To manually trigger a verified, encrypted backup snapshot:
```powershell
cd backend
uv run python -c "
import asyncio
from app.services.database_backup_service import DatabaseBackupService
svc = DatabaseBackupService()
header = asyncio.run(svc.create_encrypted_backup_snapshot())
print(f'Backup created successfully: {header.plaintext_size} bytes, Key ID: {header.key_id}')
"
cd ..
```
The resulting encrypted snapshot will be placed in `backend/data/backups/siem_backup_<timestamp>_<hash>.enc.db`.

### 4.4 Verifying and Restoring Backups
Backups must **never overwrite the active live database** during routine drills.
To test restore drill integrity into an isolated drill directory:
```powershell
cd backend
uv run python -c "
import asyncio
from pathlib import Path
from app.services.database_backup_service import DatabaseBackupService
svc = DatabaseBackupService()
drill_target = Path('data/drill/siem_restored_drill.db')
header = asyncio.run(svc.restore_encrypted_backup_snapshot(
    backup_file_path=Path('data/backups/siem_backup_<timestamp>_<hash>.enc.db'),
    target_database_path=drill_target,
    overwrite=True
))
print('Restore drill passed. Verified SHA-256 and SQLite integrity check.')
"
cd ..
```

### 4.5 Offline Disaster-Recovery Key Export and Import
In a catastrophic disaster where the host Windows machine or user profile is lost, DPAPI-protected keys cannot be decrypted directly on a new host. The platform provides an authorized, offline disaster recovery protocol using **PBKDF2-HMAC-SHA256 (600,000 iterations)** and **AES-256-GCM**.

#### Offline Key Export (Authorized Operator Only)
*Never execute this on an unencrypted or public terminal. Use a strong passphrase (minimum 16 characters).*
```powershell
cd backend
uv run python -c "
from pathlib import Path
from app.core.backup_crypto import BackupKeyManager
km = BackupKeyManager()
# Replace with secure, ephemeral operator input in production
passphrase = 'EXAMPLE_MINIMUM_16_CHAR_PASSPHRASE_REPLACE_ME'
km.export_disaster_recovery_key(
    passphrase=passphrase,
    output_recovery_path=Path('data/keys/backup_recovery_token.rec')
)
print('Exported offline recovery token.')
"
cd ..
```
Store `backup_recovery_token.rec` in an approved offline, air-gapped physical vault.

#### Offline Key Import (New Machine Restoration)
To restore the DEK onto a newly provisioned Windows host under the new Windows user profile:
```powershell
cd backend
uv run python -c "
from pathlib import Path
from app.core.backup_crypto import BackupKeyManager
km = BackupKeyManager()
passphrase = 'EXAMPLE_MINIMUM_16_CHAR_PASSPHRASE_REPLACE_ME'
km.import_disaster_recovery_key(
    recovery_path=Path('data/keys/backup_recovery_token.rec'),
    passphrase=passphrase,
    target_dpapi_path=Path('data/keys/backup_encryption_key.dpapi')
)
print('Successfully imported recovery key into local host DPAPI.')
"
cd ..
```

### 4.6 Backup Scheduling & Retention Policy
- `BACKUP_SCHEDULE_ENABLED` is `false` by default. Background scheduled backups must remain disabled unless explicitly authorized by the project owner.
- Backup retention defaults to keeping valid snapshots in `backend/data/backups/`. Deletion of backups is manual and must follow institutional data retention guidelines.

---

## 5. Troubleshooting & Diagnostics

### 5.1 Backend Fails to Start
- **Symptom:** Backend process exits immediately; port 8001 does not respond.
- **Check Logs:** Inspect `logs/backend.log` and `logs/backend.err.log`.
- **Common Cause: Port Conflict:** Check `Get-NetTCPConnection -LocalPort 8001`.
- **Common Cause: Virtual Environment Missing:** Run `cd backend && uv sync --frozen`.
- **Common Cause: SQLite Lock:** If an unexpected crash left lock files, check for orphaned python processes via `Get-Process python`.

### 5.2 Frontend Fails to Start or Build
- **Symptom:** `npm run build` or `npm run dev` fails.
- **Check Logs:** Inspect `logs/frontend.err.log`.
- **Remediation:** Run `cd frontend && npm ci && npm run build`. Verify Node.js is >= 18.0.0.

### 5.3 Wazuh API Connection Failures
- **Symptom:** UI shows `Wazuh Manager API Unavailable` or HTTP 502.
- **Diagnostic:** Run:
  ```powershell
  cd backend
  uv run python -c "
  import asyncio
  from app.core.config import get_settings
  from app.services.wazuh_client import WazuhClient
  c = WazuhClient(get_settings())
  print(asyncio.run(c.check_health()))
  "
  ```
- **Remediation:** Check Wazuh Manager service status on the deployment host. Verify `WAZUH_CA_CERT_PATH` points to the correct root CA certificate. **Never disable TLS verification.**

### 5.4 OpenSearch Connection Failures
- **Symptom:** UI shows `Wazuh Indexer / OpenSearch Unavailable`.
- **Diagnostic:** Run:
  ```powershell
  cd backend
  uv run python -c "
  import asyncio
  from app.core.config import get_settings
  from app.services.opensearch_client import OpenSearchClient
  c = OpenSearchClient(get_settings())
  print(asyncio.run(c.check_health()))
  "
  ```
- **Remediation:** Verify OpenSearch cluster health. Confirm `OPENSEARCH_CA_CERT_PATH` is valid.

### 5.5 Ollama Unavailable or Model Missing
- **Symptom:** Investigation fails with `Local AI model service (Ollama) is unavailable`.
- **Diagnostic:** Test connectivity directly:
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags"
  ```
- **Remediation:** Run `ollama serve` if the service is stopped. Run `ollama pull llama3.2:3b` if the model is not listed in tags.

### 5.6 Backup Authentication or Decryption Failure
- **Symptom:** Decryption raises `BackupAuthenticationError` or tag mismatch.
- **Cause:** The backup container file was tampered with, truncated, or modified in transit.
- **Remediation:** Do not attempt to force-read corrupted ciphertext. Re-verify the source backup archive checksum.

### 5.7 Audit Chain Verification Failure
- **Symptom:** Telemetry shows `Audit Chain Degraded` or `/health/audit-chain` returns `chain_valid: false`.
- **Cause:** One or more rows in `audit_events` had its fields, hashes, or sequence numbers modified outside application transactions.
- **Investigation:** Run:
  ```powershell
  cd backend
  uv run python -c "
  import asyncio
  from app.repositories.audit_repository import AuditRepository
  repo = AuditRepository()
  res = asyncio.run(repo.verify_chain_integrity())
  print(res)
  "
  ```
  The output will pinpoint the exact `sequence_number` where the hash chain diverged.

---

## 6. Security Operations & Invariants

### 6.1 Secret Handling Rules
- Never commit `.env` or credentials to Git.
- Never print credentials or tokens to standard output or log files.
- Passwords and bearer tokens are wrapped in `pydantic.SecretStr` to prevent accidental serialization.

### 6.2 Audit Trail Immutability & Retention Invariant
- **Sequential Hash-Chain:** Every audit record contains a SHA-256 digest linking it cryptographically to the preceding record (`previous_hash`).
- **Audit Pruning Blocked:** In accordance with **ADR-012**, destructive deletion of audit records remains **hard-blocked**. Deleting historical audit rows breaks the hash chain from genesis. The retention service returns status `BLOCKED` for audit pruning until a formal verifiable archival checkpoint protocol is implemented.

### 6.3 Local Execution Boundaries
All network services bind strictly to loopback (`127.0.0.1`). The platform must never be bound to `0.0.0.0` or exposed across public networks without an authenticated reverse proxy, mutual TLS, and approved threat model update.

---

## 7. Release Upgrade & Rollback Procedures

### 7.1 Non-Destructive Upgrade Procedure
1. Gracefully stop running services:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/stop-local.ps1
   ```
2. Create an encrypted backup of the active database before upgrading:
   ```powershell
   cd backend
   uv run python -c "
   import asyncio
   from app.services.database_backup_service import DatabaseBackupService
   asyncio.run(DatabaseBackupService().create_encrypted_backup_snapshot())
   "
   cd ..
   ```
3. Extract the new release package into a clean staging directory.
4. Copy existing runtime data into the new release:
   - Copy `.env`
   - Copy `backend/data/siem_history.db`
   - Copy `backend/data/keys/`
   - Copy `backend/data/backups/`
5. Apply any new database migrations:
   ```powershell
   cd backend
   uv run alembic upgrade head
   cd ..
   ```
6. Verify release health:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/verify-release.ps1
   ```
7. Start the upgraded application:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/start-local.ps1
   ```

### 7.2 Safe Rollback Procedure
If an issue occurs after an upgrade:
1. Stop running services immediately using `scripts/stop-local.ps1`.
2. Do not downgrade the production database using automated destructive scripts.
3. Switch back to the previous application directory.
4. Point to the verified pre-upgrade database snapshot or restore it into `backend/data/siem_history.db`.
5. Verify DPAPI key presence in `backend/data/keys/backup_encryption_key.dpapi`.
6. Start the previous version using its `scripts/start-local.ps1`.

---

## 8. Release Limitations

1. **Controlled Local Operation:** Designed for single-operator local use. It is not an enterprise distributed SIEM cluster.
2. **Windows DPAPI Bound:** Key management requires Microsoft Windows. Cross-platform Linux/macOS execution for backups is not supported.
3. **Single-Node In-Memory Scheduler:** The optional backup scheduler runs as an in-process asyncio task on a single node.
4. **External Infrastructure Dependency:** Real-time alert ingestion and AI investigations depend on external Wazuh and Ollama services being accessible.
