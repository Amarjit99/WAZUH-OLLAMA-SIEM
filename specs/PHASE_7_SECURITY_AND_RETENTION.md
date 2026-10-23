# Security, Privacy & Retention Architecture — Phase 7: Investigation Persistence

**Document ID:** `specs/PHASE_7_SECURITY_AND_RETENTION.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** Threat Modeling, Encryption at Rest, Data Minimization, Tamper-Evidence & Retention Policies  
**Target Platform:** Local Single-User Host, FastAPI Backend, SQLite WAL / PostgreSQL  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. Threat Model & Trust Boundaries

The introduction of persistent storage adds a new data-at-rest asset to the system threat model.

```
+-------------------------------------------------------------------------+
| WORKSTATION BOUNDARY (Windows Host)                                     |
|                                                                         |
|  [Untrusted Network]                                                    |
|           |                                                             |
|           x (BLOCKED: Loopback-only binding 127.0.0.1)                  |
|                                                                         |
|  [Authenticated Browser (React UI)]                                     |
|           |                                                             |
|      HTTP | Bearer Token Auth (secrets.compare_digest)                  |
|           v                                                             |
|  [FastAPI Backend Core (Process Owner: Analyst User)]                   |
|           |                                                             |
|           | Parameterized ORM Queries (SQLAlchemy Core/ORM)             |
|           v                                                             |
|  [NTFS Filesystem: Restricted ACLs]                                     |
|       `data/siem_history.db`                                            |
|       (Permissions: System & Current User ONLY)                        |
|                                                                         |
+-------------------------------------------------------------------------+
```

### 1.1 Threat Matrix & Mitigations

| Threat Vector | Risk Description | Architectural Mitigation |
|---|---|---|
| **SQL Injection (SQLi)** | Attacker inputs malicious payload via alert fields (e.g. `username`, `rule_id`) targeting history queries. | **100% Parameterized Queries:** All database interactions execute via SQLAlchemy 2.0 ORM/Core. String concatenation for SQL statements is strictly prohibited. |
| **Local File Snooping** | Unprivileged local OS user attempts to read SQLite database file or backup archives. | **OS-Level NTFS ACLs:** Database directory and file permissions restricted via `icacls` to the application runner and `NT AUTHORITY\SYSTEM`. |
| **Credential & Secret Leakage** | Database unintentionally captures API keys, JWTs, or passwords embedded in raw logs. | **Pre-Ingestion Sanitization:** All evidence records pass through `EvidenceService` redaction rules (redacting `password`, `token`, `secret`, `bearer`) before database insertion. |
| **Audit Trail Tampering** | Local user or attacker modifies historical audit records to conceal investigative activity. | **Append-Only Application Model:** `audit_events` table lacks update/delete application endpoints. Tamper-evident hash chaining provided for audit continuity. |
| **Denial of Service (Disk Exhaustion)** | Rapid execution of investigations consumes all host disk space, risking system crash. | **Proactive Disk Quota Guard:** Backend checks available host disk space before launching investigations. Rejects with HTTP 507 if $< 500\text{ MB}$ free. |
| **Path Traversal via Export** | Malicious filename or format payload attempts to write export files outside designated folders. | **In-Memory Streaming:** Exports stream directly in the HTTP response (`Content-Disposition: attachment; filename="..."`) without staging unvalidated files on the host filesystem. |

### 1.2 Filesystem ACL Platform Assumptions: Windows Host vs. WSL2

> [!CAUTION]
> File security assumptions depend heavily on the Python runtime execution context:
> 1. **Native Windows Python Execution (Current Project Baseline):**
>    - The database file is located at `data/siem_history.db` on an NTFS drive.
>    - Permissions must be locked down using Windows `icacls` to restrict access strictly to the executing user account and `NT AUTHORITY\SYSTEM`:
>      ```cmd
>      icacls data /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F"
>      ```
> 2. **WSL2 (Windows Subsystem for Linux) Execution:**
>    - If the backend is executed inside a WSL2 Linux container or distro accessing the Windows host filesystem via `/mnt/f/...`, standard Linux `chmod` commands **do not** enforce POSIX permissions on NTFS mounts unless DrvFs is mounted with `metadata` options enabled in `/etc/wsl.conf`.
>    - In WSL2 environments without metadata support, files inherit global host permissions (`0777`).
>    - **Requirement:** The deployment verification script must explicitly verify whether the running process has exclusive file ownership before opening the SQLite database file.

---

## 2. At-Rest Encryption & Realistic Platform Assumptions

### 2.1 Encryption Reality Check
> [!IMPORTANT]
> Neither standard SQLite nor default PostgreSQL provides automatic, transparent encryption at rest. Storing database files on standard storage writes plaintext pages unless explicit cryptographic controls are established.

### 2.2 Realistic Host-Level Encryption Strategy
1. **Host Operating System Encryption (BitLocker / LUKS):**
   - The primary and strongest control for local workstation deployments is full-volume encryption (Windows BitLocker). This protects the database file against offline physical theft of the storage drive.
2. **Application-Level Field Encryption (Optional Sensitive Columns):**
   - When required for compliance, sensitive text fields (`summary`, `analyst_notes`) can be encrypted prior to insertion using authenticated AES-256-GCM keys managed via DPAPI (Windows Data Protection API) or a dedicated local encryption key in `.env`.
3. **Database File Encryption (SQLCipher):**
   - SQLCipher provides 256-bit AES page encryption for SQLite. However, SQLCipher requires custom native binary compilation and third-party driver dependencies. For Phase 7, standard SQLite WAL with OS-level NTFS ACLs and BitLocker is recommended, retaining SQLCipher as an evaluation option.

---

## 3. Audit Event Integrity & Tamper-Evidence Options

### 3.1 Differentiating Tamper-Evidence from True Immutability
- **True Immutability:** Requires write-once-read-many (WORM) hardware storage, hardware security modules (HSM), or cryptographically signed external ledgers (e.g., remote append-only syslog servers or AWS S3 Object Lock).
- **Tamper-Evident Application Logging:** Achieved on local storage by computing a cryptographic SHA-256 hash chain across audit entries:
  $$\text{Hash}_n = \text{SHA-256}(\text{CanonicalJSON}(\text{AuditID}_n, \text{Timestamp}_n, \text{Actor}_n, \text{Action}_n, \text{ResourceType}_n, \text{ResourceID}_n, \text{Outcome}_n, \text{RequestID}_n, \text{Metadata}_n) \,\|\, \text{Hash}_{n-1})$$
- **Genesis Hash:** The first audit record uses a fixed genesis hash:
  $$\text{Hash}_0 = \text{'0000000000000000000000000000000000000000000000000000000000000000'} \text{ (64 zeros)}$$
- **Canonical Serialization Contract:** Fields MUST be serialized using canonical JSON (RFC 8785) or strict deterministic JSON serialization (`json.dumps(obj, sort_keys=True, separators=(',', ':'))`) with timestamps formatted in ISO 8601 UTC to prevent hash mismatches from whitespace or key ordering.
- **Critical Threat Limitation:**
  > [!WARNING]
  > A hash chain stored entirely inside the same writable SQLite file (`siem_history.db`) detects **accidental corruption** and **uncoordinated tampering**. However, it **cannot** resist a privileged attacker or local process owner who has direct write access to the database file, as such an attacker can alter an audit row and mathematically recompute the SHA-256 hash chain forward to the tip!
  > True non-repudiation requires an external trust anchor (e.g. HMAC key stored in Windows DPAPI/TPM, or streaming audit events to an external write-only syslog server). This requirement is formally recorded as an unresolved decision pending enterprise review.

### 3.2 Audit Retention Guarantee & Concurrency
- `audit_events` records are **never** deleted by user-initiated investigation purge operations.
- Audit table rows persist for a minimum of 365 days, independent of the 90-day investigation retention cycle.
- **Write Serialization:** Audit record creation must occur within the same atomic database transaction as the recorded operation. Reading the tail hash (`Hash_{n-1}`) and inserting `Hash_n` requires transaction serialization to prevent fork branching in the hash chain under concurrent requests.

---

## 4. Retention & Deletion Policy

```
[Day 0] Investigation Created & Evidence Snapshot Stored
   |
   +---> Active Operational History (Searchable via /investigations)
   |
[Day 90] Scheduled Retention Pruning (`INVESTIGATION_RETENTION_DAYS`)
   |     - Bounded batch deletion (100 rows/batch) via CASCADE.
   |     - Audit Event `INVESTIGATION_EXPIRED_PRUNED` logged in `audit_events`.
   |     - WAL checkpointing (`PRAGMA wal_checkpoint(TRUNCATE)`).
   |
[Day 365] Audit Log Retention Lifecycle (Independent Archive)
```

### 4.1 Bounded Batch Pruning Job
To prevent SQLite database locks, memory exhaustion, and WAL file explosion when purging thousands of historical records:
1. **Bounded Batching:** Cleanup must execute in bounded batches:
   ```sql
   DELETE FROM investigations
   WHERE investigation_id IN (
       SELECT investigation_id FROM investigations
       WHERE created_at < :expiration_cutoff
       LIMIT 100
   );
   ```
2. **Batch Pacing:** The maintenance task commits each batch, pauses for 100ms to allow concurrent reads/writes, and repeats until zero records remain.
3. **WAL Checkpointing:** Following cleanup completion, the service executes `PRAGMA wal_checkpoint(TRUNCATE);` to reclaim physical disk space.

### 4.2 WAL and Backup Retention Considerations
- Purged records may persist in active WAL files (`siem_history.db-wal`) or offline backup copies until overwritten.
- Backup retention policies must mirror the 90-day lifecycle; historical backup archives older than 90 days must be securely scrubbed or encrypted to prevent data retention leakage.

---

## 5. Sensitive Evidence Minimization & Redaction

1. **Allowlisted Fields Only:** The database schema rejects arbitrary document structures, persisting only the explicit allowlist defined in `PHASE_7_DATABASE_SCHEMA.md`.
2. **Regex Secret Scrubbing:** Prior to persisting evidence items or model summaries, the backend applies standard credential scrubbers matching:
   - AWS access keys (`AKIA[0-9A-Z]{16}`)
   - Generic API tokens and Bearer credentials
   - Private key headers (`-----BEGIN [A-Z]+ PRIVATE KEY-----`)
   - Password key-value pairs in URLs or query strings.
3. **Untrusted Data Tagging:** All stored evidence fields are treated as untrusted strings, requiring strict HTML escaping upon frontend rendering.
