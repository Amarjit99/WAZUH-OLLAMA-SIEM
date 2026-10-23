# Product Requirements Document (PRD) — Phase 7.5
## Audit Retention Checkpoint Architecture & Integrity Verification

**Document ID:** `specs/PHASE_7_5_PRD.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION (Implementation Authorization Withheld)  
**Phase:** 7.5  
**Target Platform:** Local Single-User Host, FastAPI Backend, SQLite WAL  
**Authors:** SOC Security Architecture & Antigravity Security Agent  
**Date:** October 20, 2026  

---

## 1. Problem Statement & Business/Security Rationale

### 1.1 The Hash-Chain Truncation Paradox
Under ADR-011 and ADR-012, the platform establishes two independent retention policies:
1. **Investigation Retention:** 90 days (`INVESTIGATION_RETENTION_DAYS=90`), where investigations and associated evidence are pruned via cascading deletions. (Implemented and verified in Phase 7.4).
2. **Audit Event Retention:** 365 days (`AUDIT_RETENTION_DAYS=365`), where audit records must be retained for at least one year to satisfy SOC compliance, forensic accountability, and security standards.

The existing audit persistence layer (`AuditEvent` model and `AuditRepository`) links every audit event into a strictly sequential SHA-256 cryptographic hash chain:
$$h_0 = \text{GENESIS\_HASH} = \text{"0"}\times 64$$
$$h_i = \text{SHA256}(\text{CanonicalJSON}(e_i) \,\|\, h_{i-1})$$

The verification algorithm (`verify_chain_integrity()`) starts at $i=0$ with $\text{GENESIS\_HASH}$ and recalculates each hash in sequence up to the latest event.

**The Paradox:** When audit records exceed 365 days, physically deleting the expired prefix ($e_0, \dots, e_k$) from the `audit_events` table permanently breaks verification for all surviving records ($e_{k+1}, \dots, e_N$). The earliest surviving record $e_{k+1}$ has `previous_hash` $= h_k$. Because record $e_k$ was deleted from the database, $h_k$ cannot be verified against genesis, causing `verify_chain_integrity()` to fail immediately at index 0.

### 1.2 The Failure of Naive Pruning
Attempting to prune expired audit events without an architectural integrity anchor produces two unacceptable outcomes:
1. **Silent Verification Failure:** Legitimate audit records are reported as tampered or broken because their predecessor is missing.
2. **Loss of Forensic Non-Repudiation:** Analysts, auditors, or automated compliance tools can no longer verify whether surviving records were altered or whether records were silently deleted out of sequence.

### 1.3 Objective of Phase 7.5
Design a verifiable, crash-safe, and deterministic checkpoint architecture that:
- Allows expired audit events ($> 365$ days) to be safely archived and pruned from the operational database.
- Preserves mathematical proof that surviving audit records ($e_{k+1}, \dots, e_N$) remain anchored to a verified cryptographic checkpoint.
- Enables external or offline verification of archived historical records ($e_0, \dots, e_k$) against the same checkpoint.
- Leaves audit physical pruning **safely blocked** until the design is formally reviewed, approved, and authorized for implementation.

---

## 2. Retention Policy vs. Physical Deletion Policy

A critical requirement of this PRD is establishing the distinction between **Retention Policy** and **Physical Deletion Policy**:

| Dimension | Audit Retention Policy | Physical Deletion Policy |
|---|---|---|
| **Definition** | The legal, operational, and regulatory mandate specifying how long audit records must remain available and verifiable. | The technical mechanism by which rows are removed from the active SQLite database file to reclaim storage and bound query overhead. |
| **Duration** | Minimum 365 days from event timestamp (`AUDIT_RETENTION_DAYS=365`). | Triggered only after records exceed 365 days **AND** a verifiable checkpoint + export archive has been validated. |
| **Prerequisites** | Events are appended continuously in real-time. | 1. Active checkpoint created.<br>2. Archive file written to cold storage.<br>3. Archive verified against checkpoint digest.<br>4. Checkpoint committed to database.<br>5. Dry-run verified. |
| **Failure Mode** | Fail-secure: If checkpointing fails, **NO records are deleted**. Records remain in operational storage indefinitely rather than being unanchored. | Fail-closed: If verification fails, pruning halts immediately. |

---

## 3. Functional Requirements

### FR-1: Checkpoint Generation
- The system must provide a mechanism to compute a cryptographic checkpoint over a contiguous, ordered range of audit events $[e_{\text{start}}, e_{\text{end}}]$.
- The checkpoint must capture:
  - Sequence number of the checkpoint.
  - Digest of the immediately preceding checkpoint (forming a checkpoint meta-chain).
  - Exact event range: `first_audit_id`, `last_audit_id`, `first_timestamp`, `last_timestamp`.
  - Number of events enclosed.
  - Final event hash of the enclosed range ($h_{\text{end}}$), which serves as the anchor for subsequent retained records.
  - Cumulative Merkle tree root or rolling digest of all enclosed events to allow independent proof-of-inclusion for individual archived events.

### FR-2: Active Suffix Verification
- The verification engine must be capable of verifying the active, retained audit trail starting from a specified trusted checkpoint anchor:
  $$\text{VerifySuffix}(\text{Checkpoint}_k, [e_{k+1}, \dots, e_N])$$
- The verifier must confirm:
  1. $e_{k+1}.\text{previous\_hash} == \text{Checkpoint}_k.\text{last\_event\_hash}$.
  2. Each subsequent record $e_j$ correctly chains to $e_{j-1}$.
  3. Every record's `event_hash` matches its recomputed canonical SHA-256 hash.

### FR-3: Archive Verification
- The system must be capable of verifying an offline or archived block of audit events ($[e_0, \dots, e_k]$) against the checkpoint metadata without requiring those events to exist in the active SQLite database.

### FR-4: Checkpoint Meta-Chain Verification
- Checkpoints themselves must be chained: Checkpoint $m$ must reference the cryptographic digest of Checkpoint $m-1$, starting from a defined `GENESIS_CHECKPOINT_HASH`.
- An operator or automated verifier can verify all historical checkpoints from genesis to the active checkpoint.

### FR-5: Atomicity and Crash Recovery
- Checkpoint creation, archive export, and subsequent prefix pruning must be strictly atomic or idempotent across restarts.
- If the backend process crashes or loses power during checkpoint generation or pruning, the system must recover automatically to a consistent state upon next startup without leaving orphaned records, broken links, or duplicate checkpoints.

### FR-6: Dry-Run and Candidate Estimation
- The system must maintain a dry-run capability that reports:
  - Number of audit events eligible for archival and pruning ($> 365$ days old).
  - Current active checkpoints and their sequence numbers.
  - Exact cutoff timestamps.
  - Verification status of the active chain against the current checkpoint.
  - Zero modifications to data during dry-run.

### FR-7: Explicit Verification Error Categorization
When verification fails, the system must report a structured error code and diagnostic payload rather than a generic boolean:
- `UNVERIFIED_EMPTY_CHAIN`: Chain is unexpectedly empty or uninitialized.
- `UNVERIFIED_GAP_DETECTED`: A gap exists between the checkpoint anchor and the first retained event.
- `PREDECESSOR_MISMATCH`: An event's `previous_hash` does not match the predecessor's `event_hash`.
- `TAMPER_DETECTED`: An event's stored `event_hash` does not match the recomputed canonical SHA-256 digest.
- `ORDERING_VIOLATION`: Event timestamps or monotonic sequence IDs are out of order.
- `CHECKPOINT_INVALID`: A checkpoint's internal digest or signature does not match its contents.
- `CHECKPOINT_META_CHAIN_BROKEN`: A checkpoint's `previous_checkpoint_hash` does not match the prior checkpoint.
- `TRUST_ANCHOR_UNAVAILABLE`: The external public key, DPAPI secret, or signature verification key is unreachable.

---

## 4. Non-Functional Requirements

### NFR-1: Cryptographic Integrity
- All digests must use SHA-256 (FIPS 180-4).
- Checkpoint signatures (if enabled) must use Ed25519 (RFC 8032) or HMAC-SHA256 (RFC 2104).
- Serialization must use RFC 8785 Canonical JSON with strict ISO 8601 UTC microsecond formatting.

### NFR-2: Durability & SQLite WAL Compatibility
- The checkpoint architecture must operate cleanly within the existing single-writer SQLite WAL concurrency model.
- Checkpoint operations must not run long-running write transactions that block real-time investigation persistence or cause SQLite `busy_timeout` (5000ms) errors.

### NFR-3: Zero Runtime Overhead on Normal Ingestion
- Real-time logging via `AuditRepository.log_event()` must remain fast ($< 5\text{ ms}$). Normal event insertion must only read the latest event hash and append the new row, without traversing checkpoints.

### NFR-4: Privacy and Minimization
- Checkpoint records and verification summaries must **never** store sensitive secrets, API keys, passwords, bearer tokens, or raw OpenSearch document bodies.
- Metadata JSON fields must be sanitized prior to hashing and checkpoint inclusion.

### NFR-5: Fail-Closed Security Posture
- If an audit verification check encounters any ambiguity, missing data, or corrupted hash, it must **fail closed** by marking the audit status as `FAILED` or `UNVERIFIED`.
- Under no circumstances may the system report an unverified or skipped verification as `VALID`.

---

## 5. Scope & Trust Assumptions

### 5.1 In-Scope
- Mathematical specification of the checkpoint record and hashing protocol.
- Comparison of architectural options for local and hybrid trust anchoring.
- Identification of threat models, residual risks, and failure scenarios.
- Definition of the future test plan and implementation phases.

### 5.2 Out-of-Scope (Phase 7.5)
- Code implementation in backend or frontend.
- Database schema migrations or table creation.
- Execution of destructive cleanup or data deletion.
- Integration of remote cloud services (AWS S3, Azure Blob, Google Cloud Storage) or third-party SaaS logging.
- Multi-user RBAC redesign.

### 5.3 Trust Boundary Assumptions
- **Host Workstation:** The system runs locally on a Windows host with loopback-only bindings (`127.0.0.1`).
- **Analyst Boundary:** The authenticated SOC analyst interacts via browser with Bearer token authentication.
- **Privileged Attacker Constraint:** As formally recognized in ADR-012, an attacker with full local administrator access or direct OS write access to the SQLite file can overwrite both data rows and local hash values. True non-repudiation against a root/admin attacker requires an external trust anchor (e.g., Windows DPAPI/TPM, offline signing key, or external append-only log).

---

## 6. Acceptance Criteria

Phase 7.5 PRD is satisfied when:
1. The mathematical and functional requirements for audit checkpointing and suffix verification are completely defined.
2. The distinction between 365-day retention policy and physical deletion policy is explicitly established.
3. Structured verification failure codes and fail-closed requirements are documented.
4. All non-functional constraints regarding SQLite WAL, performance, privacy, and determinism are codified.
5. All design artifacts confirm that audit pruning remains **blocked** until formal approval is granted.
