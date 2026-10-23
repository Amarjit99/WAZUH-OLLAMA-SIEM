# PHASE 7.5 / 7.5A DOCUMENTATION AUDIT & ARCHITECTURE REPORT
## Audit Retention Checkpoint Architecture, DPAPI Signing & Integrity Verification

**Document ID:** `specs/PHASE_7_5_DOCUMENTATION_AUDIT_REPORT.md`  
**Phase:** 7.5 / 7.5A  
**Mode:** Documentation-First | Read-Only Inspection | Zero Data Deletion  
**Date:** October 20, 2026 (Updated in Phase 7.5A)  
**Status:** **PASS** (Architecture finalized; ADR-013 and Decision Register codified; Implementation strictly withheld; Audit pruning remains blocked)  
**Git Branch:** `main`  
**Git HEAD:** `793e4c4a9e9133e69db5e8462ef3063ef3f0e86b` (0 commits, 0 pushes)  
**Deployment Repository (`wazuh-docker`):** Strictly Untouched  

---

## 1. Executive Summary

Phase 7.5 and 7.5A conducted a thorough, read-only architectural design and security assessment to resolve the **Hash-Chain Truncation Paradox** identified during Phase 7.4.

Under ADR-011 and ADR-012, audit events must be retained for at least 365 days while maintaining an unbroken SHA-256 hash chain from `GENESIS_HASH`. However, physically deleting an expired prefix of audit records breaks the predecessor links for surviving events, causing verification to fail. In Phase 7.4, destructive audit pruning was safely blocked (`status="BLOCKED"`, `deleted_count=0`).

In Phase 7.5A, the architecture and governance records were finalized:
1. **Finalized ADR-013:** Designed for **Windows DPAPI-backed signing** (`HMAC-SHA256` or `ED25519`), configurable archive destination (`AUDIT_ARCHIVE_DIR`, defaulting to `data/archives/`), strict **fail-closed verification**, and complete offline/loopback independence. Marked as **`PROPOSED — PENDING EXPLICIT USER APPROVAL`**.
2. **Created Formal Decision Register (`specs/PHASE_7_5_DECISION_REGISTER.md`):** Recorded 6 explicit decisions covering signing mode, archive location, verification policy, retention safety, offline operation, and trust boundary scope.
3. **Updated Technical Architecture (`specs/PHASE_7_5_TRD.md`):** Detailed DPAPI key lifecycle (storage, rotation, backup, recovery), single-writer SQLite WAL transactions, path traversal guards, disk space pre-checks ($\ge 1\text{ GB}$), and explicit acceptance criteria.
4. **Enhanced Threat Model (`specs/PHASE_7_5_SECURITY_THREAT_MODEL.md`):** Expanded to 18 threat vectors, including deep DPAPI trust-boundary analysis, host administrator compromise realities, external trust anchor comparisons, and archive path traversal mitigations.
5. **Updated 12-Stage Implementation Plan (`specs/PHASE_7_5_IMPLEMENTATION_PLAN.md`):** Integrated DPAPI key generation, path traversal validations, fail-closed verifier checks, retention block preservation, and explicit owner sign-off gates.
6. **Maintained Strict Non-Destructive Boundaries:** Zero application source code, test code, migrations, database files, signing keys, archives, or deployment configs were modified. Destructive audit pruning remains **strictly blocked**.

---

## 2. Inventory of Source Files Inspected

The following existing files were inspected in read-only mode to establish ground-truth constraints:

| File Path | Component / Layer | Confirmed Architectural Facts |
|---|---|---|
| [`backend/app/models/audit.py`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/models/audit.py) | Database Model | `AuditEvent` model uses UUID4 primary keys, UTC timestamps, `previous_hash` (64 chars), and `event_hash` (64 chars). No foreign key to `investigations`. |
| [`backend/app/repositories/audit_repository.py`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/repositories/audit_repository.py) | Repository Layer | Uses `GENESIS_HASH = "0"*64`. Hashing uses RFC 8785 canonical JSON formatting (`format_canonical_timestamp`). `verify_chain_integrity()` iterates from genesis to tip. `log_event()` executes `await session.flush()` for intra-transaction sequential hash consistency. |
| [`backend/app/services/retention_service.py`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/services/retention_service.py) | Service Layer | `calculate_cutoffs()` enforces 90-day investigation and 365-day audit cutoffs in UTC. `prune_expired_investigations()` prunes in bounded batches ($\le 100$) with inter-batch delays. `prune_expired_audit_events()` identifies candidates in dry-run mode but **blocks destructive execution** (`status="BLOCKED"`). |
| [`backend/app/core/config.py`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/backend/app/core/config.py) | Core Configuration | `INVESTIGATION_RETENTION_DAYS = 90`, `AUDIT_RETENTION_DAYS = 365`. |
| [`specs/PHASE_7_ADR.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_ADR.md) | Architecture Decisions | ADR-011 establishes 90-day investigation retention and independent 365-day audit retention. ADR-012 defines SHA-256 hash chaining and documents that local hashing cannot prevent local administrator tampering. |
| [`specs/PHASE_7_SECURITY_AND_RETENTION.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_SECURITY_AND_RETENTION.md) | Security Specification | Codifies threat boundaries, NTFS ACL requirements, and bounded batch pruning rules. |
| [`PHASE_7_4_IMPLEMENTATION_REPORT.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_4_IMPLEMENTATION_REPORT.md) | Milestone Report | Documents 10/10 passing retention tests and confirms that physical audit deletion was safely blocked. |

---

## 3. Implementation Facts Confirmed vs. Unverified Claims

### Confirmed Facts from Source Code
1. **Investigation Retention:** Verified in source (`retention_service.py` lines 180–255). Investigations older than 90 days are deleted in bounded batches ($\le 100$) with cascade deletion to child tables.
2. **Audit Preservation:** Verified in source (`audit_repository.py` and `retention_service.py`). Audit records are never cascade-deleted with investigations.
3. **Audit Pruning Blocked:** Verified in source (`retention_service.py` lines 270–330). Invoking destructive audit pruning returns `status="BLOCKED"`, `deleted_count=0`.
4. **Hash Chain Construction:** Verified in source (`audit_repository.py` lines 36–64). SHA-256 hashes are computed over canonical JSON concatenated with `previous_hash`.
5. **Microsecond Precision UTC:** Verified in source (`audit_repository.py` lines 23–29). Formatted as `%Y-%m-%dT%H:%M:%S.%fZ`.
6. **Zero Production DB:** Verified via shell inspection (`Test-Path "data/siem_history.db"` returned `False`).

### Claims That Remain Unverified / Out of Scope
1. **Multi-Year Performance Under Massive Volume:** Unverified on live multi-gigabyte databases (current environment has zero production rows; synthetic testing verified up to bounded batches).
2. **Hardware Security Module (HSM) Integration:** Unverified because local loopback operation does not have access to an HSM or remote KMS.

---

## 4. Key Design Decisions Codified in Phase 7.5A

1. **Windows DPAPI-Backed Checkpoint Signing:**
   - Keys are encrypted at rest using Windows DPAPI under Current User or Local Machine scope.
   - Mitigates unprivileged local user tampering and cold-disk extraction.
   - Explicitly acknowledges that a fully privileged host Administrator or `NT AUTHORITY\SYSTEM` user can call `CryptUnprotectData` and re-sign forged records.
2. **Configurable Archive Destination:**
   - Supported via `AUDIT_ARCHIVE_DIR`, defaulting to `data/archives/`.
   - Path traversal validation and disk space assertion ($\ge 1\text{ GB}$) enforced.
3. **Strict Fail-Closed Verification:**
   - Any gap, hash mismatch, signature failure, corrupted archive, or missing DPAPI key returns `is_valid=False`. Zero silent fallbacks to unsigned mode.
4. **Hard Block on Retention Deletion Preserved:**
   - Designing this architecture does **not** enable pruning. Physical audit deletion remains strictly blocked until future authorized implementation.
5. **100% Offline / Loopback Operation:**
   - Zero cloud or third-party network dependencies.

---

## 5. Deliverables Inventory in Phase 7.5 / 7.5A

| File Path | Description |
|---|---|
| [`specs/PHASE_7_5_ADR.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_ADR.md) | Finalized ADR-013 with DPAPI signing, configurable archive, fail-closed verification, and explicit non-authorization governance status. |
| [`specs/PHASE_7_5_DECISION_REGISTER.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_DECISION_REGISTER.md) | Formal Decision Register recording 6 key decisions, trust boundary scope, and open owner questions. |
| [`specs/PHASE_7_5_PRD.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_PRD.md) | Product Requirements Document defining problem statement, retention vs deletion, failure modes, and scope. |
| [`specs/PHASE_7_5_TRD.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_TRD.md) | Technical Requirements Document comparing all 4 options, SQLite WAL concurrency, DPAPI lifecycle, and acceptance criteria. |
| [`specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md) | Exact protocol specification, schema definition, field dictionary, canonical serialization, and algorithms. |
| [`specs/PHASE_7_5_SECURITY_THREAT_MODEL.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_SECURITY_THREAT_MODEL.md) | Security Threat Model analyzing 18 specific threat vectors (including DPAPI compromise and path traversal). |
| [`specs/PHASE_7_5_TEST_PLAN.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_TEST_PLAN.md) | Comprehensive 20-case test plan for future authorized implementation. |
| [`specs/PHASE_7_5_IMPLEMENTATION_PLAN.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_IMPLEMENTATION_PLAN.md) | 12-stage ordered implementation blueprint with verification gates, DPAPI integration, and stop conditions. |
| [`specs/PHASE_7_5_DOCUMENTATION_AUDIT_REPORT.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/specs/PHASE_7_5_DOCUMENTATION_AUDIT_REPORT.md) | Copy of this report within `specs/`. |
| [`PHASE_7_5_DOCUMENTATION_AUDIT_REPORT.md`](file:///F:/MY%20Project/WAZUH-OLLAMA-SIEM/PHASE_7_5_DOCUMENTATION_AUDIT_REPORT.md) | Authoritative root milestone report. |

---

## 6. Safety, Invariant & Non-Destructive Confirmations

| Invariant | Status | Evidence |
|---|---|---|
| Application Source Untouched | **CONFIRMED** | Zero edits to `backend/app/` or `frontend/src/` in Phase 7.5/7.5A. |
| Test Source Untouched | **CONFIRMED** | Zero edits to `backend/tests/` or `frontend/tests/` in Phase 7.5/7.5A. |
| Migrations Untouched | **CONFIRMED** | Zero Alembic migrations created or executed in Phase 7.5/7.5A. |
| Production DB Untouched | **CONFIRMED** | `data/siem_history.db` does not exist (`Test-Path` returned `False`). |
| Zero Records Deleted | **CONFIRMED** | Zero SQL commands, zero retention calls, zero database writes executed. |
| Audit Pruning Still Blocked | **CONFIRMED** | `RetentionService.prune_expired_audit_events()` remains blocked in code. |
| Deployment Repository Untouched | **CONFIRMED** | `F:\MY Project\wazuh-docker` remains strictly untouched. |
| Git History Untouched | **CONFIRMED** | 0 commits, 0 pushes. `HEAD` remains `793e4c4a9e9133e69db5e8462ef3063ef3f0e86b`. |
| Phase 7.6 Not Started | **CONFIRMED** | No implementation or coding work has begun. |

---

## 7. Final Recommendation & Required Approval Decision

> [!CAUTION]
> **Explicit Governance Statement:**
> **Phase 7.5 / 7.5A documentation does NOT authorize implementation or audit pruning.**
> Physical audit pruning must remain **BLOCKED** in the application runtime until the project owner explicitly approves ADR-013 and authorizes Phase 7.6.

### Exact Decision Needed to Proceed to Future Implementation
To authorize future implementation, the project owner must record an approval decision in `specs/DECISIONS.md`:
> **"ADR-013: Approval to implement the Segmented Checkpoint & Verifiable Archival Architecture with Windows DPAPI Signing (Option 2 + Option 4 Hybrid) and authorize Phase 7.6 implementation."**
