# Phase 7.5 / 7.5A Security Decision Register
## Audit Checkpoint Architecture, DPAPI Signing & Verifiable Archival

**Document ID:** `specs/PHASE_7_5_DECISION_REGISTER.md`  
**Phase:** 7.5 / 7.5A  
**Date:** October 20, 2026  
**Status:** PROPOSED DECISIONS AWAITING PROJECT OWNER APPROVAL  

---

## 1. Formal Decision Register

| Decision ID | Domain | Proposed Decision | Rationale | Alternatives Evaluated | Governance Status |
|---|---|---|---|---|---|
| **DEC-7.5-01** | **Checkpoint Signing** | Adopt **Windows DPAPI-backed signing** (`signature_algorithm='HMAC-SHA256'` or `'ED25519'`). Key material is encrypted at rest using Windows DPAPI machine or user scope. | Provides strong defense-in-depth against unprivileged local users, offline disk inspection, and accidental modification without introducing external network dependencies. | 1. Unsigned hash meta-chaining (`NONE`).<br>2. Plaintext key in `.env`.<br>3. Cloud KMS / HSM (violates offline rule). | **PROPOSED — PENDING EXPLICIT USER APPROVAL** |
| **DEC-7.5-02** | **Archive Destination** | Introduce configurable setting `AUDIT_ARCHIVE_DIR` with default value `data/archives/`. Enforce path traversal validation and NTFS permissions (`icacls`). | Allows operators to direct historical compliance archives to dedicated storage volumes while providing a secure, out-of-the-box local default. | 1. Hardcoded `data/archives/`.<br>2. In-database BLOB storage (causes database bloat).<br>3. Remote network share only. | **PROPOSED — PENDING EXPLICIT USER APPROVAL** |
| **DEC-7.5-03** | **Verification Policy** | Enforce a strict **Fail-Closed Verification Policy**. Any verification failure (broken chain, tampered event, invalid checkpoint, missing archive, missing DPAPI key) returns `is_valid=False` with a structured error code. | Prevents silent integrity degradation and guarantees that compromised, corrupt, or unanchored audit history is never reported as valid. | 1. Warn-and-pass on missing key.<br>2. Fall back silently from signed to unsigned mode.<br>3. Ignore gaps at boundary. | **PROPOSED — PENDING EXPLICIT USER APPROVAL** |
| **DEC-7.5-04** | **Retention Safety** | Maintain the current **hard block on physical audit-event pruning** (`status="BLOCKED"`, `deleted_count=0`). A successful design review does NOT authorize or enable deletion. | Prevents premature or accidental erasure of compliance audit records until the checkpoint schema, archival service, and verifier are fully implemented and tested. | 1. Unblock deletion during design review.<br>2. Delete records before checkpoint table exists. | **APPROVED & PRESERVED (Existing Baseline)** |
| **DEC-7.5-05** | **Offline Operation** | All checkpoint generation, signing, verification, and archival must function **strictly offline on loopback**. Zero mandatory cloud or third-party SaaS services. | Preserves the core platform design requirement for air-gapped, loopback-only local security operations. | 1. Mandatory AWS S3 Object Lock.<br>2. Cloud KMS key attestation.<br>3. Public blockchain notarization. | **APPROVED & PRESERVED (Existing Baseline)** |
| **DEC-7.5-06** | **Trust Boundary Scope** | Formally acknowledge that **local DPAPI signing does NOT protect against a fully privileged Windows local Administrator or `NT AUTHORITY\SYSTEM`**. External non-repudiation requires an external trust anchor. | Prevents false security claims. An attacker with kernel or administrator privileges on the host can access DPAPI keys and rewrite local files. | 1. Claim absolute local immutability (untrue).<br>2. Ignore host administrator threat vector. | **APPROVED & DOCUMENTED** |

---

## 2. Unresolved Trust-Boundary Decisions & Open Governance Questions

The following decisions are presented to the project owner for formal sign-off:

### Question 1: DPAPI Key Scope Selection
- **Option A (Machine Scope - `CRYPTPROTECT_LOCAL_MACHINE`):** Any process running on the host with sufficient local privileges can decrypt the signing key. Useful if background maintenance runs as a service account different from the analyst desktop user.
- **Option B (Current User Scope - Default):** Only processes running under the specific analyst user account can decrypt the key. Stronger isolation against other local users, but ties checkpointing to that specific user profile.
- *Recommendation:* Option B (Current User Scope) for the current single-user workstation model; Option A if background services are configured.

### Question 2: Archive Rotation & Storage Ceiling
- Should the application enforce a hard disk space threshold (e.g. abort archiving if $< 1\text{ GB}$ free) on the volume hosting `AUDIT_ARCHIVE_DIR`?
- *Recommendation:* Yes, enforce a pre-flight disk check asserting at least $1\text{ GB}$ free space before streaming archives.

### Question 3: Formal Approval of ADR-013
- Does the project owner approve proceeding with the implementation of ADR-013 in Phase 7.6?
- *Status:* **Awaiting explicit user approval**. Implementation remains strictly unauthorized.
