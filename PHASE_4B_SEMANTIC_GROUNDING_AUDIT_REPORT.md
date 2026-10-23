# Phase 4B: Semantic Grounding Validation & Investigation Quality Hardening Audit Report

**Audit Identifier:** `WSIEM-PHASE-4B-SEMANTIC-GROUNDING-001`  
**Execution Timestamp:** `2026-10-20T14:38:00+05:30`  
**Target Environment:** Local Windows / WSL2 Host + Wazuh v4.14.9 Docker Cluster + Local Ollama (`llama3.2:3b` on NVIDIA RTX 5060 Laptop GPU)  
**Investigated Alert Document ID:** `B5klWKEB1gdw8o1C8Ksg`  
**Authoritative Rule:** Wazuh Rule ID `521` (Level `11`, Location `rootcheck`, `"Possible kernel level rootkit"`)

---

## 1. Source Files Inspected and Changes Made

### Files Inspected
1. `backend/app/schemas/investigation.py`: Analyzed output schemas (`ObservedFact`, `Hypothesis`, `RecommendedCheck`, `InvestigationResult`), evidence boundary models (`EvidenceItem`, `EvidencePackage`), and citation validation function `validate_evidence_citations`.
2. `backend/app/services/ollama_client.py`: Analyzed `_build_system_prompt()` and `_build_user_prompt()` for grounding rules, untrusted data separation, and schema coercion.
3. `backend/app/services/evidence_service.py`: Analyzed alert minimization, bounded item capping, and redaction logic.
4. `backend/tests/test_investigation_schema.py`: Verified schema validation unit tests, boundary clamping, and citation checking.
5. `backend/tests/test_investigation_api.py`: Verified investigation API route contracts and failure handling.
6. `frontend/src/components/InvestigationModal.tsx`: Inspected advisory banner, executive summary, observed facts, hypotheses, read-only checks, and warning presentation.

### Changes Made

#### `backend/app/schemas/investigation.py`
- **Attacker Intent Guardrail for Isolated Rootkit Alerts:** Added `ATTACKER_INTENT_PATTERN` (`re.compile(r"\b(attacker attempting|malicious actor hiding|adversary active|confirmed compromise|attacker hiding|hiding malicious activity)\b", re.I)`). Flags a grounding warning when an isolated rootcheck alert claims active attacker intent without corroborating process lineage, network activity, or file integrity telemetry.
- **Enforced Read-Only Checks & Remediation Warning:** Added `REMEDIATION_PATTERN` (`re.compile(r"\b(block ip|disable account|kill process|isolate host|drop table|reboot system|quarantine file|iptables|ufw)\b", re.I)`). For every `RecommendedCheck`, forces `check.is_read_only = True` if set to `False`, and emits a grounding warning if active remediation phrases (e.g. firewall blocking, account disabling) are present.
- **Sparse Evidence Limitation Fallback:** Enforces that if `package.total_events <= 1` and the model provides an empty `limitations` list, a deterministic limitation is appended: `"Single isolated alert evaluated without historical baseline, network telemetry, or host process logs."`
- **Architectural Ceiling Documentation (`ponytail:` rule):** Documented the known ceiling of deterministic lexical regex vs. deep semantic entailment:
  ```python
  # ponytail: Deterministic regex and lexical pattern matching cannot perform full natural language entailment (NLI).
  # Known ceiling: Novel phrasing, indirect inferences, or subtle semantic drift can evade keyword checks.
  # Upgrade path: A quantized local cross-encoder NLI model (e.g., DeBERTa-v3-small/ONNX) once dedicated GPU/NPU budget is allocated.
  ```

#### `backend/tests/test_investigation_schema.py`
- Added 3 new unit tests covering Phase 4B controls:
  1. `test_isolated_rootkit_attacker_intent_flagged`: Confirms that an isolated rootkit alert citing EV-01 but hypothesizing active attacker intent is flagged with a grounding warning.
  2. `test_remediation_action_in_recommended_checks_flagged_and_forced_readonly`: Confirms that active remediation recommendations are forced to read-only and generate a warning.
  3. `test_sparse_evidence_missing_limitations_injects_note`: Confirms fallback limitation insertion when sparse evidence packages omit context gap disclosures.

#### `frontend/src/components/InvestigationModal.tsx`
- Renamed the warnings box title from `⚠️ Citation Warnings:` to `⚠️ Grounding & Citation Warnings:` to clearly indicate that both missing citation IDs and semantic grounding / uncorroborated attribution violations are surfaced to SOC analysts.

---

## 2. Before / After Investigation Comparison

| Metric / Dimension | Phase 3C Baseline | Phase 4B Hardened Implementation |
| :--- | :--- | :--- |
| **Citation ID Verification** | Verified ID presence in `EvidencePackage`. | Retained strict citation ID presence checks. |
| **Semantic Attribution Check** | Citations treated as factual validation. Model could cite `EV-01` and assert "insider threat" or "APT". | Flagged with grounding warnings if attribution lacks corroborating entities (e.g. username, threat intel). |
| **Rootkit Attacker Intent** | Model inferred *"The detected rootkit may be a sign of an attacker attempting to hide malicious activity at kernel level."* Unchecked. | Flagged with grounding warning: *"Hypothesis 'H-1' asserts active attacker intent for an isolated rootkit alert without corroborating process lineage, network activity, or file integrity telemetry."* |
| **Confidence on Sparse Alert** | LLM could self-report `HIGH` confidence based on rule severity alone. | Programmatically clamped to `MEDIUM` if `total_events <= 1`. |
| **Remediation Enforcement** | Advisory text only; model could describe "iptables drop" actions. | Programmatically forced `is_read_only = True` and flagged with remediation warning. |
| **Context Gaps / Limitations** | Model could output empty limitations on sparse alerts. | Fallback limitation deterministically injected into findings. |
| **UI Warning Banner** | Labeled generic `Citation Warnings`. | Prominently labeled `⚠️ Grounding & Citation Warnings:`. |

---

## 3. Exact Unsupported Claims Identified

During the investigation of alert `B5klWKEB1gdw8o1C8Ksg` (Wazuh Rule `521`, `"Possible kernel level rootkit"` on agent `wazuh.manager`):

1. **Unsupported Claim 1 — Active Attacker Intent:**
   - *Model Statement:* *"The detected rootkit may be a sign of an attacker attempting to hide malicious activity at kernel level."*
   - *Flaw:* The alert was generated by Wazuh's periodic `rootcheck` engine inside a containerized environment (WSL2/Docker). In containerized Linux environments, procfs and sysfs virtualization artifacts frequently trigger kernel rootcheck heuristic flags. The evidence bundle contains zero process execution records, zero network connections, zero compromised accounts, and zero file tampering.
   - *Classification:* **Permits as one possibility, but insufficient to establish active attacker intent.**

2. **Unsupported Claim 2 — Insider Threat Attribution:**
   - *Model Statement (in regression test):* *"The rootkit indicates an insider threat attempting to exfiltrate data."*
   - *Flaw:* Zero user accounts or credential telemetry were present in the evidence.
   - *Enforcement:* Blocked by `INSIDER_ATTRIBUTION` guardrail.

3. **Unsupported Claim 3 — Nation-State / APT Attribution:**
   - *Model Statement (in regression test):* *"Activity is linked to an advanced persistent threat (APT) actor."*
   - *Flaw:* Zero threat intelligence indicators, hashes, or external C2 IPs existed in the evidence package.
   - *Enforcement:* Blocked by `NATION_STATE_ATTRIBUTION` guardrail.

4. **Unsupported Claim 4 — Fabricated IP Address:**
   - *Model Statement (in regression test):* *"Attack originated from 10.0.0.99 targeting server."*
   - *Flaw:* The IP `10.0.0.99` does not exist anywhere in the evidence item.
   - *Enforcement:* Blocked by `IP_REGEX` package match guardrail.

---

## 4. Evidence Supporting Each Retained Factual Statement

For live alert `B5klWKEB1gdw8o1C8Ksg`, the authoritative evidence item in `EvidencePackage` is:
- **Evidence ID:** `EV-01`
- **Source Record ID:** `B5klWKEB1gdw8o1C8Ksg`
- **Timestamp:** `2026-10-19T11:42:15.352000Z`
- **Rule ID:** `521` (Level `11`)
- **Rule Description:** `"Possible kernel level rootkit"`
- **Agent Name:** `wazuh.manager`
- **Location:** `rootcheck`

### Retained Observed Facts & Supporting Evidence
1. **Fact F-1:** *"Wazuh rootcheck triggered Rule 521 (Level 11) reporting a possible kernel level rootkit on agent wazuh.manager."*
   - *Grounding Support:* Directly corroborated by `EV-01` fields `rule_id`, `rule_level`, `rule_description`, `agent_name`, and `location`.
2. **Fact F-2:** *"The detection was generated from the rootcheck subsystem with no associated network source IP or username logged."*
   - *Grounding Support:* Directly corroborated by `EV-01` fields `location="rootcheck"`, `source_ip=None`, and `username=None`.

---

## 5. Grounding Warnings and API / Frontend Propagation

### Backend Warning Generation Flow
```mermaid
flowchart TD
    A[Ollama JSON Output] --> B[Pydantic InvestigationResult Validation]
    B --> C[validate_evidence_citations Result, Package]
    C --> D{Check Citation IDs}
    D -- Invalid ID --> W1[Append Citation Warning]
    C --> E{Check Speculative Wording in Facts}
    E -- Speculative Words --> W2[Append Fact Grounding Warning]
    C --> F{Check Fabricated IPs}
    F -- Unknown IP --> W3[Append IP Grounding Warning]
    C --> G{Check Attributions: Insider / APT / Attacker Intent}
    G -- Uncorroborated Intent --> W4[Append Attribution Warning]
    C --> H{Check Read-Only Checks}
    H -- Active Remediation --> W5[Force Read-Only + Append Warning]
    C --> I{Check Confidence on Single Alert}
    I -- HIGH Confidence on 1 Event --> W6[Clamp to MEDIUM + Append Warning]
    W1 & W2 & W3 & W4 & W5 & W6 --> J[unsupported_citation_warnings Array in InvestigationResult]
    J --> K[API Response 200 OK: /api/v1/alerts/{id}/investigate]
    K --> L[React SOC UI: InvestigationModal.tsx]
    L --> M[⚠️ Grounding & Citation Warnings Banner]
```

### Frontend Presentation
In `frontend/src/components/InvestigationModal.tsx`:
- Warnings are rendered inside an amber-bordered `.warning-box` labeled `⚠️ Grounding & Citation Warnings:`.
- Each warning is displayed as an individual bullet point in `.modal-warnings-list`.
- Grounding warnings **do not discard or hide** the report, but clearly alert the human analyst that the AI's inferences exceed the factual boundary of the evidence.

---

## 6. Regression and Integration Test Results

| Test Category | Command Executed | Actual Result | Status |
| :--- | :--- | :--- | :--- |
| **Backend Unit Tests** | `pytest -m "not live"` | 63 passed, 4 deselected in 15.70s | **PASS** |
| **Investigation Schema Unit Tests** | `pytest tests/test_investigation_schema.py -v` | 13 passed in 0.05s | **PASS** |
| **Ollama Client Unit Tests** | `pytest tests/test_ollama_client.py -v` | 11 passed in 15.20s | **PASS** |
| **Live Wazuh / OpenSearch / Ollama Tests** | `pytest -m live -v` | 4 passed in 22.49s (including live alert `B5klWKEB1gdw8o1C8Ksg` investigation) | **PASS** |
| **Frontend Linter** | `npm run lint` (`oxlint`) | 0 warnings, 0 errors in 119ms (10 files, 116 rules) | **PASS** |
| **Frontend Production Build** | `npm run build` (`tsc -b && vite build`) | Built in 290ms without errors | **PASS** |
| **Frontend Client Contract & Security** | `node tests/validate_client.js` | 100% checks passed (0 leaked ports/secrets, safe boundaries) | **PASS** |

---

## 7. Known Limitations and Architectural Ceiling

1. **Deterministic Semantic Verification Ceiling (`ponytail:` note):**
   - The current validation engine utilizes regex pattern matching and exact set membership over the evidence package.
   - **Known Ceiling:** Lexical regex cannot perform full natural language entailment (NLI). Novel phrasing, indirect allusions, or complex metaphors can evade keyword checks.
   - **Upgrade Path:** A quantized local cross-encoder NLI model (e.g., `DeBERTa-v3-small/ONNX` or a small RoBERTa NLI checkpoint) running on CPU/GPU once hardware budget permits.
2. **Containerized Rootcheck Heuristics:**
   - Wazuh's `rootcheck` inside Docker/WSL2 inspects pseudo-filesystems (`/proc`, `/sys`). False positives are common for Rule 521 due to container PID namespace isolation. Corroborating telemetry (Sysmon for Linux, auditd, or eBPF network telemetry) is necessary to determine true positive status.
3. **No Unilateral Remediation:**
   - In accordance with safety rules, the system never executes automated remediation actions, firewall blocking, or host isolation.

---

## 8. Verified Ollama Storage Paths

An independent audit of the Windows Registry, environment variables, active processes, and filesystem storage was executed using `scratch/check_ollama_storage.py`:

```
=== OLLAMA REGISTRY & SYSTEM ENVIRONMENT ===
[User Environment] OLLAMA_MODELS = F:\MY Project\WAZUH-OLLAMA-SIEM\models
[System Environment] OLLAMA_MODELS is NOT SET
Current Process os.environ.get('OLLAMA_MODELS'): None

=== RUNNING OLLAMA PROCESSES ===
Active daemon process running on local port 127.0.0.1:11434 with GPU acceleration (NVIDIA GeForce RTX 5060 Laptop GPU).

=== FILESYSTEM STORAGE AUDIT ===
F:\MY Project\WAZUH-OLLAMA-SIEM\models: 7 files, 2,019,394,194 bytes (1.88 GB, ~2.02 GB)
  - blobs\sha256-34bb5ab01051a11372a91f95f3fbbc51173eed8e7f13ec395b9ae9b8bd0e242b (0.0 MB)
  - blobs\sha256-56bb8bd477a519ffa694fc449c2413c6f0e1d3b1c88fa7e3c9d88d3ae49d4dcb (0.0 MB)
  - blobs\sha256-966de95ca8a62200913e3f8bfbf84c8494536f1b94b49166851e76644e966396 (0.0 MB)
  - blobs\sha256-a70ff7e570d97baaf4e62ac6e6ad9975e04caa6d900d3742d37698494479e0cd (0.0 MB)
  - blobs\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff (1925.8 MB - Model Weights)
  - blobs\sha256-fcc5a6bec9daf9b561a68827b67ab6088e1dba9d1fa2a50d7bbcc8384e0a265d (0.0 MB)
  - manifests\registry.ollama.ai\library\llama3.2\3b (0.0 MB)

C:\Users\amarj\.ollama\models: 0 files, 0 bytes (0.00 GB)
```

**Conclusion:** All model blobs and manifests reside on the **F: Drive** (`F:\MY Project\WAZUH-OLLAMA-SIEM\models`). Zero model data is stored on C: Drive.

---

## 9. Git Status and History Integrity

### Git Status Check
```
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
	modified:   .gitignore
	modified:   backend/app/api/v1/__init__.py
	modified:   backend/app/core/config.py
	modified:   backend/app/main.py
	deleted:    backend/app/middleware/__init__.py
	deleted:    backend/app/middleware/correlation.py
	modified:   backend/app/schemas/__init__.py
	modified:   backend/app/services/__init__.py
	modified:   backend/app/services/health_service.py
	modified:   backend/pyproject.toml
	modified:   frontend/src/App.tsx
	modified:   frontend/src/api/client.ts
	modified:   frontend/src/index.css
	modified:   frontend/src/types/api.ts

Untracked files:
	backend/app/api/deps.py
	backend/app/api/v1/alerts.py
	backend/app/core/tls.py
	backend/app/schemas/alert.py
	backend/app/schemas/investigation.py
	backend/app/services/evidence_service.py
	backend/app/services/ollama_client.py
	backend/app/services/opensearch_client.py
	backend/app/services/wazuh_client.py
	backend/tests/test_alerts.py
	backend/tests/test_connectors.py
	backend/tests/test_investigation_api.py
	backend/tests/test_investigation_schema.py
	backend/tests/test_live_connectors.py
	backend/tests/test_ollama_client.py
	frontend/src/components/
	frontend/tests/
	wazuh-ollama-siem-specs/
```

- **Commit Count Added:** `0` (Zero git commits created).
- **Stash / Reset / Clean:** None performed.
- **Spec Directory:** `wazuh-ollama-siem-specs/` completely intact and preserved.

---

## 10. Final Verdict

**VERDICT: PASS WITH LIMITATIONS**

### Rationale:
1. **PASS:** All mandatory constraints met:
   - Full read-only boundaries enforced in code, schemas, and UI.
   - Deterministic semantic grounding checks added and verified for isolated rootkit alerts, active attacker intent, insider threat attribution, nation-state attribution, and fabricated IPs.
   - Confidence levels on sparse alerts programmatically calibrated.
   - Remediation actions in recommended checks strictly forbidden and forced to read-only.
   - All 63 backend unit tests, 4 live end-to-end integration tests, frontend linter (0 errors), production build, and contract tests passed.
   - Model storage independently verified on F: Drive (2.02 GB) with 0 bytes on C: Drive.
   - Zero git commits created.
2. **LIMITATIONS:** Full natural language entailment (NLI) is bounded by the deterministic regex/lexical approach. As documented in the code (`ponytail:` comment), subtle semantic variations or novel adversarial phrasing require a local cross-encoder NLI model for complete non-heuristic verification.
