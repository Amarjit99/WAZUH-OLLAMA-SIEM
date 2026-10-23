# Phase 4C: Antigravity Ollama Model Storage Forensic Audit Report

**Audit Identifier:** `WSIEM-PHASE-4C-OLLAMA-STORAGE-FORENSIC-001`  
**Execution Timestamp:** `2026-10-20T14:55:30+05:30`  
**Target Environment:** Local Windows Host / Antigravity IDE  
**Investigated Daemon:** Ollama Local Daemon listening on `127.0.0.1:11434` (PID: `10356`)  
**Target Model:** `llama3.2:3b`

---

## 1. Audit Scope & Objective

Perform a read-only forensic audit to definitively identify the **actual model storage directory used by the currently active Ollama daemon (PID 10356)**.

Specifically, investigate and explain the discrepancy observed when:
1. Running `Get-ChildItem Env:OLLAMA*` in an arbitrary PowerShell session returns empty.
2. The Ollama API (`http://127.0.0.1:11434/api/tags`) reports model `llama3.2:3b` with size `2019393189` bytes and digest `a80c4f17acd5...`.
3. Physical model files exist on `F:\MY Project\WAZUH-OLLAMA-SIEM\models`.
4. The default `C:\Users\amarj\.ollama\models` directory has 0 files.

---

## 2. Exact Commands and Tools Used

All audit operations were strictly read-only:
1. `Get-NetTCPConnection -LocalPort 11434`: Verified listener socket ownership to identify PID `10356`.
2. `Get-CimInstance Win32_Process`: Inspected process attributes, execution path, command line, creation timestamp, and parent/grandparent hierarchy.
3. **PEB Memory Extraction Script (`scratch/read_peb_env.py`):** Utilized Windows Native API (`NtQueryInformationProcess`, `ReadProcessMemory` via Python `ctypes`) to read the Process Environment Block (PEB) and extract the exact live runtime environment block of PID `10356`.
4. **Registry Key Inspection:** Read `HKEY_CURRENT_USER\Environment` and `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` via `winreg`.
5. **Cryptographic Manifest Inspection Script (`scratch/inspect_manifest.py`):** Computed SHA-256 hash of the manifest file on F: drive and compared it directly against the model digest reported by `/api/tags`.
6. **Filesystem Timestamp & Size Audit:** Evaluated file counts, exact byte lengths, `LastWriteTime`, and `LastAccessTime` across F: and C: model paths.
7. **Read-Only Inference Test (`scratch/test_inference_access.py`):** Executed a single minimal inference request (`1+1=`, `num_predict: 2`) via `http://127.0.0.1:11434/api/generate` and inspected `http://127.0.0.1:11434/api/ps` during execution to observe loaded VRAM models and file access.

---

## 3. Active Daemon Process Evidence

### PID 10356 Process Details
- **Process ID:** `10356`
- **Name:** `ollama.exe`
- **Executable Path:** `C:\Users\amarj\AppData\Local\Programs\Ollama\ollama.exe`
- **Command Line:** `"C:\Users\amarj\AppData\Local\Programs\Ollama\ollama.exe" serve`
- **Creation Timestamp:** `2026-10-20 12:27:54.789`
- **Listening Socket:** `127.0.0.1:11434` (TCP LISTEN & ESTABLISHED)

### Process Ancestry Hierarchy
```mermaid
graph TD
    GP["Grandparent: PID 6960 (language_server_windows_x64.exe)<br/>Antigravity IDE Language Server Engine"]
    P["Parent: PID 26876 (pwsh.exe)<br/>CommandLine: pwsh -Command '$env:OLLAMA_MODELS = \"F:\\MY Project\\WAZUH-OLLAMA-SIEM\\models\"; ollama serve'"]
    D["Daemon: PID 10356 (ollama.exe)<br/>CommandLine: 'C:\\Users\\amarj\\AppData\\Local\\Programs\\Ollama\\ollama.exe' serve<br/>PEB Environment: OLLAMA_MODELS=F:\\MY Project\\WAZUH-OLLAMA-SIEM\\models"]
    
    GP --> P
    P --> D
```

1. **Parent Process (PID 26876):**
   - **Name:** `pwsh.exe`
   - **Executable Path:** `C:\Program Files\PowerShell\7\pwsh.exe`
   - **Exact Command Line:**
     ```powershell
     pwsh -Command "$env:OLLAMA_MODELS = \"F:\MY Project\WAZUH-OLLAMA-SIEM\models\"; ollama serve"
     ```
2. **Grandparent Process (PID 6960):**
   - **Name:** `language_server_windows_x64.exe`
   - **Executable Path:** `c:\Users\amarj\AppData\Local\Programs\Antigravity IDE\resources\app\extensions\antigravity\bin\language_server_windows_x64.exe`
   - **Mechanism:** Antigravity IDE launched an asynchronous background terminal task that set the scoped environment variable `$env:OLLAMA_MODELS` immediately prior to starting `ollama serve`.

---

## 4. Environment & Configuration Findings

### Why `Get-ChildItem Env:OLLAMA*` Returned Empty
In Windows PowerShell, `$env:VARIABLE = "value"` sets a variable only within the memory scope of that specific PowerShell process and any child processes it spawns. It does **not** modify parent processes, external shells, or independently launched PowerShell windows.

### Forensic Comparison Across Configuration Sources

| Source | Scope | Value for `OLLAMA_MODELS` | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Active Daemon PEB** | Process-Specific (PID 10356) | `F:\MY Project\WAZUH-OLLAMA-SIEM\models` | **Extracted via `ReadProcessMemory` from PEB block `0x000001f7c22e2850`** |
| **Parent Process CommandLine** | Process-Specific (PID 26876) | `F:\MY Project\WAZUH-OLLAMA-SIEM\models` | Confirmed via `Win32_Process.CommandLine` |
| **Windows User Registry** | `HKCU\Environment` | `F:\MY Project\WAZUH-OLLAMA-SIEM\models` | Confirmed via `winreg.QueryValueEx` |
| **Windows Machine Registry** | `HKLM\...\Session Manager\Environment`| *(Not Set)* | Confirmed via `winreg` (returns FileNotFoundError) |
| **Current User Terminal Shell** | Local Shell Instance | *(Not Inherited)* | Normal Windows behavior before registry reload |

---

## 5. Physical Model File Inventory

### F: Drive Model Storage
**Path:** `F:\MY Project\WAZUH-OLLAMA-SIEM\models`  
**Total File Count:** 7 files  
**Total Directory Size:** 2,019,394,194 bytes (1.88 GiB)

| File Relpath | Type | Size (Bytes) | SHA-256 Digest |
| :--- | :--- | :--- | :--- |
| `manifests\registry.ollama.ai\library\llama3.2\3b` | Manifest | 1,005 | `a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72` |
| `blobs\sha256-dde5aa3fc5ffc17176b5...` | Model Weights | 2,019,377,376 | `sha256:dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff` |
| `blobs\sha256-34bb5ab01051a11372a9...` | Model Config | 561 | `sha256:34bb5ab01051a11372a91f95f3fbbc51173eed8e7f13ec395b9ae9b8bd0e242b` |
| `blobs\sha256-966de95ca8a62200913e...` | Template | 1,429 | `sha256:966de95ca8a62200913e3f8bfbf84c8494536f1b94b49166851e76644e966396` |
| `blobs\sha256-fcc5a6bec9daf9b561a6...` | License | 7,711 | `sha256:fcc5a6bec9daf9b561a68827b67ab6088e1dba9d1fa2a50d7bbcc8384e0a265d` |
| `blobs\sha256-a70ff7e570d97baaf4e6...` | License | 6,016 | `sha256:a70ff7e570d97baaf4e62ac6e6ad9975e04caa6d900d3742d37698494479e0cd` |
| `blobs\sha256-56bb8bd477a519ffa694...` | Parameters | 96 | `sha256:56bb8bd477a519ffa694fc449c2413c6f0e1d3b1c88fa7e3c9d88d3ae49d4dcb` |

### C: Drive Model Storage
**Path:** `C:\Users\amarj\.ollama\models`  
**Total File Count:** 0 files  
**Total Directory Size:** 0 bytes (0.00 GiB)  
*(Only an empty `manifests` folder exists; no blob storage directory exists on C:)*

---

## 6. Cryptographic Manifest & API Match Verification

The Ollama daemon API output matches the physical F: files bit-for-bit:

1. **Manifest File Hash vs. API Digest:**
   - Physical Manifest Hash: `SHA256(F:\MY Project\WAZUH-OLLAMA-SIEM\models\manifests\...\3b)` = `a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72`
   - `/api/tags` Model Digest: `"a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72"`
   - **Match Status:** **100% IDENTICAL**

2. **Model Byte Size vs. API Size:**
   - Sum of Layer Blobs + Config Blob on F: = `2,019,392,628 + 561 = 2,019,393,189 bytes`
   - `/api/tags` Model Size: `2019393189`
   - **Match Status:** **100% IDENTICAL**

3. **Modification Timestamp vs. API `modified_at`:**
   - Physical Manifest `LastWriteTime`: `20-10-2026 12:40:15`
   - `/api/tags` `modified_at`: `"2026-10-20T12:40:15.0120417+05:30"`
   - **Match Status:** **100% IDENTICAL**

---

## 7. Evidence Showing Active Storage Path & Blob Loading

A minimal read-only inference request was performed to verify whether the active daemon loads the model from F: drive or fails:

### Inference Request
- **Endpoint:** `POST http://127.0.0.1:11434/api/generate`
- **Payload:** `{"model": "llama3.2:3b", "prompt": "1+1=", "stream": false, "options": {"num_predict": 2}}`
- **Result:** Completed successfully in **2.76s** (`load_duration: 2.64s`).

### Active VRAM / Process Verification via `/api/ps`
Immediately following the inference request, `/api/ps` was queried:
```json
{
  "models": [
    {
      "name": "llama3.2:3b",
      "model": "llama3.2:3b",
      "size": 2750261248,
      "digest": "a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72",
      "details": {
        "format": "gguf",
        "family": "llama",
        "parameter_size": "3.2B",
        "quantization_level": "Q4_K_M"
      },
      "expires_at": "2026-10-20T15:00:06.7346033+05:30",
      "size_vram": 2750261248,
      "context_length": 4096
    }
  ]
}
```

### Forensic Proof:
1. The 1.88 GiB model blob (`sha256-dde5aa...`) was transferred from disk into GPU VRAM (allocated `2,750,261,248 bytes` on the NVIDIA RTX 5060 Laptop GPU).
2. During and after this active load, `C:\Users\amarj\.ollama\models` was re-scanned and confirmed to contain **0 files (0 bytes)**.
3. Because the model blob exists **only** on `F:\MY Project\WAZUH-OLLAMA-SIEM\models\blobs`, the daemon could only have loaded it from F: drive.

---

## 8. C: Drive Protection Findings & Limitations

1. **Model Storage Protection Confirmed:**
   - `C:\Users\amarj\.ollama\models` contains 0 files and 0 bytes.
   - All GGUF weights, manifests, and parameter blobs are stored exclusively on F: drive.
2. **Operational Distinction:**
   - While model weights are protected from C: drive consumption, Ollama's application binary (`ollama.exe`) resides in `C:\Users\amarj\AppData\Local\Programs\Ollama\`, and standard application logs reside in `C:\Users\amarj\AppData\Local\Ollama\app-*.log`.
   - These application logs are negligible in size (~1 KB) and do not contain model weights.

---

## 9. State Modification Declaration

- **State Changed:** **NONE.**
- No files were deleted, moved, renamed, or modified.
- No processes were terminated, restarted, or created outside standard read-only queries and a single minimal test inference request.
- No environment variables or registry values were modified.
- No Git commits, stashes, or resets were performed.

---

## 10. Final Verdict

**VERDICT: `PASS — ACTIVE DAEMON STORAGE VERIFIED`**

### Summary:
The active Ollama daemon (PID `10356`) was launched by parent process PID `26876` with explicit environment configuration `$env:OLLAMA_MODELS = "F:\MY Project\WAZUH-OLLAMA-SIEM\models"`. Direct PEB memory inspection confirms that PID `10356` holds this exact variable in its live environment block. Cryptographic verification confirms that the manifest hash, file size, and timestamp on F: drive match `/api/tags` exactly. A live read-only inference test confirmed the active loading of the 1.88 GiB model blob from F: drive into GPU VRAM with zero model data ever touching C: drive.
