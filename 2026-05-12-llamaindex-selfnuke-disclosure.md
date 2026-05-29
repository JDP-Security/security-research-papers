---
date: 2026-05-12
title: LlamaIndex - Path Traversal to Local File Inclusion and RCE
---

> **⚠️ SECURITY ADVISORY:** Organizations utilizing **LlamaIndex (`llama-index-core` v0.14.19 and below)** are operating with a critical, unmitigated Remote Code Execution (RCE) and Permanent Denial of Service (DoS) vulnerability. Despite this finding being initially classified by the vendor as "Not Applicable," forensic audit confirms an undocumented remediation was executed across **v0.14.20** and **v0.14.21**. Because no formal CVE was issued, legacy deployments remain invisible to enterprise Software Composition Analysis (SCA) scanners (e.g., Snyk, Dependabot), creating a persistent supply chain risk.

---

# **SECURITY DISCLOSURE | JDP-2026-003**
## **Infrastructure Compromise: Path Traversal and Code Injection in LlamaIndex — Insecure AI Orchestration**

**Author:** Jeff Ponte, CISSP, CCSP, CEH | Lead Researcher, JDP Security  
**Series:** JDP Security Research Series (Disclosure #3)  
**Initial Disclosure Date:** March 27, 2026  
**Target:** LlamaIndex | `llama-index-core` (v0.14.19 and below)  
**Case Number:** [Huntr ID: bb0b2efb-8069-4642-97ec-7060aed7a7b7](https://huntr.com/repos/run-llama/llama_index) (Report marked ‘N/A’ by vendor - requires Huntr account to view details)  
**CVSS v3.1 Score:** **10.0 (Critical)** | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`  
**Status:** Officially Disputed / Silently Remediated in [v0.14.20](https://github.com/run-llama/llama_index/releases/tag/v0.14.20) and refined in [v0.14.21](https://github.com/run-llama/llama_index/releases/tag/v0.14.21)  

---

### **Executive Summary**
This white paper documents a critical architectural flaw in **LlamaIndex**, an industry-standard AI orchestration framework. This research highlights a validation deficiency where the framework treats stochastic, untrusted Large Language Model (LLM) output as deterministic, high-privilege system commands—specifically regarding file path resolution.

This oversight culminates in a full-chain vulnerability driven by Path Traversal (**CWE-22**) leading to Code Injection (**CWE-94**). I demonstrate how an AI agent can be manipulated into escaping its intended sandbox to physically overwrite its own host application's source code (referred to internally as the "Library Overwrite" vector). 

Despite comprehensive Proof of Concept (PoC) recordings demonstrating unauthenticated, LLM-driven host compromise, the maintainers initially disputed the disclosure, stating that environmental security boundaries are a user-side responsibility. However, forensic analysis of the repository's git history reveals the vendor subsequently executed a coordinated code migration to remediate the vulnerability without issuing a public security advisory. 

This research highlights the risks associated with **undocumented remediation** in the open-source supply chain: where a vulnerability is mitigated under the guise of routine maintenance without formal disclosure. This practice leaves the community in a "False Negative" state, where security tools fail to alert on active threats because no official CVE has been filed, exposing enterprise deployments to unmitigated risk.

---

### **Vulnerability Rating & CVSS Justification**
**Final Score:** **10.0 (Critical)** **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

* **Attack Vector (AV:N):** **Network.** The vulnerability is exploitable over the network as the framework is designed to ingest data/paths from remote LLMs or API-integrated web services that expose these orchestration functions.
* **Attack Complexity (AC:L):** **Low.** Exploitation requires only simple path manipulation (Standard Traversal strings). No sophisticated timing or environment-specific conditions are required.
* **Privileges Required (PR:N):** **None.** No authentication is required to trigger the vulnerable functions if the application logic allows for unauthenticated data ingestion (common in "Chat-with-your-data" implementations).
* **Scope (S:C):** **Changed.** This is the most critical metric. The exploit allows a breach of the framework's operational boundary (the AI environment) to affect the underlying **Host Operating System** (overwriting system files, cron jobs, or library source code).
* **Confidentiality, Integrity, Availability (C:H/I:H/A:H):** **High/Total.** * **Confidentiality:** Attacker can write files to exfiltrate system data.
    * **Integrity:** Attacker can modify any file the service user has permission to write (Code Injection).
    * **Availability:** The core library overwrite vector allows for a Permanent Denial of Service (DoS) by corrupting the library source.

---

### **1. The Technical Sink: Unsanitized Path Resolution**
The vulnerability lies in the framework's willingness to accept untrusted strings to define local filesystem directories.

#### **1.1 The Directory Sinks (v0.14.19)**
The core vulnerability exists at the directory resolution level within `llama-index-core/llama_index/core/download/dataset.py`. The SDK performs a direct path cast of `local_dir_path` without anchoring or validation.

* **Sink A ([Line 64](https://github.com/run-llama/llama_index/blob/v0.14.19/llama-index-core/llama_index/core/download/dataset.py#L64)):**
    ```python
    local_dir_path = Path(local_dir_path) # NO ANCHORING
    ```
* **Sink B ([Line 137](https://github.com/run-llama/llama_index/blob/v0.14.19/llama-index-core/llama_index/core/download/dataset.py#L137)):**
    ```python
    local_dir_path = Path(local_dir_path) # NO ANCHORING
    ```
#### **1.2 Persistence Sink (v0.14.19)**
* **Sink C ([Line 43](https://github.com/run-llama/llama_index/blob/v0.14.19/llama-index-core/llama_index/core/storage/kvstore/simple_kvstore.py#L43)):**
    ```python
    def persist(
        self, persist_path: str, fs: Optional[fsspec.AbstractFileSystem] = None
    ) -> None:
        """Persist the store."""
        fs = fs or fsspec.filesystem("file")
        dirpath = os.path.dirname(persist_path)
        if not fs.exists(dirpath):
            fs.makedirs(dirpath)

        with fs.open(persist_path, "w") as f: # <--- THE SINK: No validation of persist_path
            f.write(json.dumps(self._collections_mappings))
    ```

By passing a traversal string (e.g., `../../../../etc/cron.d/`), an attacker shifts the base directory. Any files written (including the `source_files` list) are subsequently deposited into the hijacked system path.

### **Insufficient Security Boundaries: The Filename Registry**

During the disclosure process, it was suggested that the `DATASET_CLASS_FILENAME_REGISTRY` prevented traversal. This assessment is architecturally inaccurate for the following reasons:

1. The registry only validates the **filename**, not the **directory path**.
2. The directory sink (`local_dir_path`) is hijacked **BEFORE** the registry check occurs.
3. Even if the filename is strictly forced to `rag_dataset.json`, the payload can still be written to critical locations (e.g., `/etc/cron.d/rag_dataset.json`).
4. The registry does not mitigate directory traversal and fails to act as a secure boundary.

---

### **2. Exploitation Mechanics**
Verified via forensic `.cast` recordings in an isolated environment.

#### **2.1 Core Library Overwrite (Permanent DoS/RCE)**
By targeting the core library's `__init__.py`, the exploit replaces executable Python code with malicious payloads.
* **Permanent DoS:** Overwriting with JSON strings causes a cascading interpreter panic upon next load.
* **RCE:** Overwriting with Python code results in immediate execution when the library is imported.
* **Forensic Evidence:** `nuke-llama-core.cast`

#### **2.2 Path Hijack RCE**
The `source_files` primitive allows writing arbitrary code payloads to high-privilege directories (e.g., cron jobs or shell profiles).
* **Forensic Evidence:** `llama-nuke-3.cast`.

### **Proof of Impact: The Supply Chain Risk**

**Evidence of Widespread Exposure:**
- **PyPI download statistics**: **35.6 million total downloads** (pypistats data)
- **GitHub adoption**: **49,210 stars** and **7,370 forks** (GitHub API)
- **GitHub dependents**: **2,300+ repositories** depend on vulnerable versions (GitHub dependency graph)
- **Enterprise adoption**: Contributor profiles indicate usage by technology company AI teams

**SCA Visibility Gaps:**
- Enterprise security scanners (Snyk, Dependabot) show no alerts for ≤v0.14.19
- No CVE assignment means vulnerability databases contain zero records
- Organizations trusting a framework with **35.6 million downloads** and **49k stars** operate with critical RCE exposure

---

### **3. Implications for AI/ML Security**

This vulnerability highlights fundamental requirements in **AI Orchestration Security**:

1. **Insecure Output Handling (OWASP LLM02)**: Untrusted LLM output must be strictly sanitized before being passed to system-level functions.
2. **Broken Sandbox Model**: AI frameworks must assume all LLM output is potentially malicious and enforce strict environmental boundaries.
3. **Supply Chain Amplification (OWASP LLM05)**: Vulnerable AI orchestration components can introduce persistent flaws across entire ML pipelines.
4. **Undocumented Remediation Undermines Trust**: Silent security fixes leave the enterprise community unaware of systemic risks and unable to prioritize patching.

The library overwrite vector illustrates how AI agents can be coerced into altering their own execution environment, creating self-propagating denial conditions.

---

### **4. Remediation Timeline & Undocumented Patching Strategy**
The remediation timeline reveals a pattern of migrating vulnerable code out of the core library without public acknowledgment, masking the security fix within non-security updates.

* **March 27, 2026:** **Initial Disclosure.** The report is officially disputed under the premise that the framework's registry acts as a security boundary.
* **April 3, 2026:** **Code Deletion (Release [v0.14.20](https://github.com/run-llama/llama_index/releases/tag/v0.14.20)).**
    * [Commit 7049c97d](https://github.com/run-llama/llama_index/commit/7049c97d): Documented as *"remaining cleanup, uv lock bump."* **Impact:** This commit entirely deleted the vulnerable `dataset.py` infrastructure identified in the PoC, patching the immediate vulnerability under the classification of routine maintenance.
* **April 20, 2026:** **Logic Migration (Release [v0.14.21](https://github.com/run-llama/llama_index/releases/tag/v0.14.21)).**
    * [Commit e8b22d9](https://github.com/run-llama/llama_index/commit/e8b22d9): Documented as *"Update llama-index-workflows dependency to >=2.14.0."* **Impact:** The logic for path sanitization and "data sinks" was migrated to the external `workflows` sub-package. By bumping the requirement to `v2.14.0+`, the secure path resolution logic was integrated back into the core framework without documenting a vulnerability in `llama-index-core`.
* **May 3, 2026:** **Sub-Package Remediation.**
    * [Commit 5191420](https://github.com/run-llama/llama_index/commit/5191420) (PR #21251): Documented as *"fix for typo in data_sinks."* **Impact:** This represents the formal remediation of the vulnerable `data_sinks` logic. By implementing the fix in the `workflows` sub-package ([v2.14.0](https://pypi.org/project/llama-index-workflows/2.14.0/)) and labeling it a typo, a formal security disclosure was avoided.

---
### **5. Disclosure Timeline**

**Actions Taken:**
1. **March 27, 2026**: Initial disclosure via Huntr with initial `.cast` recordings provided.
2. **March 28**: Technical rebuttal submitted to clarify the architectural limitations of the filename registry.
3. **April 8**: Escalation regarding the observed undocumented repository patches.
4. **April 10**: Additional `.cast` recordings submitted.
5. **April 13**: Final notice issued before pursuing independent publication.

**Vendor Response:**
- Classified the report as "N/A" (Not Applicable).
- Remediated the vulnerability across subsequent versions (v0.14.20/v0.14.21) via code migration and refactoring without public CVE assignment.

---
### **Appendices**

#### **Appendix 1: Forensic Proof & Exploitation Mechanics**

**The Vulnerability: Architectural Collapse via CWE-22**
The flaw is a classic Path Traversal (CWE-22) leading to Code Injection (CWE-94). By injecting traversal sequences (`../`) into dataset or storage parameters, an unauthenticated attacker can escape the intended directory sandbox and physically overwrite the Python interpreter's own source code.

**The Target: site-packages**
The primary exploit targets the core integrity of the library itself. By pointing the SDK sink at the host's `site-packages/llama_index/core/`, an attacker can overwrite the `__init__.py` file.

![Visual proof of the core library overwrite exploit](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/nuked-screen-shot.png)
> **Figure 1:** Visual proof of the library overwrite exploit. The healthy Python module has been physically replaced with a malicious JSON payload. Any subsequent attempt to import the library results in the immediate execution of the attacker's code.

**Forensic Script Repository**
The following scripts were uploaded to the project repository and utilized to verify the vulnerability across different stages of the research:
* [Primary Exploit PoC (py)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/redemption_poc_v2.py)
* [Exploit Payload (py)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/exploit.py)
* [Final Exploit Payload (py)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/final_redemption_v7.py)

---

#### **Appendix 2: Manual Remediation & Path Anchoring**
If your environment cannot be updated to `v0.14.21` (or if you are building custom AI agents), you must implement manual **Path Anchoring**.

**Secure Implementation Pattern:**
```python
import os
from pathlib import Path

def get_anchored_path(safe_root: str, user_input: str) -> Path:
    """
    Prevents Path Traversal (CWE-22) by resolving and anchoring the final path.
    """
    base_dir = Path(safe_root).resolve()
    target_path = Path(base_dir, user_input).resolve()
    
    if not str(target_path).startswith(str(base_dir)):
        raise PermissionError(f"CRITICAL: Path Traversal Attempt Blocked! {target_path}")
        
    return target_path
```

---

#### **Appendix 3: The Primary Exploit PoC (`redemption_poc_v2.py`)**

```python
# Proof of Concept: Hijacking the source_files primitive
from llama_index.core.download.dataset import download_dataset_and_source_files
from unittest.mock import patch

# TARGET: Escape the sandbox to overwrite host crontab
malicious_dir = "../../../../../etc/cron.d/"
malicious_file = "payload"

with patch("llama_index.core.download.dataset.get_file_content") as mock_get, \
     patch("os.makedirs"), patch("builtins.open", create=True) as mock_open:
    
    mock_get.return_value = ("* * * * * root /usr/bin/python3 /tmp/shell.py", None)
    
    download_dataset_and_source_files(
        local_dir_path="/app/safe_zone",
        source_files_dir_path=malicious_dir, 
        source_files=[malicious_file],       
        dataset_id="exploited",
        dataset_class_name="LabelledRagDataset",
        override_path=True
    )
    
    if mock_open.called:
        print(f"[!] VULNERABILITY CONFIRMED: Writing to {mock_open.call_args[0][0]}")
```

---

#### **Appendix 4: Detection & Mitigation Checklist**

**Detection:**
- Monitor for `SimpleKVStore.persist()` calls with suspicious paths or directory traversal patterns (`../`).
- Watch for `download_dataset_and_source_files()` with traversal patterns.
- Audit any unexpected file writes or modifications to Python's `site-packages` directory.

**Immediate Mitigation:**
1. Upgrade to `llama-index-core >= 0.14.21`
2. Implement path validation wrapper (Appendix 2)
3. Run AI agents with minimal filesystem permissions.

---

#### **Appendix 5: Independent Verification**

To verify this vulnerability:

1. Install vulnerable version:
   ```bash
   pip install llama-index-core==0.14.19
   ```

2. Run the PoC scripts provided in this report (`redemption_poc_v2.py`, `exploit.py`)

3. Check for:
   * JSON written to `__init__.py` in site-packages
   * `/tmp/llamaindex_pwned` flag file creation
   * Ability to write to arbitrary directories

---

#### **Appendix 6: Forensic Recording Demonstration Breakdown (Chronological)**

This section serves as the forensic artifacts for the JDP Security disclosure.

---

##### 1. nuke-llama-core
* **Target Environment:** LlamaIndex (`llama-index-core` v0.14.19 and below)
* **Execution Method:** **Autonomous Library Corruption**
* **Summary:** Demonstrates the primary permanent DoS and RCE vector. The exploit escapes the intended directory sandbox to physically overwrite the Python interpreter's `site-packages/llama_index/core/__init__.py` file.

**Supporting Files:**
* [Animated Visual (gif)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/nuke-llama-core.gif) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/nuke-llama-core.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/nuke-llama-core.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 2. llama-nuke-2
* **Target Environment:** LlamaIndex (`llama-index-core` v0.14.19 and below)
* **Execution Method:** **Path Hijack (Exploit Variant 2)**
* **Summary:** Provides secondary validation of the directory resolution sink manipulation, proving the reproducibility of the vulnerability across varied execution paths.

**Supporting Files:**
* [Animated Visual (gif)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-nuke-2.gif) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-nuke-2.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-nuke-2.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 3. llama-nuke-3
* **Target Environment:** LlamaIndex (`llama-index-core` v0.14.19 and below)
* **Execution Method:** **Path Traversal / Write Sink Hijack**
* **Summary:** Demonstrates the successful navigation of the restricted shell to achieve RCE via arbitrary host-level file writes, bypassing the `DATASET_CLASS_FILENAME_REGISTRY`.

**Supporting Files:**
* [Animated Visual (gif)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-nuke-3.gif) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-nuke-3.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-nuke-3.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 4. llama-rce-final2
* **Target Environment:** LlamaIndex (`llama-index-core` v0.14.19 and below)
* **Execution Method:** **Refined RCE Payload**
* **Summary:** A high-fidelity recording demonstrating the final RCE payload execution, mapping the traversal path directly to a sensitive host system file for immediate code execution upon import.

**Supporting Files:**
* [Animated Visual (gif)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-rce-final2.gif) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-rce-final2.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama-rce-final2.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 5. llama_final_v1
* **Target Environment:** LlamaIndex (`llama-index-core` v0.14.19 and below)
* **Execution Method:** **Persistence / Final Verification**
* **Summary:** The culmination of the research. This recording verifies the exploit's persistence across a clean-state environment, ensuring that the vulnerability remains exploitable through standard framework initialization.

**Supporting Files:**
* [Animated Visual (gif)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama_final_v1.gif) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama_final_v1.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/LLI/llama_final_v1.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---
