---
date: 2026-05-13
title: Threat Modeling in AI Orchestration - Serialization Boundary Evasion in Haystack
---

> **SECURITY ADVISORY:** Environments operating **Deepset Haystack AI (haystack-ai) with the `unsafe` feature enabled** are susceptible to framework integrity compromise via serialization bypass. This research demonstrates CVSS 10.0 Scope Change attacks that persist beyond application restarts, enabling permanent infrastructure compromise. Organizations are advised to implement the runtime security patches detailed in Appendix A to enforce strict serialization boundaries pending upstream architectural shifts.

---

# **SECURITY ADVISORY | JDP-2026-005**
## **Architectural Boundary Limitations: RCE via Serialization Bypass and Persistent Framework Compromise in Haystack**

**Research Series:** JDP Security Research Series (Disclosure #5)    
**Researcher:** Jeff Ponte (CISSP, CCSP, CEH) | Lead Researcher, JDP Security    
**Target:** Deepset Haystack (`haystack-ai`)    
**Affected Versions:** **All versions supporting the `unsafe` feature (Including Current Releases)** **Proposed Taxonomy:** **AISEC-01: Insecure AI Orchestration (Framework Integrity Compromise)** **CVSS v3.1 Score:** **10.0 (Critical)** | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`    
**Status:** **Vendor Classification: Accepted Risk / Intended Behavior (Unmitigated)** ---

**Executive Highlights:**
- **Vulnerability**: A serialization validation oversight allows untrusted payloads to mutate the `unsafe=False` boundary to `unsafe=True`.
- **Impact**: CVSS 10.0 Scope Change resulting in persistent orchestration framework compromise.
- **Context**: Highlights a critical divergence in industry threat modeling regarding the handling of security configuration within untrusted data ingestion pipelines.
- **Affected**: All Haystack versions utilizing the `unsafe` execution feature.
- **Risk**: Allows single-tenant or external pipeline manipulation to achieve host-level system access.

---

### **1. Executive Summary: Architectural Boundary Limitations**
This advisory documents a critical architectural vulnerability within the Haystack AI framework, specifically located in the `from_dict()` and `from_yaml()` deserialization methods. These methods implicitly trust security configuration flags embedded within untrusted payloads. Attackers can manipulate serialized pipeline definitions to arbitrarily toggle the `unsafe` security flag from `False` to `True`, effectively bypassing the Jinja2 sandbox and achieving unrestricted system execution.

**Insecure AI Orchestration:** This vulnerability highlights the emerging risks associated with **Insecure AI Orchestration**, wherein the orchestration framework itself acts as a "Confused Deputy." This occurs when a framework fails to enforce a rigid, deterministic isolation boundary between its internal security configuration and untrusted data payloads, allowing an attacker to dictate the framework's security posture via the data it processes.

**Trust Boundary Violation:** The framework documents the `unsafe` parameter as a security control but does not implement integrity validation during deserialization. This constitutes a severe trust boundary violation; the security mechanism designed to restrict execution is natively controllable by the execution payload itself.

**Code Analysis Reveals:**
1. **Unvalidated Input Routing**: `default_from_dict()` passes all `init_params` directly to component constructors without sanitation.
2. **Missing Flag Validation**: Core components such as `OutputAdapter` and `ConditionalRouter` do not strip or restrict `unsafe` flags during deserialization.
3. **Insecure Data Processing**: The serialization logic merges application security configurations with untrusted data ingress.
4. **Implementation Lifecycle Gap**: The `unsafe` feature was introduced in commit [`3e3f79b9285c5b56432aac3e4ef2309e5f31ea74`](https://github.com/deepset-ai/haystack/commit/3e3f79b9285c5b56432aac3e4ef2309e5f31ea74) without corresponding safeguards in the `from_dict` hydration pipeline.

**Exploitation Risks:**
* **SaaS Multi-Tenant Escape**: Enables a single tenant to achieve unauthorized access to the underlying provider infrastructure.
* **Cache Integrity Compromise**: Malicious configurations injected via Redis/Memcached execute autonomously upon retrieval.
* **Persistent Framework Alteration**: Host-level code injection survives pipeline deletion and application reboots.
* **Supply Chain Propagation**: Malicious pipeline definitions can compromise downstream deployments seamlessly.

### **2. CVSS v3.1 & CWE Mapping**
The score of **10.0** is justified by the following vector: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

* **Attack Vector (AV: N)**: Network - Executable via HTTP APIs, message queues, or database ingestion of malicious pipelines.
* **Attack Complexity (AC: L)**: Low - Achieved via simple boolean manipulation (`"unsafe": true`).
* **Privileges Required (PR: N)**: None - Deserialization triggers prior to standard authentication boundaries.
* **User Interaction (UI: N)**: None - Code executes autonomously upon pipeline initialization.
* **Scope (S: C): CHANGED** - The exploit traverses the application boundary to compromise the underlying infrastructure layer.
* **Confidentiality, Integrity, Availability (C:H, I:H, A:H)**: High - Complete system access and framework modification.

**Primary CWE Mappings:**
* **CWE-502 (Deserialization of Untrusted Data):** The framework instantiates objects from YAML/Dict payloads without validating the embedded security directives.
* **CWE-94 (Improper Control of Generation of Code / 'Code Injection'):** Manipulation of the `unsafe` flag grants the attacker direct control over the Jinja2 execution environment.
* **CWE-184 (Incomplete List of Disallowed Inputs):** The serialization engine fails to filter or strip critical security parameters during object hydration.

### **3. Forensic Evidence: Architectural Source Analysis**

**A. `OutputAdapter.from_dict()` - Unvalidated Input (Lines 161-179):**
```python
def from_dict(cls, data: dict[str, Any]) -> "OutputAdapter":
    """
    Deserializes the component from a dictionary.
    """
    init_params = data.get("init_parameters", {})
    init_params["output_type"] = deserialize_type(init_params["output_type"])
    
    custom_filters = init_params.get("custom_filters", {})
    if custom_filters:
        init_params["custom_filters"] = {
            name: deserialize_callable(filter_func) if filter_func else None
            for name, filter_func in custom_filters.items()
        }
    return default_from_dict(cls, data)  # LACKS UNSAFE FLAG STRIPPING
```

**B. `ConditionalRouter.from_dict()` - Unvalidated Input (Lines 280-304):**
```python
def from_dict(cls, data: dict[str, Any]) -> "ConditionalRouter":
    """
    Deserializes the component from a dictionary.
    """
    init_params = data.get("init_parameters", {})
    routes = init_params.get("routes")
    for route in routes:
        if isinstance(route["output_type"], list):
            route["output_type"] = [deserialize_type(t) for t in route["output_type"]]
        else:
            route["output_type"] = deserialize_type(route["output_type"])

    custom_filters = init_params.get("custom_filters", {})
    if custom_filters is not None:
        for name, filter_func in custom_filters.items():
            init_params["custom_filters"][name] = deserialize_callable(filter_func) if filter_func else None
    return default_from_dict(cls, data)  # LACKS UNSAFE FLAG STRIPPING
```

**C. `default_from_dict()` - Unrestricted Deserialization (serialization.py):**
```python
def default_from_dict(cls: type[T], data: dict[str, Any]) -> T:
    """
    Utility function to deserialize a dictionary to an object.
    """
    init_params = data.get("init_parameters", {})
    # ... type validation only ...
    return cls(**init_params)  # PASSES ALL PARAMETERS TO CONSTRUCTOR UNFILTERED
```

**D. Architectural Limitations vs. Implementation**
The root cause is located in `haystack/core/serialization.py`. The deserialization sink exists because `default_from_dict` functions as a direct pass-through, mapping untrusted dictionary keys directly to Python class constructor arguments (`**init_params`). 

By implementing the `unsafe` flag as a standard constructor argument, the architecture implicitly grants the payload identical authority to the developer regarding security configuration. 

**E. Codebase Validation:**
```bash
# Audit confirms absence of security flag stripping in affected components:
$ grep -n "pop.*unsafe\|unsafe.*pop" haystack/components/converters/output_adapter.py
# NO OUTPUT - Mitigation absent

$ grep -n "pop.*unsafe\|unsafe.*pop" haystack/components/routers/conditional_router.py
# NO OUTPUT - Mitigation absent

$ grep -i "unsafe\|security" haystack/core/serialization.py
# NO OUTPUT - Security validation absent in serialization engine
```

### **4. Exploitation Lifecycle**
The following analysis details the exploitation methodology, verified via forensic terminal recordings (see Appendix C).

**A. Pipeline Manipulation**
* **Initialization:** A production-equivalent sandbox is initialized with Haystack 2.27.0. Baseline integrity checks confirm standard operation.
* **Payload Ingestion:** A malicious YAML pipeline definition is processed via `Pipeline.from_dict(data)`. 
    * **The Bypass:** The YAML strictly defines `"unsafe": true` within the `init_parameters` block of an `OutputAdapter`.
    * **The Payload:** The embedded Jinja2 template contains standard SSTI breakout logic: `{{ self.__init__.__globals__.__builtins__.__import__('os').system(...) }}`.
* **Execution:** Due to the absence of parameter validation during `from_dict`, the framework initializes the component in unsafe mode. Upon `pipe.run()`, the underlying OS commands are executed.

**B. Scope Change & Persistent Compromise**
* **Filesystem Alteration:** Forensic auditing demonstrates that the initial RCE is utilized to append obfuscated Python logic directly into the global framework dependency: `/usr/local/lib/python3.11/site-packages/haystack/__init__.py`.
* **Execution Verification:** A fully independent Python execution context is initiated. Upon executing the standard `import haystack` declaration, the compromised framework immediately executes the injected payload, confirming that the transient pipeline attack has escalated to persistent host-level infrastructure compromise.

### **5. The OWASP Bridge: Proposing AISEC-01 (Insecure AI Orchestration)**
Traditional AppSec models emphasize vulnerabilities such as Insecure Deserialization (CWE-502) and align with frameworks like the OWASP Top 10. However, this disclosure underscores a specialized, emerging threat vector necessitating expansion of the OWASP Top 10 for LLM Applications: **Insecure AI Orchestration**.

This occurs when an AI framework fails to enforce an absolute, deterministic boundary between operational "System Configuration" and "Untrusted Stochastic Data." When orchestration logic permits execution toggles to be dictated by the data payloads they are intended to govern, traditional LLM sandboxing controls (such as containerization and output parsing) become ineffective. This architectural vulnerability proves that AI orchestration frameworks introduce fundamental infrastructure risks that standard vulnerability scanning and LLM safety benchmarks currently overlook.

### **6. Implementation Context: Commit 3e3f79b9285c5b56432aac3e4ef2309e5f31ea74**
**Commit:** [`3e3f79b9285c5b56432aac3e4ef2309e5f31ea74`](https://github.com/deepset-ai/haystack/commit/3e3f79b9285c5b56432aac3e4ef2309e5f31ea74) 
**Date:** September 2, 2024
**Context:** Analysis indicates that while the vendor explicitly intended to gate sensitive execution behaviors behind a flag, the implementation omitted the necessary validation logic within the serialization engine.

**Original Release Notes:**
```yaml
features:
  - |
    Add `unsafe` argument to enable behaviour that could lead to remote code execution in `ConditionalRouter` and `OutputAdapter`.
    By default unsafe behaviour is not enabled, the user must set it explicitly to `True`.
```

**Vulnerability Introduction:**
```python
# From commit 3e3f79b9285c5b56432aac3e4ef2309e5f31ea74
class OutputAdapter:
    def __init__(self, template: str, output_type: type, unsafe: bool = False):
        self._unsafe = unsafe  # Control definition...
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OutputAdapter":
        init_params = data.get("init_parameters", {})
        return cls(
            template=init_params.get("template", ""),
            output_type=init_params.get("output_type", str),
            unsafe=init_params.get("unsafe", False)  # ...Control bypassable via untrusted dictionary.
        )
```

### **7. Impact Analysis: Persistent Framework Compromise (Scope Change)**
This vulnerability necessitates a **Critical (10.0)** classification due to the verified **Scope Change (S:C)**. The initial code execution achieved via the serialization bypass allows an attacker to modify core library binaries on the host filesystem.

**Exploitation Trajectory:**
1. **Ingestion:** The orchestration engine processes a maliciously crafted YAML pipeline, resolving the `unsafe` flag to `true`.
2. **Escalation:** The payload breaches the Jinja2 boundary, acquiring write permissions to the Python `site-packages` directory.
3. **Modification:** The attacker injects persistent code into the global `haystack/__init__.py` file.
4. **Persistence:** Any subsequent application or service on that host invoking the `haystack` library executes the injected code synchronously.

### **8. Threat Modeling Divergence & Current Status**
**A. Vendor Risk Classification**
In response to the coordinated disclosure, Deepset's Security Team provided the following assessment, highlighting a divergence in threat modeling paradigms between the framework maintainers and enterprise security practitioners:

> "After an internal investigation, we don't consider this a security vulnerability in the Haystack framework... We classify this as trusted configuration behavior rather than a framework vulnerability, and we will not be treating it as a security issue." - Julian Risch, Deepset (April 1, 2026)

**B. Release Verification (v2.28.0)**
Following the disclosure window, the vendor released `haystack-ai` v2.28.0 on **April 20, 2026**. Forensic diffing confirms the framework's continued adherence to this design philosophy, with no serialization validation implemented:

```bash
$ git tag --list | grep 2.28
v2.28.0

$ git log --oneline -1 66af63798
66af63798 (tag: v2.28.0, origin/v2.28.x) bump version to 2.28.0

$ git show 66af63798 --stat
VERSION.txt | 2 +-
1 file changed, 1 insertion(+), 1 deletion(-)
```

**C. Active Status**
**Last Analysis:** Repository HEAD 
**Vendor Stance:** Accepted Risk / Intended Behavior
**Security State:** **UNMITIGATED** - The vulnerability remains fully exploitable within default deployments.
**Detection Status:** False Negative expected across standard DAST/SAST scanners due to lack of CVE assignment.

---

### **9. Mitigation & Remediation Guidelines**
**Immediate Enterprise Actions:**
1. **Assume Compromise Model**: Treat deployments processing external Haystack pipelines as potentially vulnerable.
2. **Forensic Filesystem Auditing**: Verify the integrity of the framework source on disk:
   `tail -n 5 /usr/local/lib/python3.x/site-packages/haystack/__init__.py`
3. **Execution Isolation**: Strongly segment Haystack worker nodes from highly privileged infrastructure.
4. **Telemetry Detection**: Deploy runtime monitoring to detect unexpected instantiation of the `unsafe` flag.

**Application-Layer Mitigations (Virtual Patching):**
1. **Cryptographic Signatures**: Mandate HMAC signing and validation for all serialized pipeline definitions.
2. **Pre-Sink Schema Validation**: Implement strict JSON/YAML schema validation to drop any payload containing `"unsafe": true`.
3. **Runtime Remediation**: Implement the provided Python application-layer patch (Appendix A) to strip security parameters prior to framework ingestion.

---

### **10. Strategic Security Takeaways**

1. **AI Framework Architectures Require Auditing**: Conventional vulnerability scanners frequently miss framework-level architectural flaws. Security teams must analyze AI orchestration engines as core infrastructure components with complex trust boundaries.
2. **Serialization Sinks are Critical Vectors**: Methods like `from_dict()` represent primary trust boundaries. Any serialization mechanism processing untrusted data must explicitly filter security-critical parameters prior to object hydration.
3. **Scope Change is a Concrete Threat**: RCE within orchestration frameworks easily transitions into persistent infrastructure compromise. The CVSS S:C metric is practically demonstrated when frameworks lack filesystem write restrictions.
4. **Independent Validation is Mandatory**: Threat models vary between open-source maintainers and enterprise consumers. Organizations must rely on empirical validation and implement defense-in-depth compensating controls.
5. **Runtime Detection Imperatives**: Traditional signature-based detection is inadequate for novel AI execution paths. Organizations must monitor for security flag manipulation and unauthorized template execution natively.

---

### **11. Conclusion**

The JDP-2026-005 vulnerability within Deepset's Haystack highlights a critical industry-wide challenge in AI orchestration security design. Relying on a "trusted configuration behavior" model—when the configuration can be arbitrarily altered by untrusted pipeline data—demonstrates a gap in modern framework threat modeling. When a documented security control (`unsafe=False`) is natively bypassable via the framework's own ingestion APIs, the deterministic integrity of the application stack is degraded.

This analysis of **Insecure AI Orchestration** illustrates that conventional application security assumptions are frequently incompatible with AI framework architectures. The vulnerability resides not in an isolated code bug, but in a systemic architectural design that dissolves the boundary between security enforcement and data processing. The continued exposure in current releases underscores the need for organizations to implement immediate, independent compensating controls.

JDP Security advocates for the following industry standard practices to align with OWASP principles:
1. **Deterministic Serialization**: Implementation of explicit parameter stripping during deserialization workflows to prevent execution overlap.
2. **Cryptographic Validation**: Built-in integrity protections (HMAC/Signatures) for all serialized pipeline components.
3. **Shared Responsibility Clarity**: Explicit documentation defining the trust boundaries and limitations of framework-level sandboxing.

Security within AI orchestration cannot rely on implicit trust of serialized data; execution boundaries must be architecturally enforced and deterministically validated.

---

### **Appendix A: Application-Layer Mitigation Implementation**

**1. Runtime Security Patch (Validation Wrapper):**
Apply this logic at the application entry point to intercept and sanitize untrusted parameters before framework execution.
```python
import haystack.components.converters.output_adapter as oa
import haystack.components.routers.conditional_router as cr

# Hardened OutputAdapter Deserialization
original_from_dict = oa.OutputAdapter.from_dict
@classmethod
def secured_from_dict(cls, data):
    if "init_parameters" in data:
        data["init_parameters"].pop("unsafe", None)
    return original_from_dict(data)
oa.OutputAdapter.from_dict = secured_from_dict

# Hardened ConditionalRouter Deserialization
original_cr_from_dict = cr.ConditionalRouter.from_dict
@classmethod  
def secured_cr_from_dict(cls, data):
    if "init_parameters" in data:
        data["init_parameters"].pop("unsafe", None)
    return original_cr_from_dict(data)
cr.ConditionalRouter.from_dict = secured_cr_from_dict
```

**2. Pre-Sink Schema Validation:**
```python
from jsonschema import validate, ValidationError

SERIALIZATION_SCHEMA = {
    "type": "object",
    "properties": {
        "init_parameters": {
            "type": "object",
            "properties": {
                "unsafe": {
                    "type": "boolean",
                    "enum": [False]  # Strict enforcement of safe execution
                }
            }
        }
    }
}

def validate_pipeline(data):
    try:
        validate(instance=data, schema=SERIALIZATION_SCHEMA)
        return True
    except ValidationError:
        return False
```

### **Appendix B: Disclosure Timeline**
* **March 31, 2026:** Coordinated vulnerability disclosure submitted to Deepset.
* **April 1, 2026:** Vendor categorizes the architectural flaw as "trusted configuration behavior."
* **April 8 - 11, 2026:** Supplemental forensic demonstrations provided to the vendor.
* **April 20, 2026:** Vendor releases `haystack-ai` v2.28.0; forensic diff confirms mitigation absence.
* **May 13, 2026:** Public disclosure executed via JDP Security Research Series.
* **Current Status:** The vulnerability remains active and requires application-layer mitigation.

---

### **Appendix C: Forensic Artifacts and Demonstration Logs**

This section provides visual artifacts confirming the execution methodologies and tracking the vulnerability lifecycle across the Haystack orchestration framework.

#### **C.1 Baseline Exploit Demonstration**
* **Target Environment:** `haystack-ai` (with `unsafe` feature enabled)
* **Execution Method:** **Transient Pipeline Execution**
* **Summary:** Establishes the baseline vulnerability state. Demonstrates the execution of arbitrary host commands via manipulated pipeline initialization parameters.
* **Supporting Artifacts:**
    * [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_exploit_demo.cast)
    * [GIF Recording](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_exploit_demo.gif)

<video width="100%" controls poster="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_exploit_demo.png">
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_exploit_demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

#### **C.2 YAML Serialization Bypass**
* **Target Environment:** `haystack-ai` YAML Deserialization Engine
* **Execution Method:** **File-Based Pipeline Ingestion**
* **Summary:** Proves that standard `.yaml` pipeline configurations can natively bypass the intended `unsafe=False` security barrier during the `from_yaml()` ingestion process, leading to immediate code execution.
* **Supporting Artifacts:**
    * [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_yaml_10_0_FINAL-NUKE-3.cast)
    * [GIF Recording](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_yaml_10_0_FINAL-NUKE-3.gif)

<video width="100%" controls poster="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_yaml_10_0_FINAL-NUKE-3.png">
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_yaml_10_0_FINAL-NUKE-3.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

#### **C.3 Framework Integrity Compromise (Scope Change)**
* **Target Environment:** `haystack-ai` Host Filesystem
* **Execution Method:** **Persistent Code Injection**
* **Summary:** Demonstrates the CVSS Scope Change (S:C) impact. The initial RCE is weaponized to rewrite the global `haystack/__init__.py` dependency on the host system, converting a transient pipeline flaw into a permanent architectural backdoor.
* **Supporting Artifacts:**
    * [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V4_NUKE.cast)
    * [GIF Recording](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V4_NUKE.gif)

<video width="100%" controls poster="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V4_NUKE.png">
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V4_NUKE.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

#### **C.4 Persistence Verification and Audit**
* **Target Environment:** Compromised Application Node
* **Execution Method:** **Post-Exploitation Execution Verification**
* **Summary:** Confirms that the host-level infection survives pipeline destruction and process termination. Initializing a clean Python process and executing `import haystack` triggers the attacker's persistent payload synchronously.
* **Supporting Artifacts:**
    * [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V5_AUDIT-NUKE.cast)
    * [GIF Recording](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V5_AUDIT-NUKE.gif)

<video width="100%" controls poster="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V5_AUDIT-NUKE.png">
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/HS/haystack_10_0_FINAL_V5_AUDIT-NUKE.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---
