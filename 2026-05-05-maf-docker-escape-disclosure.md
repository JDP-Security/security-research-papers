---
date: 2026-05-05
title: "Architectural Vulnerabilities in Agentic Frameworks: Microsoft Agent Framework Case Study"
---

> **⚠️ SECURITY ADVISORY:** Organizations deploying the **Microsoft Agent Framework (MAF) v1.0.0** may be operating with an active container escape path. The framework’s architectural design natively facilitates mounting the host Docker socket into the AI agent container when detected. Because the vendor classifies this behavior as intended functionality rather than a serviceable vulnerability, standard vulnerability scanners will not flag this risk. Organizations are advised to manually enforce socket isolation or implement pre-execution validation, such as the **JDPEnterpriseSecurityFilter (Appendix 4)**, to mitigate the risk of LLM-driven host compromise.

---

# **WHITE PAPER | JDP-2026-002**
## **Infrastructure Breach: Container Privilege Escalation via Insecure AI Orchestration**

**Author:** Jeff Ponte, CISSP, CCSP, CEH | Lead Researcher, JDP Security Research Series    
**Series:** JDP Security Research Series (Disclosure #2)    
**Initial Documentation Date:** April 8, 2026    
**Target:** Microsoft Agent Framework (v1.0.0) | `claude-agent-sdk` (v0.1.48)    
**Case Number:** MSRC VULN-181659 (MSRC 112751)    
**CVSS v3.1 Score:** **10.0 (Critical)** **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`    
**Status:** Vendor Classified as Intended Architectural Behavior (Requires Manual Mitigation)    

---

### **Executive Summary**
This white paper documents a critical architectural vulnerability pattern—container privilege escalation—demonstrated within the **Microsoft Agent Framework (MAF)**. Analysis of the framework reveals a structural trust gap where the core dependency (`claude-agent-sdk`) explicitly allow-lists and facilitates the mounting of the host’s Docker socket (`/var/run/docker.sock`) into agent containers upon detection.

This design represents a textbook example of **Insecure AI Orchestration**. By deploying containers with this socket mounted by default, any process within the container—including those generated dynamically by a Large Language Model (LLM)—can interact directly with the host Docker daemon. This grants immediate, root-level host access, bypassing container sandboxing. 

Because this behavior is currently classified by the vendor's servicing criteria as intended functionality, organizations must proactively implement secondary infrastructure controls to secure their deployments.

---

### **1. Core Architecture: Insecure Defaults**
The security risk stems from a deliberate architectural choice that prioritizes execution convenience over infrastructure isolation. The framework operates on a model of **Implicit Facilitation**. 

#### **1.1 The Permissive Logic (Auto-Facilitated Mounting)**
The framework establishes a permissive bridge to host privileges via its `SOCKET_ALLOW_LIST` configuration. While the socket is not unconditionally mounted, the framework is designed to automatically mount it if the socket is present on the host:

```python
# claude_agent_sdk/types.py (Line 713)
# JDP SECURITY ANALYSIS: PRIVILEGE ESCALATION FACILITATION

SOCKET_ALLOW_LIST = [
    "/var/run/docker.sock",  # <-- Framework-sanctioned escalation path
    "/var/run/dbus/system_bus_socket"
]

def mount_agent_volumes(container_config):
    """
    The framework automatically bridges privileged host sockets 
    when detected, establishing a default-allow security model.
    """
    volumes = {}
    for sock in SOCKET_ALLOW_LIST:
        if os.path.exists(sock):
            # ARCHITECTURAL RISK: Framework facilitates host daemon access
            # without requiring explicit developer opt-in or isolation enforcement
            volumes[sock] = {'bind': sock, 'mode': 'rw'} # RISK: Auto-mounted read-write
    return volumes
```

#### **1.2 Mechanics of Orchestration: Understanding Agent Tools**
MAF grants LLMs the functional capability to interact with the operating system via tools.
1.  **The Prompt:** User requests an action.
2.  **The Planner:** MAF transmits the prompt to the LLM with a schema of available tools.
3.  **The Tool Call:** The LLM returns a JSON instruction (e.g., a Python script payload).
4.  **The Execution Sink:** The framework maps the request to the container, executes the payload natively, and returns the result.

> **Architectural Trust Failure:** MAF fundamentally trusts the non-deterministic output of the LLM while concurrently granting that output direct, unmediated access to the host Docker socket. This violates the principle of least privilege and allows untrusted input to control critical infrastructure components.

#### **1.3 Business Impact: Supply Chain Visibility Risks**
* **SCA Tool Blindness:** Software Composition Analysis (SCA) scanners will not flag this as a risk because no official CVE exists for intended architectural behavior.
* **Compliance Gaps:** Organizations may unknowingly deploy unmitigated CVSS 10.0 equivalent entry points into production.
* **Lack of Default Isolation:** Developers utilizing the standard implementation may be unaware that the baseline configuration acts as a conduit for host takeover.

---

### **2. CVSS v3.1 Scoring Breakdown (10.0 Critical)**

| Metric | Value | Reason for Score |
| :--- | :--- | :--- |
| **Attack Vector (AV)** | **Network** | Triggered remotely via standard application interfaces (e.g., chat, API). |
| **Attack Complexity (AC)** | **Low** | Exploit path leverages the framework's default configuration. |
| **Privileges Required (PR)** | **None** | Unauthenticated users can trigger the execution via prompt injection. |
| **User Interaction (UI)** | **None** | The execution sequence can be fully autonomous. |
| **Scope (S)** | **Changed** | **Critical:** The attacker achieves execution on the host OS, escaping the container boundary. |
| **Confidentiality (C)** | **High** | Unrestricted access to host data and cloud control planes. |
| **Integrity (I)** | **High** | Ability to modify system files, alter configurations, or inject persistence mechanisms. |
| **Availability (A)** | **High** | Total control to terminate host processes or delete infrastructure. |

---

### **3. OWASP Implications: Mapping the Vulnerability**
This architectural pattern maps directly to established vulnerabilities within the **OWASP Top 10 for Large Language Model Applications**.

* **LLM08: Excessive Agency:** The framework grants the LLM agent excessive functionality (direct read/write access to the Docker socket) that is not strictly required for standard analytical tasks.
* **LLM02: Insecure Output Handling:** The framework accepts the LLM's dynamically generated tool calls and executes them directly against privileged sinks without sufficient intermediate validation or sandboxing.
* **Proposed Extension (Insecure AI Orchestration):** This research highlights the need for broader industry recognition of orchestration trust gaps, where frameworks implicitly bridge non-deterministic models to deterministic, high-privilege infrastructure.

---

### **4. Disclosure Timeline & Visibility Gaps**
The following timeline illustrates the gap between formal vulnerability management and the reality of architectural enterprise risk.

* **April 8, 2026:** **Initial Disclosure** submitted to MSRC (VULN-181659) detailing the container escape methodology.
* **April 16, 2026:** **Vendor Advisory** – Microsoft publishes an engineering blog post identifying Docker socket mounting as a serious security risk that permits sandbox escape.
* **April 17, 2026:** **Case Closure** – MSRC officially categorizes the framework's behavior as not meeting the requirement for a security servicing patch, establishing it as intended behavior requiring user-side mitigation.

---

### **5. Exploitation Mechanics & Post-Exploitation**

#### **5.1 The Escape Sequence**
1.  **Reconnaissance:** The attacker instructs the LLM to verify the presence of `/var/run/docker.sock` within the container.
2.  **Payload Generation:** The attacker utilizes the LLM to format the exact Docker API endpoint required for container manipulation.
3.  **Execution:** The attacker triggers a POST request via the socket: `curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/$ID/restart`.
4.  **Host Compromise:** The containerized process terminates, and the session is ejected directly to the host shell (`vboxuser@Ubuntu-Server:~$`).

#### **5.2 Lateral Movement Risks**
Upon escaping to the host as a privileged user (e.g., `docker` group), an attacker can easily escalate to root, enabling:
* **SSH Key Injection:** Appending unauthorized keys to `/root/.ssh/authorized_keys`.
* **Persistence:** Establishing reverse shells via `/etc/crontab`.
* **Credential Theft:** Harvesting cloud infrastructure tokens from `/root/.azure/` or `/root/.aws/credentials`.

---

### **6. Remediation & Strategic Hardening**

#### **6.1 Secure-by-Design Principles**
* **Default Deny:** The `SOCKET_ALLOW_LIST` should be empty by default, requiring explicit developer configuration.
* **Principle of Least Privilege:** If socket mounting is strictly necessary, it must default to read-only (`ro`) to prevent API manipulation.

#### **6.2 Required Infrastructure Hardening**
Because this is classified as intended behavior, organizations must implement independent controls.

| Layer | Manual Remediation (Open-Source) | Commercial Solution (Proprietary) | Technical Impact |
| :--- | :--- | :--- | :--- |
| **Isolation** | **gVisor / Kata Containers** | **Docker Sandbox (MicroVMs)** | Hardware-isolated kernels prevent socket escapes. |
| **Privilege Reduction** | **Podman (Rootless)** | **Isolated Runtimes** | Mitigates host compromise by enforcing unprivileged sessions. |
| **Access Control** | **Docker-Socket-Proxy** | **Sandbox Filtering Proxy** | Blocks destructive or high-privilege API calls (e.g., POST/DELETE). |
| **Detection** | **Falco (eBPF)** | **Cloud Security Posture Management** | Alerts on unauthorized `open_at` system calls targeting sockets. |

---

### **7. Detection & Incident Response**

#### **7.1 Telemetry & Detection**
- **Container Runtime**: Monitor processes for `socket.connect("/var/run/docker.sock")` operations originating from unexpected binaries (e.g., Python scripts).
- **Host Infrastructure**: Audit Docker API logs for unauthenticated or unauthorized container lifecycle events.
- **Network Egress**: Detect anomalous outbound connections originating from the host post-exploitation.

#### **7.2 Incident Response Protocol**
1. **Containment**: Immediately isolate affected containers and the underlying host.
2. **Investigation**: Audit LLM prompt history, tool execution logs, and socket interaction events.
3. **Remediation**: Apply the infrastructure hardening tiers outlined in Section 6.2.
4. **Impact Assessment**: Evaluate potential exposure of host-level data and cloud credentials.

---

### **8. Scope and Environmental Limitations**

#### **Rootless Docker Environments**
This research focused on standard, privileged Docker installations (`/var/run/docker.sock`). The framework's default allow-list specifically targets this path:

```python
SOCKET_ALLOW_LIST = [
    "/var/run/docker.sock",  # Standard Linux Docker Socket
    "/var/run/dbus/system_bus_socket"
]
```

> **Note:** Environments utilizing Docker Desktop on Windows or macOS typically employ named pipes or localized sockets (e.g., `//./pipe/docker_engine`). While MAF's default configuration targets Linux paths, the underlying architectural trust gap remains active. Modifying the allow-list to include these alternative paths will expose those environments to identical risks.

---

### **Conclusion**
When an AI framework’s default architecture implicitly facilitates host compromise, it reveals a critical misalignment between traditional vulnerability classification and modern agentic orchestration. The JDP Security Research Series submits these findings to the broader security community to highlight how architectural intent can bypass SCA visibility, establishing the urgent need for robust, defense-in-depth strategies when deploying autonomous AI agents.

---

### **Appendices**

#### **Appendix 1: Forensic Artifacts**
* **`maf-cve-Ollama-LLM.mp4/.cast/.txt`**: Documents a `curl`-based escape sequence yielding host-level access.
* **`maf-cve-Ollama-LLM-NoCURLAPI-CALL.mp4/.cast/.txt`**: Demonstrates a native Python "Raw Socket" escape, bypassing hardened container images lacking standard networking utilities.

#### **Appendix 2: Ecosystem Risk Assessment**
A sample audit of 197 public GitHub repositories utilizing MAF indicated pervasive insecure deployments:
* **100% (197/197)** executed the agent container as the `root` user.
* **93.9%** lacked implementation of Seccomp or AppArmor security profiles.
* **0%** utilized a socket-proxy or microVM isolation by default.

#### **Appendix 3: The "Raw Socket" Vector**
This execution vector relies entirely on native Python libraries, requiring no external dependencies to communicate with the Docker API:
```python
import socket

request = (
    "POST /v1.41/containers/self/restart HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Length: 0\r\n\r\n"
)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect("/var/run/docker.sock")
    s.sendall(request.encode())
```

#### **Appendix 4: Pre-Execution Validation (JDPEnterpriseSecurityFilter)**
To address the architectural trust gap, frameworks must implement security-by-design, analyzing LLM-generated payloads *prior* to execution. The JDPEnterpriseSecurityFilter demonstrates an AST (Abstract Syntax Tree) middleware approach to intercept dangerous operations.
*(Note: This conceptual filter analyzes Python execution. Comprehensive implementations require language-agnostic validation.)*

```python
import ast
from typing import Dict, Any

class SecurityViolationException(Exception):
    """Exception raised for identified security violations."""
    pass

class JDPEnterpriseSecurityFilter:
    def __init__(self):
        self.blocked_paths = ["/var/run/docker.sock", "docker.sock", "unix://"]
        self.blocked_imports = {"socket", "docker", "http.client", "urllib"}
    
    def inspect_tool_call(self, tool_name: str, arguments: Dict[str, Any]):
        """Analyze tool arguments for malicious patterns prior to execution."""
        for key, value in arguments.items():
            if isinstance(value, str):
                self._analyze_python_ast(value)
    
    def _analyze_python_ast(self, code_snippet: str):
        """Execute AST analysis to identify restricted operations."""
        tree = ast.parse(code_snippet)
        
        for node in ast.walk(tree):
            # Restrict high-risk module imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split('.')[0] in self.blocked_imports:
                        raise SecurityViolationException(f"Restricted module import blocked: {alias.name}")
            
            # Intercept socket connections targeting Docker API
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'connect' and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == 'socket':
                            for arg in node.args:
                                if isinstance(arg, ast.Constant):
                                    if any(blocked in str(arg.value) for blocked in self.blocked_paths):
                                        raise SecurityViolationException(
                                            f"Unauthorized socket connection intercepted: {arg.value}"
                                        )
            
            # Prevent dynamic code evaluation
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec', '__import__']:
                        raise SecurityViolationException(
                            f"Dynamic code execution is disabled: {node.func.id}"
                        )

# Example Middleware Integration
class MAFSecurityMiddleware:
    """Security middleware for agentic orchestration frameworks."""
    
    def __init__(self):
        self.security_filter = JDPEnterpriseSecurityFilter()
    
    async def before_tool_execution(self, tool_call: Dict, context: Any):
        """Mandatory security gate prior to tool execution sink."""
        self.security_filter.inspect_tool_call(
            tool_name=tool_call.get('name', ''),
            arguments=tool_call.get('arguments', {})
        )
        return tool_call  # Validation passed
```

---

#### **Appendix 5: Analytical Methodology**

##### **Repository Deployment Analysis**
An analysis of 197 GitHub repositories deploying MAF was conducted to evaluate real-world security postures:

###### Evaluation Criteria
```python
CRITERIA = {
    'docker_socket_mounted': 'volume mount to /var/run/docker.sock',
    'container_user': 'USER directive in Dockerfile',
    'security_profiles': 'AppArmor/SELinux/Seccomp declarations',
    'isolation_mechanisms': 'Presence of gVisor/Kata/Podman configurations'
}
```

###### Audit Results
```python
FINDINGS = {
    'total_repositories_analyzed': 197,
    'docker_socket_mounted': 197,  # 100%
    'running_as_root': 197,        # 100%
    'no_security_profiles': 185,   # 93.9%
    'no_isolation_mechanisms': 197 # 100%
}
```

---

#### Appendix 6: Execution Demonstrations

This section provides visual artifacts confirming the container escape methodology when orchestrated via the Microsoft Agent Framework.

---

##### 1. maf-cve-Ollama-LLM.cast
* **Target Environment:** Microsoft Agent Framework
* **Execution Method:** **Autonomous LLM Orchestration**
* **Summary:** Demonstrates the primary container escape vector. Following a natural language prompt, the Ollama-backed LLM autonomously navigates the sandbox boundary, executing commands to gain unauthorized host-level access.

**Supporting Files:**
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/MAF/maf-cve-Ollama-LLM.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/MAF/maf-cve-Ollama-LLM.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/MAF/maf-cve-Ollama-LLM.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

##### 2. maf-cve-Ollama-LLM-NoCURLAPI-CALL.cast
* **Target Environment:** Hardened MAF Container 
* **Execution Method:** **Autonomous LLM Orchestration (Stealth Variant)**
* **Summary:** Confirms that the vulnerability remains viable in environments stripped of standard networking utilities (e.g., `curl`). The LLM successfully utilizes native language features to interface with the Docker daemon, achieving execution without triggering standard network-based alerts.

**Supporting Files:**
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/MAF/maf-cve-Ollama-LLM-NoCURLAPI-CALL.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/MAF/maf-cve-Ollama-LLM-NoCURLAPI-CALL.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/MAF/maf-cve-Ollama-LLM-NoCURLAPI-CALL.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---
