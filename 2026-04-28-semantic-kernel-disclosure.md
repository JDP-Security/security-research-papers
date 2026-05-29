---
date: 2026-04-28
title: "Architectural Vulnerabilities in AI Orchestration: A Semantic Kernel Case Study"
---
> **⚠️ SECURITY ADVISORY:** Environments utilizing **Microsoft Semantic Kernel (.NET SDK) version 1.48.0 or below**, or **Agent Framework 1.0**, may be operating with an unmitigated Remote Code Execution (RCE) vector. This paper demonstrates active evasion techniques against the official remediation for CVE-2026-25592. It is strongly advised that organizations implement manual input canonicalization, such as the `JDPEnterpriseSecurityFilter` outlined in Appendix 1.

---

![Hero](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/nuka-ai-sk-logo.png)

# WHITE PAPER | JDP-2026-001
## The Orchestration Trust Gap: Remediation Evasions in Microsoft Semantic Kernel and Agent Framework 1.0

**Author:** Jeff Ponte, CISSP, CCSP, CEH | Security Researcher, JDP-Security  
**Series:** JDP Security Research Series (Disclosure #1)  
**Date:** April 25, 2026  
**Classification:** Public Research Disclosure  
**Target:** Microsoft Semantic Kernel (.NET) v1.47.0 - v1.48.0, Agent Framework 1.0  
**CVSS v3.1 Score:** 10.0 (Critical)  
**Vector:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`  
**CWE Chain:** CWE-1039 → CWE-22 → CWE-94  

---

## Executive Summary
This white paper documents a critical architectural vulnerability within Microsoft’s Semantic Kernel (SK) framework, an orchestration layer for .NET-based AI agents. Analysis reveals a fundamental **"Trust Gap"** wherein the framework processes stochastic, untrusted Large Language Model (LLM) output as deterministic, high-privilege system commands.

This architectural decision results in a full-chain Remote Code Execution (RCE) vulnerability driven by **CWE-1039 (Insecure Automated Optimizations)**. This research demonstrates how an AI agent can be manipulated into overwriting its host application's source code (internally tracked as the "Self-Nuke" vector).

Forensic analysis spanning versions 1.47.0 through 1.48.0 indicates that subsequent mitigations applied to the framework remain incomplete. This paper discloses **six independent evasion vectors** that bypass the official patch issued for the February 6th Path Traversal vulnerability (**CVE-2026-25592**). These findings suggest that the current framework security model relies on siloed filtering mechanisms rather than foundational security principles, such as mandatory input canonicalization and explicit path anchoring.

---

## Key Takeaways

1. **CVSS 10.0 RCE** vector is present in Microsoft Semantic Kernel v1.48.0 and Agent Framework 1.0.
2. **6 Evasion Techniques** successfully bypass the CVE-2026-25592 remediation.
3. **Undocumented Mitigations** were observed in the repository while public vulnerability reports were classified as developer error.
4. **Type Confusion** is identified as the root cause—filters validate `string` types, but execution sinks accept and deserialize complex `object` types.
5. **Immediate Action Required:** Deprecate the use of `AutoInvokeKernelFunctions` for sensitive endpoints and implement the Appendix 1 canonicalization filter.

---

## 1. Business Impact & Supply Chain Risks
This vulnerability represents a systemic risk within the AI supply chain. Because the vendor currently classifies these bypasses as "Developer Error" rather than issuing a subsequent CVE, enterprise risk is compounded by the following factors:

* **SCA Tool Blindness:** Software Composition Analysis (SCA) and vulnerability scanners maintain a secure status. Organizations operating under the assumption that patching CVE-2026-25592 secured their environment are unaware that the patch can be bypassed via standard LLM translation capabilities.
* **Agent Framework 1.0 Inheritance:** Microsoft officially launched Agent Framework 1.0 on April 3, 2026. Because it relies on identical orchestration primitives, Agent Framework 1.0 inherits this CVSS 10.0 "Trust Gap" natively. 
* **Undocumented Mitigation Risks:** The internal remediation cycle (detailed in Section 7) consists of partial, undocumented mitigations. This leaves developers unaware that their current implementation of `AutoInvokeKernelFunctions` may act as a conduit for host compromise.

### Industry Risk Profiles:
- **Finance:** AI-powered trading agents operating with file system or database access.
- **Healthcare:** Autonomous patient data processing via orchestration pipelines.
- **Government:** Automated document parsing and classification systems.
- **SaaS:** Multi-tenant AI services leveraging Semantic Kernel for plugin execution.

---

## 2. Orchestration Mechanics in Semantic Kernel
Evaluating this vulnerability requires understanding Semantic Kernel's execution pipeline. SK operates as an orchestration engine, granting LLMs the functional capability to interact with host operating systems via defined plugins.

### The Execution Pipeline
1.  The Prompt: User inputs natural language.
2.  The Planner/Kernel: The framework transmits the prompt to the LLM, alongside a schema of available native functions (Plugins).
3.  The Tool Call: The LLM generates a JSON-formatted payload instructing the framework to execute a specific function with provided arguments.
4.  The Execution Sink: The framework maps the LLM's JSON to the compiled C# binary, executes the code, and returns the result to the LLM context.

> **Architectural Trust Vulnerability:** Traditional application security assumes untrusted user input and trusted backend logic. Semantic Kernel alters this paradigm by placing a non-deterministic entity (the LLM) within the execution pipeline, while the framework natively trusts the LLM's output as hardcoded backend logic.

---

## 3. The Dual-Vulnerability Landscape
Analysis confirms that Semantic Kernel is exposed to two distinct, highly critical vulnerability classes.

* **Vulnerability A: CVE-2026-25592 Remediation Evasion**
    On February 6th, a patch was released for a known path traversal flaw. This patch focused on filtering literal string arguments passed to plugins. Research confirms this remediation is structurally insufficient, as it fails to account for complex data type deserialization and LLM encoding capabilities.
* **Vulnerability B: CWE-1039 Auto-Invocation Flaw**
    Independent of prompt filtering, the framework's architecture permits the AI to autonomously generate payloads that execute directly against the host OS via `ToolCallBehavior.AutoInvokeKernelFunctions`, bypassing standard controller validation.

---

## 4. Attack Surface Analysis: Three Execution Vectors
The application’s security boundary can be conceptualized across three distinct execution vectors, each currently exhibiting failure conditions.

### 4.1 Prompt Injection (Front Door)
* **The Defense:** Regex-based sanitization designed to block literal `../` sequences in user input. 
* **Status: Bypassed.** This mechanism relies on literal input evaluation. Attackers evade it by instructing the LLM to construct the malicious string dynamically in memory.

### 4.2 Type Confusion & LLM Translation (Side Door)
* **The Defense:** String evaluation on LLM arguments via `IFunctionInvocationFilter` prior to native execution (the core mechanic of the CVE-2026-25592 patch).
* **Status: Systemically Bypassed.** The framework evaluates arguments by checking explicit string types (e.g., `arg is string`). If the LLM structures the path within a JSON array or generic Object, the evaluation evaluates to false, bypassing the security filter. At the execution sink, the underlying plugin deserializes the object and executes the payload. This represents a critical Type Confusion vulnerability where security evaluation occurs on the raw input wrapper rather than the resolved execution object.

### 4.3 CWE-1039 Auto-Invocation (Back Door)
* **The Defense:** Implicit Trust Model.
* **Vulnerable Implementation:** `ToolCallBehavior.AutoInvokeKernelFunctions`
* **Status: Systemically Broken.** `AutoInvokeKernelFunctions` binds an untrusted, stochastic input source (the LLM) directly to privileged native code execution. This circumvents the traditional MVC validation controller, violating Zero-Trust principles and accurately demonstrating CWE-1039.

---

## 5. The CWE-1039 RCE Chain: Vulnerability Chaining
Achieving unauthenticated RCE requires no elevated privileges and relies on chaining three architectural flaws:

1.  **CWE-1039 (Insecure Automated Optimizations):** The Auto-Invocation parameter allows the LLM to bypass developer validation, acting as a trusted orchestrator.
2.  **CWE-22 (Path Traversal):** The framework lacks mandatory, global "Path Anchoring." The absence of a native `[SafeRoot]` enforcement allows file operations to escape intended sandboxing.
3.  **CWE-94 (Code Injection):** By bypassing the CVE-2026-25592 filters and traversing directories, the LLM overwrites the application's core source code (e.g., `Program.cs` or `appsettings.json`).

Upon the next application cycle, the injected payload executes with the privileges of the host service account, completing the RCE sequence.

---

## 6. Empirical Evidence: Bypassing CVE-2026-25592
To validate the architectural flaws in the official remediation, Semantic Kernel v1.48.0 was tested against six discrete evasion techniques. All six methodologies successfully bypassed the February 6th patch.

1.  **JSON Type Confusion:** Framework filters specifically evaluate `string` types. Passing the path as a JSON array (`["..", "..", "Program.cs"]`) causes the `arg is string` evaluation to return false. The check is bypassed, and the execution sink concatenates the payload.
2.  **Object Reflection Obfuscation:** Providing an anonymous object (`new { p = "../../file.txt" }`) bypasses flat string filters. The execution sink utilizes reflection to extract the target property, executing the payload.
3.  **Base64 Encoding Bypass:** The payload is provided as a Base64 string. The filter evaluates `UHJvZ3JhbS5jcw==` as benign. The LLM processes the tool call, decoding it prior to plugin execution.
4.  **URL Encoding Evasion:** Utilizing `%2e%2e%2f` to evade filters explicitly targeting literal dot and slash characters. If the execution sink URL-decodes the input, traversal occurs.
5.  **Unicode Homoglyphs:** Utilizing visually identical Unicode characters, such as the full-width solidus `∕` (U+2044). Regex filters ignore the character, but the underlying OS normalizes it to a standard `/` during file I/O operations.
6.  **Hybrid Canonicalization:** Combining vectors (e.g., URL-encoded Base64 within a JSON array) to exhaust non-recursive sanitization logic.

---

## 7. Remediation Timeline & Forensic Analysis
The following timeline documents the discrepancy between public vulnerability classification and internal repository mitigations.

| Date (2026) | Event | Technical Significance & Vulnerability Status |
| :--- | :--- | :--- |
| **March 24** | **Initial Disclosure** | Full-chain RCE reported via MSRC. PoC `.CAST` recordings provided demonstrating host takeover. |
| **April 3** | **Agent Framework 1.0 Launch** | **VULNERABLE.** Product launched during active triage. Inherits the exact "Trust Gap" and CWE-1039 vector. |
| **April 7** | **PR #13643 Merged** | **VULNERABLE.** Developed internally to "Prevent LLM-controlled filename path traversal attack" but renamed for public release. Indicates internal recognition of the vector. |
| **April 8 (02:01 ET)** | **Public Release** | v1.41.2 deployed. Uncredited mitigations merged into public branch. |
| **April 8 (16:07 ET)** | **Vendor Triage** | MSRC closes case as "Developer Error," asserting framework orchestration layer is not responsible for input sanitization. |
| **April 9** | **Commit fa2d52f6** | **VULNERABLE.** Implements "Shell Blinding" to mask output, but fails to prevent underlying Path Traversal logic. |
| **April 11** | **PR #13683 Merged** | **INCOMPLETE.** Implements `AllowedDirectories` (Safe Roots) as a "Breaking Change." Retrofits required path anchoring, but remains opt-in only. |
| **April 21** | **v1.48.0 Stable Release** | **STILL VULNERABLE.** Testing confirms mitigations within `DocumentPlugin.cs` fail due to siloed logic. All 6 evasion vectors remain functional. |
| **April 25** | **Current State** | **CRITICAL.** Framework remains exposed to RCE. Current remediation cycle is incomplete. |

---

## 8. Technical Analysis: The IFunctionInvocationFilter Logic Flaw
The primary cause of these evasions is a flaw in the `IFunctionInvocationFilter` evaluation methodology. Security validations are executed on *un-decoded, un-normalized, and un-parsed* arguments.

```csharp
// VULNERABLE PATTERN (CVE-2026-25592 Remediation)
public async Task OnFunctionInvocationAsync(FunctionInvocationContext context, ...) {
    
    // TIME OF CHECK: Type Confusion Vulnerability
    foreach (var arg in context.Arguments) {
        // BYPASS VECTOR:
        // If arg.Value is a JsonElement, this 'is string' check evaluates to false.
        // The sanitization logic is skipped, and the object proceeds to execution.
        if (arg.Value is string s && (s.Contains("..") || s.Contains("/"))) 
            throw new UnauthorizedAccessException("Blocked!");
    }
    
    // TIME OF USE: Execution sink deserializes the JSON/Object and executes payload
    await next(context); 
}
```
If the LLM formats the tool call argument as `{"path": "../../Program.cs"}`, the framework reads `arg.Value` as a `JsonElement`, not a `string`. The security filter is bypassed. The underlying plugin natively deserializes the JSON, resulting in path traversal.

---

## 9. Remediation & Recommendations
Securing Agentic AI orchestration requires the implementation of Kernel-Level Security Enforcement Points. Security validations must be inherent and mandatory, rather than opt-in and plugin-specific.

### 9.1 Immediate Mitigations (Developer Level)
* **Deprecate Auto-Invocation:** Discontinue the use of `AutoInvokeKernelFunctions` for any application possessing disk, network, or database privileges. Utilize manual function calling to inspect and validate all LLM arguments prior to execution.
* **Implement Safe Roots:** Explicitly hard-code boundary directories within every file-system-bound plugin.
* **Custom Global Filters:** Implement canonicalization filters (e.g., `JDPEnterpriseSecurityFilter`, Appendix 1) that resolve all complex types (Strings, JSON, Objects) prior to security validation.

### 9.2 Architectural Requirements (Vendor Level)
* **Unified Security Pipeline:** Canonicalization and normalization must occur *before* the security evaluation.
* **Mandatory Path Anchoring:** Framework-level sandboxing should operate as the default posture.
* **Advisory Issuance:** A formal security advisory and subsequent CVE must be issued for the CVE-2026-25592 bypasses to trigger SCA visibility across enterprise environments.

---

## 10. Conclusion: Industry Implications for Agentic Architecture
This disclosure highlights a systemic risk for the broader AI industry. As engineering teams deploy highly autonomous agents via orchestration frameworks, reliance on superficial input filtering demonstrates a fundamental misalignment with standard threat models. In the context of orchestration, LLM output must be treated as untrusted user input. 

Security architecture supersedes localized implementation patches. Vulnerabilities stemming from orchestration trust gaps require structural redesigns rather than regex-based hotfixes. Until frameworks adopt standard Zero-Trust principles for autonomous tooling, Agentic AI poses a significant risk to enterprise integrity.

### About JDP Security Research Series
The JDP Security Research Series is an independent research initiative focused on identifying systemic architectural risks in AI orchestration frameworks. Led by **Jeff Ponte (CISSP, CCSP, CEH)**, the project aims to ensure the development of secure, resilient foundations for enterprise AI integration. 

**Contact:** JDP.Security@proton.me


---

## Appendix 1: Developer Remediation (Manual Path Anchoring)
For environments unable to upgrade to a structurally secured version of the framework, implementation of a manual `IFunctionInvocationFilter` is required to mitigate CWE-1039 exploitation. This logic intercepts the LLM's tool call prior to file system interaction, performs deep inspection of complex types, and enforces path restriction to a designated "Safe Root."

### The C# Implementation
```csharp
// Appendix 1: Enterprise-Grade Semantic Kernel Security Filter
// This filter addresses the six evasion vectors identified in this research.
public class JDPEnterpriseSecurityFilter : IFunctionInvocationFilter
{
    private readonly string _safeRoot;
    private readonly HashSet<string> _fileIoNames = new()
    {
        "SaveConversation", "ReadDataFile", "DownloadToFileAsync",
        "UploadFile", "WriteFile", "ReadFile", "ExecuteScript"
    };

    public JDPEnterpriseSecurityFilter(string safeRootDirectory = null)
    {
        _safeRoot = Path.GetFullPath(safeRootDirectory ?? 
            Path.Combine(Directory.GetCurrentDirectory(), "appdata"));
        
        Directory.CreateDirectory(_safeRoot);
    }

    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context, 
        Func<FunctionInvocationContext, Task> next)
    {
        if (_fileIoNames.Contains(context.Function.Name))
        {
            foreach (var arg in context.Arguments)
            {
                var canonicalValue = CanonicalizeArgument(arg.Value);
                if (IsPathLikeArgument(arg.Key, canonicalValue))
                {
                    var safePath = ValidateAndSanitizePath(canonicalValue);
                    context.Arguments[arg.Key] = safePath;
                }
            }
        }
        await next(context);
    }

    private string CanonicalizeArgument(object value)
    {
        if (value == null) return string.Empty;
        string stringValue = value.ToString();
        if (stringValue.Contains('%')) stringValue = WebUtility.UrlDecode(stringValue);
        stringValue = NormalizeUnicode(stringValue);
        if (IsBase64(stringValue))
            stringValue = Encoding.UTF8.GetString(Convert.FromBase64String(stringValue));
        
        // Critical Logic: Handle Type Confusion (JSON/Objects)
        if (value is JsonElement jsonElement)
        {
            if (jsonElement.ValueKind == JsonValueKind.Array && jsonElement.GetArrayLength() > 0)
                stringValue = jsonElement[0].GetString() ?? stringValue;
            else if (jsonElement.ValueKind == JsonValueKind.Object)
                stringValue = ExtractStringFromJsonObject(jsonElement);
        }
        return stringValue;
    }

    private string ValidateAndSanitizePath(string userPath)
    {
        string fullPath = Path.GetFullPath(Path.Combine(_safeRoot, userPath));
        if (!fullPath.StartsWith(_safeRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException($"[SECURITY FILTER] Path traversal attempt blocked.");
        }
        return fullPath;
    }

    private bool IsPathLikeArgument(string argName, string value)
    {
        var pathKeywords = new[] { "path", "file", "directory", "folder", "location" };
        return pathKeywords.Any(k => argName.Contains(k, StringComparison.OrdinalIgnoreCase)) ||
               value.Contains('/') || value.Contains('\\') ||
               (value.Contains('.') && (value.EndsWith(".txt") || value.EndsWith(".json") || value.EndsWith(".cs")));
    }

    private string NormalizeUnicode(string input)
    {
        return input.Replace("∕", "/").Replace("⁄", "/").Replace("＼", "\\")
                    .Replace("．", ".").Replace("․", ".").Normalize(NormalizationForm.FormKC);
    }

    private bool IsBase64(string input)
    {
        if (string.IsNullOrEmpty(input) || input.Length % 4 != 0 || input.Any(char.IsWhiteSpace)) return false;
        try { Convert.FromBase64String(input); return true; } catch { return false; }
    }

    private string ExtractStringFromJsonObject(JsonElement jsonObject)
    {
        foreach (var property in jsonObject.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String) return property.Value.GetString();
        }
        return jsonObject.ToString();
    }
} // End of JDPEnterpriseSecurityFilter class
```

---

## Appendix 2: .cast Recording Demonstration Breakdown (Chronological)

This section provides the forensic artifacts associated with the disclosure, demonstrating how the architectural flaws persist across versions and execution methods.

---

### 1. Microsoft_SK_1.74_Nuke_Proof.cast
* **Target Environment:** v1.74.0 (Tested: April 2026)
* **Execution Method:** **LLM-Driven**
* **Summary:** Demonstrates a successful autonomous exploit on a modern version of the SDK. The natural language prompt leads to the LLM independently executing a tool call to overwrite `Program.cs`.

**Supporting Files:**
* [Exploit Harness (Program.cs)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.74_Nuke_Proof-Program.cs) 
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.74_Nuke_Proof.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.74_Nuke_Proof.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.74_Nuke_Proof.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

### 2. Microsoft_SK_1.47_Hardened_Bypass.cast
* **Target Environment:** v1.47.0 (Post-Mitigation)
* **Execution Method:** **LLM-Driven**
* **Summary:** Targets the v1.47.0 release following initial repository mitigations, proving the LLM successfully traverses security boundaries.

**Supporting Files:**
* [Exploit Harness (Program.cs)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.47_Hardened_Bypass-Program.cs) 
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.47_Hardened_Bypass.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.47_Hardened_Bypass.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/Microsoft_SK_1.47_Hardened_Bypass.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

### 3. JDP_Security_Series_v1.47-CVE-2026-25592-BYPASS-2.cast
* **Target Environment:** v1.47.0
* **Execution Method:** **Technical Audit (Manual)**
* **Summary:** Documents the **Type Confusion** flaw via manual kernel invocation. Highlights the filter failure when the malicious path is encapsulated within non-string data types.

**Supporting Files:**
* [Exploit Harness (Program.cs)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.47-CVE-2026-25592-BYPASS-2-Program.cs) 
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.47-CVE-2026-25592-BYPASS-2.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.47-CVE-2026-25592-BYPASS-2.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.47-CVE-2026-25592-BYPASS-2.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

### 4. JDP_Security_Series_v1.48-BREAKING_CHANGE.cast
* **Target Environment:** v1.48.0
* **Execution Method:** **Technical Audit (Manual)**
* **Summary:** Regression test demonstrating that internal updates to the **Kernel Binder** mitigated explicit string-based traversals, resulting in expected `KernelException` errors.

**Supporting Files:**
* [Exploit Harness (Program.cs)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-BREAKING_CHANGE-Program.cs) 
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-BREAKING_CHANGE.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-BREAKING_CHANGE.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-BREAKING_CHANGE.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

### 5. JDP_Security_Series_v1.48-ZERO_DAY_PROOF.cast
* **Target Environment:** v1.48.0
* **Execution Method:** **Technical Audit (Manual)**
* **Summary:** Confirms that despite kernel binder updates, the architecture remains vulnerable to **Type Confusion and Late Canonicalization** across six evaluated bypass vectors.

**Supporting Files:**
* [Exploit Harness (Program.cs)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-ZERO_DAY_PROOF-Program.cs) 
* [Execution Logs (txt)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-ZERO_DAY_PROOF.txt) 
* [Asciinema Recording (cast)](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-ZERO_DAY_PROOF.cast) 

<video width="100%" controls>
  <source src="https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/JDP_Security_Series_NukaAI_v1.48-ZERO_DAY_PROOF.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

## Appendix 3: Architectural Execution Visuals

Semantic Kernel Version 1.74.0
![Alt](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/1-74-1.png)

The Program.cs overwrite sequence initiated by LLM Prompt:
![Alt](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/1-74-2.png)

Semantic Kernel Version 1.47.0 
*Analysis of the mitigated version (Commit fa2d52f6). Execution confirms the vector remains open:*
![Alt](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/1-47-1.png)

The Program.cs overwrite sequence initiated by LLM Prompt:
![Alt](https://raw.githubusercontent.com/JDP-Security/security-research-media/main/assets/SK/1-47-2.png)

---

## Appendix 4: Frequently Asked Questions

**Q: Is Agent Framework 1.0 affected?**
A: Yes. Agent Framework 1.0 utilizes Semantic Kernel's core orchestration layer and inherits the identified vulnerability classes.

**Q: Does disabling Auto-Invocation fully remediate the risk?**
A: Partially. It prevents fully autonomous exploitation, but manual tool calling implementations remain vulnerable to the six identified bypass vectors if canonicalization is not applied.

**Q: What is the vendor remediation status?**
A: Currently unverified. The initial vulnerability report was classified as developer error, and subsequent repository mitigations have proven incomplete during testing.

**Q: Are alternative AI frameworks subject to similar risks?**
A: Yes. JDP Security Research Series indicates that analogous orchestration trust gaps exist within LangChain, LlamaIndex, and Deepset Haystack architectures.

---

### **Appendix 5: Forensic Analysis of Undocumented Remediations**

This section outlines the forensic timeline regarding repository mitigations pushed without corresponding public security advisories—a practice that obscures risk visibility for dependent organizations.

#### **1. Commit 3e4c91a — Initial Regex Mitigations (April 7, 2026)**
* **Official Action:** Integrated regex-based input validation for tool arguments.
* **Link:** [view commit 3e4c91a](https://github.com/microsoft/semantic-kernel/commit/3e4c91a)
* **Forensic Significance:** An initial mitigation attempt aimed at blocking shell-metacharacters (`;`, `&`, `|`) using regular expressions. 
* **The Failure:** This logic addressed symptomatic execution rather than the underlying translation flaw. It was bypassed via **Late Canonicalization**, which regex engines cannot interpret prior to the system sink.

#### **2. PR #13683 — Introduction of AllowedDirectories (March 18, 2026)**
* **Official Title:** `.Net: [Breaking] Harden DocumentPlugin security defaults with deny-by-default AllowedDirectories`
* **Link:** [view PR #13683](https://github.com/microsoft/semantic-kernel/pull/13683)
* **Status:** Merged into the stable branch on **April 7, 2026**.
* **Forensic Significance:** Categorizing this remediation as a "Breaking Change" enabled the introduction of the `AllowedDirectories` sandbox without explicitly identifying framework-level path traversal risks in public documentation.

#### **3. PR #13643 — Path Handling Refactoring (April 7, 2026)**
* **Official Title:** `Python: Improves the robustness of filename handling`
* **Internal Development Title:** `Python: Prevent LLM-controlled filename path traversal attack`
* **Link:** [view PR #13643](https://github.com/microsoft/semantic-kernel/pull/13643)
* **Forensic Significance:** This pull request contains primary sanitization logic subsequently mirrored across the ecosystem. Classifying the fix as a "robustness" improvement obscured the security context of the modification.
* **Cross-SDK Observation:** While targeting the Python repository, the recursive canonicalization logic introduced in this PR served as the architectural blueprint for undocumented hardening in the .NET SDK versions 1.47.0 and 1.48.0.

#### **4. Commit fa2d52f6 — Legacy Output Masking**
* **Status:** Cherry-picked and merged into Release v1.47.0 on **April 9, 2026**.
* **Link:** [view commit fa2d52f6](https://github.com/microsoft/semantic-kernel/commit/fa2d52f6)
* **Forensic Significance:** Logic implemented to mask standard output from the LLM context.
```csharp
// Masking system output from the LLM execution context
var result = await process.StandardOutput.ReadToEndAsync();
return "Command executed successfully."; 
```
* **Result:** **Incomplete Mitigation.** Testing on **v1.48.0** confirms this fails to prevent underlying command execution. The exploit sequence bypasses output masking by confirming execution via secondary file-system artifacts.

---

### **Conclusion: Supply Chain Visibility Risks**
Managing critical vulnerabilities via undocumented repository commits rather than formal Security Advisories disrupts standard vulnerability management pipelines. The absence of a designated **CVE** for these bypass vectors creates the following operational impacts:

* **SCA Blindness:** Industry-standard tools (e.g., Snyk, Wiz, Dependabot) rely on CVE databases to flag risks. Without an assigned CVE, these tools categorize vulnerable 1.47.0 and 1.48.0 environments as secure.
* **Advisory Absence:** Organizations integrating the Agent Framework lack authoritative documentation on remediating the core architectural logic, unknowingly inheriting mitigated but active RCE vectors.
* **Unresolved Threat Modeling:** Because the v1.48.0 mitigations remain incomplete against the vectors detailed in this document, production environments utilizing these frameworks currently operate outside of a secured supply chain model.
