---
---
@import "{{ site.theme }}";

// 1. Force the page header background to midnight slate
.page-header {
  background-image: linear-gradient(120deg, #1e293b, #0f172a) !important;
  background-color: #0f172a !important;
}

// 2. Fix the text elements inside the header (Destroy the teal text)
.project-name {
  color: #ffffff !important;
}
.project-tagline {
  color: #cbd5e1 !important; // Clean off-white/gray
}

// 3. Fix the body headings (H1, H2, H3, H4) so they aren't green
.main-content h1, 
.main-content h2, 
.main-content h3, 
.main-content h4 {
  color: #0f172a !important; // Solid corporate dark slate
}

// 4. Clean up standard text links (No neon green/teal)
.main-content a {
  color: #2563eb !important; // Standard crisp professional blue
  text-decoration: none;
}
.main-content a:hover {
  text-decoration: underline;
}

// 5. Clean up the main buttons to match the slate aesthetic
.btn {
  color: #ffffff !important;
  background-color: #334155 !important;
  border-color: #475569 !important;
  border-style: solid !important;
  border-width: 1px !important;
  border-radius: 4px !important;
}
.btn:hover {
  background-color: #475569 !important;
  color: #ffffff !important;
}

# JDP Security Research Series
## Vulnerability Disclosures & Technical White Papers (2026)

Welcome to the central portal for the 2026 AI Orchestration Framework Research Series. This repository houses verified vulnerability disclosures, proof-of-concept walk-throughs, and structural defense guidelines targeting major agentic runtime frameworks.

### Published Advisories

* **[JDP-2026-001: Microsoft Semantic Kernel & Agent Framework 1.0](./2026-04-28-semantic-kernel-disclosure.html)** *The Orchestration Trust Gap: Remediation Evasions and Incomplete Output Masking (CVSS 10.0).*
    
* **[JDP-2026-002: Microsoft Agent Framework v1.0.0](./2026-05-05-maf-docker-escape-disclosure.html)** *Infrastructure Breach: Container Privilege Escalation via Automated Host Socket Mounting (CVSS 10.0).*
    
* **[JDP-2026-003: LlamaIndex Core](./2026-05-12-llamaindex-selfnuke-disclosure.html)** *Infrastructure Compromise: Path Traversal and Source File Overwrites (CVSS 10.0).*
    
* **[JDP-2026-004: LangChain Core](./2026-05-12-langchain-orchestration-poisoning-disclosure.html)** *Architectural Boundary Failures: Remote Code Execution via Symlink Traversal (CVSS 10.0).*
    
* **[JDP-2026-005: Deepset Haystack](./2026-05-13-deepset-haystack-disclosure.html)** *Serialization Boundary Evasion: Persistent Framework Integrity Compromise (CVSS 10.0).*

---
*All research published here is formatted for direct integration into enterprise application security threat models and architectural standards.*
