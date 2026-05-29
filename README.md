<style>
  /* 1. Neutralize the loud teal/blue gradient header */
  .page-header {
    background-image: linear-gradient(120deg, #1e293b, #0f172a) !important;
    background-color: #0f172a !important;
    padding: 3rem 2rem !important;
  }
  
  /* 2. Style the main action buttons to look dark/professional */
  .btn {
    color: #ffffff !important;
    background-color: #334155 !important;
    border-color: #475569 !important;
    border-radius: 4px !important;
    font-weight: 500 !important;
  }
  .btn:hover {
    background-color: #475569 !important;
    border-color: #64748b !important;
  }
  
  /* 3. Style text links so they aren't neon green */
  main a, .main-content a {
    color: #2563eb !important;
    text-decoration: none;
  }
  main a:hover, .main-content a:hover {
    text-decoration: underline;
  }
  
  /* 4. Center and clean up the header text layout */
  .project-name, .project-tagline {
    color: #fff !important;
    text-shadow: none !important;
  }
</style>

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
