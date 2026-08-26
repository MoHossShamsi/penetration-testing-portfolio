# Assessment Methodology

This document describes my general methodology for web, API, mobile, and network assessments in authorized lab environments.

## General Principles

- Work only within defined scope and authorization.
- Avoid destructive testing in production-like environments.
- Document every finding with clear reproduction steps and evidence.
- Focus on business impact, not just technical severity.
- Provide actionable remediation and retest guidance.

## Web & API Assessment

1. Reconnaissance and information gathering
2. Technology identification
3. Authentication and session testing
4. Authorization and access-control testing
5. Input validation and injection testing
6. Business logic and workflow testing
7. File upload and path handling
8. SSRF and server-side interactions
9. Error handling and information disclosure
10. Reporting and remediation recommendations

## Mobile (Android) Assessment

1. Static analysis (manifest, components, hardcoded secrets, permissions)
2. Dynamic analysis (traffic interception, runtime manipulation)
3. Authentication and authorization testing
4. Data storage and local security
5. Reverse engineering of sensitive logic
6. Reporting and remediation

## Network Assessment

1. Scope definition and rules of engagement
2. Reconnaissance and host discovery
3. Service enumeration and version detection
4. Vulnerability identification
5. Exploitation in controlled labs
6. Privilege escalation
7. Post-exploitation documentation
8. Reporting and remediation
