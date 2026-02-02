# Secure Code Review Report – CodeAlpha Internship

This repository contains a comprehensive **Secure Code Review Report** created as part of my internship at **CodeAlpha**. The task was assigned to assess and document the security posture of a web application through manual code analysis, aligned with industry-recognized standards such as **OWASP**, **CWE**, and **NIST**.

---

## Internship Task Overview

As part of the **CodeAlpha internship**, I was assigned to:
- Select a programming language and application to audit. 
- Perform a code review to identify security vulnerabilities.
- Use tools like static analyzers or manual inspection methods.
- Provide recommendations and best practices for secure coding. 
- Document findings and suggest remediation steps for safer code.

---

## What’s Inside This Report

| Section | Description |
|--------|-------------|
| **Assessment Methodology** | Approach used for reviewing code, based on OWASP & secure coding guidelines |
| **Identified Vulnerabilities** | Each issue includes a title, CVSS/CWE classification, description, impact, and suggested fix |
| **Proof of Concepts (PoCs)** | Test cases and payloads used to validate the vulnerabilities |
| **Remediation Guidance** | Actionable fixes to mitigate risks in the codebase |
| **References** | OWASP, CWE, NIST links and best practice documentation |

---

## Highlighted Vulnerabilities

- **Cross-Site Scripting (XSS)** due to use of vulnerable Bootstrap version (CVE-2024-6531)
- **Cross-Site Request Forgery (CSRF)** on multiple state-changing endpoints
- **NoSQL Injection** via unsanitized form data
- **Brute Force Login Vulnerability** due to lack of rate limiting and lockout mechanisms
- **Weak Password Policy** lacking complexity enforcement

---

## Methodology

- Manual code review of frontend and backend logic
- Analysis based on:
  - [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)
  - [OWASP Code Review Guide](https://owasp.org/www-project-code-review/)
  - [CWE Top Weaknesses](https://cwe.mitre.org/top25/)
  - [NIST 800-218 Secure Software Development Framework (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final)

---

## Contact

**Name:** Satvik Hatulkar  
**Email:** satwikhatulkar@gmail.com  
**LinkedIn:** [linkedin.com/in/satvikhatulkar](https://www.linkedin.com/in/satvik-hatulkar-a91042252)  
**GitHub:** [github.com/satvikhatulkar](https://github.com/SatvikHatulkar)
