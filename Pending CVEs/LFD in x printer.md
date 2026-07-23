# Pending CVE – x Printer Local File Disclosure (LFD) via Unsanitized `file` Parameter

> **Status:** Pending CVE Assignment  
> **Severity:** High (Proposed)  
> **Vulnerability Type:** Local File Disclosure (LFD) / Path Traversal  
> **CWE:** CWE-22 – Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal")

---

## Summary

A Local File Disclosure (LFD) vulnerability exists in the web management interface of the affected x Printer portal.

The application accepts a user-controlled parameter named:

```
file=
```

without performing sufficient input validation or path sanitization before using it to retrieve and render files.

An attacker can manipulate this parameter to access arbitrary files available within the printer's web portal directory, resulting in unauthorized disclosure of internal resources and sensitive configuration files.

---

# Vulnerability Details

The vulnerable endpoint renders files directly based on user-supplied input.

Instead of restricting access to a predefined set of allowed resources, the application trusts the value supplied through the `file` parameter.

Example:

```
GET /<endpoint>?file=<user-controlled-input>
```

Because the parameter is not properly sanitized, an attacker can request arbitrary files that exist inside the web application's accessible directories.

Depending on deployment and filesystem permissions, this may expose:

- HTML templates
- JavaScript files
- Configuration files
- Internal resources
- Web portal assets
- Application logic
- Localization files
- Documentation files
- Other sensitive portal files

---

# Root Cause

The application directly uses user-controlled input supplied through the `file` parameter when determining which resource should be rendered.

Missing security controls include:

- No allowlist validation
- No canonicalization
- No path restriction
- No directory boundary enforcement
- No sanitization of traversal sequences (if applicable)

As a result, arbitrary application files may be disclosed.

---

# Affected Parameter

```
file
```

---

# Proof of Concept

Example request:

```http
GET /<vulnerable-endpoint>?file=index.html HTTP/1.1
Host: target
```

Changing the parameter allows retrieval of additional portal resources.

Example:

```http
GET /<vulnerable-endpoint>?file=config.xml HTTP/1.1
Host: target
```

or

```http
GET /<vulnerable-endpoint>?file=language/en.xml HTTP/1.1
Host: target
```

The exact accessible files depend on the firmware version and deployment.

---

# Impact

An attacker may disclose internal files that were never intended to be publicly accessible.

Potential consequences include:

- Information disclosure
- Exposure of internal application structure
- Leakage of configuration files
- Discovery of additional attack surface
- Collection of sensitive resources for chained attacks

Although the vulnerability does not directly allow arbitrary code execution, disclosed information may significantly assist attackers in performing subsequent attacks.

---

# Attack Scenario

1. Attacker identifies the vulnerable endpoint.
2. Attacker modifies the `file` parameter.
3. The application renders the requested file.
4. Sensitive internal portal files become accessible.
5. Retrieved information can be used for reconnaissance or chained exploitation.

---

# Security Impact

### Confidentiality

**High**

Sensitive portal files can be disclosed.

### Integrity

Low

The vulnerability is read-only.

### Availability

None

The vulnerability does not directly affect service availability.

---

# CVSS v3.1 (Proposed)

**Base Score:** 7.5 (High)

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
```

---

# CWE Classification

**CWE-22**

Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal")

Depending on the implementation, the issue may also relate to:

- CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor

---

# Remediation

The application should never directly trust user-controlled file paths.

Recommended mitigations include:

- Implement a strict allowlist of permitted files.
- Reject any unexpected filename.
- Resolve canonical paths before use.
- Prevent directory traversal sequences.
- Ensure the resolved path remains inside the intended directory.
- Avoid directly mapping HTTP parameters to filesystem paths.
- Return generic errors for invalid file requests.

---

# Vendor Response

Pending.

---

# Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Vendor notified |
| YYYY-MM-DD | Vendor acknowledged |
| YYYY-MM-DD | CVE requested |
| YYYY-MM-DD | Public disclosure |

---

# References

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

---

# Credits

**Discoverer**

Mohamed Abdelhady

---

# Disclaimer

This vulnerability information is provided for defensive and educational purposes to assist vendors and users in understanding and mitigating the identified security issue.
