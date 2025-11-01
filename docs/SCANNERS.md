# Bug Bounty CLI Scanners

This document provides an overview of all vulnerability scanners integrated into the Bug Bounty CLI.

## Scanner Overview

All scanners leverage real Kali Linux tools and manual testing techniques to identify OWASP Top 10 vulnerabilities.

### 1. XSS Scanner (`xss_scanner.py`)
**Vulnerability Type:** Cross-Site Scripting (XSS)
**Kali Tools:** XSStrike (optional)
**Techniques:**
- URL parameter injection testing
- Form input testing
- Multiple payload variations (basic to advanced)
- Reflected and stored XSS detection
- Context-aware payload selection

**Coverage:**
- CWE-79: Improper Neutralization of Input During Web Page Generation

---

### 2. SQL Injection Scanner (`sqli_scanner.py`)
**Vulnerability Type:** SQL Injection
**Kali Tools:** SQLMap
**Techniques:**
- Automated SQLMap scanning with configurable risk/level
- Manual error-based detection
- Time-based blind SQL injection
- Union-based injection
- Boolean-based blind injection

**Coverage:**
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command

---

### 3. RCE Scanner (`rce_scanner.py`)
**Vulnerability Type:** Remote Code Execution
**Kali Tools:** Commix
**Techniques:**
- Command injection testing (Unix & Windows)
- Time-based command execution detection
- Content-based verification
- Deserialization vulnerabilities (Java, Python)
- Expression language injection

**Coverage:**
- CWE-78: OS Command Injection
- CWE-502: Deserialization of Untrusted Data

---

### 4. SSRF Scanner (`ssrf_scanner.py`)
**Vulnerability Type:** Server-Side Request Forgery
**Kali Tools:** None (manual testing)
**Techniques:**
- Internal IP probing (127.0.0.1, localhost, 192.168.x.x)
- Cloud metadata endpoint testing (AWS, Google, Azure, DigitalOcean)
- Protocol handler testing (file://, dict://, gopher://)
- Internal port scanning via SSRF
- Bypass technique testing (octal, hex, decimal IP)

**Coverage:**
- CWE-918: Server-Side Request Forgery

---

### 5. Access Control Scanner (`access_control_scanner.py`)
**Vulnerability Type:** Broken Access Control
**Kali Tools:** Nikto, Dirb
**Techniques:**
- Admin interface discovery
- IDOR (Insecure Direct Object Reference) testing
- Path traversal detection
- Forced browsing/directory enumeration
- Horizontal and vertical privilege escalation testing

**Coverage:**
- CWE-284: Improper Access Control
- CWE-425: Direct Request
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-22: Path Traversal

---

### 6. Misconfiguration Scanner (`misc_scanner.py`)
**Vulnerability Type:** Security Misconfiguration
**Kali Tools:** Nmap, testssl.sh
**Techniques:**
- Service version detection and vulnerability scanning
- HTTP security headers analysis
- Default credentials testing
- SSL/TLS configuration testing
- Information disclosure detection
- CORS misconfiguration testing

**Coverage:**
- CWE-16: Configuration
- CWE-200: Exposure of Sensitive Information
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-798: Use of Hard-coded Credentials
- CWE-942: Permissive Cross-domain Policy

---

### 7. XXE Scanner (`xxe_scanner.py`)
**Vulnerability Type:** XML External Entity Injection
**Kali Tools:** None (manual testing)
**Techniques:**
- Basic XXE payload injection
- Parameter entity exploitation
- Blind XXE testing
- File disclosure via XXE
- SSRF via XXE

**Coverage:**
- CWE-611: Improper Restriction of XML External Entity Reference

---

### 8. CSRF Scanner (`csrf_scanner.py`)
**Vulnerability Type:** Cross-Site Request Forgery
**Kali Tools:** None (manual testing)
**Techniques:**
- CSRF token presence verification
- Form method validation
- SameSite cookie attribute testing
- State-changing operation identification

**Coverage:**
- CWE-352: Cross-Site Request Forgery

---

### 9. Authentication Scanner (`auth_scanner.py`)
**Vulnerability Type:** Authentication Failures
**Kali Tools:** Hydra (optional)
**Techniques:**
- Weak password policy detection
- Session cookie security analysis (HttpOnly, Secure flags)
- Username enumeration testing
- Account lockout policy verification
- Brute-force protection testing

**Coverage:**
- CWE-521: Weak Password Requirements
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-307: Improper Restriction of Excessive Authentication Attempts

---

## Intensity Levels

All scanners support configurable intensity levels:

- **Low (1):** Basic checks only, minimal payloads
- **Medium (2):** Standard testing with moderate payload sets, basic tool integration
- **High (3):** Comprehensive testing with full payload sets, advanced tool integration
- **Extreme (4):** Exhaustive testing with all available techniques and tools

## Scanner Architecture

```
BaseScanner (base_scanner.py)
    ├── run_kali_tool()        # Execute Kali Linux tools
    ├── http_request()         # Make HTTP requests with error handling
    ├── create_vulnerability() # Create standardized vulnerability objects
    └── get_intensity_level()  # Get numeric intensity level

All Scanners inherit from BaseScanner and implement:
    - scan() -> List[Vulnerability]
```

## Adding New Scanners

To add a new scanner:

1. Create new scanner file in `src/scanner/`
2. Inherit from `BaseScanner`
3. Implement `scan()` method
4. Add to `orchestrator.py` scanner_map
5. Document in this file

## OWASP Top 10 Coverage

| OWASP Category | Scanner | Status |
|----------------|---------|--------|
| A01:2021 – Broken Access Control | `access_control_scanner.py` | ✅ Complete |
| A02:2021 – Cryptographic Failures | `misc_scanner.py` (SSL/TLS) | ✅ Complete |
| A03:2021 – Injection | `sqli_scanner.py`, `xss_scanner.py`, `rce_scanner.py`, `xxe_scanner.py` | ✅ Complete |
| A04:2021 – Insecure Design | Manual review recommended | ⚠️  Partial |
| A05:2021 – Security Misconfiguration | `misc_scanner.py` | ✅ Complete |
| A06:2021 – Vulnerable Components | `misc_scanner.py` (Nmap) | ✅ Complete |
| A07:2021 – Authentication Failures | `auth_scanner.py` | ✅ Complete |
| A08:2021 – Software and Data Integrity Failures | `rce_scanner.py` (deserialization) | ✅ Complete |
| A09:2021 – Security Logging Failures | Manual review recommended | ⚠️  Partial |
| A10:2021 – Server-Side Request Forgery | `ssrf_scanner.py` | ✅ Complete |

## Kali Linux Tools Used

- **SQLMap** - SQL injection testing
- **Commix** - Command injection testing
- **Nikto** - Web server vulnerability scanning
- **Nmap** - Port scanning and service detection
- **testssl.sh** - SSL/TLS configuration testing
- **Dirb** - Directory enumeration
- **XSStrike** - XSS detection (optional)
- **Hydra** - Authentication brute-forcing (optional)

## Notes

- All scanners gracefully handle missing Kali tools by logging warnings
- Scanners work on both Linux (Kali) and Windows (limited functionality)
- Results include CWE mappings, CVSS scores, and remediation guidance
- All tests include detailed steps to reproduce vulnerabilities
