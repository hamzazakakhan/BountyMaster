"""Authentication and Session Management vulnerability scanner."""
from typing import List
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class AuthScanner(BaseScanner):
    """Scanner for Authentication and Session Management failures."""
    
    def scan(self) -> List[Vulnerability]:
        """Scan for authentication vulnerabilities."""
        logger.info(f"Starting Authentication scan on {self.target}")
        vulnerabilities = []
        
        # 1. Check for weak password policy
        weak_pass_vulns = self._test_weak_passwords()
        vulnerabilities.extend(weak_pass_vulns)
        
        # 2. Check session management
        session_vulns = self._check_session_management()
        vulnerabilities.extend(session_vulns)
        
        # 3. Test for username enumeration
        enum_vulns = self._test_username_enumeration()
        vulnerabilities.extend(enum_vulns)
        
        # 4. Check for account lockout
        lockout_vulns = self._test_account_lockout()
        vulnerabilities.extend(lockout_vulns)
        
        logger.info(f"Authentication scan found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _test_weak_passwords(self) -> List[Vulnerability]:
        """Test if weak passwords are accepted."""
        vulnerabilities = []
        
        weak_passwords = ["123456", "password", "12345678", "admin"]
        
        for password in weak_passwords:
            # Attempt login (this is simplified - real implementation would find login endpoint)
            response = self.http_request(
                "POST",
                data={"username": "admin", "password": password}
            )
            
            if response and response.status_code == 200 and "welcome" in response.text.lower():
                vuln = self.create_vulnerability(
                    vuln_type="auth_failure",
                    title="Weak Password Policy",
                    description=f"Application accepts weak password: {password}",
                    severity=Severity.HIGH,
                    location=self.target,
                    cvss_score=7.5,
                    cwe_id="CWE-521",
                    remediation="Enforce strong password policy: minimum 12 characters, complexity requirements, password history.",
                    metadata={"weak_password": password}
                )
                vulnerabilities.append(vuln)
                break
        
        return vulnerabilities
    
    def _check_session_management(self) -> List[Vulnerability]:
        """Check session cookie security."""
        vulnerabilities = []
        
        response = self.http_request("GET")
        if not response or 'Set-Cookie' not in response.headers:
            return vulnerabilities
        
        cookies = response.headers['Set-Cookie'].lower()
        
        # Check HttpOnly flag
        if 'httponly' not in cookies:
            vuln = self.create_vulnerability(
                vuln_type="auth_failure",
                title="Session Cookie Missing HttpOnly Flag",
                description="Session cookies lack HttpOnly flag, making them vulnerable to XSS-based session hijacking.",
                severity=Severity.MEDIUM,
                location=self.target,
                cvss_score=6.0,
                cwe_id="CWE-1004",
                remediation="Set HttpOnly flag on all session cookies.",
                evidence=response.headers['Set-Cookie']
            )
            vulnerabilities.append(vuln)
        
        # Check Secure flag for HTTPS
        if self.scheme == "https" and 'secure' not in cookies:
            vuln = self.create_vulnerability(
                vuln_type="auth_failure",
                title="Session Cookie Missing Secure Flag",
                description="HTTPS site's session cookies lack Secure flag, allowing transmission over HTTP.",
                severity=Severity.MEDIUM,
                location=self.target,
                cvss_score=6.0,
                cwe_id="CWE-614",
                remediation="Set Secure flag on all session cookies for HTTPS sites.",
                evidence=response.headers['Set-Cookie']
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_username_enumeration(self) -> List[Vulnerability]:
        """Test for username enumeration."""
        vulnerabilities = []
        
        # Test with valid and invalid usernames
        valid_response = self.http_request(
            "POST",
            data={"username": "admin", "password": "wrongpassword"}
        )
        
        invalid_response = self.http_request(
            "POST",
            data={"username": "nonexistentuser12345", "password": "wrongpassword"}
        )
        
        if valid_response and invalid_response:
            # Check if responses are significantly different
            if abs(len(valid_response.text) - len(invalid_response.text)) > 50 or \
               valid_response.status_code != invalid_response.status_code:
                vuln = self.create_vulnerability(
                    vuln_type="auth_failure",
                    title="Username Enumeration",
                    description="Application reveals whether usernames exist through different responses, allowing attackers to enumerate valid usernames.",
                    severity=Severity.LOW,
                    location=self.target,
                    cvss_score=4.0,
                    cwe_id="CWE-200",
                    steps_to_reproduce=[
                        "1. Attempt login with known username and wrong password",
                        "2. Attempt login with non-existent username",
                        "3. Observe different response messages or timing",
                    ],
                    remediation="Use generic error messages for all authentication failures. Implement consistent response timing.",
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_account_lockout(self) -> List[Vulnerability]:
        """Test for account lockout policy."""
        vulnerabilities = []
        
        # Attempt multiple failed logins
        failed_attempts = 0
        for i in range(15):
            response = self.http_request(
                "POST",
                data={"username": "testuser", "password": f"wrongpass{i}"}
            )
            
            if response and response.status_code in [401, 403]:
                failed_attempts += 1
            elif response and "locked" in response.text.lower():
                # Account got locked, which is good
                return vulnerabilities
        
        # If we made 15 attempts without lockout
        if failed_attempts >= 15:
            vuln = self.create_vulnerability(
                vuln_type="auth_failure",
                title="Missing Account Lockout Policy",
                description="Application allows unlimited authentication attempts without account lockout, enabling brute-force attacks.",
                severity=Severity.MEDIUM,
                location=self.target,
                cvss_score=5.5,
                cwe_id="CWE-307",
                steps_to_reproduce=[
                    "1. Attempt login with wrong password multiple times (15+)",
                    "2. Account is never locked",
                    "3. Brute-force attacks are possible",
                ],
                remediation="Implement account lockout after 5-10 failed attempts. Use CAPTCHA. Implement rate limiting. Consider temporary lockouts with exponential backoff.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
