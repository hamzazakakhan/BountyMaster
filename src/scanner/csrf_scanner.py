"""CSRF (Cross-Site Request Forgery) vulnerability scanner."""
from typing import List
import re
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class CSRFScanner(BaseScanner):
    """Scanner for Cross-Site Request Forgery vulnerabilities."""
    
    def scan(self) -> List[Vulnerability]:
        """Scan for CSRF vulnerabilities."""
        logger.info(f"Starting CSRF scan on {self.target}")
        vulnerabilities = []
        
        # Check for CSRF token in forms
        response = self.http_request("GET")
        if not response:
            return vulnerabilities
        
        # Find forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
        
        for form_content in forms:
            # Check if form has CSRF token
            has_csrf_token = any(token in form_content.lower() for token in [
                'csrf', '_token', 'authenticity_token', 'xsrf'
            ])
            
            # Check if form modifies state (POST, PUT, DELETE)
            is_state_changing = any(method in form_content.lower() for method in [
                'method="post"', 'method="put"', 'method="delete"'
            ])
            
            if is_state_changing and not has_csrf_token:
                vuln = self.create_vulnerability(
                    vuln_type="csrf",
                    title="Missing CSRF Protection",
                    description="Form performs state-changing operations without CSRF token protection. Attackers can forge requests on behalf of authenticated users.",
                    severity=Severity.MEDIUM,
                    location=self.target,
                    cvss_score=6.5,
                    cwe_id="CWE-352",
                    steps_to_reproduce=[
                        "1. Identify state-changing form without CSRF token",
                        "2. Craft malicious page with auto-submitting form",
                        "3. Victim visits malicious page while authenticated",
                        "4. Form submits with victim's credentials",
                    ],
                    remediation="Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute. Verify Origin/Referer headers.",
                    references=["https://owasp.org/www-community/attacks/csrf"],
                    evidence=form_content[:300]
                )
                vulnerabilities.append(vuln)
                logger.warning("Found form without CSRF protection")
                break  # Report once
        
        # Check SameSite cookie attribute
        if 'Set-Cookie' in response.headers:
            cookies = response.headers['Set-Cookie']
            if 'samesite' not in cookies.lower():
                vuln = self.create_vulnerability(
                    vuln_type="csrf",
                    title="Missing SameSite Cookie Attribute",
                    description="Session cookies lack SameSite attribute, making them vulnerable to CSRF attacks.",
                    severity=Severity.MEDIUM,
                    location=self.target,
                    cvss_score=5.5,
                    cwe_id="CWE-352",
                    remediation="Set SameSite=Lax or SameSite=Strict on all session cookies.",
                    evidence=cookies
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
