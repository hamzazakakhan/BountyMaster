"""XSS vulnerability scanner."""
from typing import List
from urllib.parse import urljoin, urlparse, parse_qs
import re
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class XSSScanner(BaseScanner):
    """Scanner for Cross-Site Scripting vulnerabilities."""
    
    # XSS payloads ranked by intensity
    PAYLOADS = {
        "low": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ],
        "medium": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<svg onload=alert('XSS')>",
        ],
        "high": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<!--<script>alert('XSS')</script>-->",
        ],
        "extreme": [
            # Includes all above plus advanced payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<!--<script>alert('XSS')</script>-->",
            "<svg/onload=alert('XSS')>",
            "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
            "\"><svg/onload=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
        ],
    }
    
    def scan(self) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities."""
        logger.info(f"Starting XSS scan on {self.target}")
        vulnerabilities = []
        
        # Get payloads based on intensity
        payloads = self.PAYLOADS.get(self.intensity, self.PAYLOADS["medium"])
        
        # 1. Test URL parameters
        vuln_params = self._test_url_parameters(payloads)
        vulnerabilities.extend(vuln_params)
        
        # 2. Test forms
        vuln_forms = self._test_forms(payloads)
        vulnerabilities.extend(vuln_forms)
        
        # 3. Use automated tools if available
        if self.get_intensity_level() >= 3:
            tool_vulns = self._run_automated_tools()
            vulnerabilities.extend(tool_vulns)
        
        logger.info(f"XSS scan found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities
    
    def _test_url_parameters(self, payloads: List[str]) -> List[Vulnerability]:
        """Test URL parameters for XSS."""
        vulnerabilities = []
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            logger.debug("No URL parameters found to test")
            return vulnerabilities
        
        for param_name in params.keys():
            for payload in payloads:
                # Construct test URL
                test_url = self._build_test_url(param_name, payload)
                
                # Send request
                response = self.http_request("GET", test_url)
                
                if response and self._is_xss_vulnerable(response.text, payload):
                    vuln = self.create_vulnerability(
                        vuln_type="xss",
                        title=f"Reflected XSS in parameter '{param_name}'",
                        description=f"The parameter '{param_name}' is vulnerable to reflected XSS attacks. User input is not properly sanitized before being reflected in the response.",
                        severity=Severity.HIGH,
                        location=f"Parameter: {param_name}",
                        parameter=param_name,
                        payload=payload,
                        evidence=response.text[:500],
                        cvss_score=7.5,
                        cwe_id="CWE-79",
                        steps_to_reproduce=[
                            f"1. Navigate to: {test_url}",
                            f"2. Observe that the payload is reflected without proper encoding",
                            "3. The script executes in the browser context",
                        ],
                        remediation="Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ]
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found XSS in parameter {param_name}")
                    break  # Found vulnerability in this parameter, move to next
        
        return vulnerabilities
    
    def _test_forms(self, payloads: List[str]) -> List[Vulnerability]:
        """Test HTML forms for XSS."""
        vulnerabilities = []
        
        # Get the page to find forms
        response = self.http_request("GET")
        if not response:
            return vulnerabilities
        
        # Simple form detection (in production, use BeautifulSoup properly)
        forms = re.findall(r'<form[^>]*>.*?</form>', response.text, re.DOTALL | re.IGNORECASE)
        
        for form in forms[:5]:  # Test first 5 forms
            # Extract inputs
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.IGNORECASE)
            
            for input_name in inputs:
                for payload in payloads[:3]:  # Test with first 3 payloads per form
                    form_data = {input_name: payload}
                    
                    # Submit form
                    response = self.http_request("POST", data=form_data)
                    
                    if response and self._is_xss_vulnerable(response.text, payload):
                        vuln = self.create_vulnerability(
                            vuln_type="xss",
                            title=f"Reflected XSS in form input '{input_name}'",
                            description=f"The form input '{input_name}' is vulnerable to XSS. User-supplied data is reflected in the response without proper sanitization.",
                            severity=Severity.HIGH,
                            location=f"Form input: {input_name}",
                            parameter=input_name,
                            payload=payload,
                            cvss_score=7.5,
                            cwe_id="CWE-79",
                            steps_to_reproduce=[
                                f"1. Submit form with {input_name}={payload}",
                                "2. Observe payload execution in response",
                            ],
                            remediation="Implement input validation and output encoding for all user inputs.",
                        )
                        vulnerabilities.append(vuln)
                        break
        
        return vulnerabilities
    
    def _run_automated_tools(self) -> List[Vulnerability]:
        """Run automated XSS detection tools."""
        vulnerabilities = []
        
        # Example: Run XSStrike if available (Kali tool)
        # Note: This is a placeholder - actual implementation would parse tool output
        logger.info("Attempting to run XSStrike for automated XSS detection")
        
        # XSStrike command (if installed)
        command = ["xsstrike", "-u", self.target, "--crawl"]
        
        result = self.run_kali_tool(command)
        
        if result["success"]:
            # Parse output and create vulnerabilities
            # This is simplified - real implementation would parse actual output
            logger.info("XSStrike completed successfully")
        else:
            logger.warning(f"XSStrike not available or failed: {result['stderr']}")
        
        return vulnerabilities
    
    def _is_xss_vulnerable(self, response_text: str, payload: str) -> bool:
        """Check if response contains unencoded payload."""
        # Check if payload appears in response without encoding
        if payload in response_text:
            return True
        
        # Check for common XSS indicators
        xss_indicators = [
            "alert('XSS')",
            "alert(\"XSS\")",
            "onerror=alert",
            "onload=alert",
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def _build_test_url(self, param_name: str, payload: str) -> str:
        """Build test URL with payload."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        
        # Rebuild query string
        query_parts = [f"{k}={v[0]}" for k, v in params.items()]
        query_string = "&".join(query_parts)
        
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
