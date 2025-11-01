"""SQL Injection vulnerability scanner."""
from typing import List
from loguru import logger
import json

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class SQLiScanner(BaseScanner):
    """Scanner for SQL Injection vulnerabilities using SQLMap."""
    
    def scan(self) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities."""
        logger.info(f"Starting SQL injection scan on {self.target}")
        vulnerabilities = []
        
        # Run SQLMap
        sqlmap_results = self._run_sqlmap()
        vulnerabilities.extend(sqlmap_results)
        
        # Manual testing for common patterns
        if self.get_intensity_level() >= 2:
            manual_results = self._manual_sqli_test()
            vulnerabilities.extend(manual_results)
        
        logger.info(f"SQLi scan found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_sqlmap(self) -> List[Vulnerability]:
        """Run SQLMap tool for automated SQL injection testing."""
        vulnerabilities = []
        
        # Build SQLMap command
        command = [
            "sqlmap",
            "-u", self.target,
            "--batch",  # Never ask for user input
            "--level", str(min(self.get_intensity_level(), 3)),
            "--risk", str(min(self.get_intensity_level(), 3)),
            "--answers", "quit=N,follow=N",
            "--output-dir", "/tmp/sqlmap_results",
        ]
        
        logger.info(f"Running SQLMap: {' '.join(command)}")
        result = self.run_kali_tool(command)
        
        if result["success"]:
            # Parse SQLMap output
            vulns = self._parse_sqlmap_output(result["stdout"])
            vulnerabilities.extend(vulns)
        else:
            logger.warning(f"SQLMap failed or not available: {result['stderr']}")
        
        return vulnerabilities
    
    def _parse_sqlmap_output(self, output: str) -> List[Vulnerability]:
        """Parse SQLMap output to extract vulnerabilities."""
        vulnerabilities = []
        
        # Look for vulnerability indicators in output
        if "sqlmap identified the following injection" in output.lower():
            vuln = self.create_vulnerability(
                vuln_type="sqli",
                title="SQL Injection Vulnerability Detected",
                description="SQLMap detected SQL injection vulnerability in the target application.",
                severity=Severity.CRITICAL,
                location=self.target,
                cvss_score=9.0,
                cwe_id="CWE-89",
                steps_to_reproduce=[
                    f"1. Run SQLMap against: {self.target}",
                    "2. SQLMap successfully exploited SQL injection",
                    "3. Review SQLMap output for detailed exploitation steps",
                ],
                remediation="Use parameterized queries/prepared statements. Implement input validation and principle of least privilege for database accounts.",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ],
                evidence=output[:1000]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _manual_sqli_test(self) -> List[Vulnerability]:
        """Manual SQL injection testing with common payloads."""
        vulnerabilities = []
        
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "' UNION SELECT NULL--",
        ]
        
        for payload in payloads:
            # Test in URL parameters
            response = self.http_request("GET", params={"id": payload})
            
            if response and self._is_sqli_vulnerable(response):
                vuln = self.create_vulnerability(
                    vuln_type="sqli",
                    title="Potential SQL Injection",
                    description="Application shows signs of SQL injection vulnerability based on error patterns.",
                    severity=Severity.HIGH,
                    location=self.target,
                    payload=payload,
                    cvss_score=8.5,
                    cwe_id="CWE-89",
                    steps_to_reproduce=[
                        f"1. Send payload: {payload}",
                        "2. Observe SQL error messages or unexpected behavior",
                    ],
                    remediation="Use parameterized queries and input validation.",
                )
                vulnerabilities.append(vuln)
                break  # Found one, don't overwhelm with duplicates
        
        return vulnerabilities
    
    def _is_sqli_vulnerable(self, response) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "microsoft ole db provider",
            "unclosed quotation mark",
            "postgresql",
            "sqlite",
        ]
        
        response_text = response.text.lower()
        return any(error in response_text for error in sql_errors)
