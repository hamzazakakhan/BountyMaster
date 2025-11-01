"""Access Control vulnerability scanner using Nikto and IDOR testing."""
from typing import List
import re
from urllib.parse import urlparse, parse_qs, urljoin
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class AccessControlScanner(BaseScanner):
    """Scanner for Broken Access Control vulnerabilities."""
    
    # Common admin paths to test
    ADMIN_PATHS = [
        "/admin", "/admin/", "/administrator", "/wp-admin",
        "/admin.php", "/admin/login", "/admin/dashboard",
        "/console", "/management", "/panel", "/cpanel",
        "/phpmyadmin", "/adminer", "/backend",
        "/api/admin", "/api/v1/admin", "/api/users",
        "/.git", "/.env", "/config.php", "/.aws/credentials",
        "/backup", "/backups", "/backup.sql", "/db.sql",
        "/web.config", "/php.ini", "/.htaccess",
    ]
    
    # Common IDOR parameter names
    IDOR_PARAMS = ["id", "user_id", "uid", "account", "user", "profile", "doc", "file"]
    
    def scan(self) -> List[Vulnerability]:
        """Scan for access control issues."""
        logger.info(f"Starting Access Control scan on {self.target}")
        vulnerabilities = []
        
        # 1. Run Nikto for comprehensive web server scanning
        if self.get_intensity_level() >= 2:
            nikto_vulns = self._run_nikto()
            vulnerabilities.extend(nikto_vulns)
        
        # 2. Test for exposed admin interfaces
        admin_vulns = self._test_admin_access()
        vulnerabilities.extend(admin_vulns)
        
        # 3. Test for IDOR vulnerabilities
        if self.get_intensity_level() >= 2:
            idor_vulns = self._test_idor()
            vulnerabilities.extend(idor_vulns)
        
        # 4. Test for path traversal
        path_vulns = self._test_path_traversal()
        vulnerabilities.extend(path_vulns)
        
        # 5. Test for forced browsing
        if self.get_intensity_level() >= 3:
            browse_vulns = self._test_forced_browsing()
            vulnerabilities.extend(browse_vulns)
        
        logger.info(f"Access Control scan found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_nikto(self) -> List[Vulnerability]:
        """Run Nikto web server scanner."""
        vulnerabilities = []
        
        command = [
            "nikto",
            "-h", self.target,
            "-Tuning", "x",  # Reverse Proxy/XSS/Script/SQL injection checks
            "-timeout", str(self.timeout),
            "-nossl",  # Don't check SSL (faster)
        ]
        
        logger.info(f"Running Nikto: {' '.join(command)}")
        result = self.run_kali_tool(command)
        
        if result["success"]:
            vulns = self._parse_nikto_output(result["stdout"])
            vulnerabilities.extend(vulns)
        else:
            logger.warning(f"Nikto not available or failed: {result['stderr']}")
        
        return vulnerabilities
    
    def _parse_nikto_output(self, output: str) -> List[Vulnerability]:
        """Parse Nikto output to extract vulnerabilities."""
        vulnerabilities = []
        
        # Parse Nikto findings (format: + /path: Description)
        findings = re.findall(r'\+\s+([^:]+):\s+(.+)', output)
        
        for path, description in findings:
            # Determine severity based on keywords
            severity = Severity.MEDIUM
            if any(word in description.lower() for word in ["critical", "exploit", "shell", "rce"]):
                severity = Severity.HIGH
            elif any(word in description.lower() for word in ["admin", "config", "credential"]):
                severity = Severity.HIGH
            
            vuln = self.create_vulnerability(
                vuln_type="broken_access_control",
                title=f"Web Server Issue: {path.strip()}",
                description=f"Nikto detected: {description.strip()}",
                severity=severity,
                location=f"{self.target}{path.strip()}",
                cvss_score=6.5,
                cwe_id="CWE-284",
                steps_to_reproduce=[
                    f"1. Access: {self.target}{path.strip()}",
                    "2. Vulnerability identified by Nikto scanner",
                ],
                remediation="Review and remediate the identified issue. Implement proper access controls.",
                evidence=description.strip()
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_admin_access(self) -> List[Vulnerability]:
        """Test for exposed administrative interfaces."""
        vulnerabilities = []
        
        for path in self.ADMIN_PATHS:
            url = urljoin(self.base_url, path)
            response = self.http_request("GET", url)
            
            if response and response.status_code in [200, 301, 302, 401, 403]:
                # Even 401/403 indicates the resource exists
                severity = Severity.HIGH if response.status_code == 200 else Severity.MEDIUM
                
                vuln = self.create_vulnerability(
                    vuln_type="broken_access_control",
                    title=f"Exposed Administrative Interface: {path}",
                    description=f"Administrative or sensitive path '{path}' is accessible (HTTP {response.status_code}). Even if protected, exposing admin interfaces increases attack surface.",
                    severity=severity,
                    location=url,
                    cvss_score=7.0 if response.status_code == 200 else 5.0,
                    cwe_id="CWE-425",
                    steps_to_reproduce=[
                        f"1. Navigate to: {url}",
                        f"2. Received HTTP {response.status_code}",
                        "3. Administrative interface is discoverable",
                    ],
                    remediation="Move admin interfaces to non-standard paths. Implement IP allowlisting. Use VPN for admin access. Implement rate limiting and MFA.",
                    references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
                    evidence=response.text[:500]
                )
                vulnerabilities.append(vuln)
                logger.warning(f"Found exposed path: {path}")
        
        return vulnerabilities
    
    def _test_idor(self) -> List[Vulnerability]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        vulnerabilities = []
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            if any(idor_param in param_name.lower() for idor_param in self.IDOR_PARAMS):
                # Get original response
                original_response = self.http_request("GET")
                if not original_response:
                    continue
                
                original_value = params[param_name][0]
                
                # Try different IDs
                test_values = [
                    str(int(original_value) + 1) if original_value.isdigit() else "2",
                    str(int(original_value) - 1) if original_value.isdigit() else "1",
                    "999999",
                    "0",
                    "admin",
                ]
                
                for test_value in test_values:
                    test_response = self.http_request("GET", params={param_name: test_value})
                    
                    if test_response and test_response.status_code == 200:
                        # Check if response is significantly different (indicates different data)
                        if len(test_response.text) > 100 and \
                           abs(len(test_response.text) - len(original_response.text)) > 50:
                            vuln = self.create_vulnerability(
                                vuln_type="broken_access_control",
                                title=f"Insecure Direct Object Reference (IDOR) in '{param_name}'",
                                description=f"The parameter '{param_name}' is vulnerable to IDOR. By modifying the ID value, unauthorized access to other users' data is possible.",
                                severity=Severity.HIGH,
                                location=self.target,
                                parameter=param_name,
                                payload=f"{param_name}={test_value}",
                                cvss_score=8.0,
                                cwe_id="CWE-639",
                                steps_to_reproduce=[
                                    f"1. Access with original ID: {param_name}={original_value}",
                                    f"2. Change to: {param_name}={test_value}",
                                    "3. Observe access to different user's data",
                                    "4. No authorization check performed",
                                ],
                                remediation="Implement proper authorization checks. Verify user permissions before serving data. Use indirect references or session-based access control.",
                                references=[
                                    "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                                    "https://cwe.mitre.org/data/definitions/639.html"
                                ]
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"Found IDOR in parameter {param_name}")
                            break
                
                if vulnerabilities:  # Found IDOR, don't test other values
                    break
        
        return vulnerabilities
    
    def _test_path_traversal(self) -> List[Vulnerability]:
        """Test for path traversal vulnerabilities."""
        vulnerabilities = []
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..\\..\\..\\..\\..\\..\\..\\.\\etc\\passwd",
            "/etc/passwd",
            "C:\\windows\\win.ini",
        ]
        
        # Test in common file parameters
        file_params = ["file", "path", "document", "page", "include", "template"]
        
        for param in file_params:
            for payload in traversal_payloads:
                response = self.http_request("GET", params={param: payload})
                
                if response and self._is_path_traversal_successful(response):
                    vuln = self.create_vulnerability(
                        vuln_type="broken_access_control",
                        title=f"Path Traversal in parameter '{param}'",
                        description=f"The parameter '{param}' is vulnerable to path traversal attacks, allowing access to arbitrary files on the server.",
                        severity=Severity.HIGH,
                        location=self.target,
                        parameter=param,
                        payload=payload,
                        cvss_score=7.5,
                        cwe_id="CWE-22",
                        steps_to_reproduce=[
                            f"1. Set parameter {param}={payload}",
                            "2. Observe file contents in response",
                            "3. Can read arbitrary files on server",
                        ],
                        remediation="Implement input validation. Use allowlists for file paths. Avoid direct file path manipulation from user input.",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        evidence=response.text[:500]
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found path traversal in parameter {param}")
                    break
        
        return vulnerabilities
    
    def _test_forced_browsing(self) -> List[Vulnerability]:
        """Test for forced browsing vulnerabilities using dirb/gobuster."""
        vulnerabilities = []
        
        # Use dirb for directory enumeration
        command = [
            "dirb",
            self.base_url,
            "/usr/share/dirb/wordlists/common.txt",
            "-S",  # Silent mode
            "-r",  # Don't recurse
        ]
        
        logger.info(f"Running dirb for forced browsing: {' '.join(command)}")
        result = self.run_kali_tool(command)
        
        if result["success"]:
            # Parse dirb output for found directories
            found_paths = re.findall(r'\+\s+(http[^\s]+)\s+\(CODE:(\d+)', result["stdout"])
            
            for path, code in found_paths:
                if code in ["200", "301", "302"]:
                    vuln = self.create_vulnerability(
                        vuln_type="broken_access_control",
                        title=f"Exposed Directory/File: {path}",
                        description=f"Dirb discovered accessible path through forced browsing. May expose sensitive files or directories.",
                        severity=Severity.MEDIUM,
                        location=path,
                        cvss_score=5.0,
                        cwe_id="CWE-425",
                        steps_to_reproduce=[
                            f"1. Access: {path}",
                            f"2. Received HTTP {code}",
                        ],
                        remediation="Implement proper access controls. Remove unnecessary files. Use authentication for sensitive directories."
                    )
                    vulnerabilities.append(vuln)
        else:
            logger.warning(f"Dirb not available or failed: {result['stderr']}")
        
        return vulnerabilities
    
    def _is_path_traversal_successful(self, response) -> bool:
        """Check if path traversal was successful."""
        indicators = [
            "root:x:", "bin:x:",  # /etc/passwd
            "[fonts]", "[extensions]",  # win.ini
            "daemon:", "nobody:",
            "# Copyright",  # Common in config files
        ]
        
        return any(ind in response.text for ind in indicators)
