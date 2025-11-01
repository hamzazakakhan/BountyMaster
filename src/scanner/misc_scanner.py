"""Security Misconfiguration scanner using nmap, testssl, and other tools."""
from typing import List
import re
from urllib.parse import urlparse
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class MisconfigurationScanner(BaseScanner):
    """Scanner for Security Misconfigurations using Nmap, testssl, and manual checks."""
    
    def scan(self) -> List[Vulnerability]:
        """Scan for security misconfigurations."""
        logger.info(f"Starting Misconfiguration scan on {self.target}")
        vulnerabilities = []
        
        # 1. Run Nmap for service detection and OS fingerprinting
        nmap_vulns = self._run_nmap()
        vulnerabilities.extend(nmap_vulns)
        
        # 2. Check HTTP security headers
        header_vulns = self._check_security_headers()
        vulnerabilities.extend(header_vulns)
        
        # 3. Check for default credentials
        if self.get_intensity_level() >= 2:
            cred_vulns = self._check_default_credentials()
            vulnerabilities.extend(cred_vulns)
        
        # 4. Test SSL/TLS configuration (if HTTPS)
        if self.scheme == "https" and self.get_intensity_level() >= 2:
            ssl_vulns = self._run_testssl()
            vulnerabilities.extend(ssl_vulns)
        
        # 5. Check for information disclosure
        info_vulns = self._check_information_disclosure()
        vulnerabilities.extend(info_vulns)
        
        # 6. Check CORS misconfiguration
        cors_vulns = self._check_cors()
        vulnerabilities.extend(cors_vulns)
        
        logger.info(f"Misconfiguration scan found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_nmap(self) -> List[Vulnerability]:
        """Run Nmap for service and vulnerability detection."""
        vulnerabilities = []
        
        # Extract host from target
        parsed = urlparse(self.target)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]
        
        # Nmap command for service detection
        command = [
            "nmap",
            "-sV",  # Service version detection
            "--script", "vuln",  # Run vulnerability scripts
            "-p-",  # Scan all ports
            "--max-retries", "1",
            "--host-timeout", f"{self.timeout}s",
            host
        ]
        
        # For lower intensity, scan only common ports
        if self.get_intensity_level() < 3:
            command[3] = "-p80,443,8080,8443,3306,5432,6379,27017,9200"
        
        logger.info(f"Running Nmap: {' '.join(command)}")
        result = self.run_kali_tool(command)
        
        if result["success"]:
            vulns = self._parse_nmap_output(result["stdout"])
            vulnerabilities.extend(vulns)
        else:
            logger.warning(f"Nmap not available or failed: {result['stderr']}")
        
        return vulnerabilities
    
    def _parse_nmap_output(self, output: str) -> List[Vulnerability]:
        """Parse Nmap output to extract vulnerabilities."""
        vulnerabilities = []
        
        # Parse open ports
        open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)
        for port, service in open_ports:
            # Common risky ports
            risky_ports = {
                "21": ("FTP", "HIGH"),
                "23": ("Telnet", "CRITICAL"),
                "3306": ("MySQL", "HIGH"),
                "5432": ("PostgreSQL", "HIGH"),
                "6379": ("Redis", "HIGH"),
                "27017": ("MongoDB", "HIGH"),
                "9200": ("Elasticsearch", "HIGH"),
            }
            
            if port in risky_ports:
                service_name, severity_str = risky_ports[port]
                severity = getattr(Severity, severity_str)
                
                vuln = self.create_vulnerability(
                    vuln_type="security_misconfiguration",
                    title=f"Exposed {service_name} Service on Port {port}",
                    description=f"Port {port} ({service_name}) is publicly accessible. This service should not be exposed to the internet.",
                    severity=severity,
                    location=f"{self.target}:{port}",
                    cvss_score=8.0,
                    cwe_id="CWE-16",
                    steps_to_reproduce=[
                        f"1. Scan target with Nmap",
                        f"2. Port {port} is open and accessible",
                        f"3. {service_name} service detected",
                    ],
                    remediation=f"Close port {port} to public internet. Use firewall rules or VPN. Implement authentication and encryption.",
                    metadata={"port": port, "service": service}
                )
                vulnerabilities.append(vuln)
        
        # Parse vulnerability script results
        vuln_sections = re.findall(r'\|\s+([^:]+):\s*\n\|\s+(.+?)(?=\n\||$)', output, re.DOTALL)
        for vuln_name, vuln_desc in vuln_sections:
            if "VULNERABLE" in vuln_desc.upper():
                vuln = self.create_vulnerability(
                    vuln_type="security_misconfiguration",
                    title=f"Nmap Detected: {vuln_name.strip()}",
                    description=vuln_desc.strip()[:500],
                    severity=Severity.HIGH,
                    location=self.target,
                    cvss_score=7.0,
                    cwe_id="CWE-16",
                    remediation="Review Nmap findings and apply appropriate patches or configuration changes.",
                    evidence=vuln_desc.strip()[:1000]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_security_headers(self) -> List[Vulnerability]:
        """Check for missing security headers."""
        vulnerabilities = []
        
        response = self.http_request("GET")
        if not response:
            return vulnerabilities
        
        # Required security headers
        security_headers = {
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "Content-Security-Policy": "Prevents XSS and injection attacks",
            "X-XSS-Protection": "Enables browser XSS protection",
            "Referrer-Policy": "Controls referrer information leakage",
            "Permissions-Policy": "Controls browser feature permissions",
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header not in response.headers:
                missing_headers.append((header, description))
        
        if missing_headers:
            headers_list = "\n".join([f"- {h}: {d}" for h, d in missing_headers])
            vuln = self.create_vulnerability(
                vuln_type="security_misconfiguration",
                title="Missing Security Headers",
                description=f"The application is missing important security headers:\n{headers_list}",
                severity=Severity.MEDIUM,
                location=self.target,
                cvss_score=5.0,
                cwe_id="CWE-16",
                steps_to_reproduce=[
                    "1. Make HTTP request to application",
                    "2. Inspect response headers",
                    f"3. Missing headers: {', '.join([h for h, _ in missing_headers])}",
                ],
                remediation="Implement all recommended security headers in web server configuration.",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://securityheaders.com/"
                ],
                metadata={"missing_headers": [h for h, _ in missing_headers]}
            )
            vulnerabilities.append(vuln)
        
        # Check for insecure headers
        if "Server" in response.headers:
            vuln = self.create_vulnerability(
                vuln_type="security_misconfiguration",
                title="Server Version Information Disclosure",
                description=f"Server header exposes version information: {response.headers['Server']}",
                severity=Severity.LOW,
                location=self.target,
                cvss_score=3.0,
                cwe_id="CWE-200",
                remediation="Remove or obfuscate Server header to hide version information.",
                evidence=response.headers['Server']
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_default_credentials(self) -> List[Vulnerability]:
        """Check for default credentials using Hydra."""
        vulnerabilities = []
        
        # Common default credentials to test
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("administrator", "administrator"),
        ]
        
        # Test basic auth
        for username, password in default_creds:
            response = self.http_request(
                "GET",
                auth=(username, password)
            )
            
            if response and response.status_code == 200:
                vuln = self.create_vulnerability(
                    vuln_type="security_misconfiguration",
                    title="Default Credentials Accepted",
                    description=f"Application accepts default credentials: {username}/{password}",
                    severity=Severity.CRITICAL,
                    location=self.target,
                    cvss_score=9.5,
                    cwe_id="CWE-798",
                    steps_to_reproduce=[
                        f"1. Authenticate with username: {username}",
                        f"2. Use password: {password}",
                        "3. Access granted with default credentials",
                    ],
                    remediation="Change all default credentials immediately. Enforce strong password policy.",
                    metadata={"username": username}
                )
                vulnerabilities.append(vuln)
                logger.critical(f"Found default credentials: {username}/{password}")
                break
        
        return vulnerabilities
    
    def _run_testssl(self) -> List[Vulnerability]:
        """Run testssl.sh for SSL/TLS configuration testing."""
        vulnerabilities = []
        
        command = [
            "testssl.sh",
            "--quiet",
            "--fast",
            "--severity", "HIGH",
            self.target
        ]
        
        logger.info(f"Running testssl.sh: {' '.join(command)}")
        result = self.run_kali_tool(command)
        
        if result["success"]:
            output = result["stdout"]
            
            # Check for weak ciphers
            if "weak" in output.lower() or "vulnerable" in output.lower():
                vuln = self.create_vulnerability(
                    vuln_type="cryptographic_failure",
                    title="Weak SSL/TLS Configuration",
                    description="testssl.sh detected weak cryptographic configuration or vulnerabilities.",
                    severity=Severity.HIGH,
                    location=self.target,
                    cvss_score=7.5,
                    cwe_id="CWE-327",
                    steps_to_reproduce=[
                        f"1. Run testssl.sh against {self.target}",
                        "2. Weak ciphers or protocol vulnerabilities detected",
                    ],
                    remediation="Disable weak ciphers and protocols. Enable only TLS 1.2 and 1.3. Use strong cipher suites.",
                    references=["https://testssl.sh/"],
                    evidence=output[:1000]
                )
                vulnerabilities.append(vuln)
        else:
            logger.warning(f"testssl.sh not available or failed: {result['stderr']}")
        
        return vulnerabilities
    
    def _check_information_disclosure(self) -> List[Vulnerability]:
        """Check for information disclosure vulnerabilities."""
        vulnerabilities = []
        
        response = self.http_request("GET")
        if not response:
            return vulnerabilities
        
        # Check for verbose error messages
        error_indicators = [
            ("stack trace", "Stack trace exposed"),
            ("exception", "Exception details exposed"),
            ("sql", "SQL query exposed"),
            ("database", "Database information exposed"),
            ("warning", "PHP/Application warnings exposed"),
            ("fatal error", "Fatal errors exposed"),
        ]
        
        for indicator, description in error_indicators:
            if indicator in response.text.lower():
                vuln = self.create_vulnerability(
                    vuln_type="security_misconfiguration",
                    title=f"Information Disclosure: {description}",
                    description=f"Application exposes sensitive debugging information in responses.",
                    severity=Severity.MEDIUM,
                    location=self.target,
                    cvss_score=5.0,
                    cwe_id="CWE-200",
                    remediation="Disable debug mode in production. Implement custom error pages.",
                    evidence=response.text[:500]
                )
                vulnerabilities.append(vuln)
                break  # Only report once
        
        return vulnerabilities
    
    def _check_cors(self) -> List[Vulnerability]:
        """Check for CORS misconfiguration."""
        vulnerabilities = []
        
        # Test with malicious origin
        response = self.http_request(
            "GET",
            headers={"Origin": "https://evil.com"}
        )
        
        if response and "Access-Control-Allow-Origin" in response.headers:
            allow_origin = response.headers["Access-Control-Allow-Origin"]
            
            if allow_origin == "*" or allow_origin == "https://evil.com":
                vuln = self.create_vulnerability(
                    vuln_type="security_misconfiguration",
                    title="CORS Misconfiguration",
                    description=f"Application allows requests from any origin (Access-Control-Allow-Origin: {allow_origin}). This can lead to data theft.",
                    severity=Severity.HIGH,
                    location=self.target,
                    cvss_score=7.0,
                    cwe_id="CWE-942",
                    steps_to_reproduce=[
                        "1. Send request with Origin: https://evil.com",
                        f"2. Server responds with: {allow_origin}",
                        "3. Cross-origin requests are allowed from any domain",
                    ],
                    remediation="Implement strict CORS policy. Whitelist only trusted origins.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
