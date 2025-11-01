"""Server-Side Request Forgery (SSRF) vulnerability scanner."""
from typing import List
from urllib.parse import urlparse, parse_qs
import socket
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class SSRFScanner(BaseScanner):
    """Scanner for Server-Side Request Forgery vulnerabilities."""
    
    # SSRF payloads targeting different resources
    SSRF_PAYLOADS = [
        # Internal IP ranges
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",  # AWS metadata
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata endpoint
        "http://192.168.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        
        # Protocol handlers
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://localhost:11211/stats",
        "gopher://localhost:6379/_",
        "ldap://localhost:389",
        
        # Bypass techniques
        "http://127.1",
        "http://0177.0.0.1",  # Octal
        "http://2130706433",  # Decimal IP
        "http://0x7f.0x0.0x0.0x1",  # Hex
        "http://localhost@127.0.0.1",
        "http://127.0.0.1.nip.io",
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws": "http://169.254.169.254/latest/meta-data/",
        "google": "http://metadata.google.internal/computeMetadata/v1/",
        "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "digitalocean": "http://169.254.169.254/metadata/v1/",
    }
    
    def scan(self) -> List[Vulnerability]:
        """Scan for SSRF vulnerabilities."""
        logger.info(f"Starting SSRF scan on {self.target}")
        vulnerabilities = []
        
        # 1. Test URL parameters for SSRF
        param_vulns = self._test_url_parameters()
        vulnerabilities.extend(param_vulns)
        
        # 2. Test for cloud metadata access
        if self.get_intensity_level() >= 2:
            cloud_vulns = self._test_cloud_metadata()
            vulnerabilities.extend(cloud_vulns)
        
        # 3. Test for internal port scanning
        if self.get_intensity_level() >= 3:
            port_vulns = self._test_internal_port_scan()
            vulnerabilities.extend(port_vulns)
        
        logger.info(f"SSRF scan found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _test_url_parameters(self) -> List[Vulnerability]:
        """Test URL parameters for SSRF."""
        vulnerabilities = []
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            # Test common parameter names that might accept URLs
            params = {
                "url": [""], "uri": [""], "path": [""], "dest": [""], 
                "redirect": [""], "link": [""], "src": [""], "source": [""],
                "file": [""], "document": [""], "page": [""], "callback": [""]
            }
        
        for param_name in params.keys():
            for payload in self.SSRF_PAYLOADS[:15]:  # Test first 15 payloads
                response = self.http_request("GET", params={param_name: payload})
                
                if response and self._is_ssrf_vulnerable(response, payload):
                    vuln = self.create_vulnerability(
                        vuln_type="ssrf",
                        title=f"Server-Side Request Forgery in parameter '{param_name}'",
                        description=f"The parameter '{param_name}' is vulnerable to SSRF attacks. The server makes requests to arbitrary URLs provided by user input, potentially exposing internal resources.",
                        severity=Severity.HIGH,
                        location=self.target,
                        parameter=param_name,
                        payload=payload,
                        cvss_score=8.5,
                        cwe_id="CWE-918",
                        steps_to_reproduce=[
                            f"1. Set parameter {param_name}={payload}",
                            "2. Observe server fetching the specified resource",
                            "3. Can access internal resources or cloud metadata",
                        ],
                        remediation="Implement allowlist of permitted domains/IPs. Validate and sanitize all URL inputs. Use network segmentation to restrict outbound connections.",
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                        ],
                        evidence=response.text[:500]
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found SSRF in parameter {param_name}")
                    break  # Found one, move to next parameter
        
        return vulnerabilities
    
    def _test_cloud_metadata(self) -> List[Vulnerability]:
        """Test for access to cloud metadata endpoints."""
        vulnerabilities = []
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            params = {"url": [""], "uri": [""], "redirect": [""]}
        
        for cloud_provider, metadata_url in self.CLOUD_METADATA.items():
            for param_name in params.keys():
                response = self.http_request("GET", params={param_name: metadata_url})
                
                if response and self._is_cloud_metadata_accessible(response, cloud_provider):
                    vuln = self.create_vulnerability(
                        vuln_type="ssrf",
                        title=f"SSRF with {cloud_provider.upper()} Metadata Access",
                        description=f"SSRF vulnerability allows access to {cloud_provider.upper()} cloud metadata endpoint. This can leak sensitive information including credentials, API keys, and instance configuration.",
                        severity=Severity.CRITICAL,
                        location=self.target,
                        parameter=param_name,
                        payload=metadata_url,
                        cvss_score=9.5,
                        cwe_id="CWE-918",
                        steps_to_reproduce=[
                            f"1. Set parameter {param_name}={metadata_url}",
                            f"2. Server accesses {cloud_provider.upper()} metadata endpoint",
                            "3. Sensitive cloud credentials and configuration exposed",
                            "4. Potential for privilege escalation and data breach",
                        ],
                        remediation="Block access to metadata endpoints (169.254.169.254). Implement strict URL validation and allowlisting. Use IMDSv2 (AWS) which requires tokens.",
                        references=[
                            f"https://docs.{cloud_provider}.com/security/",
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                        ],
                        evidence=response.text[:1000]
                    )
                    vulnerabilities.append(vuln)
                    logger.critical(f"Found critical SSRF with {cloud_provider} metadata access!")
                    break
        
        return vulnerabilities
    
    def _test_internal_port_scan(self) -> List[Vulnerability]:
        """Test if SSRF can be used for internal network port scanning."""
        vulnerabilities = []
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            params = {"url": [""]}
        
        # Test common internal ports
        common_ports = [22, 80, 443, 3306, 5432, 6379, 27017, 9200, 8080]
        internal_hosts = ["127.0.0.1", "localhost", "192.168.1.1"]
        
        open_ports = []
        
        for param_name in list(params.keys())[:1]:  # Test first parameter only
            for host in internal_hosts[:1]:  # Test one internal host
                for port in common_ports[:5]:  # Test first 5 ports
                    test_url = f"http://{host}:{port}"
                    
                    import time
                    start = time.time()
                    response = self.http_request("GET", params={param_name: test_url})
                    elapsed = time.time() - start
                    
                    # If we get different response times, port might be open
                    if response and (response.status_code != 404 or elapsed < 2):
                        open_ports.append((host, port))
        
        if open_ports:
            ports_str = ", ".join([f"{h}:{p}" for h, p in open_ports])
            vuln = self.create_vulnerability(
                vuln_type="ssrf",
                title="SSRF Enables Internal Network Port Scanning",
                description=f"SSRF vulnerability allows scanning internal network ports. Detected potentially open ports: {ports_str}",
                severity=Severity.HIGH,
                location=self.target,
                cvss_score=7.5,
                cwe_id="CWE-918",
                steps_to_reproduce=[
                    "1. Use SSRF to probe internal hosts and ports",
                    f"2. Identified open ports: {ports_str}",
                    "3. Can map internal network topology",
                ],
                remediation="Block internal IP ranges. Implement network segmentation. Use application-level firewalls.",
                metadata={"open_ports": open_ports}
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_ssrf_vulnerable(self, response, payload: str) -> bool:
        """Check if response indicates SSRF vulnerability."""
        # Look for indicators that the payload was fetched
        indicators = []
        
        if "localhost" in payload or "127.0.0.1" in payload:
            indicators = [
                "root:", "bin:", "/etc/",  # Unix system files
                "[fonts]", "[extensions]",  # Windows INI files
                "this is the default web page",
                "apache", "nginx", "iis",
                "connection refused", "no route to host",  # Even errors indicate SSRF
            ]
        elif "169.254.169.254" in payload:
            indicators = [
                "ami-id", "instance-id", "instance-type",  # AWS metadata
                "metadata", "iam", "security-credentials",
            ]
        elif "file://" in payload:
            indicators = [
                "root:", "bin:", "[fonts]", "windows",
            ]
        
        response_text = response.text.lower()
        return any(ind in response_text for ind in indicators)
    
    def _is_cloud_metadata_accessible(self, response, cloud_provider: str) -> bool:
        """Check if cloud metadata endpoint is accessible."""
        cloud_indicators = {
            "aws": ["ami-id", "instance-id", "iam", "security-credentials"],
            "google": ["computemetadata", "instance/", "project/"],
            "azure": ["compute", "network", "subscription"],
            "digitalocean": ["droplet_id", "hostname", "region"],
        }
        
        indicators = cloud_indicators.get(cloud_provider, [])
        response_text = response.text.lower()
        
        return any(ind in response_text for ind in indicators)
