"""CVE vulnerability scanner using NVD API."""
from typing import List
import re
from loguru import logger
from pydantic import BaseModel

from src.nvd.cve_client import CVEClient, CVE
from src.scanner.models import Vulnerability, Severity


class CVEScanResult(BaseModel):
    """Result of CVE scan."""
    target: str
    cves: List[CVE]
    vulnerabilities: List[Vulnerability]


class CVEScanner:
    """Scanner that checks for known CVEs."""
    
    def __init__(self):
        self.client = CVEClient()
    
    def scan(self, target: str) -> CVEScanResult:
        """Scan target for known CVEs."""
        logger.info(f"Starting CVE scan on {target}")
        
        cves = []
        vulnerabilities = []
        
        # Try to detect technologies from HTTP headers/response
        detected_software = self._detect_software(target)
        
        for software, version in detected_software:
            logger.info(f"Detected software: {software} {version}")
            
            # Search CVEs for this software
            software_cves = self.client.search_by_product(software, version)
            cves.extend(software_cves)
            
            # Convert CVEs to Vulnerabilities
            for cve in software_cves:
                vuln = self._cve_to_vulnerability(cve, target)
                vulnerabilities.append(vuln)
        
        logger.info(f"CVE scan found {len(cves)} CVEs, {len(vulnerabilities)} vulnerabilities")
        
        return CVEScanResult(
            target=target,
            cves=cves,
            vulnerabilities=vulnerabilities
        )
    
    def _detect_software(self, target: str) -> List[tuple]:
        """Detect software and versions from target."""
        import requests
        
        detected = []
        
        try:
            response = requests.get(target, timeout=10)
            
            # Check Server header
            if "Server" in response.headers:
                server = response.headers["Server"]
                software, version = self._parse_version_string(server)
                if software:
                    detected.append((software, version))
            
            # Check X-Powered-By header
            if "X-Powered-By" in response.headers:
                powered_by = response.headers["X-Powered-By"]
                software, version = self._parse_version_string(powered_by)
                if software:
                    detected.append((software, version))
            
            # Check for common CMS/frameworks in HTML
            html = response.text.lower()
            
            if "wordpress" in html:
                version = self._extract_wordpress_version(html)
                detected.append(("wordpress", version))
            
            if "joomla" in html:
                detected.append(("joomla", ""))
            
            if "drupal" in html:
                detected.append(("drupal", ""))
            
        except Exception as e:
            logger.warning(f"Could not detect software: {str(e)}")
        
        return detected
    
    def _parse_version_string(self, value: str) -> tuple:
        """Parse software name and version from string."""
        # Examples: "Apache/2.4.41", "nginx/1.18.0", "PHP/7.4.3"
        match = re.match(r'([a-zA-Z]+)[/\s]+([\d.]+)', value)
        
        if match:
            return (match.group(1).lower(), match.group(2))
        
        # Just software name, no version
        software = re.match(r'([a-zA-Z]+)', value)
        if software:
            return (software.group(1).lower(), "")
        
        return ("", "")
    
    def _extract_wordpress_version(self, html: str) -> str:
        """Extract WordPress version from HTML."""
        match = re.search(r'wp-includes.*?ver=([\d.]+)', html)
        if match:
            return match.group(1)
        return ""
    
    def _cve_to_vulnerability(self, cve: CVE, target: str) -> Vulnerability:
        """Convert CVE to Vulnerability object."""
        # Map CVE severity to our Severity enum
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        
        severity = severity_map.get(cve.severity, Severity.MEDIUM)
        
        return Vulnerability(
            type="vulnerable_components",
            title=f"Known Vulnerability: {cve.id}",
            description=f"{cve.description}\n\nAffected products: {', '.join(cve.vulnerable_products[:3])}",
            severity=severity,
            location=target,
            cvss_score=cve.cvss_score,
            cwe_id=cve.cwe_ids[0] if cve.cwe_ids else "CWE-1035",
            steps_to_reproduce=[
                f"1. Target is running vulnerable software version",
                f"2. CVE {cve.id} applies to this version",
                f"3. Published: {cve.published_date.strftime('%Y-%m-%d')}",
                "4. Check references for exploit details",
            ],
            remediation=f"Update affected software to a patched version. Review {cve.id} for specific mitigation steps.",
            references=cve.references,
            metadata={
                "cve_id": cve.id,
                "published_date": cve.published_date.isoformat(),
                "last_modified": cve.last_modified.isoformat(),
                "cwe_ids": cve.cwe_ids,
            }
        )
