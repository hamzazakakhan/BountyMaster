"""Scanner orchestrator to coordinate all vulnerability scanners."""
import concurrent.futures
from typing import List, Dict
from loguru import logger

from src.scanner.models import ScanResult, Vulnerability
from src.scanner.base_scanner import BaseScanner
from src.scanner.xss_scanner import XSSScanner
from src.scanner.sqli_scanner import SQLiScanner
from src.scanner.rce_scanner import RCEScanner
from src.scanner.ssrf_scanner import SSRFScanner
from src.scanner.access_control_scanner import AccessControlScanner
from src.scanner.misc_scanner import MisconfigurationScanner
from src.scanner.xxe_scanner import XXEScanner
from src.scanner.csrf_scanner import CSRFScanner
from src.scanner.auth_scanner import AuthScanner


class ScanOrchestrator:
    """Orchestrates vulnerability scanning across multiple scanner modules."""
    
    def __init__(
        self,
        target: str,
        vuln_types: List[str],
        intensity: str = "medium",
        threads: int = 10,
        timeout: int = 30,
        ai_exploits: bool = False,
    ):
        self.target = target
        self.vuln_types = vuln_types
        self.intensity = intensity
        self.threads = threads
        self.timeout = timeout
        self.ai_exploits = ai_exploits
        
        # Initialize scanners based on requested vulnerability types
        self.scanners: List[BaseScanner] = self._initialize_scanners()
        
        # Initialize scan result
        self.result = ScanResult(
            target=target,
            scan_config={
                "vuln_types": vuln_types,
                "intensity": intensity,
                "threads": threads,
                "timeout": timeout,
                "ai_exploits": ai_exploits,
            }
        )
    
    def _initialize_scanners(self) -> List[BaseScanner]:
        """Initialize scanners based on requested vulnerability types."""
        scanner_map = {
            "xss": XSSScanner,
            "sqli": SQLiScanner,
            "rce": RCEScanner,
            "ssrf": SSRFScanner,
            "broken_access_control": AccessControlScanner,
            "security_misconfiguration": MisconfigurationScanner,
            "xxe": XXEScanner,
            "csrf": CSRFScanner,
            "auth_failure": AuthScanner,
            "ato": AccessControlScanner,  # Account Takeover uses access control scanner
            "idor": AccessControlScanner,  # IDOR is part of access control
            "lfi": AccessControlScanner,  # Path traversal in access control
            "rfi": AccessControlScanner,
        }
        
        scanners = []
        for vuln_type in self.vuln_types:
            if vuln_type in scanner_map:
                scanner_class = scanner_map[vuln_type]
                scanners.append(
                    scanner_class(
                        target=self.target,
                        intensity=self.intensity,
                        timeout=self.timeout,
                    )
                )
                logger.info(f"Initialized {vuln_type} scanner")
            else:
                logger.warning(f"No scanner available for {vuln_type}")
        
        return scanners
    
    def run(self) -> ScanResult:
        """Run all scanners and aggregate results."""
        logger.info(f"Starting scan orchestration for {self.target}")
        
        # Run scanners in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_scanner = {
                executor.submit(self._run_scanner, scanner): scanner
                for scanner in self.scanners
            }
            
            for future in concurrent.futures.as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    vulnerabilities = future.result()
                    for vuln in vulnerabilities:
                        self.result.add_vulnerability(vuln)
                    logger.info(f"{scanner.__class__.__name__} found {len(vulnerabilities)} vulnerabilities")
                except Exception as e:
                    error_msg = f"Error running {scanner.__class__.__name__}: {str(e)}"
                    logger.error(error_msg)
                    self.result.errors.append(error_msg)
        
        # If AI exploits enabled, enhance vulnerabilities with AI-generated exploits
        if self.ai_exploits:
            self._enhance_with_ai()
        
        self.result.complete()
        logger.info(f"Scan completed. Found {len(self.result.vulnerabilities)} total vulnerabilities")
        
        return self.result
    
    def _run_scanner(self, scanner: BaseScanner) -> List[Vulnerability]:
        """Run a single scanner and return vulnerabilities."""
        try:
            return scanner.scan()
        except Exception as e:
            logger.error(f"Error in {scanner.__class__.__name__}: {str(e)}")
            return []
    
    def _enhance_with_ai(self):
        """Enhance vulnerabilities with AI-generated exploits."""
        logger.info("Enhancing vulnerabilities with AI-generated exploits")
        
        try:
            from src.ai.exploit_generator import ExploitGenerator
            
            generator = ExploitGenerator()
            
            for vuln in self.result.vulnerabilities:
                try:
                    exploit = generator.generate_exploit(vuln)
                    if exploit:
                        vuln.payload = exploit.payload
                        vuln.steps_to_reproduce.extend(exploit.steps)
                        vuln.metadata["ai_enhanced"] = True
                except Exception as e:
                    logger.warning(f"Failed to generate AI exploit for {vuln.id}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error initializing AI exploit generator: {str(e)}")
