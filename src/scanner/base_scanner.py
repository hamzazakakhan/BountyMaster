"""Base scanner class for all vulnerability scanners."""
import subprocess
import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import requests
from loguru import logger

from src.scanner.models import Vulnerability, Severity
from src.config import config


class BaseScanner(ABC):
    """Base class for all vulnerability scanners."""
    
    def __init__(self, target: str, intensity: str = "medium", timeout: int = 30):
        self.target = target
        self.intensity = intensity
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "BugBountyCLI/1.0 (Security Scanner)"
        })
        
        # Parse target URL
        parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        self.scheme = parsed.scheme
        self.domain = parsed.netloc or parsed.path
        self.path = parsed.path
        self.base_url = f"{self.scheme}://{self.domain}"
    
    @abstractmethod
    def scan(self) -> List[Vulnerability]:
        """Perform vulnerability scan. Must be implemented by subclasses."""
        pass
    
    def run_kali_tool(
        self,
        command: List[str],
        parse_output: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a Kali Linux tool command.
        
        Args:
            command: Command and arguments as list
            parse_output: Whether to parse the output
            
        Returns:
            Dictionary with stdout, stderr, returncode, and parsed data
        """
        logger.info(f"Running Kali tool: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            logger.warning(f"Tool {command[0]} timed out after {self.timeout}s")
            return {
                "stdout": "",
                "stderr": "Command timed out",
                "returncode": -1,
                "success": False,
            }
        except FileNotFoundError:
            logger.error(f"Tool {command[0]} not found. Make sure it's installed.")
            return {
                "stdout": "",
                "stderr": f"Tool {command[0]} not found",
                "returncode": -1,
                "success": False,
            }
        except Exception as e:
            logger.error(f"Error running {command[0]}: {str(e)}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "success": False,
            }
    
    def http_request(
        self,
        method: str = "GET",
        url: Optional[str] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make HTTP request with error handling."""
        url = url or self.base_url
        
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP request failed: {str(e)}")
            return None
    
    def create_vulnerability(
        self,
        vuln_type: str,
        title: str,
        description: str,
        severity: Severity,
        location: str,
        **kwargs
    ) -> Vulnerability:
        """Create a vulnerability object with common fields."""
        return Vulnerability(
            type=vuln_type,
            title=title,
            description=description,
            severity=severity,
            location=location,
            url=self.target,
            tool_used=self.__class__.__name__,
            **kwargs
        )
    
    def get_intensity_level(self) -> int:
        """Convert intensity string to numeric level."""
        intensity_map = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "extreme": 4,
        }
        return intensity_map.get(self.intensity.lower(), 2)
