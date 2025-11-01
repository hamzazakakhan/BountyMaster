"""Data models for vulnerability scanning."""
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities based on OWASP Top 10."""
    XSS = "xss"
    SQLI = "sqli"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    CSRF = "csrf"
    LFI = "lfi"
    RFI = "rfi"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTOGRAPHIC_FAILURE = "cryptographic_failure"
    INJECTION = "injection"
    INSECURE_DESIGN = "insecure_design"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    AUTH_FAILURE = "auth_failure"
    DATA_INTEGRITY_FAILURE = "data_integrity_failure"
    ACCOUNT_TAKEOVER = "ato"


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability."""
    id: str = Field(default_factory=lambda: f"vuln_{datetime.now().timestamp()}")
    type: str
    severity: Severity
    title: str
    description: str
    location: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    steps_to_reproduce: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.now)
    tool_used: Optional[str] = None
    confidence: float = 1.0
    false_positive: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Represents the result of a security scan."""
    scan_id: str = Field(default_factory=lambda: f"scan_{datetime.now().timestamp()}")
    target: str
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: str = "running"
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    scan_config: Dict[str, Any] = Field(default_factory=dict)
    statistics: Dict[str, int] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the scan results."""
        self.vulnerabilities.append(vuln)
        self.update_statistics()
    
    def update_statistics(self):
        """Update scan statistics."""
        self.statistics = {
            "total": len(self.vulnerabilities),
            "critical": len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL]),
            "high": len([v for v in self.vulnerabilities if v.severity == Severity.HIGH]),
            "medium": len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM]),
            "low": len([v for v in self.vulnerabilities if v.severity == Severity.LOW]),
            "info": len([v for v in self.vulnerabilities if v.severity == Severity.INFO]),
        }
    
    def complete(self):
        """Mark scan as completed."""
        self.completed_at = datetime.now()
        self.status = "completed"
        self.update_statistics()


class ExploitResult(BaseModel):
    """Result of exploit testing."""
    vulnerability_id: str
    success: bool
    payload: str
    response: Optional[str] = None
    evidence: Optional[str] = None
    steps: List[str] = Field(default_factory=list)
    tested_at: datetime = Field(default_factory=datetime.now)
