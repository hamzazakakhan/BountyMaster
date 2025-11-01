"""NVD (National Vulnerability Database) API client."""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import requests
from pydantic import BaseModel
from loguru import logger
import time

from src.config import config


class CVE(BaseModel):
    """CVE vulnerability information."""
    id: str
    description: str
    cvss_score: float
    severity: str
    published_date: datetime
    last_modified: datetime
    references: List[str] = []
    cwe_ids: List[str] = []
    vulnerable_products: List[str] = []


class CVEClient:
    """Client for NVD API to fetch CVE data."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        self.api_key = config.nvd_api_key
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
            self.rate_limit_delay = 0.6  # With API key: max 100 requests per 30 seconds
        else:
            self.rate_limit_delay = 6.0  # Without API key: max 5 requests per 30 seconds
            logger.warning("NVD API key not configured. Rate limiting will be slower.")
        
        self.last_request_time = 0
    
    def search_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cve_id: Optional[str] = None,
        results_per_page: int = 20
    ) -> List[CVE]:
        """Search for CVEs by keyword, CPE, or CVE ID."""
        logger.info(f"Searching CVEs: keyword={keyword}, cpe={cpe_name}, cve_id={cve_id}")
        
        params = {
            "resultsPerPage": results_per_page
        }
        
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cve_id:
            params["cveId"] = cve_id
        
        try:
            self._respect_rate_limit()
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_cves(data)
            
            logger.info(f"Found {len(cves)} CVEs")
            return cves
            
        except Exception as e:
            logger.error(f"Error searching CVEs: {str(e)}")
            return []
    
    def get_cve_by_id(self, cve_id: str) -> Optional[CVE]:
        """Get specific CVE by ID."""
        cves = self.search_cves(cve_id=cve_id)
        return cves[0] if cves else None
    
    def search_by_product(self, product: str, version: Optional[str] = None) -> List[CVE]:
        """Search CVEs for a specific product."""
        logger.info(f"Searching CVEs for product: {product} {version or ''}")
        
        # Construct CPE name (Common Platform Enumeration)
        # Example: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        keyword = f"{product} {version}" if version else product
        
        return self.search_cves(keyword=keyword)
    
    def get_recent_cves(self, days: int = 7) -> List[CVE]:
        """Get CVEs published in the last N days."""
        logger.info(f"Fetching CVEs from last {days} days")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100
        }
        
        try:
            self._respect_rate_limit()
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            return self._parse_cves(data)
            
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {str(e)}")
            return []
    
    def _parse_cves(self, data: Dict[str, Any]) -> List[CVE]:
        """Parse CVE data from NVD API response."""
        cves = []
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln_data in vulnerabilities:
            cve_data = vuln_data.get("cve", {})
            
            cve_id = cve_data.get("id", "")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break
            
            # Get references
            references = []
            ref_data = cve_data.get("references", [])
            for ref in ref_data[:5]:  # Limit to 5 references
                references.append(ref.get("url", ""))
            
            # Get CWE IDs
            cwe_ids = []
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_ids.append(desc.get("value", ""))
            
            # Get affected products
            vulnerable_products = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe = cpe_match.get("criteria", "")
                            vulnerable_products.append(cpe)
            
            # Parse dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")
            
            try:
                published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                modified_date = datetime.fromisoformat(modified.replace("Z", "+00:00"))
            except:
                published_date = datetime.now()
                modified_date = datetime.now()
            
            cve = CVE(
                id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published_date,
                last_modified=modified_date,
                references=references,
                cwe_ids=cwe_ids,
                vulnerable_products=vulnerable_products
            )
            
            cves.append(cve)
        
        return cves
    
    def _respect_rate_limit(self):
        """Respect NVD API rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
