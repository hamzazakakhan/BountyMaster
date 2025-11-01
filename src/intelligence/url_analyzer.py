"""Intelligent URL analyzer for predicting vulnerability types."""
from typing import List
from urllib.parse import urlparse, parse_qs
from pydantic import BaseModel
from loguru import logger
import re


class VulnerabilityPrediction(BaseModel):
    """Prediction of vulnerability type for a URL."""
    type: str
    confidence: float
    reason: str


class URLAnalyzer:
    """Analyzes URLs to predict potential vulnerability types."""
    
    # Patterns that suggest specific vulnerability types
    PATTERNS = {
        "sqli": [
            r"[\?&]id=\d+",
            r"[\?&]user_id=",
            r"[\?&]product_id=",
            r"[\?&]page=\d+",
            r"[\?&]cat(egory)?=",
            r"[\?&]item=",
            r"[\?&]query=",
            r"[\?&]search=",
        ],
        "xss": [
            r"[\?&]search=",
            r"[\?&]q=",
            r"[\?&]query=",
            r"[\?&]keyword=",
            r"[\?&]term=",
            r"[\?&]name=",
            r"[\?&]message=",
            r"[\?&]comment=",
        ],
        "lfi": [
            r"[\?&]file=",
            r"[\?&]path=",
            r"[\?&]page=[\w/]+",
            r"[\?&]include=",
            r"[\?&]template=",
            r"[\?&]document=",
            r"[\?&]load=",
        ],
        "ssrf": [
            r"[\?&]url=https?://",
            r"[\?&]uri=",
            r"[\?&]link=https?://",
            r"[\?&]redirect=",
            r"[\?&]proxy=",
            r"[\?&]fetch=",
            r"[\?&]download=https?://",
        ],
        "idor": [
            r"[\?&]user(_)?id=\d+",
            r"[\?&]account=\d+",
            r"[\?&]profile=\d+",
            r"[\?&]doc(ument)?_id=",
            r"[\?&]file_id=",
            r"/user/\d+",
            r"/profile/\d+",
            r"/account/\d+",
        ],
        "rce": [
            r"[\?&]cmd=",
            r"[\?&]exec=",
            r"[\?&]command=",
            r"[\?&]execute=",
            r"[\?&]run=",
            r"[\?&]ping=",
            r"[\?&]ip=",
        ],
    }
    
    # Keywords in path that suggest vulnerability types
    PATH_KEYWORDS = {
        "sqli": ["login", "auth", "signin", "user", "admin", "search", "product", "item"],
        "xss": ["search", "comment", "message", "post", "blog", "forum"],
        "broken_access_control": ["admin", "dashboard", "panel", "management", "console"],
        "auth_failure": ["login", "signin", "auth", "register", "password", "reset"],
        "lfi": ["download", "file", "document", "view", "read", "include"],
    }
    
    def analyze(self, url: str) -> List[VulnerabilityPrediction]:
        """Analyze URL and predict potential vulnerabilities."""
        logger.info(f"Analyzing URL: {url}")
        
        predictions = []
        parsed = urlparse(url)
        
        # Analyze URL patterns
        pattern_predictions = self._analyze_patterns(url)
        predictions.extend(pattern_predictions)
        
        # Analyze path keywords
        path_predictions = self._analyze_path(parsed.path)
        predictions.extend(path_predictions)
        
        # Analyze parameters
        param_predictions = self._analyze_parameters(parsed.query)
        predictions.extend(param_predictions)
        
        # Remove duplicates and sort by confidence
        unique_predictions = self._deduplicate(predictions)
        unique_predictions.sort(key=lambda x: x.confidence, reverse=True)
        
        logger.info(f"Found {len(unique_predictions)} potential vulnerability types")
        return unique_predictions
    
    def _analyze_patterns(self, url: str) -> List[VulnerabilityPrediction]:
        """Analyze URL against known vulnerability patterns."""
        predictions = []
        
        for vuln_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    confidence = 0.7  # Base confidence for pattern match
                    
                    # Increase confidence if multiple patterns match
                    match_count = sum(1 for p in patterns if re.search(p, url, re.IGNORECASE))
                    confidence = min(0.95, confidence + (match_count - 1) * 0.1)
                    
                    predictions.append(VulnerabilityPrediction(
                        type=vuln_type,
                        confidence=confidence,
                        reason=f"URL matches {vuln_type.upper()} pattern: {pattern}"
                    ))
                    break  # One prediction per type
        
        return predictions
    
    def _analyze_path(self, path: str) -> List[VulnerabilityPrediction]:
        """Analyze URL path for vulnerability indicators."""
        predictions = []
        path_lower = path.lower()
        
        for vuln_type, keywords in self.PATH_KEYWORDS.items():
            matches = [kw for kw in keywords if kw in path_lower]
            
            if matches:
                confidence = min(0.8, 0.5 + len(matches) * 0.15)
                predictions.append(VulnerabilityPrediction(
                    type=vuln_type,
                    confidence=confidence,
                    reason=f"Path contains keywords: {', '.join(matches)}"
                ))
        
        return predictions
    
    def _analyze_parameters(self, query: str) -> List[VulnerabilityPrediction]:
        """Analyze query parameters for vulnerability indicators."""
        predictions = []
        
        if not query:
            return predictions
        
        params = parse_qs(query)
        param_names = [p.lower() for p in params.keys()]
        
        # Check for common vulnerable parameter names
        vuln_params = {
            "sqli": ["id", "user_id", "product_id", "item_id", "cat", "category"],
            "xss": ["search", "q", "query", "name", "comment", "message"],
            "lfi": ["file", "path", "page", "template", "include"],
            "ssrf": ["url", "uri", "link", "redirect", "proxy"],
            "rce": ["cmd", "command", "exec", "execute", "ping"],
        }
        
        for vuln_type, vulnerable_names in vuln_params.items():
            matching_params = [p for p in param_names if p in vulnerable_names]
            
            if matching_params:
                confidence = min(0.85, 0.6 + len(matching_params) * 0.15)
                predictions.append(VulnerabilityPrediction(
                    type=vuln_type,
                    confidence=confidence,
                    reason=f"Parameters suggest {vuln_type.upper()}: {', '.join(matching_params)}"
                ))
        
        # General analysis
        if len(params) > 5:
            predictions.append(VulnerabilityPrediction(
                type="broken_access_control",
                confidence=0.4,
                reason=f"Complex URL with {len(params)} parameters may have access control issues"
            ))
        
        return predictions
    
    def _deduplicate(self, predictions: List[VulnerabilityPrediction]) -> List[VulnerabilityPrediction]:
        """Remove duplicate predictions, keeping highest confidence."""
        seen = {}
        
        for pred in predictions:
            if pred.type not in seen or pred.confidence > seen[pred.type].confidence:
                seen[pred.type] = pred
        
        return list(seen.values())
