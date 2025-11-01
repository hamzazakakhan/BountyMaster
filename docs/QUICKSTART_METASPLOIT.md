# Quick Start: Metasploit + AI Integration

Get up and running with AI-powered Metasploit exploitation in 5 minutes.

## Prerequisites

You need:
1. Kali Linux (or any Linux with Metasploit)
2. OpenAI API key
3. Bug Bounty CLI installed

## Installation

### 1. Install Metasploit (if not already installed)

```bash
sudo apt-get update
sudo apt-get install metasploit-framework -y
```

### 2. Install Bug Bounty CLI

```bash
cd bug-bounty-cli
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 3. Configure API Keys

```bash
cp .env.example .env
nano .env
```

Add your OpenAI API key:
```env
OPENAI_API_KEY=sk-your-key-here
```

## Basic Usage

### Run a Full Pentest with Metasploit

```bash
bugbounty pentest --target https://testsite.com --metasploit
```

This will:
1. ✓ Scan for vulnerabilities
2. ✓ Search Metasploit for relevant exploits
3. ✓ Use AI to select best modules
4. ✓ Automatically exploit vulnerabilities
5. ✓ Report sessions and access levels

### Example Output

```
🎯 Bug Bounty CLI - Full Penetration Test

Target: https://testsite.com
Intensity: high
AI Exploits: Enabled
Metasploit: Enabled

[*] Phase 1: Vulnerability scanning
[✓] Found 3 vulnerabilities

[*] Phase 2: Exploit testing

[*] Testing: Remote Code Execution in /upload.php
[*] Searching Metasploit modules...
[*] Found 5 relevant modules
[*] AI selecting optimal module...
[✓] Selected: exploit/multi/http/php_upload_exec (Rank: excellent)
[*] Executing exploit against testsite.com:80
[✓] Exploit successful! Session 1 opened
[✓] Access Level: meterpreter

Impact: CRITICAL
Full system access achieved. Attacker has complete control.

✓ Penetration test completed!
Exploitable vulnerabilities: 1
```

## Command Options

### All Features Enabled
```bash
bugbounty pentest \
  --target https://site.com \
  --intensity extreme \
  --ai-exploits \
  --metasploit \
  --output report.html
```

### Without Metasploit
```bash
bugbounty pentest --target https://site.com --no-metasploit
```

### Different Intensity Levels
```bash
# Fast scan
bugbounty pentest --target https://site.com --intensity low --metasploit

# Comprehensive scan
bugbounty pentest --target https://site.com --intensity extreme --metasploit
```

## What Gets Automated

### 1. Module Search
- Searches by CVE ID
- Searches by vulnerability type
- Searches by detected technology

### 2. AI Selection
AI analyzes:
- Exploit reliability (rank)
- Platform compatibility
- Relevance to vulnerability
- Recency of exploit

### 3. Exploitation
- Configures RHOSTS, RPORT automatically
- Selects appropriate payloads
- Executes via msfconsole
- Captures session information

### 4. Result Reporting
- Session IDs
- Access levels (shell/meterpreter)
- Impact assessment
- Error messages

## Testing Environments

### Safe Targets for Testing

Practice on these intentionally vulnerable applications:

1. **DVWA** (Damn Vulnerable Web Application)
   ```bash
   docker run --rm -it -p 80:80 vulnerables/web-dvwa
   bugbounty pentest --target http://localhost --metasploit
   ```

2. **Metasploitable 2**
   ```bash
   # Download from SourceForge
   # Run in VirtualBox
   bugbounty pentest --target http://192.168.56.101 --metasploit
   ```

3. **OWASP WebGoat**
   ```bash
   docker run -p 8080:8080 webgoat/goatandwolf
   bugbounty pentest --target http://localhost:8080 --metasploit
   ```

## Common Issues

### "Metasploit not found"
```bash
# Verify installation
which msfconsole

# If not found, install
sudo apt-get install metasploit-framework
```

### "OpenAI API key not configured"
```bash
# Check .env file
cat .env | grep OPENAI_API_KEY

# If empty, add your key
echo "OPENAI_API_KEY=sk-your-key" >> .env
```

### No Exploits Found
- Vulnerability may be too new
- Check Metasploit database is updated:
  ```bash
  msfconsole -x "db_rebuild_cache; exit"
  ```

## Next Steps

1. Read full documentation: `docs/METASPLOIT_INTEGRATION.md`
2. Try different vulnerability types
3. Test on safe lab environments
4. Review AI module selections
5. Customize payloads for your needs

## Legal Reminder

⚠️ **ONLY use on authorized targets**

This tool performs **active exploitation**. Using it without permission is:
- Illegal
- Punishable by law
- Unethical

Always:
- Get written authorization
- Test in isolated environments
- Document all activities
- Follow responsible disclosure

## Support

- Issues: GitHub Issues
- Docs: `docs/` directory
- Examples: `docs/METASPLOIT_INTEGRATION.md`
