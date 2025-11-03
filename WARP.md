# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Bug Bounty CLI is an AI-powered penetration testing tool that integrates Kali Linux security tools with OpenAI for intelligent vulnerability scanning and exploit generation. It focuses on OWASP Top 10 vulnerabilities and includes CVE database integration.

## Running in Kali Linux

### Initial Setup
```bash
# Install system dependencies (Kali Linux tools)
sudo apt-get update
sudo apt-get install -y nmap sqlmap nikto dirb metasploit-framework hydra wpscan

# Clone and navigate to repository
git clone https://github.com/yourusername/bug-bounty-cli.git
cd bug-bounty-cli

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Add OPENAI_API_KEY and NVD_API_KEY

# Install CLI tool
pip install -e .
```

### Common Commands

**Development:**
```bash
# Activate virtual environment (always do this first)
source venv/bin/activate

# Run tests
pytest tests/

# Install in development mode
pip install -e .
```

**Running Scans:**
```bash
# Basic vulnerability scan
bugbounty scan --target https://example.com

# Scan specific vulnerability types
bugbounty scan --target https://example.com --types xss,sqli,rce

# Full penetration test with AI exploits and Metasploit
bugbounty pentest --target https://example.com --ai-exploits --metasploit --intensity high

# Pentest without Metasploit (manual exploit testing only)
bugbounty pentest --target https://example.com --no-metasploit --intensity medium

# URL intelligence analysis
bugbounty analyze-url --url "https://example.com/admin.php?id=123"

# CVE scanning
bugbounty cve-scan --target https://example.com --output report.html

# Update exploit database
bugbounty update-exploits

# Generate report from scan
bugbounty report --scan-id abc123 --format pdf --output report.pdf

# Show configuration
bugbounty config --show
```

## Architecture

### Core Components

**Entry Point:**
- `src/main.py` - Typer-based CLI with commands: scan, pentest, analyze-url, cve-scan, update-exploits, report, config

**Configuration:**
- `src/config.py` - Pydantic-based config using environment variables
- `.env` file - API keys and settings (OPENAI_API_KEY, NVD_API_KEY, MAX_THREADS, TIMEOUT_SECONDS, etc.)

**Modular Scanner Architecture:**
- `src/scanner/` - Individual vulnerability scanners (XSS, SQLi, RCE, SSRF, etc.)
  - `base_scanner.py` - Base class for all scanners
  - `orchestrator.py` - Coordinates multiple scanners with threading
  - Each scanner module handles specific OWASP Top 10 vulnerability types

**AI Integration:**
- `src/ai/` - OpenAI integration for exploit generation
  - `exploit_generator.py` - AI-powered exploit crafting
  - `prompt_templates.py` - Prompt engineering for security testing

**External Data Sources:**
- `src/nvd/` - NVD CVE database client for vulnerability lookups
- `src/exploits/` - Exploit-DB and PacketStorm scraping with local caching

**Intelligence:**
- `src/intelligence/url_analyzer.py` - ML-based URL pattern recognition to predict vulnerability types

**Testing & Execution:**
- `src/testing/` - Safe exploit execution framework
  - `pentest_engine.py` - Full penetration test orchestration with Metasploit integration
  - `exploit_executor.py` - Controlled exploit testing
  - `metasploit_integrator.py` - Metasploit Framework integration with AI-powered module selection

**Data Persistence:**
- `src/database/` - SQLAlchemy-based scan result storage
- Local directories: `reports/`, `exploits_cache/`, `logs/`

**Reporting:**
- `src/reporting/report_generator.py` - Multi-format report generation (JSON, HTML, PDF, Markdown)
- Uses Jinja2 templates and ReportLab for PDF generation

### Data Flow

1. CLI command → `main.py` → Check API keys
2. Target validation → Scanner orchestrator initializes
3. Parallel vulnerability scanning (threading) → Individual scanners
4. Results aggregation → Optional AI exploit generation
5. **Metasploit Integration Flow (if enabled):**
   - Search Metasploit database for relevant exploit modules
   - AI selects optimal module based on vulnerability context
   - Execute exploit via msfconsole resource files
   - Parse output for session establishment and access level
6. NVD CVE lookup for identified software
7. Results storage in database
8. Report generation in requested format

## API Keys (All Optional)

- **OPENAI_API_KEY** - **Optional** - Only needed for AI-powered features:
  - AI exploit generation
  - AI Metasploit module selection (falls back to heuristic ranking)
  - Get from https://platform.openai.com/api-keys
  - **Without this key, the tool still works fully with Metasploit and scanning**

- **NVD_API_KEY** - **Optional** - For faster CVE lookups
  - Get from https://nvd.nist.gov/developers/request-an-api-key
  - Without this, CVE lookups may be rate-limited but still work

## Metasploit Integration

### How It Works

When `--metasploit` flag is enabled in pentest mode:

1. **Automatic Module Search**: For each discovered vulnerability, searches Metasploit database for relevant exploit modules based on CVE, vulnerability type, and detected technologies

2. **AI-Powered Module Selection**: Uses OpenAI to intelligently select the best Metasploit module by analyzing:
   - Exploit rank (excellent > great > good > normal)
   - Relevance to vulnerability type
   - Target platform compatibility
   - Disclosure date and reliability

3. **Automated Exploitation**: Executes the selected module with appropriate payloads:
   - Configures RHOSTS, RPORT automatically from vulnerability data
   - Selects safe, non-destructive payloads for testing
   - Captures session information if exploitation succeeds

4. **Result Analysis**: Parses Metasploit output to determine:
   - Exploitation success/failure
   - Session ID if shell/meterpreter obtained
   - Access level achieved (shell vs meterpreter)
   - Error messages for debugging

### Example Workflow

```bash
# Full pentest with AI + Metasploit
bugbounty pentest --target https://vulnerable-site.com --metasploit --ai-exploits

# Output shows:
# - Vulnerability scan results
# - Metasploit module selected by AI
# - Exploitation attempt results
# - Session IDs if successful
# - Comprehensive impact assessment
```

### Metasploit Module Selection

The AI considers:
- **Vulnerability context**: Type, severity, CVE ID, description
- **Module ranking**: Prioritizes "excellent" and "great" ranked modules
- **Technology match**: Matches detected platforms (PHP, Apache, WordPress, etc.)
- **Recent modules**: Newer exploits often have better reliability

### Safe Exploitation

- Uses non-destructive payloads by default (`cmd/unix/reverse_netcat`)
- Timeouts prevent hanging exploits
- Execution isolated via resource files
- Sessions auto-terminated after testing

## Legal & Security Warning

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always:
- Obtain written permission before testing
- Use only on systems you own or have explicit authorization to test
- Follow responsible disclosure practices
- Be aware of legal implications in your jurisdiction
- **Metasploit exploitation can cause service disruption** - use extreme caution

## Key Dependencies

- **CLI:** typer, rich, click
- **HTTP:** requests, aiohttp
- **AI:** openai
- **Security Tools:** python-nmap, scapy, selenium
- **ML:** scikit-learn, numpy, pandas
- **Reports:** jinja2, reportlab, markdown
- **Data:** pydantic, sqlalchemy
- **Logging:** loguru
