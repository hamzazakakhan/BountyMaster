# Bug Bounty CLI 🛡️

An AI-powered bug bounty CLI tool that leverages Kali Linux penetration testing tools, OpenAI for intelligent exploit generation, and automated vulnerability scanning based on the OWASP Top 10 framework.

## Features

- **🎯 OWASP Top 10 Vulnerability Detection**
  - Broken Access Control
  - Remote Code Execution (RCE)
  - Injection (SQL, Command, LDAP, etc.)
  - Insecure Design
  - Security Misconfiguration
  - Account Takeover (ATO)
  - Vulnerable and Outdated Components
  - Identification and Authentication Failures
  - Software and Data Integrity Failures
  - Server-Side Request Forgery (SSRF)
  - Cross-Site Scripting (XSS)
  - Cryptographic Failures

- **🤖 AI-Powered Exploit Generation**
  - Uses OpenAI API to generate custom exploits based on discovered vulnerabilities
  - Intelligent payload crafting and testing
  - Automated proof-of-concept generation

- **🎯 Metasploit Framework Integration**
  - Automated Metasploit module search for discovered vulnerabilities
  - AI-powered module selection based on exploit rank and relevance
  - Automatic exploitation with session management
  - Support for CVE-based and type-based exploit matching

- **🔧 Kali Linux Tools Integration**
  - Nmap for reconnaissance and port scanning
  - SQLMap for SQL injection testing
  - Nikto for web server scanning
  - Dirb/Dirbuster for directory enumeration
  - Metasploit integration for exploit testing
  - And many more...

- **📊 NVD CVE Database Integration**
  - Automatic CVE lookup for identified software versions
  - Vulnerability scoring and severity assessment
  - Historical vulnerability tracking

- **🧠 Intelligent URL Analysis**
  - ML-based pattern recognition to predict vulnerability types
  - Smart parameter detection
  - Automated attack surface mapping

- **🌐 Exploit Database Scraping**
  - Real-time exploit collection from Exploit-DB
  - PacketStorm Security integration
  - Local caching for offline use

- **📝 Comprehensive Reporting**
  - Detailed vulnerability reports
  - Steps to reproduce
  - Severity ratings based on CVSS
  - Remediation recommendations
  - Export to HTML, PDF, JSON

## Prerequisites

### System Requirements
- **Operating System**: Kali Linux (recommended) or any Linux distribution with penetration testing tools
- **Python**: 3.9 or higher
- **Tools**: Ensure the following Kali tools are installed:
  ```bash
  sudo apt-get update
  sudo apt-get install -y nmap sqlmap nikto dirb metasploit-framework hydra wpscan
  ```

### API Keys
- **OpenAI API Key**: Required for AI exploit generation ([Get API Key](https://platform.openai.com/api-keys))
- **NVD API Key**: Optional but recommended for faster CVE lookups ([Request API Key](https://nvd.nist.gov/developers/request-an-api-key))

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/bug-bounty-cli.git
cd bug-bounty-cli
```

### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
```bash
cp .env.example .env
# Edit .env and add your API keys
nano .env
```

### 5. Install the CLI tool
```bash
pip install -e .
```

## Usage

### Basic Scan
```bash
bugbounty scan --target https://example.com
```

### Scan with specific vulnerability types
```bash
bugbounty scan --target https://example.com --types xss,sqli,rce
```

### Full penetration test with AI exploit generation and Metasploit
```bash
bugbounty pentest --target https://example.com --ai-exploits --metasploit --intensity high
```

### Pentest without Metasploit (manual testing only)
```bash
bugbounty pentest --target https://example.com --no-metasploit --intensity medium
```

### URL Intelligence Analysis
```bash
bugbounty analyze-url --url "https://example.com/admin.php?id=123&user=admin"
```

### Generate CVE Report
```bash
bugbounty cve-scan --target https://example.com --output report.html
```

### Update Exploit Database
```bash
bugbounty update-exploits
```

### Generate Report from Previous Scan
```bash
bugbounty report --scan-id abc123 --format pdf --output vulnerability_report.pdf
```

## Command Reference

### Main Commands

| Command | Description |
|---------|-------------|
| `scan` | Perform vulnerability scan on target |
| `pentest` | Full penetration test with exploit generation |
| `analyze-url` | Intelligent URL vulnerability prediction |
| `cve-scan` | Check for known CVEs in target software |
| `update-exploits` | Update local exploit database |
| `report` | Generate comprehensive vulnerability report |
| `config` | Manage configuration and API keys |

### Scan Options

| Option | Description |
|--------|-------------|
| `--target URL` | Target URL or IP address |
| `--types TYPES` | Comma-separated list of vulnerability types |
| `--intensity LEVEL` | Scan intensity: low, medium, high, extreme |
| `--ai-exploits` | Enable AI-powered exploit generation |
| `--threads N` | Number of concurrent threads (default: 10) |
| `--timeout N` | Request timeout in seconds (default: 30) |
| `--output FILE` | Save results to file |
| `--format FORMAT` | Output format: json, html, pdf, markdown |

## Configuration

Edit the `.env` file to configure:

```env
OPENAI_API_KEY=sk-...
NVD_API_KEY=...
MAX_THREADS=10
TIMEOUT_SECONDS=30
RATE_LIMIT_DELAY=1
EXPLOIT_DB_UPDATE_INTERVAL=86400
CACHE_EXPIRY_DAYS=7
LOG_LEVEL=INFO
```

## Architecture

```
bug-bounty-cli/
├── src/
│   ├── main.py              # CLI entry point
│   ├── config.py            # Configuration management
│   ├── scanner/
│   │   ├── base_scanner.py  # Base scanner class
│   │   ├── xss_scanner.py   # XSS detection
│   │   ├── sqli_scanner.py  # SQL injection
│   │   ├── rce_scanner.py   # RCE detection
│   │   └── ...
│   ├── ai/
│   │   ├── exploit_generator.py  # OpenAI integration
│   │   └── prompt_templates.py   # AI prompts
│   ├── nvd/
│   │   └── cve_client.py    # NVD API client
│   ├── intelligence/
│   │   └── url_analyzer.py  # ML-based URL analysis
│   ├── exploits/
│   │   ├── scraper.py       # Exploit database scraper
│   │   └── cache.py         # Local exploit cache
│   ├── testing/
│   │   └── exploit_executor.py  # Safe exploit testing
│   └── reporting/
│       └── report_generator.py  # Report generation
├── tests/
├── docs/
└── requirements.txt
```

## Security Considerations

⚠️ **WARNING**: This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal.

- Always obtain written permission before testing
- Use only on systems you own or have explicit authorization to test
- Be aware of the legal implications in your jurisdiction
- Follow responsible disclosure practices
- Do not use for malicious purposes

## Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct.

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developers assume no liability for misuse or damage caused by this program.

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/yourusername/bug-bounty-cli/issues
- Documentation: https://github.com/yourusername/bug-bounty-cli/wiki

## Acknowledgments

- OWASP Foundation for the OWASP Top 10 framework
- Kali Linux project for penetration testing tools
- OpenAI for AI capabilities
- NVD for vulnerability database
- Security research community
