"""Prompt templates for AI exploit generation."""

EXPLOIT_GENERATION_TEMPLATE = """
You are an expert security researcher conducting authorized penetration testing.

Generate a detailed proof-of-concept exploit for:

Vulnerability: {vuln_type}
Target: {target}
Description: {description}
Severity: {severity}

Provide:
1. Working exploit code/payload
2. Step-by-step instructions
3. Technical explanation
4. Mitigation recommendations
"""

XSS_EXPLOIT_TEMPLATE = """
Generate XSS payloads for:
Context: {context}
Filter bypass needed: {filters}
Target browser: {browser}

Provide multiple bypass techniques.
"""

SQLI_EXPLOIT_TEMPLATE = """
Generate SQL injection exploits for:
Database type: {db_type}
Injection point: {injection_point}
WAF present: {waf}

Include blind and time-based variants.
"""

RCE_EXPLOIT_TEMPLATE = """
Generate RCE exploit for:
OS: {os_type}
Language: {language}
Injection context: {context}

Provide reverse shell and command execution variants.
"""
