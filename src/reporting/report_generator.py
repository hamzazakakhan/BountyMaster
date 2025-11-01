"""Comprehensive vulnerability report generator."""
from typing import List
from pathlib import Path
from datetime import datetime
import json
from jinja2 import Template
from loguru import logger

from src.scanner.models import ScanResult, Vulnerability
from src.config import config


class ReportGenerator:
    """Generates vulnerability reports in multiple formats."""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-label { font-weight: bold; color: #7f8c8d; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        .info { color: #95a5a6; }
        .vuln { border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vuln-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
        .vuln-meta { color: #7f8c8d; font-size: 14px; margin-bottom: 10px; }
        .vuln-desc { margin: 10px 0; line-height: 1.6; }
        .steps { background: #f8f9fa; padding: 15px; border-radius: 3px; margin: 10px 0; }
        .steps ol { margin: 5px 0; padding-left: 20px; }
        .code { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .remediation { background: #d5f4e6; padding: 15px; border-left: 3px solid #27ae60; margin: 10px 0; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Bug Bounty Security Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Scan Date:</strong> {{ scan_date }}</p>
            <p><strong>Duration:</strong> {{ duration }}</p>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-label">Total Vulnerabilities</div>
                    <div class="stat-value">{{ stats.total }}</div>
                </div>
                <div class="stat critical">
                    <div class="stat-label">Critical</div>
                    <div class="stat-value">{{ stats.critical }}</div>
                </div>
                <div class="stat high">
                    <div class="stat-label">High</div>
                    <div class="stat-value">{{ stats.high }}</div>
                </div>
                <div class="stat medium">
                    <div class="stat-label">Medium</div>
                    <div class="stat-value">{{ stats.medium }}</div>
                </div>
                <div class="stat low">
                    <div class="stat-label">Low</div>
                    <div class="stat-value">{{ stats.low }}</div>
                </div>
            </div>
        </div>
        
        <h2>📋 Vulnerability Details</h2>
        
        {% for vuln in vulnerabilities %}
        <div class="vuln" style="border-left-color: {% if vuln.severity == 'CRITICAL' %}#e74c3c{% elif vuln.severity == 'HIGH' %}#e67e22{% elif vuln.severity == 'MEDIUM' %}#f39c12{% else %}#3498db{% endif %};">
            <div class="vuln-title {{ vuln.severity.lower() }}">
                {{ loop.index }}. {{ vuln.title }}
            </div>
            
            <div class="vuln-meta">
                <span><strong>Severity:</strong> <span class="{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></span> |
                <span><strong>Type:</strong> {{ vuln.type.upper() }}</span> |
                <span><strong>CVSS:</strong> {{ vuln.cvss_score or 'N/A' }}</span>
                {% if vuln.cwe_id %} | <span><strong>CWE:</strong> {{ vuln.cwe_id }}</span>{% endif %}
            </div>
            
            <div class="vuln-desc">
                <strong>Description:</strong><br>
                {{ vuln.description }}
            </div>
            
            <div class="vuln-meta">
                <strong>Location:</strong> {{ vuln.location }}
                {% if vuln.parameter %} | <strong>Parameter:</strong> {{ vuln.parameter }}{% endif %}
            </div>
            
            {% if vuln.payload %}
            <div>
                <strong>Payload:</strong>
                <div class="code">{{ vuln.payload }}</div>
            </div>
            {% endif %}
            
            {% if vuln.steps_to_reproduce %}
            <div class="steps">
                <strong>Steps to Reproduce:</strong>
                <ol>
                    {% for step in vuln.steps_to_reproduce %}
                    <li>{{ step }}</li>
                    {% endfor %}
                </ol>
            </div>
            {% endif %}
            
            {% if vuln.remediation %}
            <div class="remediation">
                <strong>🔧 Remediation:</strong><br>
                {{ vuln.remediation }}
            </div>
            {% endif %}
            
            {% if vuln.references %}
            <div>
                <strong>References:</strong>
                <ul style="margin: 5px 0;">
                    {% for ref in vuln.references %}
                    <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>Generated by Bug Bounty CLI | {{ generation_time }}</p>
            <p><strong>⚠️ Disclaimer:</strong> This report is for authorized security testing only. Unauthorized access to computer systems is illegal.</p>
        </div>
    </div>
</body>
</html>
    """
    
    def generate(self, scan_result: ScanResult, output_path: Path, format: str = "html"):
        """Generate vulnerability report."""
        logger.info(f"Generating {format.upper()} report: {output_path}")
        
        if format == "json":
            self._generate_json(scan_result, output_path)
        elif format == "html":
            self._generate_html(scan_result, output_path)
        elif format == "markdown":
            self._generate_markdown(scan_result, output_path)
        elif format == "pdf":
            self._generate_pdf(scan_result, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Report generated successfully: {output_path}")
    
    def _generate_json(self, scan_result: ScanResult, output_path: Path):
        """Generate JSON report."""
        data = scan_result.dict()
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _generate_html(self, scan_result: ScanResult, output_path: Path):
        """Generate HTML report."""
        template = Template(self.HTML_TEMPLATE)
        
        # Calculate duration
        if scan_result.completed_at and scan_result.started_at:
            duration = scan_result.completed_at - scan_result.started_at
            duration_str = f"{duration.seconds // 60}m {duration.seconds % 60}s"
        else:
            duration_str = "N/A"
        
        html = template.render(
            target=scan_result.target,
            scan_date=scan_result.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            duration=duration_str,
            stats=scan_result.statistics,
            vulnerabilities=scan_result.vulnerabilities,
            generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_markdown(self, scan_result: ScanResult, output_path: Path):
        """Generate Markdown report."""
        md = f"# 🛡️ Bug Bounty Security Report\n\n"
        md += f"**Target:** {scan_result.target}\\n"
        md += f"**Scan Date:** {scan_result.started_at.strftime('%Y-%m-%d %H:%M:%S')}\\n\\n"
        
        md += "## Summary\\n\\n"
        md += f"- **Total Vulnerabilities:** {scan_result.statistics.get('total', 0)}\\n"
        md += f"- **Critical:** {scan_result.statistics.get('critical', 0)}\\n"
        md += f"- **High:** {scan_result.statistics.get('high', 0)}\\n"
        md += f"- **Medium:** {scan_result.statistics.get('medium', 0)}\\n"
        md += f"- **Low:** {scan_result.statistics.get('low', 0)}\\n\\n"
        
        md += "## Vulnerabilities\\n\\n"
        
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            md += f"### {i}. {vuln.title}\\n\\n"
            md += f"**Severity:** {vuln.severity.value} | "
            md += f"**Type:** {vuln.type.upper()} | "
            md += f"**CVSS:** {vuln.cvss_score or 'N/A'}\\n\\n"
            
            md += f"**Description:**\\n{vuln.description}\\n\\n"
            md += f"**Location:** {vuln.location}\\n\\n"
            
            if vuln.payload:
                md += f"**Payload:**\\n```\\n{vuln.payload}\\n```\\n\\n"
            
            if vuln.steps_to_reproduce:
                md += "**Steps to Reproduce:**\\n"
                for step in vuln.steps_to_reproduce:
                    md += f"- {step}\\n"
                md += "\\n"
            
            if vuln.remediation:
                md += f"**Remediation:**\\n{vuln.remediation}\\n\\n"
            
            md += "---\\n\\n"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)
    
    def _generate_pdf(self, scan_result: ScanResult, output_path: Path):
        """Generate PDF report using reportlab."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors
            
            doc = SimpleDocTemplate(str(output_path), pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2c3e50')
            )
            story.append(Paragraph("🛡️ Bug Bounty Security Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Summary
            summary_data = [
                ["Target:", scan_result.target],
                ["Scan Date:", scan_result.started_at.strftime("%Y-%m-%d %H:%M:%S")],
                ["Total Vulnerabilities:", str(scan_result.statistics.get('total', 0))],
                ["Critical:", str(scan_result.statistics.get('critical', 0))],
                ["High:", str(scan_result.statistics.get('high', 0))],
                ["Medium:", str(scan_result.statistics.get('medium', 0))],
                ["Low:", str(scan_result.statistics.get('low', 0))],
            ]
            
            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.5*inch))
            
            # Vulnerabilities
            story.append(Paragraph("Vulnerabilities", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                story.append(Paragraph(f"{i}. {vuln.title}", styles['Heading3']))
                story.append(Paragraph(f"<b>Severity:</b> {vuln.severity.value} | <b>Type:</b> {vuln.type.upper()}", styles['Normal']))
                story.append(Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal']))
                
                if vuln.remediation:
                    story.append(Paragraph(f"<b>Remediation:</b> {vuln.remediation}", styles['Normal']))
                
                story.append(Spacer(1, 0.2*inch))
            
            doc.build(story)
            
        except ImportError:
            logger.error("reportlab not installed. Cannot generate PDF. Use: pip install reportlab")
            raise
    
    def generate_cve_report(self, cve_result, output_path: Path):
        """Generate CVE-specific report."""
        logger.info(f"Generating CVE report: {output_path}")
        
        # Generate HTML report for CVEs
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CVE Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        .cve {{ border: 1px solid #ddd; padding: 15px; margin: 15px 0; }}
        .critical {{ border-left: 4px solid #e74c3c; }}
        .high {{ border-left: 4px solid #e67e22; }}
    </style>
</head>
<body>
    <h1>CVE Vulnerability Report</h1>
    <p><strong>Target:</strong> {cve_result.target}</p>
    <p><strong>CVEs Found:</strong> {len(cve_result.cves)}</p>
    
    <h2>CVE Details</h2>
"""
        
        for cve in cve_result.cves:
            severity_class = "critical" if cve.severity == "CRITICAL" else "high"
            html += f"""
    <div class="cve {severity_class}">
        <h3>{cve.id}</h3>
        <p><strong>Severity:</strong> {cve.severity} ({cve.cvss_score})</p>
        <p><strong>Description:</strong> {cve.description}</p>
        <p><strong>Published:</strong> {cve.published_date.strftime('%Y-%m-%d')}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"CVE report generated: {output_path}")
