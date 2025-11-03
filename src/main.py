"""Main CLI entry point for Bug Bounty CLI."""
import sys
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from loguru import logger

from src.config import config

app = typer.Typer(
    name="bugbounty",
    help="AI-powered bug bounty CLI leveraging Kali Linux tools and OWASP Top 10",
    add_completion=False,
)
console = Console()


# Setup logging
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level=config.log_level,
)
logger.add(
    config.logs_dir / config.log_file,
    rotation="10 MB",
    retention="10 days",
    level=config.log_level,
)


def check_api_keys(require_openai: bool = False):
    """Check if required API keys are configured."""
    api_status = config.validate_api_keys()
    
    if not api_status["openai"]:
        if require_openai:
            console.print("[bold red]Error: OpenAI API key required for AI features but not configured.[/bold red]")
            console.print("[dim]Set OPENAI_API_KEY in your .env file or disable AI features[/dim]\n")
        else:
            console.print("[yellow]⚠️  Info: OpenAI API key not configured. AI features will be disabled.[/yellow]")
            console.print("[dim]This is optional - Metasploit and scanning will still work[/dim]\n")
    
    if not api_status["nvd"]:
        console.print("[yellow]⚠️  Info: NVD API key not configured. CVE lookups may be rate-limited.[/yellow]")
        console.print("[dim]This is optional - you can still scan without it[/dim]\n")


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP address"),
    types: Optional[str] = typer.Option(None, "--types", help="Comma-separated vulnerability types (e.g., xss,sqli,rce)"),
    intensity: str = typer.Option("medium", "--intensity", "-i", help="Scan intensity: low, medium, high, extreme"),
    ai_exploits: bool = typer.Option(False, "--ai-exploits", help="Enable AI-powered exploit generation"),
    threads: int = typer.Option(config.max_threads, "--threads", help="Number of concurrent threads"),
    timeout: int = typer.Option(config.timeout_seconds, "--timeout", help="Request timeout in seconds"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results to file"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, html, pdf, markdown"),
):
    """Perform vulnerability scan on target."""
    console.print(Panel.fit("🛡️  Bug Bounty CLI - Vulnerability Scanner", style="bold blue"))
    check_api_keys()
    
    logger.info(f"Starting scan on target: {target}")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Intensity:[/bold] {intensity}")
    console.print(f"[bold]Threads:[/bold] {threads}\n")
    
    # Parse vulnerability types
    vuln_types = types.split(",") if types else [
        "xss", "sqli", "rce", "ssrf", "ato", "lfi", "rfi", "xxe", "csrf", "idor"
    ]
    
    console.print(f"[bold]Scanning for:[/bold] {', '.join(vuln_types)}\n")
    
    # Import scanner orchestrator
    from src.scanner.orchestrator import ScanOrchestrator
    
    orchestrator = ScanOrchestrator(
        target=target,
        vuln_types=vuln_types,
        intensity=intensity,
        threads=threads,
        timeout=timeout,
        ai_exploits=ai_exploits,
    )
    
    with console.status("[bold green]Running scan...", spinner="dots"):
        results = orchestrator.run()
    
    # Display results
    console.print(f"\n[bold green]✓ Scan completed![/bold green]")
    console.print(f"[bold]Vulnerabilities found:[/bold] {len(results.vulnerabilities)}\n")
    
    if results.vulnerabilities:
        table = Table(title="Vulnerability Summary")
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("Location", style="yellow")
        
        for vuln in results.vulnerabilities:
            table.add_row(vuln.type, vuln.severity, vuln.location)
        
        console.print(table)
    
    # Save results if output specified
    if output:
        from src.reporting.report_generator import ReportGenerator
        generator = ReportGenerator()
        generator.generate(results, output, format)
        console.print(f"\n[bold green]Report saved to:[/bold green] {output}")
    
    logger.info(f"Scan completed. Found {len(results.vulnerabilities)} vulnerabilities")


@app.command()
def pentest(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP address"),
    intensity: str = typer.Option("high", "--intensity", "-i", help="Test intensity: low, medium, high, extreme"),
    ai_exploits: bool = typer.Option(True, "--ai-exploits/--no-ai-exploits", help="Enable AI exploit generation"),
    use_metasploit: bool = typer.Option(True, "--metasploit/--no-metasploit", help="Use Metasploit Framework for exploitation"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results to file"),
):
    """Full penetration test with exploit generation."""
    console.print(Panel.fit("🎯  Bug Bounty CLI - Full Penetration Test", style="bold red"))
    
    # Only require OpenAI if user explicitly wants AI exploits
    if ai_exploits and not config.openai_api_key:
        console.print("[bold red]Error: AI exploits enabled but OpenAI API key not configured.[/bold red]")
        console.print("[dim]Either set OPENAI_API_KEY in .env or use --no-ai-exploits flag[/dim]")
        raise typer.Exit(1)
    
    check_api_keys(require_openai=False)
    
    logger.info(f"Starting penetration test on target: {target}")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Intensity:[/bold] {intensity}")
    console.print(f"[bold]AI Exploits:[/bold] {'Enabled' if ai_exploits else 'Disabled'}")
    console.print(f"[bold]Metasploit:[/bold] {'Enabled' if use_metasploit else 'Disabled'}\n")
    
    from src.testing.pentest_engine import PentestEngine
    
    engine = PentestEngine(target=target, intensity=intensity, ai_exploits=ai_exploits, use_metasploit=use_metasploit)
    
    with console.status("[bold red]Running penetration test...", spinner="dots"):
        results = engine.run()
    
    console.print(f"\n[bold green]✓ Penetration test completed![/bold green]")
    console.print(f"[bold]Exploitable vulnerabilities:[/bold] {len(results.exploitable)}\n")
    
    if output:
        from src.reporting.report_generator import ReportGenerator
        generator = ReportGenerator()
        generator.generate(results, output, "html")
        console.print(f"\n[bold green]Report saved to:[/bold green] {output}")


@app.command()
def analyze_url(
    url: str = typer.Option(..., "--url", "-u", help="URL to analyze"),
):
    """Intelligent URL vulnerability prediction."""
    console.print(Panel.fit("🧠  Bug Bounty CLI - URL Intelligence", style="bold cyan"))
    
    logger.info(f"Analyzing URL: {url}")
    
    from src.intelligence.url_analyzer import URLAnalyzer
    
    analyzer = URLAnalyzer()
    predictions = analyzer.analyze(url)
    
    console.print(f"\n[bold]URL:[/bold] {url}\n")
    
    table = Table(title="Vulnerability Predictions")
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Confidence", style="magenta")
    table.add_column("Reason", style="yellow")
    
    for pred in predictions:
        table.add_row(pred.type, f"{pred.confidence:.1%}", pred.reason)
    
    console.print(table)


@app.command()
def cve_scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP address"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results to file"),
):
    """Check for known CVEs in target software."""
    console.print(Panel.fit("📊  Bug Bounty CLI - CVE Scanner", style="bold yellow"))
    check_api_keys()
    
    logger.info(f"Starting CVE scan on target: {target}")
    
    from src.nvd.cve_scanner import CVEScanner
    
    scanner = CVEScanner()
    
    with console.status("[bold yellow]Scanning for CVEs...", spinner="dots"):
        results = scanner.scan(target)
    
    console.print(f"\n[bold green]✓ CVE scan completed![/bold green]")
    console.print(f"[bold]CVEs found:[/bold] {len(results.cves)}\n")
    
    if results.cves:
        table = Table(title="CVE Summary")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("CVSS Score", style="yellow")
        table.add_column("Description", style="white")
        
        for cve in results.cves[:10]:  # Show top 10
            table.add_row(cve.id, cve.severity, str(cve.cvss_score), cve.description[:50] + "...")
        
        console.print(table)
    
    if output:
        from src.reporting.report_generator import ReportGenerator
        generator = ReportGenerator()
        generator.generate_cve_report(results, output)
        console.print(f"\n[bold green]Report saved to:[/bold green] {output}")


@app.command()
def update_exploits():
    """Update local exploit database."""
    console.print(Panel.fit("🌐  Bug Bounty CLI - Exploit Database Update", style="bold magenta"))
    
    logger.info("Updating exploit database")
    
    from src.exploits.updater import ExploitUpdater
    
    updater = ExploitUpdater()
    
    with console.status("[bold magenta]Updating exploit database...", spinner="dots"):
        stats = updater.update()
    
    console.print(f"\n[bold green]✓ Exploit database updated![/bold green]")
    console.print(f"[bold]Total exploits:[/bold] {stats.total}")
    console.print(f"[bold]New exploits:[/bold] {stats.new}")
    console.print(f"[bold]Updated exploits:[/bold] {stats.updated}\n")


@app.command()
def report(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID to generate report for"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: json, html, pdf, markdown"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
):
    """Generate comprehensive vulnerability report."""
    console.print(Panel.fit("📝  Bug Bounty CLI - Report Generator", style="bold green"))
    
    logger.info(f"Generating report for scan ID: {scan_id}")
    
    from src.reporting.report_generator import ReportGenerator
    from src.database.scan_repository import ScanRepository
    
    repo = ScanRepository()
    scan_results = repo.get_scan(scan_id)
    
    if not scan_results:
        console.print(f"[bold red]Error: Scan ID {scan_id} not found.[/bold red]")
        raise typer.Exit(1)
    
    generator = ReportGenerator()
    generator.generate(scan_results, output, format)
    
    console.print(f"\n[bold green]✓ Report generated![/bold green]")
    console.print(f"[bold]Format:[/bold] {format}")
    console.print(f"[bold]Location:[/bold] {output}\n")


@app.command()
def config_cmd(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    set_key: Optional[str] = typer.Option(None, "--set", help="Set configuration key=value"),
):
    """Manage configuration and API keys."""
    if show:
        console.print(Panel.fit("⚙️  Bug Bounty CLI - Configuration", style="bold blue"))
        
        table = Table(title="Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="yellow")
        
        table.add_row("OpenAI API Key", "✓ Configured" if config.openai_api_key else "✗ Not set")
        table.add_row("NVD API Key", "✓ Configured" if config.nvd_api_key else "✗ Not set")
        table.add_row("Max Threads", str(config.max_threads))
        table.add_row("Timeout", f"{config.timeout_seconds}s")
        table.add_row("Log Level", config.log_level)
        table.add_row("Reports Directory", str(config.reports_dir))
        
        console.print(table)
    
    if set_key:
        # Parse key=value
        if "=" not in set_key:
            console.print("[bold red]Error: Use format key=value[/bold red]")
            raise typer.Exit(1)
        
        key, value = set_key.split("=", 1)
        console.print(f"[bold green]Set {key} = {value}[/bold green]")
        console.print("[dim]Update your .env file to make this change persistent.[/dim]")


@app.callback()
def main():
    """Bug Bounty CLI - AI-powered vulnerability scanner."""
    pass


if __name__ == "__main__":
    app()
