from __future__ import annotations

import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from consec.models import Severity, TrivyReport, Vulnerability

console = Console()
error_console = Console(stderr=True, style="bold red")

CONSEC_HOME = Path(os.environ.get("CONSEC_HOME", Path.home() / ".consec"))
CHROMA_DIR = CONSEC_HOME / "chromadb"
DEFAULT_MODEL = os.environ.get("CONSEC_MODEL", "llama3.1:8b")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "UNKNOWN": "dim",
}


def ensure_dirs() -> None:
    CONSEC_HOME.mkdir(parents=True, exist_ok=True)
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)


def display_scan_summary(report: TrivyReport) -> None:
    counts = report.severity_counts()

    table = Table(title=f"Scan Summary: {report.artifact_name}", show_lines=True)
    table.add_column("Severity", style="bold", justify="center")
    table.add_column("Count", justify="center")

    for severity in Severity:
        count = counts.get(severity.value, 0)
        color = SEVERITY_COLORS.get(severity.value, "white")
        table.add_row(f"[{color}]{severity.value}[/{color}]", str(count))

    table.add_row("[bold]TOTAL[/bold]", f"[bold]{report.total_vulnerabilities}[/bold]")
    console.print(table)


def display_vulnerability_table(vulns: list[Vulnerability], max_rows: int = 50) -> None:
    table = Table(title=f"Vulnerabilities ({len(vulns)} found)", show_lines=True)
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Package", style="green")
    table.add_column("Installed", style="dim")
    table.add_column("Fixed", style="bold green")
    table.add_column("Title", max_width=40)

    for vuln in vulns[:max_rows]:
        color = SEVERITY_COLORS.get(vuln.severity, "white")
        fixed = vuln.fixed_version or "[dim]—[/dim]"
        title = (vuln.title or "")[:40]
        table.add_row(
            vuln.vulnerability_id,
            f"[{color}]{vuln.severity}[/{color}]",
            vuln.pkg_name,
            vuln.installed_version,
            fixed,
            title,
        )

    if len(vulns) > max_rows:
        table.add_row("...", "...", "...", "...", "...", f"({len(vulns) - max_rows} more)")

    console.print(table)


def display_response(response: str, title: str = "Security Analysis") -> None:
    console.print(Panel(response, title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan"))


def print_error(message: str) -> None:
    error_console.print(f"✗ {message}")


def print_success(message: str) -> None:
    console.print(f"[bold green]✓[/bold green] {message}")


def print_info(message: str) -> None:
    console.print(f"[bold blue]ℹ[/bold blue] {message}")
