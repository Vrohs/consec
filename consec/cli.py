from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from consec import __version__
from consec.models import Severity
from consec.parser import (
    ParseError,
    extract_vulnerabilities,
    filter_by_severity,
    parse_trivy_json,
    to_documents,
)
from consec.utils import (
    console,
    display_response,
    display_scan_summary,
    display_vulnerability_table,
    print_error,
    print_info,
    print_success,
)

app = typer.Typer(
    name="consec",
    help="🔒 consec — LLM-Powered Container Security Assistant",
    add_completion=False,
    no_args_is_help=True,
)


def version_callback(value: bool):
    if value:
        console.print(f"consec v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    pass


@app.command()
def scan(
    image: str = typer.Argument(..., help="Docker image to scan (e.g., nginx:latest)"),
    severity: str = typer.Option(
        "LOW", "--severity", "-s", help="Minimum severity to show"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save JSON output to file"
    ),
    ingest: bool = typer.Option(
        False, "--ingest", "-i", help="Also ingest results into vector DB"
    ),
):
    print_info(f"Scanning image: {image}")

    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", image],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        print_error(
            "Trivy not found. Install it: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
        raise typer.Exit(1)
    except subprocess.TimeoutExpired:
        print_error("Trivy scan timed out after 5 minutes.")
        raise typer.Exit(1)

    if result.returncode != 0:
        print_error(f"Trivy scan failed:\n{result.stderr}")
        raise typer.Exit(1)

    if output:
        Path(output).write_text(result.stdout, encoding="utf-8")
        print_success(f"Raw JSON saved to {output}")

    try:
        report = parse_trivy_json(result.stdout)
    except ParseError as e:
        print_error(f"Failed to parse Trivy output: {e}")
        raise typer.Exit(1)

    display_scan_summary(report)

    min_sev = Severity.from_string(severity)
    vulns = extract_vulnerabilities(report)
    filtered = filter_by_severity(vulns, min_sev)
    display_vulnerability_table(filtered)

    if ingest:
        _do_ingest_report(report)


@app.command()
def parse(
    json_file: str = typer.Argument(..., help="Path to Trivy JSON output file"),
    severity: str = typer.Option(
        "LOW", "--severity", "-s", help="Minimum severity to show"
    ),
):
    try:
        report = parse_trivy_json(json_file)
    except ParseError as e:
        print_error(f"Parse error: {e}")
        raise typer.Exit(1)

    display_scan_summary(report)

    min_sev = Severity.from_string(severity)
    vulns = extract_vulnerabilities(report)
    filtered = filter_by_severity(vulns, min_sev)
    display_vulnerability_table(filtered)


@app.command()
def ingest(
    json_file: str = typer.Argument(..., help="Path to Trivy JSON file to ingest"),
):
    try:
        report = parse_trivy_json(json_file)
    except ParseError as e:
        print_error(f"Parse error: {e}")
        raise typer.Exit(1)

    _do_ingest_report(report)


@app.command()
def query(
    question: str = typer.Argument(..., help="Security question to ask"),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help="Ollama model name"
    ),
    scan_file: Optional[str] = typer.Option(
        None, "--scan", help="Trivy JSON for additional context"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-I", help="Interactive Q&A mode"
    ),
):
    from consec.llm import OllamaConnectionError
    from consec.rag import SecurityRAGChain

    try:
        chain = SecurityRAGChain(model=model)
    except OllamaConnectionError as e:
        print_error(str(e))
        raise typer.Exit(1)

    scan_context = None
    if scan_file:
        try:
            report = parse_trivy_json(scan_file)
            vulns = extract_vulnerabilities(report)
            scan_context = "\n".join(v.to_summary() for v in vulns[:20])
        except ParseError as e:
            print_error(f"Could not parse scan file: {e}")

    if interactive:
        _interactive_mode(chain, scan_context)
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Analyzing with LLM...", total=None)
        response = chain.ask(question, scan_context=scan_context)

    display_response(response)


@app.command()
def review(
    dockerfile: str = typer.Argument(..., help="Path to Dockerfile to review"),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help="Ollama model name"
    ),
    scan_file: Optional[str] = typer.Option(
        None, "--scan", help="Trivy JSON for correlation"
    ),
):
    from consec.llm import OllamaConnectionError
    from consec.rag import SecurityRAGChain

    path = Path(dockerfile)
    if not path.exists():
        print_error(f"Dockerfile not found: {dockerfile}")
        raise typer.Exit(1)

    dockerfile_content = path.read_text(encoding="utf-8")

    try:
        chain = SecurityRAGChain(model=model)
    except OllamaConnectionError as e:
        print_error(str(e))
        raise typer.Exit(1)

    scan_summary = None
    if scan_file:
        try:
            report = parse_trivy_json(scan_file)
            vulns = extract_vulnerabilities(report)
            scan_summary = "\n".join(v.to_summary() for v in vulns[:20])
        except ParseError as e:
            print_error(f"Could not parse scan file: {e}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Reviewing Dockerfile...", total=None)
        response = chain.review_dockerfile(dockerfile_content, scan_summary)

    display_response(response, title="Dockerfile Security Review")


def _do_ingest_report(report):
    from consec.vectordb import VulnVectorStore

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Ingesting into vector database...", total=None)
        store = VulnVectorStore()
        added = store.ingest_scan(report)

    print_success(
        f"Ingested {added} new vulnerability documents (total: {store.count})"
    )


def _interactive_mode(chain, scan_context=None):
    console.print(
        "\n[bold cyan]🔒 consec Interactive Mode[/bold cyan]\n"
        "Ask security questions. Type [bold]quit[/bold] or [bold]exit[/bold] to leave.\n"
    )

    while True:
        try:
            question = console.input("[bold green]consec>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\nGoodbye!")
            break

        if not question:
            continue
        if question.lower() in ("quit", "exit", "q"):
            console.print("Goodbye!")
            break

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Thinking...", total=None)
            response = chain.ask(question, scan_context=scan_context)

        display_response(response)
        console.print()


if __name__ == "__main__":
    app()
