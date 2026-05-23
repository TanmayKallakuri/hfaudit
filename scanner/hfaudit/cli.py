from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

from hfaudit.scanner import scan_model

console = Console()

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim",
}

# Exit codes: 0 = clean, 1 = findings detected, 2 = scan error (incomplete results)
_EXIT_CLEAN = 0
_EXIT_FINDINGS = 1
_EXIT_ERROR = 2


@click.group()
@click.version_option(package_name="hfaudit")
def cli() -> None:
    """HFAudit -- automated security scanner for HuggingFace model repositories."""


@cli.command()
@click.argument("model_id")
@click.option("--json-output", "-j", is_flag=True, help="Output results as JSON.")
@click.option("--sarif", is_flag=True, help="Output results in SARIF format.")
@click.option("--token", envvar="HF_TOKEN", default=None, help="HuggingFace API token.")
def scan(model_id: str, json_output: bool, sarif: bool, token: str | None) -> None:
    """Scan a HuggingFace model repository for malicious payloads.

    Exit codes: 0 = clean, 1 = findings detected, 2 = scan error.
    """
    console.print(f"[bold]hfaudit[/bold] scanning [cyan]{model_id}[/cyan] ...")

    result = scan_model(model_id, token=token)
    exit_code = _EXIT_FINDINGS if result.has_findings else _EXIT_CLEAN
    if result.has_errors and not result.has_findings:
        exit_code = _EXIT_ERROR

    if sarif:
        click.echo(json.dumps(result.to_sarif(), indent=2))
        sys.exit(exit_code)

    if json_output:
        click.echo(result.to_json())
        sys.exit(exit_code)

    console.print()
    console.print(
        f"Scanned [bold]{result.files_scanned}[/bold] files, "
        f"skipped {result.files_skipped}"
    )

    if result.errors:
        for err in result.errors:
            console.print(f"[yellow]warning:[/yellow] {err}")

    if not result.findings:
        if result.has_errors:
            console.print("[yellow]Scan completed with errors (results may be incomplete).[/yellow]")
        else:
            console.print("[green]No findings.[/green]")
        console.print(f"[dim]Completed in {result.duration_ms}ms[/dim]")
        sys.exit(exit_code)

    table = Table(title=f"Findings ({len(result.findings)})")
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("File", style="dim")
    table.add_column("Description")

    for f in sorted(result.findings, key=lambda x: _severity_rank(x.severity)):
        style = _SEVERITY_STYLE.get(f.severity, "")
        table.add_row(f.rule_id, f"[{style}]{f.severity}[/{style}]", f.file_path, f.description)

    console.print(table)
    console.print(f"[dim]Completed in {result.duration_ms}ms[/dim]")
    sys.exit(exit_code)


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(severity, 5)
