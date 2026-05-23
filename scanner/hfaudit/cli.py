from __future__ import annotations

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(package_name="hfaudit")
def cli() -> None:
    """HFAudit -- automated security scanner for HuggingFace model repositories."""


@cli.command()
@click.argument("model_id")
def scan(model_id: str) -> None:
    """Scan a HuggingFace model repository for malicious payloads."""
    console.print(f"[bold]hfaudit[/bold] scanning [cyan]{model_id}[/cyan] ...")
    console.print("[dim]Scanner pipeline not yet wired. This is a scaffold.[/dim]")
