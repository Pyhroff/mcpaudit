"""
mcpaudit -- security scanner for MCP server tool surfaces.

  mcpaudit scan -- python samples/malicious_server/server.py
  mcpaudit baseline -- python my_server.py -o baseline.json
  mcpaudit diff baseline.json -- python my_server.py

v0.1: static checks only (description_scan, permission_scope).
v0.2 adds: baseline/diff (rug-pull detection).
v0.3 adds: --dynamic confused-deputy check against a live target model.
See CHANGELOG.md.
"""

from __future__ import annotations

import asyncio
import json as _json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from mcpaudit import __version__
from mcpaudit.checks.description_scan import scan_descriptions
from mcpaudit.checks.permission_scope import check_scope
from mcpaudit.findings import Finding
from mcpaudit.manifest import ServerManifest
from mcpaudit.mcp_client import StdioMCPClient
from mcpaudit.report import render_text, to_json, risk_score

app = typer.Typer(
    name="mcpaudit",
    help="[bold red]mcpaudit[/] -- security scanner for MCP server tool surfaces.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcpaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
) -> None:
    pass


async def _fetch_manifest(command: list[str]) -> ServerManifest:
    async with StdioMCPClient(command) as client:
        return await client.fetch_manifest()


def _run_static_checks(manifest: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []
    findings += scan_descriptions(manifest)
    findings += check_scope(manifest)
    return findings


@app.command()
def scan(
    server_command: list[str] = typer.Argument(
        ..., help="MCP server launch command, after `--`. e.g. -- python server.py"
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSON scorecard to this path"),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding at/above this severity (low|medium|high|critical). "
                                 "For CI gates."
    ),
):
    """Fetch a server's tool manifest and run the static checks against it."""
    try:
        manifest = asyncio.run(_fetch_manifest(server_command))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Could not connect to server:[/] {exc}")
        raise typer.Exit(2)

    findings = _run_static_checks(manifest)
    console.print(render_text(manifest.server_name, findings))

    if json_out:
        json_out.write_text(to_json(manifest.server_name, findings), encoding="utf-8")
        console.print(f"\n[dim]JSON scorecard written to {json_out}[/]")

    if fail_on:
        order = ["low", "medium", "high", "critical"]
        threshold = order.index(fail_on.lower())
        if any(order.index(f.severity.value) >= threshold for f in findings):
            raise typer.Exit(1)


@app.command()
def baseline(
    server_command: list[str] = typer.Argument(..., help="MCP server launch command, after `--`."),
    out: Path = typer.Option(Path("mcpaudit-baseline.json"), "--out", "-o"),
):
    """Snapshot a server's current manifest, for later rug-pull comparison (see `diff`)."""
    try:
        manifest = asyncio.run(_fetch_manifest(server_command))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Could not connect to server:[/] {exc}")
        raise typer.Exit(2)

    out.write_text(_json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
    console.print(f"Baseline saved: {len(manifest.tools)} tool(s) -> {out}")


if __name__ == "__main__":
    app()
