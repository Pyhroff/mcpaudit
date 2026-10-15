"""
mcpaudit -- security scanner for MCP server tool surfaces.

  mcpaudit scan -- python samples/malicious_server/server.py
  mcpaudit baseline -- python my_server.py -o baseline.json
  mcpaudit diff baseline.json -- python my_server.py

v0.1: static checks (description_scan, permission_scope).
v0.2: baseline/diff (rug-pull detection).
v0.3: --dynamic confused-deputy check against a live target model.
v0.4: --url for MCP's Streamable HTTP transport, not just local stdio.
v0.5: --policy to suppress reviewed/accepted findings (CI-gate friendly). <- current
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
from mcpaudit.checks.rug_pull import diff_manifests
from mcpaudit.checks.confused_deputy import run_confused_deputy_check, to_finding
from mcpaudit.findings import Finding
from mcpaudit.manifest import ServerManifest
from mcpaudit.mcp_client import MCPClient, StdioMCPClient, HttpMCPClient
from mcpaudit.policy import Policy
from mcpaudit.report import render_text, to_json, to_sarif, risk_score

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


def _make_client(server_command: list[str], url: Optional[str]) -> MCPClient:
    if url and server_command:
        raise typer.BadParameter("pass either a server command (after --) or --url, not both")
    if url:
        return HttpMCPClient(url)  # type: ignore[return-value]
    if not server_command:
        raise typer.BadParameter("need a server command after -- (or --url for an HTTP server)")
    return StdioMCPClient(server_command)  # type: ignore[return-value]


async def _fetch_manifest(server_command: list[str], url: Optional[str] = None) -> ServerManifest:
    async with _make_client(server_command, url) as client:
        return await client.fetch_manifest()


def _run_static_checks(manifest: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []
    findings += scan_descriptions(manifest)
    findings += check_scope(manifest)
    return findings


@app.command()
def scan(
    server_command: list[str] = typer.Argument(
        None, help="MCP server launch command, after `--`. e.g. -- python server.py. "
                    "Omit if using --url instead."
    ),
    url: Optional[str] = typer.Option(
        None, "--url", help="Scan a remote server over MCP's Streamable HTTP transport "
                             "instead of launching a local stdio process."
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSON scorecard to this path"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif", help="Write SARIF v2.1.0 report to this path (for GitHub Security / CI)"),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding at/above this severity (low|medium|high|critical). "
                                 "For CI gates."
    ),
    dynamic: bool = typer.Option(
        False, "--dynamic", help="Also run the confused-deputy check against a real target model "
                                  "(needs --target and GROQ_API_KEY)."
    ),
    target: str = typer.Option(
        "groq/openai/gpt-oss-120b", "--target", help="Target model for --dynamic: groq/<model>."
    ),
    dynamic_tool: Optional[str] = typer.Option(
        None, "--tool", help="Which tool to run the confused-deputy trial against "
                              "[default: every tool in the manifest]."
    ),
    policy_file: Optional[Path] = typer.Option(
        None, "--policy", help="JSON file of reviewed/accepted findings to suppress "
                                "(see samples/example-policy.json). Suppressed findings are "
                                "dropped before rendering, --json, and --fail-on."
    ),
):
    """Fetch a server's tool manifest and run the static checks against it (add --dynamic for the
    confused-deputy check, which also needs a live target model)."""
    try:
        manifest = asyncio.run(_fetch_manifest(server_command or [], url))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Could not connect to server:[/] {exc}")
        raise typer.Exit(2)

    findings = _run_static_checks(manifest)

    if dynamic:
        findings += asyncio.run(_run_dynamic_check(manifest, target, dynamic_tool))

    suppressed: list[Finding] = []
    if policy_file:
        try:
            policy = Policy.load(policy_file)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Could not read policy file:[/] {exc}")
            raise typer.Exit(2)
        findings, suppressed = policy.apply(findings)

    console.print(render_text(manifest.server_name, findings))

    if suppressed:
        console.print(f"[dim]{len(suppressed)} finding(s) suppressed by policy ({policy_file})[/]")

    if json_out:
        json_out.write_text(to_json(manifest.server_name, findings), encoding="utf-8")
        console.print(f"\n[dim]JSON scorecard written to {json_out}[/]")

    if sarif_out:
        sarif_out.write_text(to_sarif(manifest.server_name, findings), encoding="utf-8")
        console.print(f"\n[dim]SARIF report written to {sarif_out}[/]")

    if fail_on:
        order = ["low", "medium", "high", "critical"]
        threshold = order.index(fail_on.lower())
        if any(order.index(f.severity.value) >= threshold for f in findings):
            raise typer.Exit(1)


async def _run_dynamic_check(manifest: ServerManifest, target: str, tool_name: Optional[str]) -> list[Finding]:
    import os

    provider, model = target.split("/", 1) if "/" in target else ("groq", target)
    if provider != "groq":
        console.print(f"[yellow]--dynamic currently only supports groq/<model> targets, got '{target}'[/]")
        return []

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        console.print("[yellow]--dynamic needs GROQ_API_KEY set -- skipping confused-deputy check.[/]")
        return []

    from mcpaudit.adapters.groq import GroqAdapter
    adapter = GroqAdapter(api_key=api_key, model=model)

    tool_names = [tool_name] if tool_name else [t.name for t in manifest.tools]
    findings: list[Finding] = []
    for name in tool_names:
        console.print(f"[dim]running confused-deputy trial against tool '{name}'...[/]")
        result = await run_confused_deputy_check(adapter, manifest, name)
        finding = to_finding(result)
        if finding:
            findings.append(finding)
    return findings


@app.command()
def baseline(
    server_command: list[str] = typer.Argument(None, help="MCP server launch command, after `--`."),
    url: Optional[str] = typer.Option(None, "--url", help="Snapshot a remote server over HTTP instead."),
    out: Path = typer.Option(Path("mcpaudit-baseline.json"), "--out", "-o"),
):
    """Snapshot a server's current manifest, for later rug-pull comparison (see `diff`)."""
    try:
        manifest = asyncio.run(_fetch_manifest(server_command or [], url))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Could not connect to server:[/] {exc}")
        raise typer.Exit(2)

    out.write_text(_json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
    console.print(f"Baseline saved: {len(manifest.tools)} tool(s) -> {out}")


@app.command()
def diff(
    baseline_file: Path = typer.Argument(..., help="Previously saved baseline JSON (from `mcpaudit baseline`)"),
    server_command: list[str] = typer.Argument(None, help="MCP server launch command, after `--`."),
    url: Optional[str] = typer.Option(None, "--url", help="Compare against a remote server over HTTP instead."),
    fail_on_any: bool = typer.Option(True, help="Exit 1 if any drift is found"),
):
    """Compare a live server's manifest against a trusted baseline (rug-pull detection)."""
    try:
        baseline_manifest = ServerManifest.from_dict(_json.loads(baseline_file.read_text(encoding="utf-8")))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Could not read baseline file:[/] {exc}")
        raise typer.Exit(2)

    try:
        current_manifest = asyncio.run(_fetch_manifest(server_command or [], url))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Could not connect to server:[/] {exc}")
        raise typer.Exit(2)

    findings = diff_manifests(baseline_manifest, current_manifest)
    console.print(render_text(current_manifest.server_name, findings))

    if fail_on_any and findings:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
