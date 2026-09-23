"""Integration test: the real StdioMCPClient against the real clean_server
fixture, as a subprocess -- exercises the actual JSON-RPC wire protocol,
not a mock. Skipped automatically if the current interpreter can't be used
to spawn the fixture (shouldn't happen in CI, but keeps this from being
flaky in unusual environments)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcpaudit.mcp_client import StdioMCPClient

_SERVER = Path(__file__).parent.parent / "samples" / "clean_server" / "server.py"


@pytest.mark.asyncio
async def test_fetch_manifest_from_real_subprocess_server():
    async with StdioMCPClient([sys.executable, str(_SERVER)]) as client:
        manifest = await client.fetch_manifest()

    names = {t.name for t in manifest.tools}
    assert names == {"add_numbers", "get_time", "read_workspace_file"}
    add_tool = manifest.tool("add_numbers")
    assert add_tool is not None
    assert "sum" in add_tool.description.lower()


@pytest.mark.asyncio
async def test_call_tool_against_real_subprocess_server():
    async with StdioMCPClient([sys.executable, str(_SERVER)]) as client:
        result = await client.call_tool("add_numbers", {"a": 2, "b": 3})

    assert result.is_error is False
    assert result.content_text == "5"


@pytest.mark.asyncio
async def test_clean_server_manifest_passes_static_checks():
    """End-to-end sanity check: the benign fixture should produce zero findings."""
    from mcpaudit.checks.description_scan import scan_descriptions
    from mcpaudit.checks.permission_scope import check_scope

    async with StdioMCPClient([sys.executable, str(_SERVER)]) as client:
        manifest = await client.fetch_manifest()

    findings = scan_descriptions(manifest) + check_scope(manifest)
    assert findings == [], f"clean fixture should have zero findings, got: {findings}"
