"""Minimal MCP client -- stdio transport only, just enough to (a) fetch a
server's tool manifest and (b) call a tool for the dynamic checks. Not a
full MCP SDK: no resources/prompts support, no SSE/HTTP transport (v0.1
scope -- see CHANGELOG.md).

Wire format: MCP's stdio transport is newline-delimited JSON-RPC 2.0 (no
Content-Length framing, unlike LSP) -- one complete JSON object per line on
both stdin and stdout.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from mcpaudit.manifest import ServerManifest, ToolManifest


class MCPClientError(RuntimeError):
    pass


@dataclass
class ToolCallResult:
    is_error: bool
    content_text: str
    raw: dict[str, Any] = field(default_factory=dict)


class StdioMCPClient:
    """Spawns an MCP server as a subprocess and speaks JSON-RPC over its stdio."""

    def __init__(self, command: list[str]) -> None:
        self._command = command
        self._proc: asyncio.subprocess.Process | None = None
        self._next_id = 1

    async def __aenter__(self) -> "StdioMCPClient":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpaudit", "version": "0.1.0"},
            },
        )
        await self._notify("notifications/initialized", {})

    async def close(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except (ProcessLookupError, asyncio.TimeoutError):
            pass
        self._proc = None

    async def _send(self, payload: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        line = (json.dumps(payload) + "\n").encode("utf-8")
        self._proc.stdin.write(line)
        await self._proc.stdin.drain()

    async def _recv_response(self, expected_id: int) -> dict[str, Any]:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            raw = await asyncio.wait_for(self._proc.stdout.readline(), timeout=15)
            if not raw:
                stderr = b""
                if self._proc.stderr is not None:
                    stderr = await self._proc.stderr.read()
                raise MCPClientError(
                    f"MCP server closed stdout before responding to id={expected_id}. "
                    f"stderr: {stderr.decode('utf-8', 'replace')[:2000]}"
                )
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # server logged something non-JSON-RPC to stdout; skip it
            if msg.get("id") == expected_id:
                return msg

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        await self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        resp = await self._recv_response(req_id)
        if "error" in resp:
            raise MCPClientError(f"{method} failed: {resp['error']}")
        return resp.get("result", {})

    async def _notify(self, method: str, params: dict[str, Any]) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    async def fetch_manifest(self) -> ServerManifest:
        result = await self._request("tools/list", {})
        tools = [ToolManifest.from_dict(t) for t in result.get("tools", [])]
        return ServerManifest(server_name=" ".join(self._command), tools=tools)

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        result = await self._request("tools/call", {"name": name, "arguments": args})
        content = result.get("content", [])
        text = "\n".join(part.get("text", "") for part in content if part.get("type") == "text")
        return ToolCallResult(is_error=bool(result.get("isError")), content_text=text, raw=result)
