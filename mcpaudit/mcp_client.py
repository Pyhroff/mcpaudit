"""MCP clients -- two transports.

StdioMCPClient: spawns a server as a subprocess, speaks newline-delimited
JSON-RPC over its stdio (v0.1).

HttpMCPClient: speaks MCP's "Streamable HTTP" transport (the current spec,
2025-03-26+) against a URL -- a single POST endpoint that answers either
with a direct `application/json` response or a one-shot `text/event-stream`
carrying the same response, plus an `Mcp-Session-Id` response header the
client echoes back on subsequent requests (v0.4).

Both implement the same minimal surface -- fetch_manifest() / call_tool()
-- so every check in mcpaudit/checks/ is transport-agnostic; they only ever
see a ServerManifest or a ToolCallResult.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from mcpaudit.manifest import ServerManifest, ToolManifest


class MCPClientError(RuntimeError):
    pass


@dataclass
class ToolCallResult:
    is_error: bool
    content_text: str
    raw: dict[str, Any] = field(default_factory=dict)


class MCPClient(Protocol):
    """What every check actually depends on -- not the transport."""

    async def __aenter__(self) -> "MCPClient": ...
    async def __aexit__(self, *exc: object) -> None: ...
    async def fetch_manifest(self) -> ServerManifest: ...
    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolCallResult: ...


_CLIENT_INFO = {"name": "mcpaudit", "version": "0.4.0"}
_PROTOCOL_VERSION = "2024-11-05"


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
            {"protocolVersion": _PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _CLIENT_INFO},
        )
        await self._notify("notifications/initialized", {})

    async def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin and not self._proc.stdin.is_closing():
                self._proc.stdin.close()
            self._proc.terminate()
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except (ProcessLookupError, asyncio.TimeoutError):
            pass
        finally:
            # Close the subprocess transport explicitly, now, while the loop
            # is still running. Left to garbage collection, its __del__ can
            # fire *after* asyncio.run() has already closed the loop --
            # "RuntimeError: Event loop is closed" from a finalizer, not an
            # exception either caller or callee can catch. Observed on a
            # real scan (npx-launched MCP server, Python 3.10/Linux).
            transport = getattr(self._proc, "_transport", None)
            if transport is not None:
                transport.close()
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


class HttpMCPClient:
    """Speaks MCP's Streamable HTTP transport against a single URL.

    A POST to that URL carrying a JSON-RPC request answers either with a
    plain `application/json` body (the response itself) or a `text/event-
    stream` body -- for a single request/response exchange (all this client
    does), that stream carries exactly one `data:` event containing the
    same JSON-RPC response, then closes. Session continuity across the
    initialize -> tools/list -> tools/call sequence is via the
    `Mcp-Session-Id` header the server returns on `initialize` and the
    client echoes back on every request after.
    """

    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 30.0) -> None:
        self._url = url
        self._extra_headers = headers or {}
        self._timeout = timeout
        self._client = None  # httpx.AsyncClient, imported lazily
        self._session_id: str | None = None
        self._next_id = 1

    async def __aenter__(self) -> "HttpMCPClient":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def start(self) -> None:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise ImportError("HttpMCPClient requires httpx: pip install mcpaudit[http]") from exc
        self._client = httpx.AsyncClient(timeout=self._timeout)
        await self._request(
            "initialize",
            {"protocolVersion": _PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _CLIENT_INFO},
        )
        await self._notify("notifications/initialized", {})

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._extra_headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    @staticmethod
    def _parse_sse_json(text: str) -> dict[str, Any]:
        for line in text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:"):].strip())
        raise MCPClientError(f"no 'data:' event in SSE response body: {text[:500]!r}")

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        assert self._client is not None
        resp = await self._client.post(self._url, json=payload, headers=self._headers())
        if resp.status_code == 202:
            return None  # accepted, notification-style, no body expected
        resp.raise_for_status()

        session_id = resp.headers.get("Mcp-Session-Id")
        if session_id:
            self._session_id = session_id

        content_type = resp.headers.get("Content-Type", "")
        if "text/event-stream" in content_type:
            return self._parse_sse_json(resp.text)
        return resp.json()

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        msg = await self._post({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        if msg is None:
            raise MCPClientError(f"{method}: server returned no body for a request expecting a response")
        if "error" in msg:
            raise MCPClientError(f"{method} failed: {msg['error']}")
        return msg.get("result", {})

    async def _notify(self, method: str, params: dict[str, Any]) -> None:
        await self._post({"jsonrpc": "2.0", "method": method, "params": params})

    async def fetch_manifest(self) -> ServerManifest:
        result = await self._request("tools/list", {})
        tools = [ToolManifest.from_dict(t) for t in result.get("tools", [])]
        return ServerManifest(server_name=self._url, tools=tools)

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        result = await self._request("tools/call", {"name": name, "arguments": args})
        content = result.get("content", [])
        text = "\n".join(part.get("text", "") for part in content if part.get("type") == "text")
        return ToolCallResult(is_error=bool(result.get("isError")), content_text=text, raw=result)
