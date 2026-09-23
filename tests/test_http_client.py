"""Tests for HttpMCPClient (MCP's Streamable HTTP transport) against a
mocked httpx transport -- deterministic, no real network required, but
exercises the actual request/response/session-header handling code, not a
mock of the client itself."""

from __future__ import annotations

import json

import httpx
import pytest

from mcpaudit.mcp_client import HttpMCPClient, MCPClientError


def _json_response(request: httpx.Request, result: dict, session_id: str | None = None) -> httpx.Response:
    body = json.loads(request.content)
    payload = {"jsonrpc": "2.0", "id": body.get("id"), "result": result}
    headers = {"Content-Type": "application/json"}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return httpx.Response(200, json=payload, headers=headers)


def _sse_response(request: httpx.Request, result: dict) -> httpx.Response:
    body = json.loads(request.content)
    payload = {"jsonrpc": "2.0", "id": body.get("id"), "result": result}
    text = f"event: message\ndata: {json.dumps(payload)}\n\n"
    return httpx.Response(200, content=text, headers={"Content-Type": "text/event-stream"})


TOOLS = [
    {"name": "add", "description": "Adds two numbers.", "input_schema": {"properties": {}}},
]


@pytest.mark.asyncio
async def test_fetch_manifest_over_json_response(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            return _json_response(request, {"protocolVersion": "2024-11-05"}, session_id="sess-abc")
        if body.get("method") == "notifications/initialized":
            return httpx.Response(202)
        if body.get("method") == "tools/list":
            return _json_response(request, {"tools": TOOLS})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    _patch_client(monkeypatch, transport)

    async with HttpMCPClient("https://example.test/mcp") as client:
        manifest = await client.fetch_manifest()

    assert [t.name for t in manifest.tools] == ["add"]


@pytest.mark.asyncio
async def test_fetch_manifest_over_sse_response(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            return _sse_response(request, {"protocolVersion": "2024-11-05"})
        if body.get("method") == "notifications/initialized":
            return httpx.Response(202)
        if body.get("method") == "tools/list":
            return _sse_response(request, {"tools": TOOLS})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    _patch_client(monkeypatch, transport)

    async with HttpMCPClient("https://example.test/mcp") as client:
        manifest = await client.fetch_manifest()

    assert [t.name for t in manifest.tools] == ["add"]


@pytest.mark.asyncio
async def test_session_id_echoed_back_on_subsequent_requests(monkeypatch):
    seen_session_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_session_headers.append(request.headers.get("Mcp-Session-Id"))
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            return _json_response(request, {"protocolVersion": "2024-11-05"}, session_id="sess-xyz")
        if body.get("method") == "notifications/initialized":
            return httpx.Response(202)
        if body.get("method") == "tools/list":
            return _json_response(request, {"tools": TOOLS})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    _patch_client(monkeypatch, transport)

    async with HttpMCPClient("https://example.test/mcp") as client:
        await client.fetch_manifest()

    # initialize itself has no session header yet; every request after does.
    assert seen_session_headers[0] is None
    assert all(h == "sess-xyz" for h in seen_session_headers[1:])


@pytest.mark.asyncio
async def test_call_tool_returns_text_content(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            return _json_response(request, {"protocolVersion": "2024-11-05"})
        if body.get("method") == "notifications/initialized":
            return httpx.Response(202)
        if body.get("method") == "tools/call":
            return _json_response(request, {"content": [{"type": "text", "text": "42"}], "isError": False})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    _patch_client(monkeypatch, transport)

    async with HttpMCPClient("https://example.test/mcp") as client:
        result = await client.call_tool("add", {"a": 40, "b": 2})

    assert result.is_error is False
    assert result.content_text == "42"


@pytest.mark.asyncio
async def test_jsonrpc_error_raises_mcpclienterror(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            payload = {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32000, "message": "boom"}}
            return httpx.Response(200, json=payload, headers={"Content-Type": "application/json"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    _patch_client(monkeypatch, transport)

    with pytest.raises(MCPClientError, match="boom"):
        async with HttpMCPClient("https://example.test/mcp"):
            pass


def _patch_client(monkeypatch, transport: httpx.MockTransport) -> None:
    """HttpMCPClient builds its own httpx.AsyncClient in start(); patch the
    constructor it calls so requests go through the mock transport instead
    of hitting real network."""
    import httpx as httpx_module

    real_init = httpx_module.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx_module.AsyncClient, "__init__", patched_init)
