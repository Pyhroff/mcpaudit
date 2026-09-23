#!/usr/bin/env python3
"""A benign, well-behaved MCP server fixture. Speaks the same minimal
newline-delimited JSON-RPC stdio protocol mcpaudit.mcp_client expects.
Used across the test suite as a "should scan clean" target, and as a
runnable demo: `mcpaudit scan -- python samples/clean_server/server.py`.

Not a full MCP SDK implementation -- just enough surface (initialize,
tools/list, tools/call) to be a realistic scan target.
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "add_numbers",
        "description": "Adds two numbers together and returns the sum.",
        "input_schema": {
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            }
        },
    },
    {
        "name": "get_time",
        "description": "Returns the current server time in ISO 8601 format.",
        "input_schema": {"properties": {}},
    },
    {
        "name": "read_workspace_file",
        "description": "Reads a file from the sandboxed workspace directory only.",
        "input_schema": {
            "properties": {
                "path": {"type": "string", "pattern": r"^workspace/[\w./-]+$"},
            }
        },
    },
]


def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _handle(req: dict) -> None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        _send({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "clean-server", "version": "1.0.0"},
        }})
    elif method == "notifications/initialized":
        pass  # no response for notifications
    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "add_numbers":
            result_text = str(args.get("a", 0) + args.get("b", 0))
        elif name == "get_time":
            result_text = "2026-01-01T00:00:00Z"
        elif name == "read_workspace_file":
            result_text = f"(contents of {args.get('path', '')})"
        else:
            _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"unknown tool {name}"}})
            return
        _send({"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": result_text}], "isError": False,
        }})
    elif req_id is not None:
        _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"unknown method {method}"}})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        _handle(req)


if __name__ == "__main__":
    main()
