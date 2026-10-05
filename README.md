# 🔌 mcpaudit

<div align="center">

**Security scanner for MCP tool surfaces.**

[![CI](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Overview

MCP servers expose tool names, descriptions, and schemas that become model context.

`mcpaudit` evaluates that surface for **tool poisoning, over-broad permission scopes, rug pulls, and confused-deputy behavior**.

It is the **MCP module inside [aisec-suite](https://github.com/Pyhroff/aisec-suite)**.

## Install

```bash
pip install pyhroff-mcpaudit
```

From source:

```bash
pip install -e ".[dev,dynamic]"
```

## Usage

```bash
mcpaudit scan -- python samples/malicious_server/server.py
mcpaudit scan --url https://example.com/mcp
mcpaudit scan --json report.json --fail-on high -- python my_server.py
mcpaudit baseline -o approved.json -- python my_server.py
mcpaudit diff approved.json -- python my_server.py
GROQ_API_KEY=... mcpaudit scan --dynamic -- python my_server.py
```

## Detector families

| Check | Purpose |
|---|---|
| `description_scan` | Model-directed instructions hidden in tool descriptions |
| `permission_scope` | Unconstrained filesystem, command, network, or URL parameters |
| `rug_pull` | Changes since an approved tool manifest |
| `confused_deputy` | Whether untrusted tool-returned content changes model behavior |

## Umbrella integration

```bash
aisec scan .
```

The umbrella uses source extraction plus mcpaudit's static checks and adds structural poisoning analysis and reachability annotations.

Use `mcpaudit` directly when you need its live-server URL workflow, baseline/diff workflow, or dynamic confused-deputy test.

## Security model

Static findings are review signals. Runtime restrictions and application-specific guarantees may not be visible in a declared schema.

## Development

```bash
pytest -q
```

## License

MIT
