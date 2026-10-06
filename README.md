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

The umbrella adds repository-level extraction, structural poisoning analysis, and reachability annotations around the static mcpaudit checks.

Use `mcpaudit` directly for live-server workflows and its dynamic confused-deputy experiment.

## Security model

Static findings are review signals. Runtime restrictions and application-specific guarantees may not be visible in a declared schema.

## Development

```bash
pytest -q
```

## License

MIT


## CI and cross-repository regression

The project participates in the shared `agent-test-range` regression suite. CI runs the local test matrix and then exercises the scanner against the controlled integration corpus through a private composite install action.

Cross-repository installation no longer requires a long-lived `TOOLS_PAT` checkout credential. The shared action is pinned to an immutable commit and GitHub supplies a short-lived scoped installation token for private-action access.

This keeps regression testing reproducible while reducing credential exposure in CI.
