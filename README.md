# 🔌 mcpaudit

<div align="center">

**Security scanner for MCP server tool surfaces.**

[![CI](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Why mcpaudit?

MCP servers turn **tool names, descriptions, schemas, and tool output into model-visible context**. That surface can become an attack boundary.

`mcpaudit` is a focused scanner for that boundary. It inspects MCP tool surfaces for:

- **Tool poisoning** — model-directed instructions embedded in tool descriptions.
- **Over-broad scope** — filesystem, command, network, or URL parameters that expose excessive authority.
- **Rug pulls** — unexpected changes to a previously approved tool manifest.
- **Confused-deputy behavior** — whether untrusted tool-returned content can influence model actions during a controlled dynamic experiment.

It is the MCP-focused scanner inside [aisec-suite](https://github.com/Pyhroff/aisec-suite), but can also be used independently.

> **Status:** Beta · Python 3.10+ · version 0.7.0

## What it actually scans

```text
MCP server
    │
    ├── tool name
    ├── description
    ├── input schema
    └── tool output (dynamic mode)
          │
          ▼
      mcpaudit
          │
          ├── description_scan
          ├── permission_scope
          ├── rug_pull
          └── confused_deputy
          │
          ▼
   findings / JSON scorecard
```

The scanner is intentionally **surface-oriented**: it does not claim that a static finding is proof of exploitation, and it does not execute package installation hooks.

## Install

From PyPI:

```bash
pip install pyhroff-mcpaudit
```

For HTTP transport support:

```bash
pip install "pyhroff-mcpaudit[http]"
```

For the optional dynamic model experiment:

```bash
pip install "pyhroff-mcpaudit[dynamic]"
```

For local development:

```bash
git clone https://github.com/Pyhroff/mcpaudit.git
cd mcpaudit
pip install -e ".[dev]"
```

## Quick start

### Scan a local stdio server

```bash
mcpaudit scan -- python samples/malicious_server/server.py
```

### Scan a Streamable HTTP server

```bash
mcpaudit scan --url https://example.com/mcp
```

### Produce a machine-readable scorecard

```bash
mcpaudit scan \
  --json report.json \
  --fail-on high \
  -- python my_server.py
```

`--fail-on` makes the scanner useful as a CI gate: the command exits non-zero when a finding meets or exceeds the selected severity.

### Track tool-manifest drift

Create a trusted baseline:

```bash
mcpaudit baseline -o approved.json -- python my_server.py
```

Compare a later server state:

```bash
mcpaudit diff approved.json -- python my_server.py
```

This treats unexpected tool-surface changes as reviewable security findings rather than silently accepting them.

### Suppress reviewed findings with policy

```bash
mcpaudit scan \
  --policy samples/example-policy.json \
  --fail-on high \
  -- python my_server.py
```

Policy suppression is explicit and happens before rendering, JSON output, and `--fail-on` evaluation.

## Detector matrix

| Detector | Input | Security question |
|---|---|---|
| `description_scan` | Tool descriptions | Is the model being instructed by attacker-controlled metadata? |
| `permission_scope` | Tool schemas | Does a tool expose unusually broad authority or dangerous parameter shapes? |
| `rug_pull` | Trusted + current manifests | Did the tool surface change after approval? |
| `confused_deputy` | Live tool + target model | Can untrusted tool output influence the model's subsequent behavior? |

Static detectors run by default. The confused-deputy experiment is opt-in with `--dynamic`.

## Dynamic confused-deputy experiment

```bash
GROQ_API_KEY=... \
mcpaudit scan \
  --dynamic \
  --target groq/openai/gpt-oss-120b \
  -- python my_server.py
```

You can restrict the experiment to one tool:

```bash
GROQ_API_KEY=... \
mcpaudit scan \
  --dynamic \
  --tool suspicious_tool \
  -- python my_server.py
```

The dynamic path currently uses a Groq target adapter. If the API key is absent, the dynamic check is skipped rather than treating the missing model connection as a scanner finding.

## CI usage

A minimal security gate:

```bash
mcpaudit scan --fail-on high --json mcpaudit-report.json -- python server.py
```

Recommended workflow:

1. Run static checks on every change.
2. Fail CI for findings at or above your chosen severity.
3. Keep an approved manifest for production tool surfaces.
4. Run `mcpaudit diff` when the server's tool surface changes.
5. Treat dynamic results as experimental evidence that should be reviewed alongside the static findings.

## Umbrella integration

```bash
aisec scan .
```

The umbrella adds repository-level extraction, structural poisoning analysis, and reachability annotations around the static mcpaudit checks.

Use `mcpaudit` directly when you need **live MCP-server scanning, manifest baselines, or the dynamic confused-deputy experiment**.

## Security model and limitations

`mcpaudit` is a security analysis tool, not a malware verdict or a complete MCP sandbox.

- Static analysis can miss runtime behavior and novel attack paths.
- A flagged pattern may be legitimate application behavior and requires review.
- A clean scan does not prove that a server is safe.
- Dynamic experiments are bounded by the selected model, tool, fixture, and prompt.
- Network and application-specific authorization controls remain outside the scanner's guarantees.

Use it against systems you own or are explicitly authorized to test.

## Development

Run the test suite:

```bash
pytest -q
```

The project also participates in the shared `agent-test-range` regression suite. Cross-repository CI uses pinned shared actions and short-lived GitHub-provided installation credentials rather than a long-lived checkout token.

## Project structure

```text
mcpaudit/
├── cli.py                 # Typer CLI and scan/baseline/diff commands
├── manifest.py            # MCP server/tool manifest representation
├── mcp_client.py          # stdio + Streamable HTTP clients
├── findings.py            # normalized finding model
├── report.py              # text/JSON reporting and risk scoring
├── policy.py              # reviewed-finding suppression
├── checks/
│   ├── description_scan.py
│   ├── permission_scope.py
│   ├── rug_pull.py
│   └── confused_deputy.py
└── adapters/
    └── groq.py            # dynamic target adapter
```

## Relationship to the Pyhroff AI-security stack

| Project | Role |
|---|---|
| **mcpaudit** | MCP tool-surface scanner |
| **memsentry** | Memory-injection / persistent-context analysis |
| **ragsentry** | RAG-oriented security analysis |
| **wormsentry** | Package-worm / supply-chain behavior detection |
| **adversagen** | Adversarial evaluation and payload mutation |
| **aisec-suite** | Umbrella CLI and repository-level integration |

The projects are intentionally separated by attack surface so individual scanners can remain focused and composable.



## Security research & evaluation

This project documents its security boundary explicitly:

- [Threat model](docs/THREAT_MODEL.md)
- [Evaluation methodology](docs/EVALUATION.md)

The intended evidence chain is **threat → fixture → detector → benchmark → limitation**, so scan results are reproducible rather than presented as universal security guarantees.

## License

MIT
