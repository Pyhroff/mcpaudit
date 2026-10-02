# mcpaudit

[![CI](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A security scanner for MCP server tool surfaces. It reads a server's declared tools (names, descriptions, input schemas), flags patterns associated with tool poisoning and over-broad access, detects changes against a previously approved manifest, and can optionally test a live model for confused-deputy behavior.

## Why

An MCP server ships tool descriptions that the client passes to the model as context on every turn. Users rarely see that text, but the model always reads it, so it is a prompt-injection channel. mcpaudit checks four related problems:

- **Tool poisoning**: instructions hidden in a tool description ("always call this tool first", "do not mention this to the user").
- **Over-broad scope**: a tool described for a narrow job whose schema accepts arbitrary paths, commands, or URLs.
- **Rug pulls**: a server changes a tool's description or schema after the user approved it.
- **Confused deputy**: a tool returns untrusted content (a web page, an issue comment) that the model then treats as trusted context.

## Install

From PyPI:

```bash
pip install pyhroff-mcpaudit          # installs the `mcpaudit` command; the Python package is still `mcpaudit`
```

From source:

```bash
git clone https://github.com/Pyhroff/mcpaudit.git
cd mcpaudit
pip install -e ".[dev,dynamic]"    # drop ",dynamic" if you only need static checks
```

Python 3.10 or newer.

## Usage

```bash
# static checks against a local stdio server
mcpaudit scan -- python samples/malicious_server/server.py

# scan a remote server over Streamable HTTP
mcpaudit scan --url https://example.com/mcp

# JSON output and a CI gate (exit 1 on any finding at or above HIGH)
mcpaudit scan --json report.json --fail-on high -- python my_server.py

# rug-pull detection: snapshot once, compare later
mcpaudit baseline -o approved.json -- python my_server.py
mcpaudit diff approved.json -- python my_server.py

# suppress findings you have reviewed and accepted
mcpaudit scan --policy policy.json --fail-on high -- python my_server.py

# dynamic confused-deputy check (needs GROQ_API_KEY)
GROQ_API_KEY=... mcpaudit scan --dynamic -- python my_server.py
```

`--url` and a `-- <server command>` are mutually exclusive.

### Options for `scan`

| Option | Meaning |
|---|---|
| `--url URL` | Scan a remote server over Streamable HTTP instead of launching a process |
| `--json PATH` | Write a JSON scorecard |
| `--fail-on LEVEL` | Exit 1 if any finding is at or above `low`, `medium`, `high`, or `critical` |
| `--policy PATH` | JSON file of accepted findings to suppress |
| `--dynamic` | Also run the confused-deputy check against a live model |
| `--target groq/MODEL` | Model for `--dynamic` (default `groq/openai/gpt-oss-120b`) |
| `--tool NAME` | Restrict `--dynamic` to one tool |

## Checks

| Check | What it looks for |
|---|---|
| `description_scan` | Coercive or hidden-instruction phrasing in tool descriptions: forced call ordering, secrecy from the user, cross-tool instructions, "regardless of what was asked" |
| `permission_scope` | Tools whose name or description implies a narrow purpose but whose schema takes unconstrained filesystem, network, or command parameters |
| `rug_pull` | Differences between a saved baseline manifest and the live server (`diff` command) |
| `confused_deputy` | Whether injected content returned as a tool result changes a live model's behavior (`--dynamic`) |

## Suppressing accepted findings

Some findings are true but already reviewed. For example, a filesystem server may restrict directories at startup, which its tool schema cannot express, so `permission_scope` will always flag it. A policy file records that review so `--fail-on` stays usable in CI:

```json
{
  "ignore": [
    {
      "tool": "*",
      "check": "permission_scope",
      "title": "Unscoped filesystem access",
      "reason": "directories are restricted by the server at startup"
    }
  ]
}
```

`tool: "*"` matches any tool. Omitting `title` matches every finding for that tool and check. Suppressed findings are removed before the report, the JSON output, and `--fail-on`. `baseline` and `diff` do not accept a policy, because rug-pull detection should never go quiet.

## Evaluation

The scanner has been run against real software, not only fixtures.

- **Official filesystem server** (`@modelcontextprotocol/server-filesystem`): the first run turned up a false positive (a "DEPRECATED: use read_text_file instead" description matched a cross-tool pattern) and an asyncio cleanup crash on every subprocess scan. Both were fixed with regression tests.
- **Public MCP repositories**: tools were extracted from public repos and scanned, and findings were labelled by hand. The v0.6 `permission_scope` HIGH findings had 37.5% strict precision (95% CI 24-53%). v0.7 changes the category logic and raised precision to 64.3% on a held-out sample of 40, at the cost of retaining 60% of the accurate findings. Method, labels, and limits are in [mcp-scan-study](https://github.com/Pyhroff/mcp-scan-study).
- **Adversarial payloads**: [adversagen](https://github.com/Pyhroff/adversagen) generated tool-poisoning phrasings that the v0.5 patterns missed. v0.6 broadened the patterns to cover them.

## Development

```bash
pytest -q        # 49 tests
```

```
mcpaudit/
  cli.py               typer CLI: scan, baseline, diff
  manifest.py          ServerManifest / ToolManifest data model
  mcp_client.py        stdio and Streamable HTTP clients
  policy.py            suppression policy
  findings.py          Finding and Severity types
  report.py            text and JSON output
  checks/              description_scan, permission_scope, rug_pull, confused_deputy
  adapters/            model adapter used by the dynamic check
samples/               clean and deliberately poisoned fixture servers, example policy
tests/
```

The poisoned fixture under `samples/malicious_server` exists only as test data.

## Limitations

- The static checks are heuristics. A clean scan means nothing matched known patterns, not that the server is safe.
- Schema analysis cannot see restrictions enforced at runtime, so `permission_scope` over-reports on servers that sandbox internally.
- The dynamic check has been tested with mocks only. It has not been run against a live model yet.
- Only the tool manifest is inspected, not the server's implementation.

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

[MIT](LICENSE)
