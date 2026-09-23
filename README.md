# mcpaudit

A security scanner for **MCP server tool surfaces** — the thing every AI
agent now plugs into for tools, and the thing almost nothing audits before
it's live.

Red-teaming an LLM (jailbreaking it into saying something bad) and
validating detection rules (does your SIEM catch a known technique) are
both well-covered ground at this point. Auditing the *infrastructure layer*
an agent runs on — the MCP servers supplying its tools — is not. This
project audits that layer directly: a server's declared tool manifest, and
optionally its live behavior, before you wire it into an agent that trusts
it.

Built as a deliberate follow-on to [PromptStrike](https://github.com/Pyhroff/promptstrike)'s
agent-mode work: PromptStrike tests whether *content delivered as a tool's
return value* can carry a jailbreak the same way a direct user message can.
`mcpaudit` applies that exact technique the other direction — pointed at
real MCP servers, checking whether one can manipulate the model consuming
its tools.

---

## Why this exists (the threat model)

An MCP server ships **tool descriptions** as part of its manifest. A
client hands that text straight to the calling LLM as context, on every
turn the model might use a tool — and no UI ever shows the user that text.
That's a channel a user never reviews but a model always reads, which
makes it a live prompt-injection surface with its own name in the
literature: **tool poisoning**. Related, adjacent failure modes this
project also targets:

- **Over-broad scope** — a tool named/described for one narrow purpose
  (`read_config`) but whose input schema accepts arbitrary paths, commands,
  or URLs with no constraint at all.
- **Rug pulls** — a server a user already approved silently changes a tool's
  description or schema on a later connection, after trust was granted once.
- **Confused deputy via tool output** — even a "clean" server, if
  compromised or if it fetches untrusted upstream data (a webpage, an
  issue comment, a file), can return adversarial content *as a tool
  result*. The model reads that as trusted context, not as user input —
  the same class of gap PromptStrike's `channel="tool_output"` mode tests
  against a mocked tool, applied here to a real one.

---

## Status: version-incremental prototype

Each version below is a complete, working, tested slice — not a stub.
See [CHANGELOG.md](CHANGELOG.md) for the running detail.

| Version | Adds |
|---|---|
| **v0.1** | Static scanner core — manifest fetch + `description_scan` + `permission_scope` checks, text/JSON scorecard, CI-gate exit code |
| **v0.2** | Rug-pull detection — `baseline`/`diff` against a previously trusted manifest |
| **v0.3** | Dynamic confused-deputy check — a real target LLM wrapped in a tool-use loop against the live server, tool-output injection test |

---

## Quickstart

```bash
pip install -e ".[dev]"

# scan a server (everything after -- is its launch command)
mcpaudit scan -- python samples/malicious_server/server.py

# machine-readable output + CI gate
mcpaudit scan --json report.json --fail-on high -- python my_server.py
```

## CLI reference

```
mcpaudit scan [OPTIONS] -- <server command>
  --json PATH        write a JSON scorecard
  --fail-on LEVEL     exit 1 if any finding >= LEVEL (low|medium|high|critical)

mcpaudit baseline [OPTIONS] -- <server command>
  --out PATH          where to save the manifest snapshot [default: mcpaudit-baseline.json]

mcpaudit diff <baseline.json> -- <server command>
  # compares live manifest against the snapshot, flags any drift
```

---

## Project structure

```
mcpaudit/
├── manifest.py            # ServerManifest / ToolManifest data model
├── mcp_client.py           # minimal stdio MCP client (tools/list, tools/call)
├── findings.py             # shared Finding / Severity types
├── report.py               # scorecard rendering (text + JSON)
├── cli.py                  # typer CLI
├── checks/
│   ├── description_scan.py # tool-poisoning pattern detection
│   ├── permission_scope.py # over-broad capability heuristics
│   └── rug_pull.py         # baseline-vs-live manifest diff (v0.2)
└── adapters/                # BaseAdapter/GroqAdapter -- same shape as PromptStrike's,
                              # used only by the dynamic confused-deputy check (v0.3)

samples/
├── clean_server/            # benign fixture MCP server
└── malicious_server/        # deliberately poisoned fixture -- test data only,
                              # see the warning at the top of that file
```

## Limitations

This is a heuristic scanner, not a formal verifier. A clean scan means
"nothing matched known-bad patterns," not "provably safe" — the static
checks are pattern/heuristic-based and can both over- and under-flag. It
currently supports MCP's stdio transport only (no SSE/HTTP). Treat findings
as a starting point for human review, not an automated block, until you've
validated the false-positive rate against your own servers.

## License

[MIT](LICENSE)
