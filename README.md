# mcpaudit

![CI](https://github.com/Pyhroff/mcpaudit/actions/workflows/ci.yml/badge.svg)

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
| **v0.3** | Dynamic confused-deputy check — a real target LLM wrapped in a tool-use loop against the live server's real manifest, tool-output injection test — `--dynamic` |
| **v0.4** | Streamable HTTP transport — `--url` scans a remote/hosted MCP server, not just a local stdio process |
| **v0.5** | Finding-suppression policy — `--policy policy.json` silences reviewed/accepted findings so `--fail-on` is actually usable as a CI gate |

---

## Quickstart

```bash
pip install -e ".[dev,dynamic]"

# static checks only (no API key needed)
mcpaudit scan -- python samples/malicious_server/server.py

# add the dynamic confused-deputy check against a real target model
GROQ_API_KEY=... mcpaudit scan --dynamic -- python samples/malicious_server/server.py

# machine-readable output + CI gate
mcpaudit scan --json report.json --fail-on high -- python my_server.py

# rug-pull detection
mcpaudit baseline -o approved.json -- python my_server.py
mcpaudit diff approved.json -- python my_server.py   # later, on the same or updated server

# suppress findings you've reviewed and accepted, so --fail-on stays usable in CI
mcpaudit scan --policy policy.json --fail-on high -- python my_server.py
```

## Suppressing accepted findings

A real scan against real software (see below) turns up findings that are true but
already known and accepted -- e.g. a tool's schema can't express a runtime `--allowed-dir`
restriction, so `permission_scope` will always flag it, even though the server actually
scopes access correctly. Without a way to say "I looked at this, it's fine," `--fail-on`
becomes unusable in CI: the first accepted finding blocks every future run forever.

A policy file records that review, per `(tool, check[, title])`, so re-scans stay quiet
on exactly that finding while anything new still surfaces:

```json
{
  "ignore": [
    {
      "tool": "*",
      "check": "permission_scope",
      "title": "Unscoped filesystem access",
      "reason": "why this is accepted -- shown for humans, not enforced"
    }
  ]
}
```

`tool: "*"` matches any tool; omitting `title` matches any finding for that `(tool, check)`.
See [`samples/example-policy.json`](samples/example-policy.json) for the policy used against
the real filesystem-server scan below. Suppressed findings are dropped before the printed
report, `--json`, and `--fail-on` all see them -- a suppressed CRITICAL will not fail a build.
`baseline`/`diff` intentionally do NOT take `--policy`: the whole point of rug-pull detection
is catching *unexpected change*, so it should never go quiet.

## CLI reference

```
mcpaudit scan [OPTIONS] (-- <server command> | --url <endpoint>)
  --url URL            scan a remote server over Streamable HTTP instead of a local process
  --json PATH          write a JSON scorecard
  --fail-on LEVEL      exit 1 if any finding >= LEVEL (low|medium|high|critical)
  --dynamic            also run the confused-deputy check against a real target model
  --target groq/MODEL  target for --dynamic [default: groq/openai/gpt-oss-120b]
  --tool NAME          restrict --dynamic to one tool [default: every tool in the manifest]
  --policy PATH        JSON file of reviewed/accepted findings to suppress (see samples/example-policy.json)

mcpaudit baseline [OPTIONS] (-- <server command> | --url <endpoint>)
  --out PATH          where to save the manifest snapshot [default: mcpaudit-baseline.json]

mcpaudit diff <baseline.json> (-- <server command> | --url <endpoint>)
  # compares live manifest against the snapshot, flags any drift
```

`--url` and a `-- <server command>` are mutually exclusive -- pass exactly one.

---

## Project structure

```
mcpaudit/
├── manifest.py            # ServerManifest / ToolManifest data model
├── mcp_client.py           # StdioMCPClient + HttpMCPClient (tools/list, tools/call)
├── findings.py             # shared Finding / Severity types
├── report.py               # scorecard rendering (text + JSON)
├── cli.py                  # typer CLI
├── checks/
│   ├── description_scan.py # tool-poisoning pattern detection
│   ├── permission_scope.py # over-broad capability heuristics
│   ├── rug_pull.py         # baseline-vs-live manifest diff
│   └── confused_deputy.py  # tool-output injection test against a live target model
└── adapters/                # BaseAdapter/GroqAdapter -- same shape as PromptStrike's,
                              # used only by the dynamic confused-deputy check

samples/
├── clean_server/            # benign fixture MCP server
└── malicious_server/        # deliberately poisoned fixture -- test data only,
                              # see the warning at the top of that file
```

## Validated against real software

Every check has a unit test, but tests against your own fixtures only
prove the code does what you told it to. So: `mcpaudit scan` was also run
against the real, official [MCP filesystem server](https://github.com/modelcontextprotocol/servers)
(`npx @modelcontextprotocol/server-filesystem`), not just the two local
fixtures. Two real things came out of that, both already fixed (see
[CHANGELOG.md](CHANGELOG.md)'s v0.3.1 entry for the detail):

- **A real false positive**: the server's real `read_file` tool has the
  description *"DEPRECATED: Use read_text_file instead"* — ordinary
  deprecation text that an earlier, looser version of the cross-tool
  heuristic flagged as possible poisoning. Narrowed the pattern and added
  a regression test using that exact real description.
- **A real bug**: scanning a real (subprocess-launched) server threw an
  uncaught `RuntimeError: Event loop is closed` from asyncio's own cleanup
  path on every run. Fixed.

After both fixes, a scan of that real server correctly flags all 9 of its
tools for unscoped filesystem access (no schema constraint on any `path`
parameter) with zero false positives.

The dynamic `--dynamic` confused-deputy check is covered by 8 mocked
tests, including one asserting the injected payload never leaks into a
direct user message — but hasn't yet been run against a live target model
from this environment (outbound access to LLM API hosts is blocked here
by network policy, not by anything in the check itself). If you run it
yourself, this section will get updated with a real result.

## Limitations

This is a heuristic scanner, not a formal verifier. A clean scan means
"nothing matched known-bad patterns," not "provably safe" — the static
checks are pattern/heuristic-based and can both over- and under-flag. It
currently supports MCP's stdio transport only (no SSE/HTTP). Treat findings
as a starting point for human review, not an automated block, until you've
validated the false-positive rate against your own servers.

## License

[MIT](LICENSE)
