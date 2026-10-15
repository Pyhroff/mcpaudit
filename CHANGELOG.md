# Changelog

Notable changes by version.

## v0.8.0

- **SARIF v2.1.0 Export**: Added `--sarif <path>` flag to `mcpaudit scan` for direct integration with GitHub Code Scanning, Security tabs, and standard SARIF consumers.
- **Synchronized Version Metadata**: Aligned `pyproject.toml`, `mcpaudit.__version__`, and `mcp_client._CLIENT_INFO` to unified version `0.8.0`.
- **Expanded Heuristic Prompt Injection & Guardrail Bypass Detection**:
  - Added detection patterns for safety-bypass directives (`bypass/disable/override safety/filters/guardrails`).
  - Added detection for jailbreak-style model mode manipulation (`act in developer mode`).
  - Added detection for logging and audit trail evasion directives (`do not/never log/audit this call`).
- Added test suite coverage for SARIF report formatting and new prompt injection detection patterns.

## v0.7.0 (patch, from a 90-repo public scan)

Driven by hand-labelled findings from scanning 90 public MCP-server repos (see mcp-scan-study/REPORT.md).

- permission_scope: risk category now derived from tool name + first sentence of the description, not the whole description.
- permission_scope: parameter-name matching is per category (fs: path/file/dir, network: url/uri/endpoint/host, exec: cmd/command/script/code/query/...).
- permission_scope: in-application paths (node/menu/parent/asset/prefab/clip/json/key/pattern/reference/relative) no longer count as filesystem paths; bare "run" no longer implies command execution.
- description_scan: "Cross-tool instruction" is LOW (was MEDIUM) when the wording is ordering guidance (first/before/after/prerequisite/then).
- Measured on 40 held-out labelled findings: strict precision of HIGH permission_scope 37.5% -> 64.3% (n=14 remaining, 95% CI 39-84%); false positives removed 87.5%; accurate findings retained 60% (recall cost, known).

## [Unreleased]

## [0.6.0] -- description_scan coverage fix, found via adversagen
- Broadened four `description_scan` patterns after `adversagen` (a
  separate adaptive red-teaming tool, github.com/Pyhroff/adversagen)
  wired its `RealScannerDefender` directly into this CLI and showed the
  *unevolved, unobfuscated* baseline attack population already evading
  mcpaudit 83-100% of the time on the tool_poisoning surface -- before any
  mutation happened at all. Root cause: several v0.1 patterns were more
  literal than the threat model intends.
  - "always call this tool first" now also matches a tool naming
    *itself* ("always call the delete_all_files tool first").
  - "do not mention THE USER" now tolerates words in between ("do not
    mention IT TO the user").
  - "you must always/never" now also matches passive/impersonal phrasing
    with no "you" at all ("this tool must be invoked on every request").
  - New patterns: "regardless of what was asked" (disregards user
    intent) and "call/invoke ... silently" (coercive secrecy about the
    call itself, distinct from hiding it from the user).
- 3 new regression tests using the exact phrasings adversagen's baseline
  attack payloads used. All 46 pre-existing tests, including the
  benign-deprecation-notice false-positive guard, still pass unchanged --
  this widens recall without reintroducing that false positive.

## [0.5.0] -- Finding-suppression policy
- `mcpaudit/policy.py`: `PolicyRule` (matches on `tool` ["*" wildcard
  supported], optional `check`, optional exact `title`) and `Policy`
  (loads an `{"ignore": [...]}` JSON file, `.apply(findings) -> (kept,
  suppressed)`).
- `mcpaudit scan --policy PATH`: suppressed findings are dropped before
  the printed report, `--json`, and `--fail-on` all see them, with a
  one-line summary of how many were suppressed and by which file. Not
  added to `baseline`/`diff` -- rug-pull detection's whole point is
  catching *unexpected* change, so it should never go quiet.
- `samples/example-policy.json`: a real policy suppressing the 9
  "Unscoped filesystem access" findings from the official
  `@modelcontextprotocol/server-filesystem` scan (see "Validated against
  real software" below and in README.md) -- documents why that finding
  is a known limitation of static schema analysis rather than a real gap
  in that server.
- 7 new tests (`tests/test_policy.py`): exact tool+check match, wildcard
  tool, title-narrowed match, check-only rule, multiple rules OR'd
  together, and loading a policy from a JSON file end-to-end.
- Motivation: every real scan (e.g. against the real filesystem server)
  produces the same accepted findings on every run with no way to say
  "reviewed, this is fine" -- which is what actually makes `--fail-on`
  unusable as a CI gate in practice. This is the standard mechanism real
  scanners ship (bandit's `# nosec`, semgrep's `.semgrepignore`-style
  rules) applied to mcpaudit's finding shape.

46 tests total (was 39). CLI smoke-tested against `samples/malicious_server`:
a policy suppressing `description_scan` findings leaves `permission_scope`
findings untouched; a policy suppressing everything flips `--fail-on high`
from exit 1 to exit 0; no policy passed behaves exactly as before.

## [0.4.0] -- Streamable HTTP transport
- `HttpMCPClient`: speaks MCP's current Streamable HTTP transport (a
  single POST endpoint, `application/json` or one-shot `text/event-stream`
  responses, session continuity via the `Mcp-Session-Id` header) -- so
  mcpaudit can scan a remote/hosted MCP server, not only a local
  subprocess.
- `StdioMCPClient` and `HttpMCPClient` now share a minimal `MCPClient`
  Protocol (`fetch_manifest`/`call_tool`); every check only ever sees a
  `ServerManifest`, so nothing in checks/ needed to change.
- `mcpaudit scan|baseline|diff --url <endpoint>` in place of a `-- <server
  command>`; passing both, or neither, is a clear error rather than a
  silent wrong-transport pick.
- 5 new tests against `HttpMCPClient` using `httpx.MockTransport` --
  exercises the real request/response/session-header code against a fake
  server, not a mock of the client itself. Covers both response shapes
  (plain JSON and SSE), session-ID propagation across requests, and a
  JSON-RPC error response.

39 tests total (was 34). CLI smoke-tested: stdio path unchanged, --url
against an unreachable host degrades to a clean exit-2 error (no
traceback), and passing both / neither is rejected before any connection
attempt.

## [0.3.1] -- validated against a real MCP server, two real bugs fixed
Ran `mcpaudit scan` against the official MCP filesystem server
(`@modelcontextprotocol/server-filesystem`, github.com/modelcontextprotocol/servers)
instead of only the two local fixtures. Found two real issues in the
process:
- **False positive fixed**: `read_file`'s real description is "Read the
  complete contents of a file as text. DEPRECATED: Use read_text_file
  instead." -- an ordinary deprecation notice. The cross-tool-poisoning
  pattern in `description_scan` was matching on "instead"/"never" alone,
  which is far too common in benign text. Narrowed to require "must" or
  "always" (real coercive language) instead. Added a regression test
  using this exact real-world description.
- **Real bug fixed**: `StdioMCPClient.close()` left a subprocess transport
  for the garbage collector to close, whose `__del__` finalizer could fire
  *after* `asyncio.run()` had already closed the event loop, throwing an
  uncaught `RuntimeError: Event loop is closed` on every scan of a real
  (npx-launched) server. Fixed by explicitly closing the transport while
  the loop is still running.

Result after both fixes: a clean scan against a real, widely-used server
correctly flags all 9 of its tools for unscoped filesystem access (no
enum/pattern/format on any `path` parameter) and raises zero false
positives.

Also confirmed: the dynamic `--dynamic` confused-deputy check is exercised
by 8 mocked tests (including the tool-output channel-isolation test) but
was not runnable against a live model from this environment -- the sandbox
this was built in blocks outbound access to LLM API hosts by policy. Run
`GROQ_API_KEY=... mcpaudit scan --dynamic -- <server>` yourself for a live
result; nothing about the check depends on this environment specifically.

34 tests total (was 33): +1 regression test for the false positive.

## [0.3.0] -- dynamic confused-deputy check
- `mcpaudit scan --dynamic --target groq/<model> [--tool NAME]`: wraps a
  real target LLM in a bounded tool-use loop, has it pick a tool from the
  server's real manifest, then substitutes an adversarial payload for that
  tool's *return value* -- delivered only inside a `[TOOL RESULT: ...]`
  message, never as a direct user message -- and checks whether the model
  complies anyway. Flags CRITICAL when it does.
- Reuses the tool-output-injection technique built for PromptStrike's
  `AgentAdapter` (see github.com/Pyhroff/promptstrike), pointed at a real
  server's real manifest instead of a mocked `search` tool.
- `samples/malicious_server`: a deliberately poisoned MCP server fixture
  (inert -- canned text only, no real filesystem/network/exec access) used
  by the test suite and as a live demo target. `samples/clean_server`
  used as the "should be quiet" control.
- 33 tests total (was 25): +8 for the confused-deputy check, including one
  that asserts the injected instruction only ever reaches the target
  inside a tool-result message, mirroring PromptStrike's channel-isolation
  test.

## [0.2.0] -- rug-pull detection
- `mcpaudit baseline -- <server cmd>`: snapshot a server's manifest to disk.
- `mcpaudit diff <baseline.json> -- <server cmd>`: compare a live server
  against a previously trusted baseline; flags any tool whose description
  or input schema changed, and any tool added or removed, since approval.
- `samples/clean_server`: benign fixture server used across the test suite.

## [0.1.0] -- static scanner core
- `ServerManifest`/`ToolManifest` data model.
- `StdioMCPClient`: minimal MCP client (stdio transport, newline-delimited
  JSON-RPC) -- just enough to fetch `tools/list`.
- `description_scan`: flags tool descriptions containing model-directed
  instructions, zero-width/hidden characters, cross-tool poisoning,
  exfiltration-shaped phrasing, and other tool-poisoning patterns.
- `permission_scope`: flags tools whose name/description implies broad
  filesystem/network/exec capability with no scoping in their input schema.
- `mcpaudit scan -- <server cmd>`: CLI entry point, text + JSON scorecard,
  `--fail-on` for CI gates.
- 16 tests, all static/no-network.
