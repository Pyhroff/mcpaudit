# Changelog

This project is built as an explicit version-incremental prototype: each
stage is a small, working, tested slice rather than one big-bang commit.

## [Unreleased]

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
