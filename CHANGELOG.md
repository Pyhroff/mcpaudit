# Changelog

This project is built as an explicit version-incremental prototype: each
stage is a small, working, tested slice rather than one big-bang commit.

## [Unreleased]

## [0.3.0] -- dynamic confused-deputy check
- `mcpaudit scan --dynamic --target groq/<model>`: wraps a real target LLM
  in a bounded tool-use loop against the live MCP server, injects an
  adversarial instruction as a tool's *return value* (not a user message),
  and checks whether the model complies -- the confused-deputy scenario.
- Reuses the tool-output-injection technique built for PromptStrike's
  `AgentAdapter` (see github.com/Pyhroff/promptstrike), pointed at a real
  server instead of a mock tool.
- `samples/malicious_server`: a deliberately poisoned MCP server fixture
  used by the test suite and as a live demo target.

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
