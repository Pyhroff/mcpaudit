# Hostile-input hardening

A scanned MCP server controls every field of its manifest, so the static checks must survive any value it sends.

Harness: `tools/hostile_inputs.py` (`python tools/hostile_inputs.py . mcpaudit`). Regression tests: `tests/test_hostile_input.py`.

## Protocol (written before the first run)

- 54 text families (long runs, whitespace, repeated trigger phrases, Unicode edge cases, NUL, huge line counts) placed in a tool description at 20k, 40k and 80k characters, plus 17 structural families at 1k, 2k and 4k tools or properties: many tools, repeated and regex-like names, huge or deeply nested schemas, and wrong types (null, number, list where text or an object is expected).
- Each case runs in its own subprocess with a 10 s limit.
- A finding is a crash, a timeout, more than 1.0 s at the middle size, or superlinear growth (largest over middle time above 3.0, with the largest time above 0.2 s).
- Run once on the unmodified code, fix every finding with a regression test, then run again.

Deviation: the harness reports the best of 3 runs per case (see the same note in ragsentry and memsentry, where timing noise showed up first).

## First run

| Family | Result |
|---|---|
| `struct_desc_int`, `struct_desc_list` | **Crash**: `TypeError` in text normalisation. A server sending a number or list as a description aborted the whole scan. |
| `struct_name_int` | **Crash**: `AttributeError` on a non-string tool name. |
| `struct_props_list` | **Crash**: `AttributeError` when `properties` is a list. |
| `struct_many_tools_same_name` | Superlinear: 0.38 s at 4,000 tools, 1.15 s at 8,000. The cross-tool rule compared every tool with every duplicate of every name. |
| `struct_regex_names` | 1.12 s at 4,000 tools: the process-wide regex cache holds 1,024 entries and thrashed. |

The 54 text families found no crashes, timeouts or backtracking.

## Fixes

- `ToolManifest` coerces name and description to text (null becomes empty, other values keep their JSON form) and a non-object schema to `{}`; `properties` that is not an object is treated as empty.
- The cross-tool rule works on distinct tool names and uses a per-scan regex cache. One consequence: two tools sharing a name used to produce a duplicated "Cross-tool instruction" finding for each tool that references it; it is now reported once.
- The rug-pull finding quotes at most 300 characters of each schema, like it already did for descriptions.

## Second run

No crashes or timeouts. One finding remains open: `struct_regex_names` at 1.03 s for 4,000 distinct tool names. The cross-tool rule still tests every description against every distinct name (tools squared); with typical servers (under 100 tools) that is milliseconds. A fully sub-quadratic version would need a multi-pattern matcher such as Aho-Corasick; not done.

## Checks that behaviour did not change

mcpaudit's description and scope checks on the 485 poisoned and 362 clean MCPTox tools (pinned commit used by aisec-suite's external evaluation), as single-tool manifests and as per-server manifests: findings byte-identical before and after.
