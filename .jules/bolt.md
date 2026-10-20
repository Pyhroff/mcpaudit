## 2026-03-31 - Pre-compiling Regex Patterns and Fast Substring Filtering in `description_scan`

**Learning:** In MCP tool audit scans, tool description matching frequently evaluates regex patterns across all declared tools. Pre-compiling static regexes at module load time and short-circuiting nested $O(N^2)$ cross-tool regex checks with fast string membership (`in`) guards yields a ~20x performance improvement (~0.7s down to ~0.03s for 200 tools).

**Action:** Always pre-compile module-level regexes and apply `substring in text` guards prior to running `re.search(rf"...\b{other}\b...", text)` loops when scanning collections of objects.
