# Bolt's Journal - Critical Learnings

## 2025-05-18 - Fast Substring Pre-checks for $O(N^2)$ Cross-Tool Regex Scanning
**Learning:** In static manifest analysis, cross-tool checks scale quadratically ($O(N^2)$) with tool count. Executing `re.search()` inside nested loops without string pre-filtering causes massive overhead. Adding cheap substring checks (`"must" in lower` and `other in lower`) before compiling and executing regexes, alongside module-level precompilation of fixed patterns, yields an ~85% speedup without altering match behavior.
**Action:** Always pre-filter candidate strings using fast `in` operations before invoking regex searches in nested tool inspection loops.
