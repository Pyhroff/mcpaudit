## 2025-05-18 - Fast Substring Pre-checks for O(N^2) Cross-Tool Manifest Regex Scans
**Learning:** Cross-tool manifest scan loops in `mcpaudit` scale quadratically O(N^2) with the number of declared tools on a server. Evaluating dynamic `re.search` for every tool pair is expensive. Adding fast string pre-checks (`"must" in lower or "always" in lower`, and `other in lower`) bypasses regex compilation and matching for >99% of tool pairs on typical manifests.
**Action:** Always consider fast substring pre-checks before executing regexes in loops across manifest collections.
