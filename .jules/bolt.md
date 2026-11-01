## 2026-03-31 - Partition Indexing for Wildcard-Supported Policy Rules
**Learning:** When matching findings against suppression rules where rules may specify a concrete entity (e.g. `tool="foo"`) or a wildcard (e.g. `tool="*"`), linear iteration checks $O(F \times R)$ rules. Partitioning the rule list into a dictionary of lists keyed by concrete entity plus a separate small list of wildcard rules enables $O(1)$ tool lookup for tool-specific rules, reducing comparisons by ~75% while maintaining exact wildcard semantics without complex trie structures.
**Action:** When filtering or suppressing items with wildcard support, bucket rules into specific hash map entries and a wildcard list instead of scanning all rules iteratively.

## 2026-03-30 - Fast Substring Guard in Cross-Tool Scanning
**Learning:** In static tool scanners where tools are compared pairwise ($O(N^2)$ cross-tool analysis), dynamic regex matching on every tool pair dominates scan duration. Adding a fast C-level string containment check (`other_lower in lower`) before attempting regex matching skips ~99% of unnecessary regex executions. Additionally, compiling static heuristic patterns at module load avoids repeated regex search/compilation overhead per scan turn.
**Action:** Always check substring presence (`sub in text`) before executing complex dynamic regexes in $O(N^2)$ cross-item comparisons.
