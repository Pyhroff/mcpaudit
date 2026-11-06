## 2026-03-30 - Fast Substring Guard in Cross-Tool Scanning
**Learning:** In static tool scanners where tools are compared pairwise ($O(N^2)$ cross-tool analysis), dynamic regex matching on every tool pair dominates scan duration. Adding a fast C-level string containment check (`other_lower in lower`) before attempting regex matching skips ~99% of unnecessary regex executions. Additionally, compiling static heuristic patterns at module load avoids repeated regex search/compilation overhead per scan turn.
**Action:** Always check substring presence (`sub in text`) before executing complex dynamic regexes in $O(N^2)$ cross-item comparisons.

## 2026-04-18 - Fast ASCII Guards in Unicode Normalization Pipelines
**Learning:** Unicode normalization (`unicodedata.normalize("NFKC", text)`), per-character category inspection (`category(ch) != "Cf"`), and confusable dictionary mapping are CPU-heavy operations. The vast majority of MCP tool manifests and software descriptions are pure ASCII. Pure ASCII strings are already invariant under NFKC normalization, contain no `Cf` formatting codepoints, and cannot contain non-Latin confusable characters.
**Action:** Guard Unicode normalization and confusable detection pipelines with `text.isascii()`. Return early or take a lean string transform path for ASCII text.
