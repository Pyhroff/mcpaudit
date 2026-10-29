## 2026-03-30 - Fast Substring Guard in Cross-Tool Scanning
**Learning:** In static tool scanners where tools are compared pairwise ($O(N^2)$ cross-tool analysis), dynamic regex matching on every tool pair dominates scan duration. Adding a fast C-level string containment check (`other_lower in lower`) before attempting regex matching skips ~99% of unnecessary regex executions. Additionally, compiling static heuristic patterns at module load avoids repeated regex search/compilation overhead per scan turn.
**Action:** Always check substring presence (`sub in text`) before executing complex dynamic regexes in $O(N^2)$ cross-item comparisons.

## 2026-03-30 - Large Regex Disjunctions vs Fast Loop Indexing
**Learning:** Replacing regexes containing lookbehinds or sentence split patterns (`re.split(r"(?<=[.!?])\s|\n", ...)`) with simple character-iteration loops (`for i, ch in enumerate(s)`) yields clean speedups without regex engine overhead. However, attempting to pre-filter strings using a single combined regex with dozens of OR alternatives (`r"exec|shell|cmd|fetch|http|file|path|..."`) can actually degrade performance by ~30% due to NFA/DFA backtrack state evaluation across large disjunctions.
**Action:** Prefer direct string indexing or tight targeted regexes over mega-disjunction regex pre-filters.
