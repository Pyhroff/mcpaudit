## 2026-03-30 - Fast Substring Guard in Cross-Tool Scanning
**Learning:** In static tool scanners where tools are compared pairwise ($O(N^2)$ cross-tool analysis), dynamic regex matching on every tool pair dominates scan duration. Adding a fast C-level string containment check (`other_lower in lower`) before attempting regex matching skips ~99% of unnecessary regex executions. Additionally, compiling static heuristic patterns at module load avoids repeated regex search/compilation overhead per scan turn.
**Action:** Always check substring presence (`sub in text`) before executing complex dynamic regexes in $O(N^2)$ cross-item comparisons.

## 2026-04-06 - ASCII Fast-Path Bypass for Unicode Normalization and Confusable Checks
**Learning:** In static text scanners processing thousands of tool descriptions/schemas, strings are predominantly ASCII. Characters in 0-127 are invariant under NFKC normalization, contain no Unicode category 'Cf' (format/control) characters, and cannot contain mixed-script confusables (Cyrillic, Greek, Armenian, etc.). Adding a fast C-level `text.isascii()` check completely bypasses expensive NFKC decomposition, Python-level character-by-character filtering, and regex word extraction on clean ASCII text.
**Action:** Use `text.isascii()` guards before invoking heavy Unicode normalization and confusable detection algorithms when scanning text.
