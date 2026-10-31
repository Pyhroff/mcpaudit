## 2026-03-30 - Fast Substring Guard in Cross-Tool Scanning
**Learning:** In static tool scanners where tools are compared pairwise ($O(N^2)$ cross-tool analysis), dynamic regex matching on every tool pair dominates scan duration. Adding a fast C-level string containment check (`other_lower in lower`) before attempting regex matching skips ~99% of unnecessary regex executions. Additionally, compiling static heuristic patterns at module load avoids repeated regex search/compilation overhead per scan turn.
**Action:** Always check substring presence (`sub in text`) before executing complex dynamic regexes in $O(N^2)$ cross-item comparisons.

## 2026-10-31 - Direct Dict Serialization vs dataclasses.asdict
**Learning:** In report serialization, `dataclasses.asdict()` relies on recursive introspection, creating deep copies of field values and performing dynamic attribute inspection per dataclass instance. In high-finding scans, this introduces significant CPU overhead (~40% of JSON generation). Providing a direct `to_dict()` method on flat dataclasses eliminates dynamic introspection and deep copying overhead while preserving exact JSON structure.
**Action:** Prefer explicit `to_dict()` methods over `dataclasses.asdict()` on flat dataclasses in performance-sensitive serialization paths.
