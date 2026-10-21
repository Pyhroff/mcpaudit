## 2026-03-30 - Pre-compiled Regex Patterns and Fast-Path String Checking in Description Scanner
**Learning:** In static scanner checks evaluating lists of tools against regex patterns, re-compiling static regexes or performing un-guarded regex matching per tool call introduces significant runtime overhead (up to ~10x execution time on 100 tools).
**Action:** Pre-compile static regex patterns at module load time, and add fast string containment guards (`other.lower() in lower`) before performing dynamic regex evaluations.
