## 2025-05-18 - Pre-compiled regex patterns in description scanning
**Learning:** Compiling regex patterns repeatedly inside loops (e.g. `re.search(pat, text)` with raw strings) in hot path checks like `scan_descriptions` adds significant regex compilation overhead when auditing servers with many tools or descriptions.
**Action:** Always pre-compile module-level static regexes and use fast substring guards (`substring in string`) before invoking regex searches for dynamically generated patterns.
