# Bolt's Journal

## 2026-03-30 - Dynamic regex compilation in cross-tool scans
**Learning:** `mcpaudit` static scans evaluate $O(N^2)$ cross-tool description references using dynamic regex string interpolation (`re.search(rf"\b{re.escape(other)}...")`). For servers with many tools, dynamic regex compilation in python is extremely expensive compared to native string `in` checks.
**Action:** Always pre-filter candidate descriptions using fast string membership (`in`) before compiling dynamic regexes or running regex searches across tool sets.
