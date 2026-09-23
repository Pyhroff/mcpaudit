"""Static check: does a tool's declared capability match what a benign use
of it should need? Heuristic, not a formal analysis -- flags tools whose
name/description implies broad filesystem/network/process access with no
scoping in the input schema (no enum/pattern constraining *what* it can
touch), which is the shape of an over-privileged tool a compromised server
can abuse beyond its stated purpose.
"""

from __future__ import annotations

import re

from mcpaudit.findings import Finding, Severity
from mcpaudit.manifest import ServerManifest, ToolManifest

_EXEC_NAME_RE = re.compile(r"\b(exec|execute|shell|cmd|command|run|eval|spawn)\b", re.I)
_FS_NAME_RE = re.compile(r"\b(file|path|dir|read|write|delete|remove)\b", re.I)
_NET_NAME_RE = re.compile(r"\b(fetch|http|url|request|download|upload|curl)\b", re.I)

_UNSCOPED_PATH_HINTS = ("any file", "entire filesystem", "any directory", "any url", "arbitrary")


def _schema_params(tool: ToolManifest) -> dict:
    return (tool.input_schema or {}).get("properties", {}) or {}


def _param_is_unconstrained_string(param: dict) -> bool:
    if param.get("type") != "string":
        return False
    # any of these narrows what values are acceptable
    return not any(k in param for k in ("enum", "pattern", "format", "maxLength"))


def check_scope(manifest: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []

    for tool in manifest.tools:
        name_and_desc = f"{tool.name} {tool.description}".lower()
        params = _schema_params(tool)

        risk_category = None
        if _EXEC_NAME_RE.search(name_and_desc):
            risk_category = "arbitrary code/command execution"
        elif _NET_NAME_RE.search(name_and_desc):
            risk_category = "outbound network access"
        elif _FS_NAME_RE.search(name_and_desc):
            risk_category = "filesystem access"

        if risk_category is None:
            continue

        unconstrained = [
            pname for pname, pschema in params.items()
            if isinstance(pschema, dict) and _param_is_unconstrained_string(pschema)
            and re.search(r"path|file|dir|url|cmd|command|query", pname, re.I)
        ]

        if unconstrained:
            findings.append(Finding(
                check="permission_scope", tool=tool.name, severity=Severity.HIGH,
                title=f"Unscoped {risk_category}",
                detail=f"Tool '{tool.name}' looks like it performs {risk_category} but its "
                       f"parameter(s) {unconstrained} accept any string with no enum/pattern/format "
                       f"constraint -- nothing in the schema limits what it can touch.",
            ))

        if any(hint in name_and_desc for hint in _UNSCOPED_PATH_HINTS):
            findings.append(Finding(
                check="permission_scope", tool=tool.name, severity=Severity.MEDIUM,
                title="Description admits unscoped access",
                detail=f"Tool '{tool.name}' description itself claims unrestricted "
                       f"({risk_category}) scope.",
            ))

        if not tool.input_schema and risk_category:
            findings.append(Finding(
                check="permission_scope", tool=tool.name, severity=Severity.LOW,
                title="No input schema for a capability-bearing tool",
                detail=f"Tool '{tool.name}' implies {risk_category} but declares no input schema "
                       f"at all -- can't reason about what it's constrained to.",
            ))

    return findings
