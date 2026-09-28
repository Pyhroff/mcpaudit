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

_EXEC_NAME_RE = re.compile(r"\b(exec|execute|shell|cmd|command|commands|eval|spawn)\b", re.I)
_FS_NAME_RE = re.compile(r"\b(file|path|dir|read|write|delete|remove)\b", re.I)
_NET_NAME_RE = re.compile(r"\b(fetch|http|url|request|download|upload|curl)\b", re.I)

# v0.7: which parameter names are relevant depends on the risk category. Previously one regex
# (path|file|dir|url|cmd|command|query) applied to every category, so a "filesystem" finding could be
# raised on a `url` parameter and vice versa.
_PARAM_BY_CATEGORY = {
    "arbitrary code/command execution": re.compile(r"cmd|command|script|code|query|args|(?:input|hash|core|memory)_?file|output_?file", re.I),
    "outbound network access": re.compile(r"url|uri|endpoint|host|baseurl", re.I),
    "filesystem access": re.compile(r"path|file|dir", re.I),
}
# v0.7: names that contain "path" but denote an in-application hierarchy/asset/JSON path, not a filesystem path.
_NON_FS_PATH_RE = re.compile(r"node|menu|parent|hierarchy|gameobject|asset|prefab|clip|json|key|pattern|reference|relative", re.I)


def _first_sentence(desc: str) -> str:
    # v0.7: categorise on the tool name plus the *first sentence* of the description. Matching the whole
    # description let incidental words in usage notes ("Use when native Bash hooks are wrong ...") assign a category.
    head = re.split(r"(?<=[.!?])\s|\n", (desc or "").strip(), maxsplit=1)[0]
    return head[:200]

_UNSCOPED_PATH_HINTS = ("any file", "entire filesystem", "any directory", "any url", "arbitrary")


def _schema_params(tool: ToolManifest) -> dict:
    return (tool.input_schema or {}).get("properties", {}) or {}


def _param_is_unconstrained_string(param: dict) -> bool:
    if param.get("type") != "string":
        return False
    # any of these narrows what values are acceptable
    return not any(k in param for k in ("enum", "pattern", "format", "maxLength"))


def _param_matches_category(pname: str, category: str) -> bool:
    if not _PARAM_BY_CATEGORY[category].search(pname):
        return False
    if category == "filesystem access" and _NON_FS_PATH_RE.search(pname):
        return False
    return True


def check_scope(manifest: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []

    for tool in manifest.tools:
        name_and_desc = f"{tool.name} {tool.description}".lower()   # still used for the "admits unscoped" hint
        categorise_text = f"{tool.name} {_first_sentence(tool.description)}".lower()
        params = _schema_params(tool)

        risk_category = None
        if _EXEC_NAME_RE.search(categorise_text):
            risk_category = "arbitrary code/command execution"
        elif _NET_NAME_RE.search(categorise_text):
            risk_category = "outbound network access"
        elif _FS_NAME_RE.search(categorise_text):
            risk_category = "filesystem access"

        if risk_category is None:
            continue

        unconstrained = [
            pname for pname, pschema in params.items()
            if isinstance(pschema, dict) and _param_is_unconstrained_string(pschema)
            and _param_matches_category(pname, risk_category)
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
