"""Turns a flat list of Findings into something a human (or a CI gate) can
act on: a severity-sorted scorecard, plain text or JSON.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from mcpaudit.findings import Finding, Severity

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_SEVERITY_WEIGHT = {Severity.CRITICAL: 40, Severity.HIGH: 15, Severity.MEDIUM: 4, Severity.LOW: 1}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.tool, f.check))


def risk_score(findings: list[Finding]) -> int:
    """0 (clean) upward, roughly comparable across servers with a similar
    tool count. Not calibrated against any external standard -- a relative
    signal for triage, not a certified score."""
    return sum(_SEVERITY_WEIGHT[f.severity] for f in findings)


def to_json(server_name: str, findings: list[Finding]) -> str:
    payload = {
        "server": server_name,
        "risk_score": risk_score(findings),
        "finding_count": len(findings),
        "findings": [asdict(f) for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, default=str)


def to_sarif(server_name: str, findings: list[Finding]) -> str:
    """Format findings as standard SARIF v2.1.0 JSON for GitHub Security and CI tools."""
    findings = sort_findings(findings)

    sarif_level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    results = []
    rules = {}
    for f in findings:
        rule_id = f"{f.check}/{f.title.lower().replace(' ', '-')}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": sarif_level_map.get(f.severity, "warning")},
            }

        results.append({
            "ruleId": rule_id,
            "level": sarif_level_map.get(f.severity, "warning"),
            "message": {"text": f.detail},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": f.tool,
                            "kind": "function" if f.tool != "*" else "module",
                        }
                    ]
                }
            ],
            "properties": {
                "severity": f.severity.value,
                "tool": f.tool,
                "check": f.check,
            },
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpaudit",
                        "informationUri": "https://github.com/Pyhroff/mcpaudit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def render_text(server_name: str, findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    lines = [f"mcpaudit scorecard -- {server_name}", "=" * 60]
    if not findings:
        lines.append("No findings. (A clean scan is not a guarantee -- see README limitations.)")
        return "\n".join(lines)

    by_sev: dict[Severity, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    summary = ", ".join(f"{by_sev[s]} {s.value}" for s in Severity if s in by_sev)
    lines.append(f"risk score: {risk_score(findings)}  ({summary})")
    lines.append("")

    for f in findings:
        lines.append(f"[{f.severity.value.upper():8s}] {f.check:18s} tool={f.tool}")
        lines.append(f"          {f.title}")
        lines.append(f"          {f.detail}")
        lines.append("")

    return "\n".join(lines)
