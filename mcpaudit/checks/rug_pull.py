"""Static check: compare a live server's manifest against a previously
saved, trusted baseline. Flags any tool that changed shape since a human
last approved it -- the "rug pull" scenario: a server behaves innocuously
at install/review time, then changes its tool descriptions or schemas
later, after the user has already granted it standing trust.
"""

from __future__ import annotations

from mcpaudit.findings import Finding, Severity
from mcpaudit.manifest import ServerManifest, ToolManifest


def diff_manifests(baseline: ServerManifest, current: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []

    baseline_by_name = {t.name: t for t in baseline.tools}
    current_by_name = {t.name: t for t in current.tools}

    for name, base_tool in baseline_by_name.items():
        if name not in current_by_name:
            findings.append(Finding(
                check="rug_pull", tool=name, severity=Severity.MEDIUM,
                title="Tool removed since baseline",
                detail=f"Tool '{name}' was present in the trusted baseline but is no longer "
                       f"offered by the server. Not dangerous on its own, but confirm this was "
                       f"an intentional change.",
            ))
            continue

        cur_tool = current_by_name[name]
        _diff_one_tool(base_tool, cur_tool, findings)

    for name, cur_tool in current_by_name.items():
        if name not in baseline_by_name:
            findings.append(Finding(
                check="rug_pull", tool=name, severity=Severity.HIGH,
                title="New tool added since baseline",
                detail=f"Tool '{name}' was not present when the baseline was captured. A newly "
                       f"added tool has not been through prior review -- run the full static "
                       f"check suite against it before trusting it.",
            ))

    return findings


def _diff_one_tool(base_tool: ToolManifest, cur_tool: ToolManifest, findings: list[Finding]) -> None:
    if base_tool.description != cur_tool.description:
        findings.append(Finding(
            check="rug_pull", tool=cur_tool.name, severity=Severity.CRITICAL,
            title="Tool description changed since baseline",
            detail=(
                f"Tool '{cur_tool.name}' description changed after it was approved. "
                f"This is exactly the rug-pull pattern: a tool that read as safe at review "
                f"time can be edited afterward with no further approval step in most clients.\n"
                f"  baseline: {base_tool.description[:300]!r}\n"
                f"  current:  {cur_tool.description[:300]!r}"
            ),
        ))

    if base_tool.input_schema != cur_tool.input_schema:
        findings.append(Finding(
            check="rug_pull", tool=cur_tool.name, severity=Severity.HIGH,
            title="Tool input schema changed since baseline",
            detail=(
                f"Tool '{cur_tool.name}' input schema changed since the baseline was captured "
                f"(e.g. a new parameter, or a constraint like an enum/pattern was loosened or "
                f"removed).\n"
                f"  baseline: {base_tool.input_schema}\n"
                f"  current:  {cur_tool.input_schema}"
            ),
        ))
