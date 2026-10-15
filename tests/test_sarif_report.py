"""Tests for SARIF export in report.py."""

import json

from mcpaudit.findings import Finding, Severity
from mcpaudit.report import to_sarif


def test_sarif_output_structure_and_levels():
    findings = [
        Finding(
            check="description_scan",
            tool="exec_tool",
            severity=Severity.HIGH,
            title="Model-directed instruction in description",
            detail="Contains imperative prompt injection directives",
        ),
        Finding(
            check="permission_scope",
            tool="exec_tool",
            severity=Severity.CRITICAL,
            title="Unscoped arbitrary code execution",
            detail="Accepts arbitrary bash strings without constraints",
        ),
        Finding(
            check="permission_scope",
            tool="list_dir",
            severity=Severity.LOW,
            title="Empty tool description",
            detail="Missing documentation",
        ),
    ]

    sarif_str = to_sarif("my-server", findings)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpaudit"

    rules = run["tool"]["driver"]["rules"]
    assert len(rules) >= 2

    results = run["results"]
    assert len(results) == 3

    # CRITICAL -> error, HIGH -> error, LOW -> note
    levels = [r["level"] for r in results]
    assert "error" in levels
    assert "note" in levels
