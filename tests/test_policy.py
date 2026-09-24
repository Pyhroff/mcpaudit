"""Tests for the finding-suppression policy -- pure data transformation,
no network, no fixtures needed."""

from __future__ import annotations

import json

from mcpaudit.findings import Finding, Severity
from mcpaudit.policy import Policy, PolicyRule


def _finding(tool="read_file", check="permission_scope", title="Unscoped filesystem access") -> Finding:
    return Finding(check=check, tool=tool, severity=Severity.HIGH, title=title, detail="detail text")


def test_empty_policy_suppresses_nothing():
    policy = Policy(rules=[])
    kept, suppressed = policy.apply([_finding(), _finding(tool="run_command")])
    assert len(kept) == 2
    assert suppressed == []


def test_rule_matches_exact_tool_and_check():
    policy = Policy(rules=[PolicyRule(tool="read_file", check="permission_scope")])
    f1 = _finding(tool="read_file", check="permission_scope")
    f2 = _finding(tool="run_command", check="permission_scope")
    kept, suppressed = policy.apply([f1, f2])
    assert kept == [f2]
    assert suppressed == [f1]


def test_wildcard_tool_matches_any_tool():
    policy = Policy(rules=[PolicyRule(tool="*", check="permission_scope")])
    f1 = _finding(tool="read_file")
    f2 = _finding(tool="run_command")
    f3 = _finding(tool="search", check="description_scan", title="x")
    kept, suppressed = policy.apply([f1, f2, f3])
    assert kept == [f3]
    assert set(id(s) for s in suppressed) == {id(f1), id(f2)}


def test_title_narrows_the_match():
    policy = Policy(rules=[PolicyRule(tool="read_file", check="permission_scope", title="Unscoped filesystem access")])
    matching = _finding(tool="read_file", check="permission_scope", title="Unscoped filesystem access")
    different_title = _finding(tool="read_file", check="permission_scope", title="Some other finding")
    kept, suppressed = policy.apply([matching, different_title])
    assert kept == [different_title]
    assert suppressed == [matching]


def test_check_only_rule_ignores_tool_and_title():
    policy = Policy(rules=[PolicyRule(check="description_scan")])
    a = _finding(tool="x", check="description_scan", title="a")
    b = _finding(tool="y", check="permission_scope", title="b")
    kept, suppressed = policy.apply([a, b])
    assert kept == [b]
    assert suppressed == [a]


def test_multiple_rules_are_ORed():
    policy = Policy(rules=[
        PolicyRule(tool="read_file", check="permission_scope"),
        PolicyRule(tool="run_command", check="permission_scope"),
    ])
    f1 = _finding(tool="read_file")
    f2 = _finding(tool="run_command")
    f3 = _finding(tool="search", check="description_scan", title="z")
    kept, suppressed = policy.apply([f1, f2, f3])
    assert kept == [f3]
    assert len(suppressed) == 2


def test_from_dict_and_load(tmp_path):
    data = {
        "ignore": [
            {"tool": "read_file", "check": "permission_scope", "reason": "scoped at runtime, not in schema"},
            {"tool": "*", "check": "description_scan", "title": "Unusually long tool description", "reason": "known verbose vendor"},
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(data), encoding="utf-8")

    policy = Policy.load(policy_file)
    assert len(policy.rules) == 2
    assert policy.rules[0].reason == "scoped at runtime, not in schema"
    assert policy.rules[1].tool == "*"

    kept, suppressed = policy.apply([
        _finding(tool="read_file", check="permission_scope"),
        _finding(tool="anything", check="description_scan", title="Unusually long tool description"),
        _finding(tool="anything", check="description_scan", title="Empty tool description"),
    ])
    assert len(kept) == 1
    assert kept[0].title == "Empty tool description"
    assert len(suppressed) == 2
