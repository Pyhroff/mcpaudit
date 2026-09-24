"""Finding-suppression policy -- the thing that makes --fail-on usable in a
real CI pipeline. Without it, any accepted/reviewed finding (a real one,
just judged not worth blocking on) fails every future scan forever, which
is how CI gates get disabled out of frustration. A policy file records
"I looked at this, it's fine" per finding, so re-scans stay quiet on it
while still catching anything new.

Deliberately NOT a blanket severity suppression -- a rule targets a
specific (tool, check[, title]) so a new, different finding on the same
tool still surfaces.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from mcpaudit.findings import Finding


@dataclass
class PolicyRule:
    tool: str = "*"          # "*" matches any tool
    check: str | None = None  # e.g. "permission_scope"; None matches any check
    title: str | None = None  # exact Finding.title; None matches any title
    reason: str = ""          # human-readable justification, not enforced, just recorded

    def matches(self, finding: Finding) -> bool:
        if self.tool != "*" and self.tool != finding.tool:
            return False
        if self.check is not None and self.check != finding.check:
            return False
        if self.title is not None and self.title != finding.title:
            return False
        return True


@dataclass
class Policy:
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(rules=[PolicyRule(**r) for r in d.get("ignore", [])])

    @classmethod
    def load(cls, path: Path) -> "Policy":
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Returns (kept, suppressed). A finding is suppressed if ANY rule matches it."""
        kept: list[Finding] = []
        suppressed: list[Finding] = []
        for f in findings:
            if any(rule.matches(f) for rule in self.rules):
                suppressed.append(f)
            else:
                kept.append(f)
        return kept, suppressed
