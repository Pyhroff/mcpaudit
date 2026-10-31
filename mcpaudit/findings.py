"""Shared Finding type every check (static or dynamic) reports through."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    check: str          # which check raised this, e.g. "description_scan"
    tool: str            # tool name, or "*" for server-level findings
    severity: Severity
    title: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        """Convert finding to dictionary representation.

        Bolt performance optimization: Avoids dataclasses.asdict() overhead
        (deep copying and recursive introspection) during report serialization.
        """
        return {
            "check": self.check,
            "tool": self.tool,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }
