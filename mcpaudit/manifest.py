"""Data model for what a scan actually looks at: an MCP server's declared
tool surface (its manifest), and nothing more. Everything under
mcpaudit/checks/ operates on a ServerManifest -- static checks don't need a
live connection at all, only the JSON a server already returns from
`tools/list`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolManifest:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ToolManifest":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            input_schema=d.get("input_schema") or d.get("inputSchema") or {},
        )


@dataclass
class ServerManifest:
    server_name: str
    server_version: str = ""
    tools: list[ToolManifest] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "server_version": self.server_version,
            "tools": [t.to_dict() for t in self.tools],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServerManifest":
        return cls(
            server_name=d["server_name"],
            server_version=d.get("server_version", ""),
            tools=[ToolManifest.from_dict(t) for t in d.get("tools", [])],
        )

    def tool(self, name: str) -> ToolManifest | None:
        return next((t for t in self.tools if t.name == name), None)
