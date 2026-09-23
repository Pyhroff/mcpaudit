"""Chat-model adapter interface, shared by the (optional) dynamic checks.

Deliberately the same shape as promptstrike's BaseAdapter/ChatMessage so the
confused-deputy check (mcpaudit/checks/confused_deputy.py) can reuse the same
tool-use-loop technique that PromptStrike's AgentAdapter uses against a
mocked `search` tool -- except here it's pointed at a *real* MCP server.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class AdapterStats:
    calls_made: int = 0
    tokens_used: int = 0


class BaseAdapter(ABC):
    def __init__(self) -> None:
        self.stats = AdapterStats()

    @abstractmethod
    async def chat(self, messages: list[ChatMessage], model: str | None = None) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...
