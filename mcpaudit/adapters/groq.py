"""Thin Groq adapter, used only by the dynamic (--dynamic) confused-deputy
check. Optional dependency -- `pip install mcpaudit[dynamic]`."""

from __future__ import annotations

from .base import BaseAdapter, ChatMessage


class GroqAdapter(BaseAdapter):
    def __init__(self, api_key: str, model: str = "openai/gpt-oss-120b") -> None:
        super().__init__()
        try:
            from groq import AsyncGroq
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "GroqAdapter requires the 'groq' package: pip install mcpaudit[dynamic]"
            ) from exc
        self._client = AsyncGroq(api_key=api_key)
        self._model = model

    @property
    def name(self) -> str:
        return f"groq/{self._model}"

    async def chat(self, messages: list[ChatMessage], model: str | None = None) -> str:
        resp = await self._client.chat.completions.create(
            model=model or self._model,
            messages=[{"role": m.role, "content": m.content} for m in messages],
        )
        self.stats.calls_made += 1
        usage = getattr(resp, "usage", None)
        if usage is not None:
            self.stats.tokens_used += getattr(usage, "total_tokens", 0) or 0
        return resp.choices[0].message.content or ""
