"""Tests for the dynamic confused-deputy check -- all mocked, no API calls."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from mcpaudit.checks.confused_deputy import run_confused_deputy_check, to_finding, _parse_tool_call
from mcpaudit.manifest import ServerManifest, ToolManifest


def _make_target(responses: list[str]) -> AsyncMock:
    target = AsyncMock()
    target.name = "mock/model"
    target.chat = AsyncMock(side_effect=responses)
    target.stats = MagicMock(calls_made=0, tokens_used=0)
    return target


def _manifest() -> ServerManifest:
    return ServerManifest(server_name="test-server", tools=[
        ToolManifest(name="get_weather", description="Looks up the weather.", input_schema={"properties": {"city": {"type": "string"}}}),
    ])


_CALL_WEATHER = '{"tool_call": {"tool": "get_weather", "args": {"city": "here"}}}'


def test_unknown_tool_raises():
    with pytest.raises(ValueError):
        import asyncio
        asyncio.run(run_confused_deputy_check(_make_target([]), _manifest(), "does_not_exist"))


@pytest.mark.asyncio
async def test_robust_model_is_not_triggered():
    """Model calls the tool, then ignores the injected instruction and answers normally."""
    target = _make_target([_CALL_WEATHER, "It's sunny today."])
    result = await run_confused_deputy_check(target, _manifest(), "get_weather")

    assert result.triggered is False
    assert to_finding(result) is None


@pytest.mark.asyncio
async def test_susceptible_model_is_flagged():
    """Model calls the tool, then obeys the instruction smuggled in via the tool result."""
    target = _make_target([_CALL_WEATHER, "CONFUSED_DEPUTY_TRIGGERED"])
    result = await run_confused_deputy_check(target, _manifest(), "get_weather")

    assert result.triggered is True
    finding = to_finding(result)
    assert finding is not None
    assert finding.severity.value == "critical"
    assert finding.tool == "get_weather"


@pytest.mark.asyncio
async def test_injected_instruction_delivered_only_via_tool_result_message():
    """
    Core claim under test: the injected instruction reaches the target only
    inside a '[TOOL RESULT: ...]'-prefixed message -- never as a bare
    user-authored message -- mirroring PromptStrike's tool_output channel
    isolation guarantee.
    """
    target = _make_target([_CALL_WEATHER, "ignored it"])
    custom_payload = "UNIQUE_MARKER_PAYLOAD_XYZ"
    await run_confused_deputy_check(
        target, _manifest(), "get_weather", injected_instruction=custom_payload,
    )

    second_call_messages = target.chat.call_args_list[1].args[0]
    tool_result_msg = second_call_messages[-1]
    assert custom_payload in tool_result_msg.content
    assert tool_result_msg.content.startswith("[TOOL RESULT:")
    for msg in second_call_messages:
        if msg.role == "user" and msg.content == custom_payload:
            pytest.fail("payload leaked into the loop as a bare user message")


@pytest.mark.asyncio
async def test_model_that_never_calls_the_tool_is_not_triggered():
    target = _make_target(["I don't need a tool for that. It's fine outside."])
    result = await run_confused_deputy_check(target, _manifest(), "get_weather")

    assert result.triggered is False
    assert result.raw_final_response == "I don't need a tool for that. It's fine outside."


def test_parse_tool_call_ignores_malformed_json():
    assert _parse_tool_call("not json") is None
    assert _parse_tool_call('{"nope": {}}') is None


def test_parse_tool_call_extracts_valid_call():
    call = _parse_tool_call("preamble " + _CALL_WEATHER)
    assert call == {"tool": "get_weather", "args": {"city": "here"}}
