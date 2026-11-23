"""CLI argument handling that does not need a live server."""
import re

from typer.testing import CliRunner

from mcpaudit.cli import app

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Rich colours output when it detects CI (GITHUB_ACTIONS / FORCE_COLOR); compare on plain text."""
    return _ANSI.sub("", text)


def test_invalid_fail_on_is_rejected_before_connecting():
    # The server command does not exist: if --fail-on were checked only after the scan, this would fail on
    # the connection instead (exit 2 with "Could not connect"), or crash with a ValueError traceback.
    result = runner.invoke(app, ["scan", "--fail-on", "hgih", "--", "definitely-not-a-real-command-xyz"])
    out = _plain(result.output)
    assert result.exit_code == 2
    assert "Could not connect" not in out
    assert "--fail-on" in out and "hgih" in out


def test_version_flag():
    from mcpaudit import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in _plain(result.output)
