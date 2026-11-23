"""CLI argument handling that does not need a live server."""
from typer.testing import CliRunner

from mcpaudit.cli import app

runner = CliRunner()


def test_invalid_fail_on_is_rejected_before_connecting():
    # The server command does not exist: if --fail-on were checked only after the scan, this would fail on
    # the connection instead (exit 2 with "Could not connect"), or crash with a ValueError traceback.
    result = runner.invoke(app, ["scan", "--fail-on", "hgih", "--", "definitely-not-a-real-command-xyz"])
    assert result.exit_code == 2
    assert "Could not connect" not in result.output
    assert "--fail-on" in result.output


def test_version_flag():
    from mcpaudit import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
