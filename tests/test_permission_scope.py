"""Static, no-network tests for the permission-scope check."""

from mcpaudit.checks.permission_scope import check_scope
from mcpaudit.findings import Severity
from mcpaudit.manifest import ServerManifest, ToolManifest


def _manifest(*tools: ToolManifest) -> ServerManifest:
    return ServerManifest(server_name="test-server", tools=list(tools))


def test_scoped_file_tool_raises_nothing():
    m = _manifest(ToolManifest(
        name="read_config",
        description="Reads a config file from a fixed known location.",
        input_schema={"properties": {}},
    ))
    findings = check_scope(m)
    assert findings == []


def test_flags_unscoped_arbitrary_exec():
    m = _manifest(ToolManifest(
        name="run_command",
        description="Executes a shell command.",
        input_schema={"properties": {"command": {"type": "string"}}},
    ))
    findings = check_scope(m)
    assert any(f.severity == Severity.HIGH and "code/command execution" in f.title for f in findings)


def test_flags_unscoped_filesystem_path():
    m = _manifest(ToolManifest(
        name="read_file",
        description="Reads the contents of a file.",
        input_schema={"properties": {"path": {"type": "string"}}},
    ))
    findings = check_scope(m)
    assert any("filesystem access" in f.title for f in findings)


def test_does_not_flag_constrained_path_param():
    m = _manifest(ToolManifest(
        name="read_file",
        description="Reads a file from the sandboxed workspace.",
        input_schema={"properties": {"path": {"type": "string", "pattern": r"^workspace/[\w./-]+$"}}},
    ))
    findings = check_scope(m)
    assert findings == []


def test_flags_description_admitting_unscoped_access():
    m = _manifest(ToolManifest(
        name="fetch",
        description="Fetches any url the model requests.",
        input_schema={"properties": {"url": {"type": "string"}}},
    ))
    findings = check_scope(m)
    assert any("unscoped access" in f.title.lower() for f in findings)


def test_flags_missing_schema_on_capability_tool():
    m = _manifest(ToolManifest(name="delete_file", description="Deletes a file.", input_schema={}))
    findings = check_scope(m)
    assert any(f.title == "No input schema for a capability-bearing tool" for f in findings)


def test_non_capability_tool_ignored():
    m = _manifest(ToolManifest(
        name="add_numbers", description="Adds two numbers together.",
        input_schema={"properties": {"a": {"type": "number"}, "b": {"type": "number"}}},
    ))
    findings = check_scope(m)
    assert findings == []
