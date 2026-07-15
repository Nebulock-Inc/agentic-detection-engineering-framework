"""Tests for adef schema CLI commands."""

import json
import tempfile
from pathlib import Path

from click.testing import CliRunner
from adef.commands.schema import schema
from adef.core.schema import read_schema


def test_schema_init_help():
    """Test schema init --help shows usage."""
    runner = CliRunner()
    result = runner.invoke(schema, ['init', '--help'])
    assert result.exit_code == 0
    assert "Initialize a data schema" in result.output


def test_schema_init_creates_file(monkeypatch):
    """Test schema init creates schema YAML file."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as workspace:
        workspace_path = Path(workspace)
        schema_dir = workspace_path / "schema"
        schema_dir.mkdir()

        # Mock environment
        monkeypatch.setenv("ADEF_WORKSPACE", str(workspace_path))

        # Mock stdin for interactive prompts
        # language=sql, no rules, no data
        input_data = "sql\nn\nn\n"

        result = runner.invoke(schema, ['init', 'test_source'], input=input_data)

        assert result.exit_code == 0
        schema_file = schema_dir / "test_source.yml"
        assert schema_file.exists()


def test_schema_show_displays_schema(monkeypatch):
    """Test schema show displays schema contents."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as workspace:
        workspace_path = Path(workspace)
        schema_dir = workspace_path / "schema"
        schema_dir.mkdir()

        monkeypatch.setenv("ADEF_WORKSPACE", str(workspace_path))

        # Create a schema first
        input_data = "sql\nn\nn\n"
        runner.invoke(schema, ['init', 'test_source'], input=input_data)

        # Show the schema
        result = runner.invoke(schema, ['show', 'test_source'])

        assert result.exit_code == 0
        assert "test_source" in result.output
        assert "Query language: sql" in result.output


def test_schema_show_missing_file(monkeypatch):
    """Test schema show errors when file doesn't exist."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as workspace:
        workspace_path = Path(workspace)
        schema_dir = workspace_path / "schema"
        schema_dir.mkdir()

        monkeypatch.setenv("ADEF_WORKSPACE", str(workspace_path))

        result = runner.invoke(schema, ['show', 'nonexistent'])

        assert result.exit_code == 1
        assert "Error" in result.output
        assert "not found" in result.output


def test_schema_update_stub():
    """Test schema update is callable (stub for v1)."""
    runner = CliRunner()
    result = runner.invoke(schema, ['update', 'test_source'])
    assert result.exit_code == 0
    assert "Updating schema" in result.output


def test_schema_rescan_stub():
    """Test schema rescan is callable (stub for v1)."""
    runner = CliRunner()
    result = runner.invoke(schema, ['rescan', 'test_source'])
    assert result.exit_code == 0
    assert "Rescanning rules" in result.output


def test_schema_init_with_data_sample(monkeypatch):
    """Test schema init with JSON data sample creates fields."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as workspace:
        workspace_path = Path(workspace)
        schema_dir = workspace_path / "schema"
        schema_dir.mkdir()

        monkeypatch.setenv("ADEF_WORKSPACE", str(workspace_path))

        # Sample JSON data
        sample_data = json.dumps([
            {"user_id": "123", "action": "login", "timestamp": "2023-01-01T00:00:00Z"},
            {"user_id": "456", "action": "logout", "timestamp": "2023-01-01T01:00:00Z"}
        ])

        # Interactive: sql, no rules, yes to data, paste data
        input_data = f"sql\nn\ny\n{sample_data}\n"

        result = runner.invoke(schema, ['init', 'test_source'], input=input_data)

        assert result.exit_code == 0
        schema_file = schema_dir / "test_source.yml"
        assert schema_file.exists()

        # Verify fields were created
        schema_obj = read_schema(schema_file)
        assert len(schema_obj.fields) == 3
        field_names = {f.name for f in schema_obj.fields}
        assert field_names == {"user_id", "action", "timestamp"}

        # Verify all fields marked as in_data
        assert all(f.in_data for f in schema_obj.fields)
        assert not any(f.in_rules for f in schema_obj.fields)
