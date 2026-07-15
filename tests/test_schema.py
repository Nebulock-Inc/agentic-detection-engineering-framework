"""Tests for schema data model and YAML I/O."""

import tempfile
from pathlib import Path
from adef.core.schema import Schema, SchemaField, write_schema, read_schema, merge_fields


def test_schema_field_creation():
    """Test SchemaField dataclass can be created with all fields."""
    field = SchemaField(
        name="parent_image",
        in_rules=True,
        in_data=True,
        type="string",
        population=0.98,
        sample_values=["cmd.exe", "mshta.exe", None],
        description="Executable path of the parent process",
        description_source="generated"
    )
    assert field.name == "parent_image"
    assert field.in_rules is True
    assert field.in_data is True
    assert field.type == "string"
    assert field.population == 0.98
    assert len(field.sample_values) == 3


def test_schema_creation():
    """Test Schema dataclass can be created with all fields."""
    fields = [
        SchemaField(
            name="process_id",
            in_rules=False,
            in_data=True,
            type="integer",
            population=1.0,
            sample_values=[1234, 5678],
            description="Process identifier",
            description_source="generated"
        )
    ]
    schema = Schema(
        source="edr_process",
        query_language="sql",
        last_rule_scan="2026-07-15T10:00:00-04:00",
        last_data_sample="2026-07-15T10:15:00-04:00",
        sample_window="30d",
        sample_size=10000,
        fields=fields
    )
    assert schema.source == "edr_process"
    assert schema.query_language == "sql"
    assert len(schema.fields) == 1


def test_write_schema():
    """Test schema can be written to YAML file."""
    fields = [
        SchemaField(
            name="command_line",
            in_rules=True,
            in_data=True,
            type="string",
            population=0.85,
            sample_values=["powershell.exe", None],
            description="Command line arguments",
            description_source="generated"
        )
    ]
    schema = Schema(
        source="test_source",
        query_language="sql",
        last_rule_scan="2026-07-15T10:00:00-04:00",
        last_data_sample=None,
        sample_window=None,
        sample_size=None,
        fields=fields
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "test_schema.yml"
        write_schema(schema, path)

        assert path.exists()
        content = path.read_text()
        assert "source: test_source" in content
        assert "command_line" in content


def test_read_schema():
    """Test schema can be read from YAML file."""
    yaml_content = """
source: test_source
query_language: sql
last_rule_scan: '2026-07-15T10:00:00-04:00'
last_data_sample: null
sample_window: null
sample_size: null
fields:
  - name: parent_image
    in_rules: true
    in_data: true
    type: string
    population: 0.98
    sample_values: ['cmd.exe', null]
    description: Parent process executable
    description_source: generated
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "test_schema.yml"
        path.write_text(yaml_content)

        schema = read_schema(path)

        assert schema.source == "test_source"
        assert schema.query_language == "sql"
        assert len(schema.fields) == 1
        assert schema.fields[0].name == "parent_image"
        assert schema.fields[0].population == 0.98


def test_merge_fields_overlap():
    """Test merging rule fields and data fields with overlap."""
    rule_fields = {"parent_image", "command_line", "parent_pid"}
    data_fields = {
        "parent_image": {"type": "string", "population": 0.98, "sample_values": ["cmd.exe"]},
        "command_line": {"type": "string", "population": 0.85, "sample_values": ["whoami"]},
        "process_id": {"type": "integer", "population": 1.0, "sample_values": [1234]},
    }

    merged = merge_fields(rule_fields, data_fields)

    # Should have 4 fields: 3 from rules, 1 data-only
    assert len(merged) == 4

    # Find parent_image (in both)
    parent_image = next(f for f in merged if f.name == "parent_image")
    assert parent_image.in_rules is True
    assert parent_image.in_data is True
    assert parent_image.type == "string"

    # Find parent_pid (rules only)
    parent_pid = next(f for f in merged if f.name == "parent_pid")
    assert parent_pid.in_rules is True
    assert parent_pid.in_data is False
    assert parent_pid.type == "null"

    # Find process_id (data only)
    process_id = next(f for f in merged if f.name == "process_id")
    assert process_id.in_rules is False
    assert process_id.in_data is True
    assert process_id.type == "integer"
