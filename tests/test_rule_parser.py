"""Tests for SQL rule parser."""

from adef.core.rule_parser import (
    extract_sql_fields,
    extract_spl_fields,
    extract_cql_fields,
    extract_kql_fields,
)


def test_extract_sql_fields_simple_select():
    """Test SQL parser extracts fields from simple SELECT."""
    query = """
    SELECT parent_image, command_line, process_id
    FROM processes
    WHERE command_line LIKE '%powershell%'
    """

    fields = extract_sql_fields(query)

    assert fields == {"parent_image", "command_line", "process_id"}


def test_extract_sql_fields_subquery():
    """Test SQL parser handles subqueries."""
    query = """
    SELECT parent_image, count
    FROM (
        SELECT parent_image, COUNT(*) as count
        FROM processes
        WHERE command_line IS NOT NULL
        GROUP BY parent_image
    ) subq
    WHERE count > 10
    """

    fields = extract_sql_fields(query)

    # Should extract all column references
    assert "parent_image" in fields
    assert "command_line" in fields
    # 'count' is an alias, may or may not be extracted depending on AST walk


def test_extract_sql_fields_invalid_query():
    """Test SQL parser returns empty set on parse failure."""
    query = "SELECT FROM WHERE invalid syntax"

    fields = extract_sql_fields(query)

    assert fields == set()


def test_extract_spl_fields():
    """Test SPL parser extracts fields."""
    query = """
    index=edr earliest=-30d
    | where process_name="cmd.exe"
    | stats count by parent_process, command_line
    | table parent_process, command_line, count
    """

    fields = extract_spl_fields(query)

    assert "process_name" in fields
    assert "parent_process" in fields
    assert "command_line" in fields


def test_extract_cql_fields():
    """Test CQL parser extracts fields."""
    query = """
    #event_simpleName=ProcessRollup2
    ComputerName="HOSTNAME"
    FileName="cmd.exe"
    CommandLine contains "powershell"
    """

    fields = extract_cql_fields(query)

    assert "#event_simpleName" in fields
    assert "ComputerName" in fields
    assert "FileName" in fields
    assert "CommandLine" in fields


def test_extract_kql_fields():
    """Test KQL parser extracts fields."""
    query = """
    DeviceProcessEvents
    | where FileName == "cmd.exe"
    | where ProcessCommandLine contains "powershell"
    | project FileName, ProcessCommandLine, InitiatingProcessFileName
    | summarize count() by ComputerName
    """

    fields = extract_kql_fields(query)

    assert "FileName" in fields
    assert "ProcessCommandLine" in fields
    assert "InitiatingProcessFileName" in fields
    assert "ComputerName" in fields
