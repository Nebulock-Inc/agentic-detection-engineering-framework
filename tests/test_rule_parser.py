"""Tests for SQL rule parser."""

from adef.core.rule_parser import extract_sql_fields


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
