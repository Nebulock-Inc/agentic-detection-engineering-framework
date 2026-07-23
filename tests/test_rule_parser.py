"""Tests for SQL rule parser."""

import textwrap

from adef.core.rule_parser import (
    extract_sql_fields,
    extract_spl_fields,
    extract_cql_fields,
    extract_kql_fields,
    extract_sigma_fields,
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


def test_extract_spl_fields_space_separated_lists():
    """SPL `by`/`fields`/`table` lists use spaces, not just commas (D-0002 regression)."""
    query = (
        'index=thrunt sourcetype="cisco:asa" action=denied '
        "| stats count by src_ip dest_ip dest_port | where count > 20"
    )

    fields = extract_spl_fields(query)

    assert {"src_ip", "dest_ip", "dest_port"} <= fields
    assert "src_ip dest_ip dest_port" not in fields

    fields = extract_spl_fields("index=web | fields src_ip uri_path | table src_ip uri_path")
    assert {"src_ip", "uri_path"} <= fields
    assert all(" " not in f for f in fields)


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


def test_extract_spl_fields_excludes_aggregation_outputs():
    """`count` / `as total` are created by stats, not read from events —
    they must not surface as schema-check findings (HANDOFF follow-up)."""
    fields = extract_spl_fields(
        "index=thrunt action=denied | stats count by src_ip dest_port | where count > 20"
    )
    assert {"src_ip", "dest_port"} <= fields
    assert "count" not in fields

    fields = extract_spl_fields(
        "index=web | stats sum(bytes) as total, dc(uri_path) as paths by src_ip "
        "| where total > 5000 | where paths > 10"
    )
    assert "src_ip" in fields
    assert "total" not in fields and "paths" not in fields

    # a genuine event field named count (field comparison, no stats) survives
    assert "count" in extract_spl_fields("index=x count=5")


def test_extract_sigma_fields():
    """Sigma fields are the detection-block map keys, stripped of |modifiers.
    `condition` is boolean logic over identifier names, not a field source."""
    query = textwrap.dedent(
        """\
        title: Suspicious mshta child
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image|endswith: '\\mshta.exe'
                ParentImage|contains:
                    - '\\winword.exe'
                    - '\\excel.exe'
            filter:
                CommandLine|contains: 'update.mshta'
            condition: selection and not filter
        """
    )
    fields = extract_sigma_fields(query)
    assert fields == {"Image", "ParentImage", "CommandLine"}
    assert "selection" not in fields and "condition" not in fields


def test_extract_sigma_fields_list_of_maps_and_keyword_list():
    """A search-identifier can be a list of maps (OR-ed); a bare keyword list
    has no fields. Both must be handled without spurious field names."""
    query = textwrap.dedent(
        """\
        detection:
            selection:
                - EventID: 4688
                  NewProcessName|endswith: '\\rundll32.exe'
                - EventID: 1
                  Image|endswith: '\\rundll32.exe'
            keywords:
                - 'password'
                - 'secret'
            condition: selection or keywords
        """
    )
    fields = extract_sigma_fields(query)
    assert fields == {"EventID", "NewProcessName", "Image"}


def test_extract_sigma_fields_malformed_returns_empty():
    """Unparseable YAML or a rule with no detection map → empty set, no crash."""
    assert extract_sigma_fields("this: is: not: valid: yaml:") == set()
    assert extract_sigma_fields("title: no detection block here") == set()
    assert extract_sigma_fields("") == set()
