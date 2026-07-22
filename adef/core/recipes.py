"""SIEM-specific recipes for extracting data source field inventories.

This module provides templates and rendering for platform-specific commands
that extract field schemas from various SIEMs. Recipes are documentation,
not connectors — they tell users what command to run, not how to execute it.
"""

from dataclasses import dataclass


@dataclass
class SIEMRecipe:
    """Template for extracting field inventory from a SIEM platform."""

    platform: str  # Display name (e.g., "Splunk", "Microsoft Sentinel")
    query_language: str  # Query language used (spl, kql, sql, etc.)
    command: str  # Exact command to run in the SIEM
    export_format: str  # Output format (csv, json, text)
    export_instructions: str  # How to export/save the results
    reshaping_guide: str  # How to convert output to ADEF declaration format
    version_notes: str | None = None  # Platform version caveats


# Recipe templates for supported platforms
RECIPES = {
    "splunk": SIEMRecipe(
        platform="Splunk",
        query_language="spl",
        command="""index=<your_index> sourcetype=<your_sourcetype> earliest=-7d latest=now
| fieldsummary maxvals=50
| fields field count distinct_count numeric_count values""",
        export_format="csv",
        export_instructions="""1. Run the search in Splunk Web (Search & Reporting app) — one search
   per sourcetype (one declaration per event shape; that's what `scope:` is for)
2. Wait for search to complete
3. Click "Export" → "CSV"
4. Browser downloads the results (typically as results.csv)
5. Rename to fields.csv for the reshaping step

Keep the count/distinct_count/numeric_count/values columns — they are what
lets `adef schema reshape` harvest enum values, infer types, and detect
mixed-shape exports.

Note: Don't use `| outputcsv fields.csv` in the query — that writes server-side
to /opt/splunk/var/run/splunk/csv/ (inaccessible in Splunk Cloud). The UI
Export button downloads directly to your browser.""",
        reshaping_guide="""adef schema reshape fields.csv --platform splunk

# Applies the five reshape rules (drops _*/date_*/punct internals, folds
# case-duplicates into aliases, harvests capped enum values, infers int/float
# types, refuses mixed-sourcetype exports) and prints a transformation report.
# scope: (index/sourcetype) is filled in from the export automatically.
# Set `platform:` in the output YAML before ingesting — never inferred.""",
        version_notes="Works on Splunk 8.x and 9.x. For large indexes, limit time range to avoid search limits.",
    ),
    "sentinel": SIEMRecipe(
        platform="Microsoft Sentinel",
        query_language="kql",
        command="""// Run for each table you want to declare
SecurityEvent
| getschema
| project ColumnName, DataType""",
        export_format="csv",
        export_instructions="""1. Open Azure Portal → Microsoft Sentinel → Logs
2. Run the query for each table (SecurityEvent, Syslog, etc.)
3. Click "Export" → "Export to CSV - all columns"
4. Repeat for each table, save as <table>-schema.csv""",
        reshaping_guide="""# One reshape per exported table:
adef schema reshape SecurityEvent-schema.csv --platform sentinel --source securityevent

# KQL DataType maps to ADEF field types automatically. Set `platform:` in the
# output YAML before ingesting — never inferred. To declare several tables in
# one file, reshape each and merge the `sources:` lists.""",
        version_notes="Requires Log Analytics Contributor role or higher.",
    ),
    "elastic": SIEMRecipe(
        platform="Elastic / Kibana",
        query_language="eql",
        command="""GET <index-pattern>/_mapping""",
        export_format="json",
        export_instructions="""1. Open Kibana → Dev Tools → Console
2. Run: GET <index-pattern>/_mapping (e.g., GET logs-*/_mapping)
3. Copy the JSON response
4. Save to mapping.json""",
        reshaping_guide="""adef schema reshape mapping.json --platform elastic --source <index_name>

# Walks the _mapping properties (nested objects flattened to dotted names)
# and maps Elasticsearch types to ADEF field types. Set `platform:` in the
# output YAML before ingesting; `query_language` is left unset because ADEF's
# schema check does not parse EQL/ES|QL yet.""",
        version_notes="Works with Elasticsearch 7.x and 8.x. ECS fields come pre-documented.",
    ),
    "chronicle": SIEMRecipe(
        platform="Google Chronicle",
        query_language="udm",
        command="""# Chronicle doesn't expose a direct schema query
# Use the UDM Search reference documentation instead""",
        export_format="manual",
        export_instructions="""1. Open Chronicle → UDM Search reference docs
2. Identify the log_type(s) you query (e.g., WINDOWS_SYSMON, GCP_CLOUDAUDIT)
3. List fields from the UDM schema for each log type
4. Export as a text list of field names""",
        reshaping_guide="""# Save the UDM field names for your log_type as a plain text file,
# one field per line (e.g. principal.process.command_line), then:
adef schema reshape udm-fields.txt --platform chronicle --source windows_sysmon

# In the output YAML, add `scope: {log_type: WINDOWS_SYSMON}` and set
# `platform:` before ingesting. `query_language` stays unset — ADEF's schema
# check does not parse UDM search yet.""",
        version_notes="Chronicle uses UDM schema. Reference: https://cloud.google.com/chronicle/docs/reference/udm-field-list",
    ),
    "sumo": SIEMRecipe(
        platform="Sumo Logic",
        query_language="sumo",
        command="""_sourceCategory=<your_category>
| count by _raw
| fields - _count
| limit 1
| parse regex field=_raw "(?<field>\\w+)=(?<value>[^\\s]+)" multi
| fields field
| dedup field""",
        export_format="csv",
        export_instructions="""1. Run the query in Sumo Logic web UI
2. Let it scan recent data (e.g., last 24h)
3. Export results as CSV
4. Save as fields.csv""",
        reshaping_guide="""# Save the exported field column as plain text, one field per line
# (drop the CSV header row), then:
adef schema reshape fields.txt --platform sumo --source <source_category>

# Set `platform:` in the output YAML before ingesting. `query_language`
# stays unset — ADEF's schema check does not parse Sumo query language yet.""",
        version_notes="Field extraction depends on log parsing. Pre-parsed JSON logs work best.",
    ),
    "qradar": SIEMRecipe(
        platform="IBM QRadar",
        query_language="aql",
        command="""SELECT DISTINCT(propertyname)
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = '<your_log_source>'
LAST 7 DAYS""",
        export_format="csv",
        export_instructions="""1. Open QRadar → Log Activity → Search
2. Run the AQL query
3. Export results as CSV
4. Save as qradar-fields.csv""",
        reshaping_guide="""# Save the propertyname column as plain text, one field per line
# (drop the CSV header row), then:
adef schema reshape qradar-fields.txt --platform qradar --source <log_source>

# Set `platform:` in the output YAML before ingesting. `query_language`
# stays unset — ADEF's schema check does not parse AQL yet.""",
        version_notes="Requires QRadar 7.3+. Custom properties require DSM configuration.",
    ),
    "other": SIEMRecipe(
        platform="Generic / Other",
        query_language="sql",
        command="""-- For SQL-based systems (e.g., data lakes, warehouses):
-- Query information schema or use platform-specific metadata tables

-- PostgreSQL/MySQL:
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = '<your_table>';

-- Or manually list fields from your query authoring experience""",
        export_format="csv",
        export_instructions="""1. Export schema from your SIEM/platform
2. Options:
   - Run metadata queries (information_schema, SHOW COLUMNS, etc.)
   - Export field list from UI/docs
   - Manually list fields you query
3. Create a text file or CSV with field names""",
        reshaping_guide="""# Save your field names as a plain text file, one per line, then:
adef schema reshape fields.txt --platform other --source <source_name>

# In the output YAML, set `platform:` and — if you query this source with
# spl/kql/cql/sql — `query_language:` before ingesting.""",
        version_notes="Generic recipe. Adapt to your platform's schema export capabilities.",
    ),
}


def get_recipe(platform: str) -> SIEMRecipe:
    """Retrieve recipe for a platform.

    Args:
        platform: Platform name (case-insensitive)

    Returns:
        SIEMRecipe for the platform

    Raises:
        ValueError: If platform is unknown
    """
    platform_lower = platform.lower()
    if platform_lower not in RECIPES:
        supported = ", ".join(sorted(RECIPES.keys()))
        raise ValueError(
            f"Unknown platform: {platform}\n"
            f"Supported platforms: {supported}"
        )
    return RECIPES[platform_lower]


def list_platforms() -> list[str]:
    """Return list of supported platform names."""
    return sorted(RECIPES.keys())


def render_recipe_markdown(recipe: SIEMRecipe) -> str:
    """Format recipe as markdown for CLI display.

    Args:
        recipe: SIEMRecipe to render

    Returns:
        Markdown-formatted recipe
    """
    lines = [
        f"# {recipe.platform} Field Extraction Recipe",
        "",
        f"**Query Language:** {recipe.query_language}",
        f"**Export Format:** {recipe.export_format}",
        "",
    ]

    if recipe.version_notes:
        lines.extend([
            "## Version Notes",
            "",
            recipe.version_notes,
            "",
        ])

    lines.extend([
        "## Command",
        "",
        "Run this command/query in your SIEM:",
        "",
        "```",
        recipe.command.strip(),
        "```",
        "",
        "## Export Instructions",
        "",
        recipe.export_instructions.strip(),
        "",
        "## Reshaping to ADEF Declaration",
        "",
        "Convert the exported data to ADEF's declaration format:",
        "",
        "```",
        recipe.reshaping_guide.strip(),
        "```",
        "",
        "## Next Steps",
        "",
        "1. Review the transformation report `adef schema reshape` prints",
        "2. Validate the YAML: `adef schema lint <your-sources>.yml`",
        "3. Ingest it: `adef schema ingest <your-sources>.yml`",
        "4. Verify schemas created: `ls ~/work/adef-workspace/schema/`",
        "",
    ])

    return "\n".join(lines)
