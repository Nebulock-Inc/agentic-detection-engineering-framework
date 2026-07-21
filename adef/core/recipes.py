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
        command="""index=<your_index> earliest=-7d latest=now
| fieldsummary
| fields field
| outputcsv fields.csv""",
        export_format="csv",
        export_instructions="""1. Run the search in Splunk Web (Search & Reporting app)
2. Wait for search to complete
3. Click "Export" → "CSV"
4. Download fields.csv""",
        reshaping_guide="""# Convert CSV to ADEF declaration YAML

import csv
import yaml

# Read Splunk fieldsummary output
with open('fields.csv', 'r') as f:
    reader = csv.DictReader(f)
    fields = [{'name': row['field']} for row in reader]

# Create declaration structure
declaration = {
    'version': 1,
    'sources': [{
        'name': 'your_index_name',
        'platform': 'windows',  # or linux, network, cloud, etc.
        'query_language': 'spl',
        'description': 'Description of your data source',
        'fields': fields
    }]
}

# Write YAML
with open('splunk-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created splunk-sources.yml — review and run: adef schema ingest splunk-sources.yml")""",
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
        reshaping_guide="""# Convert Sentinel getschema output to ADEF declaration

import csv
import yaml

# Map KQL types to ADEF types
TYPE_MAP = {
    'string': 'string',
    'int': 'int',
    'long': 'int',
    'real': 'float',
    'datetime': 'datetime',
    'bool': 'bool',
    'dynamic': 'object',
}

def convert_table_schema(table_name, csv_path):
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        fields = [
            {
                'name': row['ColumnName'],
                'type': TYPE_MAP.get(row['DataType'], 'string')
            }
            for row in reader
        ]

    return {
        'name': table_name.lower(),
        'platform': 'windows',  # Adjust per table
        'query_language': 'kql',
        'description': f'{table_name} table from Sentinel',
        'fields': fields
    }

# Process all tables
sources = [
    convert_table_schema('SecurityEvent', 'SecurityEvent-schema.csv'),
    convert_table_schema('Syslog', 'Syslog-schema.csv'),
    # Add more tables...
]

declaration = {'version': 1, 'sources': sources}

with open('sentinel-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created sentinel-sources.yml")""",
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
        reshaping_guide="""# Convert Elastic mapping to ADEF declaration

import json
import yaml

# Map Elasticsearch types to ADEF types
TYPE_MAP = {
    'keyword': 'string',
    'text': 'string',
    'long': 'int',
    'integer': 'int',
    'short': 'int',
    'byte': 'int',
    'double': 'float',
    'float': 'float',
    'boolean': 'bool',
    'date': 'datetime',
    'ip': 'ip',
    'object': 'object',
    'nested': 'array',
}

def extract_fields(properties, prefix=''):
    fields = []
    for name, spec in properties.items():
        field_name = f'{prefix}{name}' if prefix else name
        field_type = spec.get('type', 'string')

        fields.append({
            'name': field_name,
            'type': TYPE_MAP.get(field_type, 'string')
        })

        # Recurse into nested objects (flatten for ADEF)
        if 'properties' in spec:
            fields.extend(extract_fields(spec['properties'], f'{field_name}.'))

    return fields

with open('mapping.json', 'r') as f:
    mapping = json.load(f)

# Extract from first index in response
index_name = list(mapping.keys())[0]
properties = mapping[index_name]['mappings']['properties']

fields = extract_fields(properties)

declaration = {
    'version': 1,
    'sources': [{
        'name': index_name.replace('*', '').strip('-'),
        'platform': 'linux',  # Adjust based on your data
        'query_language': 'eql',
        'description': f'Elastic index {index_name}',
        'fields': fields
    }]
}

with open('elastic-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created elastic-sources.yml")""",
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
        reshaping_guide="""# Manually create Chronicle declaration from UDM docs

# Example for WINDOWS_SYSMON log type:
import yaml

fields = [
    {'name': 'metadata.event_timestamp', 'type': 'datetime'},
    {'name': 'metadata.event_type', 'type': 'string'},
    {'name': 'principal.hostname', 'type': 'string'},
    {'name': 'principal.process.command_line', 'type': 'string'},
    {'name': 'principal.process.file.full_path', 'type': 'string'},
    {'name': 'principal.process.pid', 'type': 'int'},
    {'name': 'target.process.command_line', 'type': 'string'},
    {'name': 'target.process.file.full_path', 'type': 'string'},
    {'name': 'target.process.pid', 'type': 'int'},
    # Add more fields from UDM docs...
]

declaration = {
    'version': 1,
    'sources': [{
        'name': 'windows_sysmon',
        'platform': 'windows',
        'query_language': 'udm',
        'description': 'Windows Sysmon logs via Chronicle UDM',
        'scope': {
            'log_type': 'WINDOWS_SYSMON'
        },
        'fields': fields
    }]
}

with open('chronicle-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created chronicle-sources.yml")""",
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
        reshaping_guide="""# Convert Sumo Logic field list to ADEF declaration

import csv
import yaml

with open('fields.csv', 'r') as f:
    reader = csv.DictReader(f)
    fields = [{'name': row['field']} for row in reader]

declaration = {
    'version': 1,
    'sources': [{
        'name': 'your_source_category',
        'platform': 'linux',  # Adjust based on data
        'query_language': 'sumo',
        'description': 'Sumo Logic source category',
        'fields': fields
    }]
}

with open('sumo-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created sumo-sources.yml")""",
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
        reshaping_guide="""# Convert QRadar property list to ADEF declaration

import csv
import yaml

with open('qradar-fields.csv', 'r') as f:
    reader = csv.DictReader(f)
    fields = [{'name': row['propertyname']} for row in reader]

declaration = {
    'version': 1,
    'sources': [{
        'name': 'your_log_source_name',
        'platform': 'network',  # Adjust based on data
        'query_language': 'aql',
        'description': 'QRadar log source',
        'fields': fields
    }]
}

with open('qradar-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created qradar-sources.yml")""",
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
        reshaping_guide="""# Manual declaration creation for any platform

import yaml

# List all fields you use in your queries
fields = [
    {'name': 'timestamp', 'type': 'datetime'},
    {'name': 'event_type', 'type': 'string'},
    {'name': 'source_ip', 'type': 'ip'},
    {'name': 'destination_ip', 'type': 'ip'},
    {'name': 'username', 'type': 'string'},
    # Add all your fields...
]

declaration = {
    'version': 1,
    'sources': [{
        'name': 'your_data_source',
        'platform': 'linux',  # windows, network, cloud, etc.
        'query_language': 'sql',  # or whatever you use
        'description': 'Description of your data source',
        'fields': fields
    }]
}

with open('sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created sources.yml — review and run: adef schema ingest sources.yml")""",
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
        "```python",
        recipe.reshaping_guide.strip(),
        "```",
        "",
        "## Next Steps",
        "",
        "1. Review the generated YAML file",
        "2. Validate it: `adef schema lint <your-sources>.yml`",
        "3. Ingest it: `adef schema ingest <your-sources>.yml`",
        "4. Verify schemas created: `ls ~/work/adef-workspace/schema/`",
        "",
    ])

    return "\n".join(lines)
