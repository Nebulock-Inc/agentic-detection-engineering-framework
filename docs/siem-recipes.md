# SIEM Field Extraction Recipes

Per-platform guides for extracting field inventories from SIEMs and converting them to ADEF data source declarations.

## Overview

ADEF's schema system requires a **data source declaration** — a YAML file listing your data sources and their fields. This document provides platform-specific recipes for extracting that field inventory from your SIEM.

**Quick start:**
```bash
adef schema recipe <platform>  # Generate platform-specific recipe
adef schema lint sources.yml   # Validate your declaration
adef schema ingest sources.yml # Build schemas
```

---

## Splunk

**Query Language:** SPL  
**Export Format:** CSV

### Command

Run this search in Splunk Web (Search & Reporting app):

```spl
index=<your_index> earliest=-7d latest=now
| fieldsummary
| fields field
| outputcsv fields.csv
```

**Adjust:**
- `index=<your_index>` — Your target index(es)
- `earliest=-7d` — Time range (larger = more fields discovered, but slower)

### Export

1. Wait for search to complete
2. Click "Export" → "CSV"
3. Download `fields.csv`

### Reshaping

Convert the CSV to ADEF declaration format:

```python
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
        'name': 'wineventlog',  # Choose a meaningful name
        'platform': 'windows',   # windows, linux, network, cloud, etc.
        'query_language': 'spl',
        'description': 'Windows event logs via Universal Forwarder',
        'scope': {
            'index': 'wineventlog',
            'sourcetype': 'XmlWinEventLog'  # Optional: narrows scope
        },
        'fields': fields
    }]
}

# Write YAML
with open('splunk-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created splunk-sources.yml")
print("Next: adef schema lint splunk-sources.yml")
```

### Version Notes

- Works on Splunk 8.x and 9.x
- For large indexes, limit time range to avoid search limits
- Multiple indexes → run `fieldsummary` per index, declare as separate sources

---

## Microsoft Sentinel

**Query Language:** KQL  
**Export Format:** CSV

### Command

Run this query in Azure Portal → Microsoft Sentinel → Logs for each table:

```kql
// Run for each table you want to declare
SecurityEvent
| getschema
| project ColumnName, DataType
```

**Common tables:**
- `SecurityEvent` — Windows security events
- `Syslog` — Linux/Unix syslog
- `CommonSecurityLog` — CEF format
- `AzureActivity` — Azure control plane
- `SigninLogs` — Azure AD sign-ins

### Export

1. Run query for each table
2. Click "Export" → "Export to CSV - all columns"
3. Save as `<table>-schema.csv`
4. Repeat for all tables

### Reshaping

Convert Sentinel `getschema` output to ADEF format:

```python
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
    """Convert one Sentinel table schema to ADEF source."""
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

print("Created sentinel-sources.yml")
```

### Version Notes

- Requires Log Analytics Contributor role or higher
- `getschema` returns current table schema (may change with ingestion updates)
- Custom tables follow same pattern

---

## Elastic / Kibana

**Query Language:** EQL  
**Export Format:** JSON

### Command

Run this in Kibana → Dev Tools → Console:

```
GET <index-pattern>/_mapping
```

**Examples:**
- `GET logs-*/_mapping` — All log indices
- `GET winlogbeat-*/_mapping` — Winlogbeat indices
- `GET filebeat-*/_mapping` — Filebeat indices

### Export

1. Copy the JSON response
2. Save to `mapping.json`

### Reshaping

Convert Elasticsearch `_mapping` to ADEF format:

```python
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
    """Recursively extract fields from Elastic mapping."""
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

print("Created elastic-sources.yml")
```

### Version Notes

- Works with Elasticsearch 7.x and 8.x
- ECS (Elastic Common Schema) fields come pre-documented
- Nested fields are flattened with dot notation

---

## Google Chronicle

**Query Language:** UDM (Unified Data Model)  
**Export Format:** Manual

### Command

Chronicle doesn't expose a direct schema query. Use the **UDM Search reference documentation** instead.

**Reference:** [Chronicle UDM Field List](https://cloud.google.com/chronicle/docs/reference/udm-field-list)

### Export

1. Identify your `log_type` (e.g., `WINDOWS_SYSMON`, `GCP_CLOUDAUDIT`, `OKTA`)
2. Find that log type in the UDM docs
3. List all fields you query for that log type
4. Export as a text list of field paths

### Reshaping

Manually create declaration from UDM docs:

```python
import yaml

# Example for WINDOWS_SYSMON log type
# Field paths from Chronicle UDM docs
fields = [
    {'name': 'metadata.event_timestamp', 'type': 'datetime'},
    {'name': 'metadata.event_type', 'type': 'string'},
    {'name': 'metadata.product_log_id', 'type': 'string'},
    {'name': 'principal.hostname', 'type': 'string'},
    {'name': 'principal.process.command_line', 'type': 'string'},
    {'name': 'principal.process.file.full_path', 'type': 'string'},
    {'name': 'principal.process.pid', 'type': 'int'},
    {'name': 'target.process.command_line', 'type': 'string'},
    {'name': 'target.process.file.full_path', 'type': 'string'},
    {'name': 'target.process.pid', 'type': 'int'},
    {'name': 'target.user.userid', 'type': 'string'},
    # Add all fields you actually query...
]

declaration = {
    'version': 1,
    'sources': [{
        'name': 'windows_sysmon',
        'platform': 'windows',
        'query_language': 'udm',
        'description': 'Windows Sysmon logs via Chronicle UDM',
        'scope': {
            'log_type': 'WINDOWS_SYSMON'  # Critical for Chronicle
        },
        'fields': fields
    }]
}

with open('chronicle-sources.yml', 'w') as f:
    yaml.dump(declaration, f, default_flow_style=False, sort_keys=False)

print("Created chronicle-sources.yml")
```

### Version Notes

- Chronicle uses UDM schema (standardized field names)
- `scope.log_type` is required for Chronicle sources
- UDM field list: https://cloud.google.com/chronicle/docs/reference/udm-field-list

---

## Sumo Logic

**Query Language:** Sumo Logic Query Language  
**Export Format:** CSV

### Command

```
_sourceCategory=<your_category>
| count by _raw
| fields - _count
| limit 1
| parse regex field=_raw "(?<field>\\w+)=(?<value>[^\\s]+)" multi
| fields field
| dedup field
```

**Adjust:**
- `_sourceCategory=<your_category>` — Your source category
- Time range: Use UI time picker (e.g., last 24h)

### Export

1. Let query scan recent data
2. Export results as CSV
3. Save as `fields.csv`

### Reshaping

```python
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

print("Created sumo-sources.yml")
```

### Version Notes

- Field extraction depends on log parsing
- Pre-parsed JSON logs work best
- Adjust regex pattern for your log format

---

## IBM QRadar

**Query Language:** AQL  
**Export Format:** CSV

### Command

Run in QRadar → Log Activity → Search:

```sql
SELECT DISTINCT(propertyname)
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = '<your_log_source>'
LAST 7 DAYS
```

**Adjust:**
- `<your_log_source>` — Your log source name
- `LAST 7 DAYS` — Time range

### Export

1. Run AQL query
2. Export results as CSV
3. Save as `qradar-fields.csv`

### Reshaping

```python
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

print("Created qradar-sources.yml")
```

### Version Notes

- Requires QRadar 7.3+
- Custom properties require DSM configuration
- `propertyname` includes both built-in and custom properties

---

## Generic / Other Platforms

For SQL-based systems, data lakes, or platforms not listed above.

### Command

**PostgreSQL/MySQL:**
```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = '<your_table>';
```

**Or manually list fields** you use in your queries.

### Export

- Run metadata query
- Export as CSV or JSON
- Or create a text file with one field per line

### Reshaping

```python
import yaml

# List all fields you query
fields = [
    {'name': 'timestamp', 'type': 'datetime'},
    {'name': 'event_type', 'type': 'string'},
    {'name': 'source_ip', 'type': 'ip'},
    {'name': 'destination_ip', 'type': 'ip'},
    {'name': 'username', 'type': 'string'},
    {'name': 'result', 'type': 'string'},
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

print("Created sources.yml")
print("Next: adef schema lint sources.yml")
```

---

## Next Steps

After creating your declaration:

1. **Validate:**
   ```bash
   adef schema lint <your-sources>.yml
   ```

2. **Ingest:**
   ```bash
   adef schema ingest <your-sources>.yml
   ```

3. **Verify:**
   ```bash
   ls ~/work/adef-workspace/schema/
   adef schema show <source_name>
   ```

4. **Catalog rules (if you have existing rules):**
   ```bash
   adef catalog /path/to/rules
   ```

5. **Cross-reference:**
   ```bash
   adef schema check  # Rules vs schemas
   ```

---

## Multi-Source Declarations

Combine multiple data sources in one declaration:

```yaml
version: 1
sources:
  - name: windows_security
    platform: windows
    query_language: spl
    scope:
      index: wineventlog
      sourcetype: XmlWinEventLog
    fields:
      - name: EventCode
      # ... more fields

  - name: linux_syslog
    platform: linux
    query_language: spl
    scope:
      index: linux
      sourcetype: syslog
    fields:
      - name: severity
      # ... more fields
```

One `adef schema ingest` creates all schemas.

---

## Updating Schemas

When data source fields change (new fields added, types change):

1. Re-run the field extraction command
2. Re-run the reshaping script
3. Re-ingest: `adef schema ingest <sources>.yml`

ADEF preserves human corrections (fields marked `provenance: corrected`) and reports drift (added/removed/type-changed fields).

---

## Troubleshooting

**"No fields returned"**
- Increase time range (more data = more fields discovered)
- Check index/table name is correct
- Ensure you have read permissions

**"Declaration validation failed"**
- Check YAML syntax (indentation, colons, dashes)
- Ensure `version: 1` is present
- Run `adef schema lint` for detailed errors

**"Schema ingest succeeded but fields missing"**
- Check field names for typos
- Some SIEMs use different field names in results vs queries (aliases)
- Add `aliases:` to declaration for known variants

---

## CLI Quick Reference

```bash
# Generate recipe for your platform
adef schema recipe <platform>

# List supported platforms
adef schema recipe --help

# Validate declaration
adef schema lint <sources>.yml

# Ingest (build schemas)
adef schema ingest <sources>.yml

# Show schema
adef schema show <source>

# Check rules vs schemas
adef schema check
```

---

## Getting Help

- [Declaration format spec](./declaring-data-sources.md)
- [Schema design doc](./plans/2026-07-20-schema-declaration-design.md)
- Run `adef schema --help` for CLI options
- File issue: [ADEF GitHub](https://github.com/nebulock/agentic-detection-engineering-framework/issues)
