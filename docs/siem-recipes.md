# SIEM Field Extraction Recipes

Per-platform guides for extracting field inventories from SIEMs and converting them to ADEF data source declarations.

## Overview

ADEF's schema system requires a **data source declaration** — a YAML file listing your data sources and their fields. This document provides platform-specific recipes for extracting that field inventory from your SIEM.

**Quick start:**
```bash
adef schema recipe <platform>                        # the export command for your SIEM
adef schema reshape <export> --platform <platform>   # export -> draft declaration + report
adef schema lint sources.yml                         # validate your declaration
adef schema ingest sources.yml                       # build schemas
```

`reshape` applies the five reshape rules in tested code — internals filter,
case-duplicates → `aliases`, capped enum harvesting, type inference, and a
mixed-shape guard — and prints a transformation report so you approve the
transformations, not a wall of YAML. It never guesses `platform:`; set that
(and `description:`) before ingesting.

---

## Splunk

**Query Language:** SPL  
**Export Format:** CSV

### Command

Run this search in Splunk Web (Search & Reporting app):

```spl
index=<your_index> sourcetype=<your_sourcetype> earliest=-7d latest=now
| fields - eventtype, tag, tag::*
| fieldsummary maxvals=50
| fields field count distinct_count numeric_count values
```

The `| fields - eventtype, tag, tag::*` line strips Splunk *search-time*
metadata before the summary — these aren't raw event fields, and lowercase
`eventtype` is known to case-collide with raw fields like Sysmon's
`EventType`. If your detections genuinely query `tag=`/`eventtype=`, drop
that line and review the fold report carefully instead.

**Adjust:**
- `index=<your_index> sourcetype=<your_sourcetype>` — one search per
  sourcetype: one declaration per event *shape* (`adef schema reshape`
  refuses mixed-sourcetype exports)
- `earliest=-7d` — Time range (larger = more fields discovered, but slower)

Keep the `count`/`distinct_count`/`numeric_count`/`values` columns — they are
what lets `adef schema reshape` harvest enum values, infer types, and detect
mixed-shape exports.

### Export

1. Wait for search to complete
2. Click "Export" → "CSV"
3. Browser downloads the results (typically as `results.csv`)
4. Rename to `fields.csv` for the reshaping step

**Note:** Don't use `| outputcsv fields.csv` in the query — that writes server-side to `/opt/splunk/var/run/splunk/csv/` (inaccessible in Splunk Cloud). The UI Export button downloads directly to your browser.

### Reshaping

```
adef schema reshape fields.csv --platform splunk

# Applies the five reshape rules (drops _*/date_*/punct internals, folds
# case-duplicates into aliases, harvests capped enum values, infers int/float
# types, refuses mixed-sourcetype exports) and prints a transformation report.
# scope: (index/sourcetype) is filled in from the export automatically.
# Set `platform:` in the output YAML before ingesting — never inferred.
```

**Review `[SUSPECT]` folds.** Reshape flags a fold when the two variants'
harvested values are disjoint — the signature of two different fields
colliding on spelling. Real examples from a mixed Security+Sysmon
sourcetype: `signature` (event descriptions) vs `Signature` (code-signing
publishers), `Name` (provider) vs `name` (event description). Split those
with a re-run: `adef schema reshape ... --no-fold Signature --no-fold name`.
But disjoint values can also mean *one* field under two encodings —
`user`/`User` (`SYSTEM` vs `NT AUTHORITY\SYSTEM`), `ProcessID`/`ProcessId`
(decimal vs hex) — those folds are correct; approve them.

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

```
# One reshape per exported table:
adef schema reshape SecurityEvent-schema.csv --platform sentinel --source securityevent

# KQL DataType maps to ADEF field types automatically. Set `platform:` in the
# output YAML before ingesting — never inferred. To declare several tables in
# one file, reshape each and merge the `sources:` lists.
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

```
adef schema reshape mapping.json --platform elastic --source <index_name>

# Walks the _mapping properties (nested objects flattened to dotted names)
# and maps Elasticsearch types to ADEF field types. Set `platform:` in the
# output YAML before ingesting; `query_language` is left unset because ADEF's
# schema check does not parse EQL/ES|QL yet.
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

```
# Save the UDM field names for your log_type as a plain text file,
# one field per line (e.g. principal.process.command_line), then:
adef schema reshape udm-fields.txt --platform chronicle --source windows_sysmon

# In the output YAML, add `scope: {log_type: WINDOWS_SYSMON}` and set
# `platform:` before ingesting. `query_language` stays unset — ADEF's schema
# check does not parse UDM search yet.
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

```
# Save the exported field column as plain text, one field per line
# (drop the CSV header row), then:
adef schema reshape fields.txt --platform sumo --source <source_category>

# Set `platform:` in the output YAML before ingesting. `query_language`
# stays unset — ADEF's schema check does not parse Sumo query language yet.
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

```
# Save the propertyname column as plain text, one field per line
# (drop the CSV header row), then:
adef schema reshape qradar-fields.txt --platform qradar --source <log_source>

# Set `platform:` in the output YAML before ingesting. `query_language`
# stays unset — ADEF's schema check does not parse AQL yet.
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

```
# Save your field names as a plain text file, one per line, then:
adef schema reshape fields.txt --platform other --source <source_name>

# In the output YAML, set `platform:` and — if you query this source with
# spl/kql/cql/sql — `query_language:` before ingesting.
```

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
- Run `adef schema --help` for CLI options
- File issue: [ADEF GitHub](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/issues)
