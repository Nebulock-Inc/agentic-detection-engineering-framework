---
name: adef-schema
description: Guide users through data schema setup and maintenance for ADEF
---

# adef-schema Skill

You help users build and maintain their data schema for ADEF detection engineering.

## When to use this skill

- User wants to set up their data schema for the first time
- User wants to check for schema drift (field populations changed)
- User added new detection rules and needs to refresh the schema

## Initial Setup Workflow

1. Ask: "What's your primary data source name?" (e.g., `edr_process`, `cloudtrail_events`)
2. Ask: "Which query language? [SQL/SPL/CQL/KQL]"
3. Ask: "Do you have existing detection rules I should scan?"
   - If yes: get path, call `adef schema init <source> --rule-root <path> --skip-data`
4. Ask: "Want to sample your data now to discover field types?"
   - If yes: "I can generate a discovery query. Do you have an MCP tool to run it, or should I show you the query to run manually?"
     - **If MCP available:** Call user's MCP tool (e.g., `@splunk`, `@clickhouse`), get results, pipe to `adef schema init <source> --stdin`
     - **If manual:** Show query, wait for user to paste results
5. Schema created, show summary: "Found X fields from rules, Y from data, Z overlap. Review with `adef schema show <source>`"

## Drift Detection Workflow

1. User: "check if my schema has drifted"
2. You: "I'll generate a fresh sample query. Run and pipe results, or I can use your MCP?"
3. User provides data → call `adef schema update <source> --results -`
4. Summarize drift: "command_line population dropped 13%, parent_pid went missing"

## Rescan Workflow

1. User: "I added new detections, update the schema"
2. Call `adef schema rescan <source>`
3. Summarize: "Found 2 new fields in rules: process_integrity_level, process_hash"

## CLI commands you'll use

- `adef schema init <source>` — initial setup wizard
- `adef schema update <source> --results -` — refresh data sample
- `adef schema rescan <source>` — re-parse rules
- `adef schema show <source>` — display current schema

## MCP integration

If user has MCP tools (Splunk, ClickHouse, etc.), you can:
1. Generate the discovery query
2. Call their MCP tool to run it
3. Pipe results to `adef schema init/update --stdin`

Otherwise, show them the query and wait for them to paste/pipe results.

## Discovery Query Templates

**SQL:**
```sql
SELECT * FROM <source>
WHERE timestamp >= NOW() - INTERVAL '30 days'
LIMIT 10000;
```

**SPL:**
```spl
index=<source> earliest=-30d | head 10000
```

**CQL:**
```
#event_simpleName=* | limit 10000
```

**KQL:**
```kql
<source> | where TimeGenerated > ago(30d) | limit 10000
```
