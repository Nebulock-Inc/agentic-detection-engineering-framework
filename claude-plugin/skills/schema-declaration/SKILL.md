---
name: schema-declaration
description: Help users generate data source declarations for ADEF schema system
---

# Schema Declaration Workflow

Guide users through extracting field inventories from their SIEM and building ADEF data source declarations.

## When to Use

- User mentions "schema", "data sources", "field inventory"
- User runs `adef schema` commands and has no schemas
- User asks how to set up ADEF for their SIEM
- During catalog onboarding when rules reference undeclared data sources

## The Problem

ADEF's schema system needs a **data source declaration** — a YAML file listing sources and their fields — to build schemas. Users need:
1. The right SIEM-specific command to extract field inventories
2. Help reshaping that output into ADEF's declaration format
3. Validation that the declaration is correct before ingestion

## Workflow

### 1. Check Current State

```bash
ls -la ~/work/adef-workspace/schema/
```

If empty or missing, user needs to create schemas.

### 2. Determine Platform

Read from workspace config:
```
schema_list_platforms  # Show available platforms
```

Check if platform is configured:
```bash
cat ~/work/adef-workspace/config/.adefconfig.yaml
```

If no `platform:` key exists, ask user which SIEM they use:
- Splunk
- Microsoft Sentinel
- Elastic/Kibana
- Google Chronicle
- Sumo Logic
- IBM QRadar
- Other

### 3. Generate Recipe

Use MCP tool to get platform-specific recipe:

```
schema_recipe platform="<platform>"
```

This returns:
- `command`: Exact query to run in their SIEM
- `export_instructions`: How to save the output
- `reshaping_guide`: The `adef schema reshape` invocation for this platform
- `recipe_markdown`: Full formatted guide

**Present the recipe to the user:**
- Show the command they need to run
- Explain where to run it (UI, CLI, API)
- Tell them to save the export to a file (do NOT hand-reshape pasted output)

### 4. Reshape with the deterministic command

Never draft the declaration by hand — `adef schema reshape` applies the five
reshape rules in tested code and reports every transformation:

```bash
adef schema reshape <export-file> --platform <platform> --source <name>
```

The rules it applies: internals filter (`_*`, `date_*`, `punct`, routing
fields), case-duplicates folded into `aliases`, enum values harvested for
low-cardinality fields (length-capped), int/float type inference, and a
mixed-shape guard — a multi-sourcetype export is refused with re-export
guidance (one declaration per event shape; that is what `scope:` is for).

**Walk the user through the transformation report it prints** — dropped
internals, folded aliases, harvested enums — and get their approval of the
*transformations*, not a wall of YAML. If they veto a drop or a fold, edit
the output YAML with them.

Then finish the fields the command never guesses:
- `platform:` — set from what the user tells you (windows/linux/network/cloud)
- `query_language:` — only if the source is queried in spl/kql/cql/sql
- `description:` — one line on what the source is

Re-validate after manual edits:
```
schema_lint_declaration content="<yaml_content>"
```

### 5. Write and Ingest Declaration

Once user approves (`adef schema reshape` already wrote the file — move it
into the workspace if it isn't there):

1. Ingest using MCP tool:
   ```
   schema_ingest declaration_path="~/work/adef-workspace/<platform>-sources.yml"
   ```

2. Confirm schemas created:
   ```bash
   ls -la ~/work/adef-workspace/schema/
   adef schema show <source_name>
   ```

### 6. Next Steps

Suggest:
- `adef catalog <rule-repo>` to catalog existing rules
- `adef detection new TITLE` to create a new detection
- `adef schema check` to cross-reference rules vs schemas

## Anti-Patterns

**❌ Don't:**
- Run `adef schema init` (deprecated command, removed pre-v0.1.0)
- Try to derive schemas from rules (declaration-driven only)
- Guess at fields — user must provide real SIEM output
- Add fields the user didn't mention (no hallucinating schema fields)
- Hand-reshape an export into YAML — `adef schema reshape` does it in tested
  code and its transformation report is the human-approval artifact
- Guess `platform:` — always confirmed with the user, never inferred

**✅ Do:**
- Use `adef schema reshape` for the export → declaration step
- Use MCP tools (`schema_recipe`, `schema_lint_declaration`, `schema_ingest`)
- Validate before writing any files
- Ask for confirmation before ingesting
- Show user what you're about to create

## Example Flow

**User:** "I need to set up schemas for my Splunk environment"

**Assistant:**
1. Check if schemas exist: `ls ~/work/adef-workspace/schema/`
2. Call `schema_recipe platform="splunk"`
3. Present recipe:
   > "Run this search in Splunk Web:
   > ```
   > index=wineventlog earliest=-7d | fieldsummary | fields field | outputcsv fields.csv
   > ```
   > Export the CSV, then paste the contents here."
4. User pastes CSV output
5. Parse CSV → draft YAML
6. Call `schema_lint_declaration` to validate
7. Show drafted YAML, ask for approval
8. Write file and call `schema_ingest`
9. Confirm success, suggest next steps

## Multi-Source Scenarios

If user has multiple data sources (e.g., Windows logs, Linux logs, network logs):

1. Generate one declaration file with multiple sources:
   ```yaml
   version: 1
   sources:
     - name: windows_security
       platform: windows
       query_language: spl
       fields: [...]
     - name: linux_syslog
       platform: linux
       query_language: spl
       fields: [...]
   ```

2. Run recipe for each platform if needed
3. Combine into single declaration
4. Single `schema ingest` creates all schemas

## Chronicle/UDM Special Case

Chronicle doesn't expose a field query — users must reference UDM docs manually.

For Chronicle:
1. Show recipe (references UDM field list docs)
2. Help user list fields from UDM schema for their log_type
3. Include `scope` in declaration:
   ```yaml
   scope:
     log_type: WINDOWS_SYSMON
   ```

## Success Criteria

Workflow succeeds when:
- ✅ User has `schema/*.yml` files in their workspace
- ✅ `adef schema show <source>` displays fields
- ✅ Schemas match what user actually queries in their SIEM
- ✅ User understands how to update schemas if fields change (re-run recipe, re-ingest)

## Workflow Duration

Typical session: 5-10 minutes
- 1 min: Check state, determine platform
- 2 min: Generate recipe, user runs command
- 3-5 min: User exports, reshapes, validates
- 1 min: Ingest and verify

Offer to help again if user adds new data sources later.
