---
name: schema-declaration
description: Set up or update ADEF schema declarations — the YAML listing a SIEM's data sources and their fields — from a real field export. Use when the user wants to declare data sources or build a field inventory, when `adef schema` commands report no schemas, when they ask how to set ADEF up for their SIEM (Splunk, Sentinel, Elastic, Chronicle, Sumo, QRadar), when they have a raw field export to reshape, or when SIEM fields changed and the schema needs refreshing (a re-ingest, not a separate sync). Drives `adef schema recipe → reshape → ingest`; never hand-writes the YAML or derives schemas from rules. For cataloging rules use catalog-onboarding; for field-vs-rule gaps use `adef schema check`.
---

# Schema Declaration Workflow

Guide users through extracting field inventories from their SIEM and building
ADEF data source declarations. ADEF's schema system needs a **declaration** — a
YAML file listing sources and their fields — to build schemas; you get the user
the right export command, reshape their export into the declaration, and
validate it before ingestion. Never hand-write the YAML or derive it from rules.

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

It returns the exact query to run, how to save the output, and the matching
`adef schema reshape` invocation. **Present the recipe's own `command`
verbatim** — never paraphrase or invent the export query. The recipe keeps the
distribution columns (`count`, `distinct_count`, `values`) that reshape needs
to harvest enums and infer types; a hand-shortened query silently drops them.

Then: show where to run it (UI/CLI/API) and tell the user to save the export to
a file (do NOT hand-reshape pasted output).

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

**Walk the user through the transformation report it prints** — inferred
scope, dropped internals, folded aliases, harvested enums — and get their
approval of the *transformations*, not a wall of YAML.

**Adjudicate `[SUSPECT]` folds.** The case-fold rule is lexical; occasionally
two *different* fields differ only by case. Reshape flags a fold `SUSPECT`
when the two variants' harvested value sets are disjoint — the signature of
two different fields, since two spellings of one field share values. For each
suspect fold, judge whether the pair is one concept or two (use the values as
evidence plus what you know about the platform), confirm with the user, and
encode the verdict as a **re-run**, not a YAML edit:

```bash
adef schema reshape <export> --platform <p> --no-fold EventType
```

`--no-fold <variant>` keeps that spelling as its own field; it's repeatable.
Re-running with flags keeps the veto reproducible — a hand-edited YAML loses
the fix the next time anyone reshapes a fresh export. (A human driving the
CLI directly can use `--interactive` instead: it shows each suspect fold's
value evidence, asks keep-or-split, and echoes the equivalent `--no-fold`
command for scripts.)

A `SUSPECT` flag has two legitimate outcomes — read the values, don't assume:

- **Different fields → split.** Live examples (Splunk XmlWinEventLog mixing
  Security + Sysmon events): `eventtype ← EventType` (Splunk tag names vs
  Sysmon's `SetValue`), `signature ← Signature` (event descriptions vs
  code-signing publishers), `Name ← name` (provider names vs event
  descriptions). Split with `--no-fold`.
- **Same field, different encodings → keep the fold.** `user ← User` flags
  because `SYSTEM` vs `NT AUTHORITY\SYSTEM` are disjoint *as strings*, but
  one is the domain-stripped normalization of the other; `ProcessID ←
  ProcessId` flags on decimal vs hex. When one variant's values are a
  transformation of the other's, the fold is correct — approve it.

(The Splunk recipe now strips `eventtype`/`tag` at query time, so that
specific collision only appears in exports that bypassed the recipe. Mixed
raw/CIM sourcetypes like XmlWinEventLog will flag many folds — that's the
true state of the data, not noise.)

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

### 7. Keeping Schemas Current

When the SIEM's fields change, there is **no separate schema sync** — updating a
schema *is* a re-ingest:

1. Re-run the recipe and re-export (or reshape a fresh export).
2. `adef schema ingest <declaration>` again.

Re-ingest **preserves human corrections** (`corrected`-provenance fields survive)
and **reports drift** — fields added, removed, or changed since the last ingest —
so you see what moved without losing edits. (Contrast the catalog, which
reconciles via `adef sync` + the `catalog-sync` skill; schemas reconcile by
re-ingesting the declaration.)

## Anti-Patterns

**❌ Don't:**
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

## Multi-Source Scenarios

A declaration can hold several sources (Windows logs, Linux syslog, network) in
one file. Don't merge YAML by hand — reshape each export and let `--append`
grow the file:

```bash
adef schema reshape win.csv   --platform splunk --source windows_security
adef schema reshape linux.csv --platform splunk --source linux_syslog --append windows_security-sources.yml
```

One `schema ingest <file>` then creates all schemas. (One reshape per event
shape still holds — `--append` combines *sources*, it does not merge two
sourcetypes into one source.)

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

Done when the workspace has `schema/*.yml` files, `adef schema show <source>`
displays fields that match what the user actually queries, and they know a
field change is just a re-run + re-ingest. Offer to help again when they add a
new source.
