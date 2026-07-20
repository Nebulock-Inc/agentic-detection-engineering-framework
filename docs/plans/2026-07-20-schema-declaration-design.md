# Schema Ingest Rework — Data Source Declarations

**Date:** 2026-07-20
**Status:** Accepted by Jarrett (team decision to simplify schema ingest); built this session
**Supersedes:** rules-as-schema-source (the `from-catalog` field-derivation path and the
`schema init` wizard become deprecated inputs). The 2026-07-16 `data_source`
capture on `CatalogRecord` is **kept** — its role inverts (see "Rules' new role").
**Touches:** new `adef/core/declaration.py`, `adef/commands/schema.py` (new
`ingest`/`lint`/`check` subcommands, deprecation notices), `docs/`

---

## Why

The schema exists so an assistant can (a) write a correct query against the
user's data and (b) suggest detections grounded in what the data can express.
Deriving the schema *from existing rules* failed at both, structurally:

1. Queries reference **aliased, calculated, macro-expanded** field names — two
   layers of distortion away from the real event shape.
2. Rules only touch fields someone **already thought to use** — precisely the
   wrong input for suggesting *new* detections.
3. Parse fidelity varies by query language, so coverage was uneven and silently
   wrong.

Team decision: the user hands ADEF a **declaration document** — data sources
and their fields — and ADEF builds schemas from that. Not samples of event
data: a field inventory. Nobody hand-types 300 fields, so the format's one job
is to be **trivially producible from artifacts that already exist** (Splunk
`| fieldsummary`, KQL `| getschema`, Elastic index mappings, vendor data
dictionaries) — by hand, by recipe, or by an agent reshaping whatever the user
has.

## The declaration format (v1)

One YAML file, any number of sources. Committable, reviewable, no event data.

```yaml
# adef-sources.yml
version: 1
sources:
  - name: wineventlog            # the literal used in queries (index=, table name)
    platform: windows            # optional
    query_language: spl          # optional but recommended (enables `schema check`)
    description: Windows Security events via UF   # optional
    fields:
      - name: EventCode          # in QUERY-LANGUAGE terms — what authoring needs
        type: int                # optional, default string
        description: Windows event ID              # optional
        values: [4624, 4688, 4720]                 # optional — enum-ish fields
      - name: CommandLine
      - name: user
        aliases: [User, user_name]                 # optional — the aliasing mess, documented
```

**Low floor, high ceiling.** Required: `version`, source `name`, field
`name`s. Everything else is optional enrichment that directly improves
authoring quality and can be added incrementally.

Lint rules (`adef schema lint`): `version: 1`; unique source names; unique
field names per source; no path separators in source names; `type` in
`string | int | float | bool | datetime | ip | array | object | unknown`;
`values`/`aliases` are lists of scalars/strings; unknown keys rejected (typo
guard). Missing `query_language` is a **warning**, not an error.

## Schema artifact (v2)

`adef schema ingest adef-sources.yml` writes one `schema/<source>.yml` per
declared source:

```yaml
schema_version: 2
source: wineventlog
platform: windows
query_language: spl
description: Windows Security events via UF
declared: 2026-07-20T14:03:00-07:00     # last ingest timestamp
fields:
  - name: EventCode
    type: int
    description: Windows event ID
    values: [4624, 4688, 4720]
    aliases: []
    provenance: declared                 # declared | corrected
```

**Provenance + merge semantics** (the contract that makes re-ingest safe):

- Ingested fields are `declared`.
- A human may edit the generated YAML: fix a type, add a missing field. Marking
  a field `provenance: corrected` (or adding a new field with it) protects it.
- Re-ingest **replaces** the `declared` set, **preserves** every `corrected`
  field (matched by name; a corrected field shadows an incoming declared field
  of the same name), and prints a **drift report**: fields added / removed /
  type-changed since the previous declaration.
- `schema_version: 2` distinguishes new files from v1 (rules-derived) schemas;
  v1 files are readable but no longer produced.
- Future ingest paths (event samples, if ever wanted) become a third
  provenance value — additive, no redesign.

## Rules' new role: consumer and prioritizer, never source

- **Prioritization:** the catalog's `by_data_source` index tells the user what
  to declare first — "214 rules query `wineventlog`; no schema exists for it."
- **`adef schema check`:** cross-references the fields rules actually use
  (existing `rule_parser` extractors over catalog records, grouped by
  `data_source`/language) against declared schemas (names + aliases). Two
  finding types, both actionable:
  - *rule field missing from schema* — broken rule, undeclared alias, or a
    macro worth documenting;
  - *schema field unused by any rule* — detection surface nobody exploits
    (feeds the suggestion story).
  `--report json` for the agent/skill path; findings never block.

## CLI surface

```bash
adef schema ingest adef-sources.yml      # declaration → schema/<source>.yml (+ drift report)
adef schema lint adef-sources.yml        # validate, exit 1 on errors
adef schema check                        # rules vs schemas cross-reference
adef schema show <source>                # renders v2 (and legacy v1) files
```

**Removed** (2026-07-20, same session — pulled forward from the original v0.2
target since ADEF is unreleased and a deprecation window protects nobody):
`schema init` (the interactive wizard), `schema from-catalog` (rules-derived
field schemas), `schema update`/`rescan` (unimplemented stubs), the MCP
`schema_init` tool, and the old model's supporting modules
(`adef/core/schema.py`, `data_sampler.py`, `llm_client.py`,
`rule_discovery.scan_rule_fields`) plus their tests and the `llm` optional
dependency group. MCP gains `schema_ingest` (declaration-driven, same engine
as the CLI). The `rule_parser` extractors and catalog `data_source` capture
are kept — `check` consumes both.

## Getting a declaration made (adoption paths)

1. **Recipes (docs, no code):** per-SIEM one-liners that emit a field
   inventory — Splunk `| fieldsummary | fields field`, KQL `<Table> | getschema`,
   Elastic `GET <index>/_mapping` — plus the two-minute reshape into the format.
2. **Agent (`declaration-author`, future plugin skill):** the user pastes
   whatever they have — fieldsummary output, CSV, a vendor data-dictionary
   page — and the agent reshapes it into a valid declaration; `adef schema
   lint` validates; human approves. Profile-author's twin: the format stays
   dumb and stable, the agent absorbs the hundred input shapes.
3. **Vendor MCP:** where the user runs their SIEM's MCP server alongside
   `adef-mcp`, the assistant can run the inventory query itself and draft the
   declaration in one conversation.

## Known tradeoff

Declarations can't express field *coverage* (how often a field is populated),
which affects rule reliability. Accepted for v1 — optional enrichment or a
future samples provenance can add it back; the simplification is worth it.

## Anti-goal check

No vendor connectors (declarations are files; recipes are docs). No new engine
types. Read-only on rule repos. No web UI.

## ISA entries to record

- Schema ingest is declaration-driven: users provide a data-source declaration
  (v1 format above); ADEF builds `schema_version: 2` artifacts with
  `declared | corrected` provenance and drift reporting on re-ingest.
- Rules are demoted from schema *source* to schema *consumer*: `schema check`
  cross-references rule field usage against declarations; `from-catalog` field
  derivation and the `schema init` wizard are deprecated (removal v0.2).
