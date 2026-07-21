# AGENTS.md — ADEF Workspace

This directory is an **ADEF workspace**: the durable memory and enrichment
layer for a detection-engineering program. If you are an AI assistant working
here, this file is your briefing. The `adef` CLI is your toolset — prefer it
over hand-editing generated files.

## Ground rules

1. **Never write to upstream rule repositories.** ADEF reads them; all
   enrichment (MITRE mappings, platform, lifecycle state, notes) is written
   to *catalog records* and *journals* in this workspace.
2. **Never invent MITRE technique IDs.** Only record IDs found in the rule
   or explicitly confirmed by the human.
3. **`catalog/INDEX.yml` is generated** — rebuild it via `adef catalog`;
   never hand-edit.
4. **`schema/*.yml` fields marked `provenance: corrected` are human edits** —
   preserved across re-ingest. Don't overwrite them; add your own corrections
   with that marker only when the human approves.
5. When writing or reviewing queries, **use only fields declared in
   `schema/<source>.yml`** (names + aliases). Enum `values` there are the
   legal predicate values — don't guess others.

## What lives here

- `catalog/` — one enrichment record per detection (`D-XXXX-<slug>.yml`:
  title, query, platform, MITRE, lifecycle stage/status, provenance pointers
  back to the source rule) + generated `INDEX.yml`
- `journals/` — per-detection FORGE journals (`D-XXXX.md`): the *why*,
  timestamped stage transitions, tuning decisions. Read the journal before
  proposing changes to a detection.
- `schema/` — declared data sources: fields, types, enum values, aliases,
  `scope` (the literals queries use to address the source)
- `config/profiles/` — extraction profiles teaching ADEF in-house rule formats
- `templates/` — journal template used by `adef detection new`

## Command map

```bash
# Browse (all support --report json for machine-readable output)
adef detection list                          # + --platform --rule-format --status --stage
adef detection list --needs-review           # structural problems (reasons shown)
adef detection list --needs-review no_mitre  # ATT&CK enrichment queue
adef detection show D-0042                   # record + query + journal history

# Onboard rules (read-only on the source repo)
adef catalog /path/to/rules --dry-run --report json   # triage first
adef catalog /path/to/rules                           # records + journals + INDEX

# Data schemas (user-provided declarations, never inferred from rules)
adef schema ingest adef-sources.yml          # drift reported on re-ingest
adef schema lint adef-sources.yml
adef schema show <source>
adef schema check --report json              # rule fields vs declared schemas

# FORGE lifecycle (journals)
adef detection new "Title"
adef detection observe|refine|govern|evolve D-XXXX --note "..."
```

## Workflows you should drive (not just describe)

**Unclaimed files after `adef catalog`** — in-house formats need an
*extraction profile*. Cluster the report's unclaimed files by
`top_level_keys` (one cluster = one format), read 2–3 samples, draft a
profile, then let the engine score it:
`adef profile lint <draft>` → `adef catalog <root> --dry-run --profile
<draft>` (targets: query ≥95%, title ≥90%). On human approval, save to
`config/profiles/` and re-run. Full guide: `docs/creating-extraction-profiles.md`
in the ADEF repo.

**Declaring data sources** — when the human provides a field inventory
(Splunk `| fieldsummary`, KQL `| getschema`, a vendor data dictionary),
reshape it into a declaration: drop platform internals (`_*`, `punct`,
`date_*`, `splunk_server`), fold case-duplicates into `aliases`, keep top
values for low-cardinality fields, one source per event *shape* with
`scope: {index: ..., sourcetype: ...}` when a container holds several.
`adef schema lint` before ingesting. If one export mixes shapes, ask for
per-sourcetype re-exports rather than guessing the split.

**Review triage** — `needs_review` carries reasons: `malformed` and
`external_logic` are structural (investigate); `no_platform` usually means
no declared schema matches the rule's literals (declaring the data source
fixes it at the next catalog run); `no_mitre` is enrichment work — propose
mappings to the human, never auto-write them.

**Before drafting a new detection** — check for overlap first
(`adef detection list --report json`, journal search), confirm the target
fields exist in `adef schema show <source>`, and run `adef schema check`
after cataloguing the result.

## Method

FORGE: Find → Observe → Refine → Govern → Evolve. Journals are the memory —
every material decision gets a stage note (`--note`). Framework docs:
https://github.com/Nebulock-Inc/agentic-detection-engineering-framework
(methodology.md, maturity-model.md, declaring-data-sources.md,
creating-extraction-profiles.md).
