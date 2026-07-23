# ADEF — What's Real (Status)

**Living doc.** The single answer to "what actually works right now?" Update it
when a command ships or changes. For *why* decisions were made, see `ISA.md`
(`## Decisions`); for the full command reference, see `CLAUDE.md`; for a
hands-on walkthrough, `docs/quickstart.md`.

> Supersedes the 2026-06-25 snapshot docs (`existing-vs-roadmap`,
> `whats-real-vs-proposed`, `v0.1.0-current-state`, `command-summary-for-team`),
> now in `docs/archive/`.

**Version:** v0.1.0 (unreleased — not on PyPI; install from source).
**Last updated:** 2026-07-23.

---

## Shipped and working

Everything below is implemented, tested, and exercised end-to-end.

### Workspace & lifecycle
- **`adef init`** — scaffold a workspace (`journals/`, `catalog/`, `schema/`,
  `config/`, `templates/`, operator `AGENTS.md`). `--interactive` captures
  SIEM platform + query languages into config; `--force` refreshes. Using ADEF
  as your detection home? Version the workspace with native git —
  `docs/detection-home.md`.
- **`adef detection new "title"`** — create a FORGE journal at Find stage.
  `--source <schema>` also scaffolds a **schema-grounded draft catalog record**
  (platform / query_language / scope literals from the declaration) — the
  starting point for authoring a new rule. Omit `--source` for a journal only.
- **`adef detection observe / refine / govern / evolve`** — advance FORGE
  stages, append timestamped journal blocks. `refine` runs the
  Similarity → Overlap → Verification chain. (These update the journal; they
  don't auto-query data sources.)
- **`adef detection tag-mitre D-XXXX T####`** — add ATT&CK IDs to a catalog
  record, validated against the shipped reference; drops the `no_mitre` flag.
- **`adef hunt-promote H-XXXX`** — promote an ATHF hunt to a draft detection.
- **`adef backfill journals`** — bulk-create journals for existing rules.

### Cataloging (read-only over a rules repo)
- **`adef catalog <rule-root>`** — walk a detection repo read-only; recognize
  format by content signature (Sigma, Splunk ESCU, Panther, SPL `.conf`, raw
  sql/kql/cql); write `catalog/<platform>/D-XXXX.yml` + `INDEX.yml` + skeleton
  journals. `--dry-run`, `--report json` (unclaimed clustering), `--profile`
  (extraction-rate scoreboard for in-house formats). Re-cataloging a repo whose
  rules are already present is **refused** (→ use `adef sync`, or `--force`);
  a genuinely new repo appends cleanly.
- **`adef profile lint`** — validate an extraction profile for an in-house format.
- **`adef sync <rule-root>`** — reconcile the catalog after the repo changes:
  identity cascade (`rule_uuid` → `source_hash` → path → new; gone → orphaned,
  never deleted); refreshes derived fields, **preserves enrichment** (mitre /
  status / owner / journal); journals out-of-band edits. Skips `origin: authored`
  records (created in ADEF, no upstream). `--dry-run` /`--check` (CI). Fuzzy
  rename-match deferred (falls to `new`, never mis-attributes).

### Browse
- **`adef detection list`** — filter by `--platform / --rule-format / --status /
  --stage / --tactic / --engine / --needs-review`; `--report json`.
- **`adef detection show D-XXXX`** — record + query + derived ATT&CK tactics +
  paired-journal stage history.

### Schema (declaration-driven)
- **`adef schema ingest adef-sources.yml`** — build `schema/<source>.yml`
  (v2, `declared|corrected` provenance, drift on re-ingest).
- **`adef schema lint`** — validate a declaration.
- **`adef schema check`** — cross-reference rule field usage vs. schemas
  (sql / spl / cql / kql / **sigma** — Sigma fields are the `detection:` block's
  map keys, minus `|modifiers`).
- **`adef schema show <source>`** — display a schema.
- **`adef schema recipe [platform]`** — SIEM-specific field-extraction recipe
  (7 platforms). The Splunk query keeps distribution columns
  (`fieldsummary maxvals=50`) and strips search-time meta
  (`eventtype`/`tag`) before export.
- **`adef schema reshape <export> [--platform p]`** — convert a raw SIEM field
  export (Splunk fieldsummary CSV / Sentinel getschema CSV / Elastic `_mapping`
  JSON / plain field list) into a draft declaration via the five reshape rules:
  internals filter, case-dupes → aliases, capped enum harvesting (≤50 distinct),
  type inference, mixed-shape guard (refuses multi-sourcetype exports). Prints a
  transformation report (inferred scope, drops, folds, `[SUSPECT]` folds with
  per-spelling value evidence). Folds that merge two different fields are split
  with repeatable `--no-fold <name>` flags, or walk them with `--interactive`
  (keep/split prompts with a `?` help checklist; adjudicated pairs are recorded
  as decisions, never re-flagged; ends by prompting for source `platform:` +
  `description:` so the file is ingest-ready; closes with a reproducible
  `--no-fold` command). SIEM platform is never inferred; read from workspace
  config when omitted. `--append <decl.yml>` adds the source to an existing
  declaration (multi-table flows). Also exposed as the `schema_reshape` MCP
  tool (returns suspect evidence structurally for agent adjudication). `--append <decl.yml>`
  adds the source to an existing declaration (multi-table flows; duplicate
  source names refused). Also exposed as the `schema_reshape` MCP tool
  (returns the report incl. suspect-merge evidence for agent adjudication).

All workspace-reading commands resolve the workspace identically
(`adef/core/workspace.py`): explicit `--workspace` → `ADEF_WORKSPACE` →
current dir (if it has `catalog/` or `journals/`) → `~/work/adef-workspace`.

### ATT&CK & coverage
- **`adef attack info / show / refresh`** — ATT&CK reference layer (shipped
  snapshot; `refresh` pulls newer from official STIX).
- **`adef coverage [--navigator layer.json] [--gaps]`** — coverage *quality*
  report (solid/fragile tiers, log-source concentration, single points of
  failure, fictional coverage) + scored Navigator export.

### Interfaces
- **`adef-mcp`** — FastMCP server exposing lifecycle / memory / schema tools.
- **Claude plugin** (`claude-plugin/`) — skills: `catalog-onboarding`,
  `detection-explorer`, `coverage-review`, `mitre-tagger`, `detection-author`,
  `schema-declaration`; `profile-author` sub-agent. Inactive until `/plugin install`.

## Not built yet (roadmap)

- **Staleness-aware reads** — `adef sync` reconciles on demand; the CLI/MCP read
  paths don't yet auto-warn "catalog is N commits behind" (sync design doc §
  staleness-aware reads). The `catalog_sha` needed for it is already stored.
- **Fuzzy rename-match in sync** — UUID-less renamed+edited rules show as `new`
  today (safe: a duplicate a human merges, never a silent mis-attribution).
- **Repo write-back for authored rules** — authored rules land in the ADEF
  catalog; getting them into the user's rules repo is deferred (options weighed
  in `ISA.md`).
- **Evolve data seam** — `adef detection stats --results` for FP/volume data.
- **Per-alias values + namespace preference (v2)** — a folded field keeps only
  the canonical spelling's `values`; pairing the alias spelling with those
  values (`Status=failure`) is legal per schema but matches nothing in the
  SIEM. Until v2: author with the canonical spelling, or split
  encoding-variant folds with `--no-fold` (each spelling then keeps its own
  vocabulary).
- **Data-model schemas (v2)** — declarations model the index namespace;
  Splunk `tstats` rules query data-model fields (`Processes.process_name`)
  that never appear in a `fieldsummary` export, so `schema check` union-misses
  them (~39% of ESCU). Future seam: declare a data model as a source.

## Anti-goals (CI-enforced — will never ship)

No writes under any `detections/` tree · no new engine types beyond
`sigma|sql|sch_sql|composite` · no vendor API connectors · no web-UI deps.
