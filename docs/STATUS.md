# ADEF — What's Real (Status)

**Living doc.** The single answer to "what actually works right now?" Update it
when a command ships or changes. For *why* decisions were made, see `ISA.md`
(`## Decisions`); for the full command reference, see `CLAUDE.md`; for a
hands-on walkthrough, `docs/quickstart.md`.

> Supersedes the 2026-06-25 snapshot docs (`existing-vs-roadmap`,
> `whats-real-vs-proposed`, `v0.1.0-current-state`, `command-summary-for-team`),
> now in `docs/archive/`.

**Version:** v0.1.0 (unreleased — not on PyPI; install from source).
**Last updated:** 2026-07-22.

---

## Shipped and working

Everything below is implemented, tested, and exercised end-to-end.

### Workspace & lifecycle
- **`adef init`** — scaffold a workspace (`journals/`, `catalog/`, `schema/`,
  `config/`, `templates/`, operator `AGENTS.md`). `--interactive` captures
  SIEM platform + query languages into config; `--force` refreshes.
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
  (extraction-rate scoreboard for in-house formats).
- **`adef profile lint`** — validate an extraction profile for an in-house format.
- **`adef sync <rule-root>`** — reconcile the catalog after the repo changes:
  identity cascade (`rule_uuid` → `source_hash` → path → new; gone → orphaned,
  never deleted); refreshes derived fields, **preserves enrichment** (mitre /
  status / owner / journal); journals out-of-band edits. `--dry-run` /`--check`
  (CI). Fuzzy rename-match deferred (falls to `new`, never mis-attributes).

### Browse
- **`adef detection list`** — filter by `--platform / --rule-format / --status /
  --stage / --tactic / --engine / --needs-review`; `--report json`.
- **`adef detection show D-XXXX`** — record + query + derived ATT&CK tactics +
  paired-journal stage history.

### Schema (declaration-driven)
- **`adef schema ingest adef-sources.yml`** — build `schema/<source>.yml`
  (v2, `declared|corrected` provenance, drift on re-ingest).
- **`adef schema lint`** — validate a declaration.
- **`adef schema check`** — cross-reference rule field usage vs. schemas.
- **`adef schema show <source>`** — display a schema.
- **`adef schema recipe [platform]`** — SIEM-specific field-extraction recipe
  (7 platforms).
- **`adef schema reshape`** — convert a raw SIEM field export into a draft
  declaration.

### ATT&CK & coverage
- **`adef attack info / show / refresh`** — ATT&CK reference layer (shipped
  snapshot; `refresh` pulls newer from official STIX).
- **`adef coverage [--navigator layer.json] [--gaps]`** — coverage *quality*
  report (solid/fragile tiers, log-source concentration, single points of
  failure, fictional coverage) + scored Navigator export.

### Interfaces
- **`adef-mcp`** — FastMCP server exposing lifecycle / memory / schema tools.
- **Claude plugin** (`claude-plugin/`) — skills: `catalog-onboarding`,
  `mitre-tagger`, `detection-author`, `schema-declaration`; `profile-author`
  sub-agent. Inactive until `/plugin install`.

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

## Anti-goals (CI-enforced — will never ship)

No writes under any `detections/` tree · no new engine types beyond
`sigma|sql|sch_sql|composite` · no vendor API connectors · no web-UI deps.
