# ADEF Catalog — Design & Implementation Notes

**Date:** 2026-07-15
**Status:** Implemented (v1, this session)
**Shortcut:** Epic 6996 (ADEF) — stories 7387 (Catalog Detections), 7388 (YAML
format), 7389 (INDEX.yml), 7393 (browsing, deferred)

---

## What this is

The **catalog** turns an existing detection-rule repository into ADEF's
enrichment artifact. You point ADEF at a repo; it walks the repo read-only,
classifies each rule, and writes an ADEF record per rule that *references* the
source file and layers ADEF's metadata on top. The source repo is never
modified.

This is the first of two ingestion paths discussed with the team:

1. **Point-at-a-repo** (built now) — walk a rules repo, catalog what's there.
2. **Export-from-a-tool** (future) — ingest rules exported from a SIEM/EDR via
   the same results-in seam. Designed around, not built.

## Artifacts

```
<workspace>/
  catalog/
    windows/D-0002-suspicious-mshta-exe-child-process.yml
    cloud-aws/D-0005-iam-backdoor-user.yml
    multi-platform/D-0001-iam.yml        # escape hatch when platform unknown
    INDEX.yml                            # generated, never hand-edited
  journals/
    D-0002.md                            # paired skeleton journal (shared ID)
```

### Catalog record — `catalog/<platform>/D-XXXX-<slug>.yml`

```yaml
id: D-0002
title: Suspicious mshta.exe child process
rule_ref: their-detections/windows/mshta.yml   # pointer to source (relative)
original_path: /abs/.../their-detections/windows/mshta.yml  # provenance
rule_uuid: 03cc0c25-389f-...                    # embedded rule UUID (Sigma id:) — sync identity key; '' if none
query: |                                        # detection logic, verbatim (block scalar)
  <the rule's query / SPL / SQL / Sigma body>   # empty when logic is external (Panther .py)
platform: windows
kind: atomic                 # atomic | correlation | composite
engine: sigma                # INTERNAL 4-value taxonomy (sigma|sql|sch_sql|composite)
format: sigma                # TRUE source format (sigma|spl|kql|cql|sql) — lossless
mitre: [T1218.005]
status: draft                # draft | ready | tuning | deprecated
stage: find                  # find | observe | refine | govern | evolve
owner: ''
needs_review: false          # true when platform/MITRE couldn't be inferred
created: 2026-07-15T...
updated: 2026-07-15T...
```

**`engine` vs `format`.** `engine` is ADEF's internal four-value taxonomy, kept
intact so `tests/test_no_new_engine_types.py` still guards it. `format` carries
the true source language losslessly. Non-Sigma formats fold their `engine` to
`sql` while `format`/`query_language` preserve `spl`/`kql`/`cql`/`sql`. (The
four engines are an internal convention, not a limit imposed on a user's repo —
so we record the real format rather than lose it.)

### INDEX.yml — generated lookup

`detections` (ID→path) plus reverse maps `by_platform`, `by_tactic` (keyed by
MITRE technique until tactics are resolved), `by_engine`, `by_status`. Rebuilt
on every `adef catalog` run.

## Behaviour

- **Read-only** on the source repo. CI-enforced: no ADEF write path contains a
  `detections/` segment (`tests/test_schema_parity.py`). Catalog output is
  always under `catalog/`.
- **Infer-and-flag, never block.** Cataloging never prompts. Ambiguous rules
  (raw SQL/CQL with no platform/MITRE) get `needs_review: true` and the
  `multi-platform` platform fallback.
- **Shared ID space.** `D-XXXX` IDs clear the max of both catalog and journals,
  so catalog + journal + INDEX stay tied by ID. Each catalogued rule also gets
  a skeleton journal.
- **Multi-format sniff.** Sigma `.yml` (full auto-extract: title, logsource →
  platform, tags → MITRE), Splunk `.conf` savedsearches, `.kql` (table →
  platform), `.sql`, `.cql`.

## Code

- `adef/core/rule_discovery.py` — the **shared** repo walk. `discover_rules()`
  yields `DiscoveredRule` (format, query_text, best-effort platform/MITRE/kind).
  `sniff_format()` classifies a file. `scan_rule_fields()` returns field names
  for a query language — this closes the schema feature's documented v1 gap (the
  stubbed rule scanner in `adef/commands/schema.py`).
- `adef/core/catalog.py` — `CatalogRecord`, `Catalog` (write + `rebuild_index`),
  `record_from_discovered`, `next_id` (shared ID space).
- `adef/commands/catalog.py` — the `adef catalog` CLI command.

## Overlap with the schema feature (deliberate)

The schema feature (`adef schema init`, shipped 2026-07-15) needs to scan a rule
repo for field names but shipped that scanner stubbed. Cataloging needs the same
walk. Both now consume `rule_discovery`, so there is one repo-walker, not two.
Schema ignores Sigma (structured YAML, not a query language); catalog handles
all formats. `adef schema init --rule-root <path>` now populates `in_rules`
fields for real.

## Deferred (not this session)

- `adef detection list/show` + `adef coverage` browsing (story 7393).
- Reconciliation / `adef sync` when the source repo changes externally.
- Export-from-tool ingestion path.
- Slim-ADS enrichment fields (goal/strategy/blind_spots/...) — filled through
  FORGE stages, not at catalog time.
