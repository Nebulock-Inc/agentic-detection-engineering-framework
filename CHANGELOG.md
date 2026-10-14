# Changelog

All notable changes to ADEF are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut by tagging `vX.Y.Z` — `.github/workflows/publish.yml` refuses a
tag that doesn't match `version` in `pyproject.toml`, and `adef/__init__.py`
must agree with both.

## [Unreleased]

## [2.0.0] — 2026-10-13

The second major pass over ADEF. The headline is that the Evolve stage now
closes: numbers go in, a dated keep/tune/deprecate verdict comes out, and
nothing in the loop contacts your environment.

### Added

- **Detection health capture (`adef ingest`).** Five self-describing document
  kinds — `metrics`, `performance`, `deployment_drift`, `source_health`,
  `field_observations` — stored under `<workspace>/health/`. The three
  detection-keyed kinds get a latest snapshot *plus* an append-only `.jsonl`
  history, so each new capture is a data point (re-ingesting the same document
  adds nothing, and a backfill of an older capture never replaces a newer
  `latest/` entry); the two source-keyed kinds
  (`source_health`, `field_observations`) are latest-only. A producer hands over
  a file; ADEF never queries the environment the numbers came from. `--dry-run`
  validates and writes nothing. Also exposed as the `health_ingest` MCP tool.
- **Health readback (`adef health show`).** Prints the stored document plus the
  derived values the Evolve heuristics actually read — `fp_ratio`,
  `weekly_signal_volume`, `days_since_true_positive`. This closed the loop that
  was open: `adef detection evolve` used to report `insufficient-data` on
  numbers the user had just ingested. Twin MCP tool: `health_show`.
- **Workspace self-check (`adef doctor`).** Ten checks over one workspace, each
  carrying the literal next command to run. Warnings (an optional capability
  nobody set up) exit 0 so it's safe in CI; problems (state that makes another
  command *lie*, like a stale `INDEX.yml`) exit 1. Read-only, including on the
  directory it's pointed at.
- **GATES import (`adef hunt-promote --gates`).** Imports an ATHF GATES
  document: deployable candidates (`PROMOTE` / `CONDITIONAL` / `TIME_BOX`) each
  land as a catalog record with `origin: promoted` plus a journal carrying the
  hunt's reasoning, with `CONDITIONAL` and `TIME_BOX` flagged for review.
  Archival verdicts are reported and nothing is written. Idempotent on
  `hunt_ref`.
- **Cross-language similarity retrieval.** Two retrieval passes beyond BM25,
  fused by reciprocal rank fusion: a field-set pass that matches rules on the
  predicate fields their queries filter on (canonicalized through declared
  schema aliases, so a Sigma rule and a SQL rule reading the same field find
  each other with no shared tokens), and a value pass that matches rules in a
  *different* query language testing the same rare literals — which needs no
  schema at all. Each run reports a `field_matching` state naming how well
  canonicalization worked, rather than degrading silently.
- **`adef schema reshape`** — converts a raw field export into a draft
  declaration deterministically, folding case-duplicate fields into aliases and
  printing a transformation report to approve. **`adef schema recipe`** prints
  the exact field-export command for six named SIEMs.
- **Bulk-export extraction profiles.** A profile can fan out over a records
  container, so one JSON or YAML export file yields many rules.
- **`adef attack refresh`** — pull a fresh ATT&CK snapshot from official STIX
  into the workspace, where it wins over the shipped copy. Shipped snapshot is
  now ATT&CK v19.1.
- **Coverage gaps.** `adef coverage` reports how many ATT&CK techniques you
  cover of the total with fully-blind tactics flagged; `--gaps` lists the
  uncovered technique IDs by tactic.
- **`adef detection list` filters** `--origin`, `--engine` and `--tactic`, plus
  `--report json`.
- **ADEF-native Refine agents.** Similarity, Overlap and Verification now run
  natively by default. An `ADEF_WRAPPER_*` binding is an opt-in override, not a
  prerequisite — a missing binding no longer raises `WrapperUnavailable`.
- **Nine task-specific skills** and the `profile-author` sub-agent, installable
  for Claude Code or Codex/ChatGPT via `adef install-skills`.
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and this changelog.
- `examples/weekly-metrics.yml` — a runnable health capture for the bundled
  demo, so the Evolve half of the arc works out of the box.

### Changed

- **`adef sync` reconciles instead of re-cataloging.** Each rule is matched to
  its record through an identity cascade (`rule_uuid` → `source_hash` →
  `rule_ref` path → new). On a match, derived fields are refreshed while
  enrichment — `mitre`, `status`, `stage`, `owner`, and the journal — is
  preserved. A rule whose source vanished is marked orphaned, never deleted.
  `--check` is the CI/PR mode.
- **Records carry `origin`** (`authored` / `catalogued` / `promoted`). `sync`
  skips `authored` and `promoted` records, so a team using ADEF as its detection
  home keeps its own rules through a sync.
- **`adef catalog` refuses a re-catalog** of rules already in the workspace
  rather than minting duplicates, pointing at `adef sync` or `--force`.
- **Overlap is honest about what it can't compare.** A pair in two different
  query languages comes back `unassessed` rather than scored — retrieval across
  languages works; comparing logic across them doesn't yet.
- **Schemas are declaration-driven.** Users provide a sources-and-fields
  document; ingest writes `schema/<source>.yml` with `declared | corrected`
  provenance, and a re-ingest preserves human corrections and reports drift.
  Rules are a schema *consumer* (`adef schema check`), never a schema *source*.
- `ADEF_WRAPPER_PERFORMANCE_METRICS` is now `ADEF_WRAPPER_METRICS`; the old name
  keeps working as a deprecated alias. When set, the collector's numbers
  override stored health for both Evolve recommendations; it must report
  `window_days` for the silence rules to fire, since a detection only reads as
  silent over a window of at least seven days.
- A backward FORGE stage move is refused unless explicitly asked for.
- The built-in recognizer for the maintainers' in-house rule format was removed.
  ADEF ships no dialect-specific recognizer for a private format — teach it one
  with an extraction profile.

### Fixed

- **`adef install-skills` works from a PyPI install, not only a clone.** The
  bundled skills sat in a repo-root `claude-plugin/`, outside any declared
  package, so no `package-data` glob could reach them — the 1.0.0 wheel on PyPI
  contains none of them, and `_bundled_plugin_dir()` resolved into
  `site-packages`, so the command failed with "no bundled skills found". They
  now live at `adef/data/claude-plugin/` and ship with the wheel; the plugin
  marketplace reads the same single copy. `adef doctor`'s skills check works on
  a wheel install too, where it previously reported `cannot verify`.
- **A misspelled `metrics` row key is no longer silent.** A row carrying
  `false_positives_count` validated, reported as ingested, and derived nothing —
  so `adef detection evolve` returned `keep` for a rule that was 480/482 false
  positive. Both `adef ingest` and the `health_ingest` MCP tool now report it.
- `fp_ratio` is withheld unless *both* the FP and TP counts are present:
  defaulting an absent TP count to zero reported `fp_ratio: 1.0` about a number
  nobody supplied. Derived keys are omitted when absent, never emitted as `0.0`
  — both recommenders decide "insufficient data" on key presence, so a
  fabricated zero would read as a measured zero. Negative and junk values count
  as absent.
- Recommenders return insufficient data instead of a reassuring verdict when
  they have nothing to reason from.
- Sigma rules are searched and compared as their `logsource`/`detection` blocks
  and description, not as whole YAML files — so references, authors and dates
  stopped polluting both retrieval and the egress sent in `llm` mode.
- Overlap compares a technique against its parent and sub-techniques, never
  sibling sub-techniques, and an SPL duplicate requires an identical canonical
  form rather than passing a similarity threshold.
- `adef sync` on one repo no longer orphans another repo's records, and
  same-named repos stay separate.
- A catalog write can never land outside `catalog/`; a declaration source name
  can never escape `schema/`; a health document's detection ID and source name
  can never escape `health/`.
- `hunt-promote --dry-run` wrote for real when `--gates` was absent.
- Splunk ESCU rules read their MITRE IDs from `tags.mitre_attack_id`, where they
  actually live.
- The `mcp` extra is pinned to `mcp>=1.0.0,<2`, and an incompatible installed
  SDK is named as such rather than reported as "not installed".

## [1.0.0] — 2026-08

First tagged release: the FORGE lifecycle (`adef detection new` / `observe` /
`refine` / `govern` / `evolve`) over per-detection journals, `adef catalog` for
walking a rule repo read-only, BM25 memory search, the coverage-quality report,
the plugin system (`adef.commands` / `adef.agents` / `adef.mcp_tools`), and the
`adef-mcp` FastMCP server.

[Unreleased]: https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/releases/tag/v1.0.0
