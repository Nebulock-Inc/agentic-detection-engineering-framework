# ADEF Feature-Branch Handoff — `feature/adef-v1-design`

**Last updated:** 2026-07-15
**Audience:** the two of us collaborating on this branch, and any future Claude
Code session that needs cross-session context.
**Keep this current.** When you finish a chunk of work on this branch, add a
dated entry under "Session log" and update "Current state" + "Open threads".

> This doc is the *branch collaboration* view. For the broader v0.1.0 inventory
> see `docs/v0.1.0-current-state.md`; for the catalog spec see
> `docs/plans/2026-07-15-catalog-design.md`; for schema see
> `docs/superpowers/specs/2026-07-14-schema-storage-design.md`. The system of
> record for decisions is `ISA.md`.

---

## Who's building what

| Area | Owner | Shortcut | Status |
|------|-------|----------|--------|
| Schema storage (`adef schema *`) | co-worker (Eric) | Epic 6996 / story 7396 | v1 shipped, in tree |
| Cataloging (`adef catalog`) | Jarrett | Epic 6996 / stories 7387, 7388, 7389 | v1 built this session (uncommitted) |
| Browsing (`adef detection list/show`, `adef coverage`) | unassigned | story 7393 | deferred |

Both features share one module — see "The shared seam" below. Coordinate before
changing `adef/core/rule_discovery.py`, the catalog record shape, or the schema
YAML shape, because each is consumed by the other's feature.

---

## The environment (read this first if commands fail)

- There is **no committed virtualenv**. This session created `.venv/` (gitignored)
  from pyenv Python **3.11.11**, which is the only interpreter here with `adef`
  editable-installed + `pytest`.
- Run tests with: `.venv/bin/python -m pytest -q`
- Run the CLI with: `.venv/bin/adef ...`
- If `.venv` is missing, recreate: `~/.pyenv/versions/3.11.11/bin/python -m venv .venv && .venv/bin/pip install -e ".[dev]"`
- `sqlglot` is a real runtime dep (SQL parsing). `anthropic`/`openai` are optional
  (`.[llm]`); without them, schema description generation degrades gracefully.

---

## Current state (as of 2026-07-15)

**Everything from the cataloging session is UNCOMMITTED** (working tree only).
`git status` shows new files + modifications; nothing is staged/committed yet.

Full suite: **106 passed** (73 pre-existing schema/core tests + 33 new).
Anti-goal guards green: `test_schema_parity` (no `detections/` writes),
`test_no_new_engine_types` (engine stays 4-value).

### New files (catalog feature)
- `adef/core/rule_discovery.py` — **shared** read-only repo walk. Public API:
  `discover_rules()`, `sniff_format()`, `scan_rule_fields()`, `DiscoveredRule`.
- `adef/core/catalog.py` — `CatalogRecord`, `Catalog` (`.write`, `.rebuild_index`,
  `.next_id`), `record_from_discovered`, `catalog_dir`.
- `adef/commands/catalog.py` — the `adef catalog <rule-root>` command.
- `tests/test_rule_discovery.py`, `tests/test_catalog.py`,
  `tests/test_catalog_command.py`, `tests/test_rule_field_scan.py`.
- `docs/plans/2026-07-15-catalog-design.md` — the spec.

### Modified files
- `adef/commands/schema.py` — the stubbed rule scanner (`rule_fields = set()`) is
  replaced with `scan_rule_fields(rule_root, query_language)`. **This closed the
  schema feature's documented v1 gap.**
- `adef/commands/init.py` — `adef init` now creates `catalog/`.
- `pyproject.toml` — registered `catalog` entry point.
- `AGENTS.md`, `CLAUDE.md`, `ISA.md`, `docs/development/schema-feature-progress.md`
  — doc updates.
- `.gitignore` — added `.venv/`.

---

## What `adef catalog` does

`adef catalog /path/to/rules` walks a detection repo read-only, sniffs each
rule's format (Sigma `.yml`, Splunk `.conf`, `.kql`, `.sql`, `.cql`), and writes:
- `catalog/<platform>/D-XXXX-<slug>.yml` — enrichment record referencing the
  source via `rule_ref` (+ absolute `original_path`). Never modifies the source.
- `catalog/INDEX.yml` — generated lookup: `detections` + `by_platform`/`by_tactic`
  /`by_engine`/`by_status`.
- a paired skeleton journal per rule (shared `D-XXXX` ID space with journals).

Rules whose platform/MITRE can't be inferred get `needs_review: true` (we never
prompt mid-run — "infer and flag"). `--dry-run` previews without writing.

**`engine` vs `format` — remember this.** Catalog `engine` stays in ADEF's
internal 4-value taxonomy (`sigma|sql|sch_sql|composite`) so
`test_no_new_engine_types.py` keeps guarding it. The *true* source format lives
in a separate `format` field (`sigma|spl|kql|cql|sql`), lossless. Jarrett
confirmed the 4 engines are an internal convention, not a limit on a user's repo.

---

## The shared seam (why the two features touch)

The schema feature needs to scan a rule repo for field names; cataloging needs to
walk the same repo. Both now go through **`adef/core/rule_discovery.py`** so there
is one repo-walker, not two that drift.

- `scan_rule_fields(rule_root, language)` → `set[str]` field names for one query
  language. Used by `adef schema init --rule-root`.
- `discover_rules(rule_root)` → `DiscoveredRule` per file (format, query_text,
  best-effort platform/MITRE/kind). Used by `adef catalog`.

Schema ignores Sigma (structured YAML, not a query language); catalog handles all
formats. If you extend the walker, keep both callers working.

---

## Open threads (decide before building)

### 1. Generate schema *from the catalog* (✅ IMPLEMENTED 2026-07-16)
Built as designed. `data_source` is now inferred at catalog time (raw literal)
and carried on `CatalogRecord`; `adef schema from-catalog` groups by
`(data_source, query_language)` into `schema/<source>.yml`, un-inferred rules
pool by language. 119 tests pass. See ISA.md for the verification entry.
Remaining follow-ups from this thread: (a) `adef schema update`/`rescan` are
still stubs — from-catalog writes rules-only schemas (`in_data: false`), so
piping data to populate types/populations depends on `update` being finished;
(b) raw-literal fragmentation watch (below) if source naming proves inconsistent.

<details><summary>Original decision (kept for context)</summary>
Today `adef schema init` re-walks the raw repo and makes you pick one
`query_language`. The catalog already inventoried those rules. The ask: drive
schema generation from the catalog instead of a second raw walk.

**The crux:** a schema is per-data-source (`schema/edr_process.yml`), but catalog
records carry `format`, **not** which data source a rule queries. So catalog→schema
needs a mapping.

**RESOLVED 2026-07-16 (design agreed, not yet built).** Hybrid of the three
options discussed (A: group-by-language, B: capture data_source at catalog time,
C: named per-source). See `ISA.md` Decisions for the authoritative entry. Shape:

- **Capture `data_source` on `CatalogRecord`** (B's mechanism), inferred during
  discovery from the **raw table/index/logsource literal, verbatim — no
  normalization**: Sigma `logsource` value, KQL lead table, SQL `FROM` table,
  SPL `index=`. When no literal is resolvable, `data_source` stays empty and the
  record keeps `needs_review: true` (reuses the existing flag).
- **`adef schema from-catalog`** (new command) reads the catalog/INDEX and writes
  one `schema/<data_source>.yml` per confident `(data_source, query_language)`
  group. Rules with **no** inferred source **fall back to pool-by-language**
  (`schema/sql.yml`, `schema/kql.yml`, …) — Option A as the catch-all, so fields
  are never lost; the coarse bucket is the triage queue.

**Why hybrid:** serves both drift detection (fields captured regardless of source)
and authoring grounding (per-source accuracy where we're confident), while the
un-inferrable tail degrades to coarse pooling instead of a false-confident schema.

**Known tradeoff (flag for co-worker):** raw-literal source names can fragment the
same logical source if the repo isn't consistent (`cloudtrail` vs `aws_cloudtrail`
vs `CloudTrail` → three schema files). Accepted to avoid guessing. Upgrade path if
messy: a normalization/alias map later; nothing here blocks it.

**Status:** design locked in writing; **no code written yet.** Next step when
building: add `data_source` to `CatalogRecord` + inference in `rule_discovery`,
then the `from-catalog` command, TDD. Coordinate with co-worker before changing
`CatalogRecord` since schema consumes it.

</details>

### 2. Deferred catalog work (not started)
- `adef detection list/show` + `adef coverage` browsing (story 7393).
- Reconciliation / `adef sync` when the source repo changes externally.
- Export-from-tool ingestion (the second ingestion path; v1 is point-at-a-repo).
- Slim-ADS enrichment fields (goal/strategy/blind_spots/…) filled via FORGE stages.

### 3. Pre-existing lint (not ours, don't fix blindly)
`ruff check adef/` reports ~11 errors in files we didn't author for this feature
(`cli.py`, `data_sampler.py`, `journal.py`, `schema_tools.py`, and unused imports
in `schema.py`). Out of scope for the catalog work; leave unless you own that file.

---

## Session log

### 2026-07-16 (later) — Schema-from-catalog implemented (Jarrett + Claude)
- Built the agreed design TDD: `data_source` inference in `rule_discovery`,
  carried onto `CatalogRecord` (+ `by_data_source` in INDEX), new
  `adef schema from-catalog` command (group by source, pool-by-language fallback,
  Sigma excluded).
- Full suite **119 passed** (was 106). Guards green. End-to-end verified.
- Follow-up: `adef schema update`/`rescan` still stubs → from-catalog writes
  rules-only schemas until `update` populates data fields.

### 2026-07-16 — Schema-from-catalog design agreed (Jarrett + Claude)
- Resolved open thread #1. Hybrid design (capture raw-literal `data_source` at
  catalog time; `adef schema from-catalog` groups by `(data_source, language)`;
  un-inferred rules pool by language as the fallback). Logged in `ISA.md`.
- No code yet — awaiting co-worker sign-off on the `CatalogRecord` change and the
  raw-literal fragmentation tradeoff.

### 2026-07-15 — Cataloging v1 (Jarrett + Claude)
- Built `adef catalog` (discovery → catalog records + INDEX + skeleton journals).
- Introduced `adef/core/rule_discovery.py` as the shared repo-walk; wired it into
  `adef schema init`, closing schema's stubbed-scanner gap.
- Kept `engine` in the internal 4-set; added lossless `format` field.
- 106 tests pass. Work is uncommitted on `feature/adef-v1-design`.
- Paused on "schema from catalog" (open thread #1) pending co-worker alignment.
