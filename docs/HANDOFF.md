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

## Strategic feedback & direction (captured 2026-07-17)

> **Status: input, not decisions.** This section is external design feedback
> plus the usage scenarios we want to support. It's captured verbatim-in-spirit
> so we can make design decisions *from* it. Nothing here is committed until it's
> agreed and logged in `ISA.md`. When we adopt a point, note the decision there
> and link back to it here.

### Why this matters

The bar to judge v0.1 against: **what does a skeptical detection-engineering lead
get in the first 15 minutes with zero manual journaling?** Right now the honest
answer is "an index." The feedback below is mostly about turning that into
"things I'd screenshot into Slack" — i.e. deriving value from what we can extract
*without* human input, and never putting ADEF in the human write-path.

### A. Design feedback on the current build

The core bet — a read-only enrichment layer over wherever rules already live — is
right; it's the only architecture that doesn't force migration, and the anti-goals
(no vendor connectors, no new YAML format, no web UI) are correctly chosen. Where
the current design works against adoption:

1. **Cold-start value inversion (biggest risk).** `adef catalog` over 600 rules
   yields 600 blank skeleton journals + an index — a graveyard, not a wow moment.
   The compelling first-ten-minutes features are exactly the ones derivable with
   zero human input: a **coverage summary**, a **MITRE Navigator layer export**, a
   **duplicate / near-duplicate report** (we already have the similarity agent —
   run it across the whole catalog, not just per-detection at Refine), and a
   "what you have vs. don't" gap view. **`adef catalog` should end with a printed
   report, not just files.** Navigator layers especially are community currency —
   cheap to generate from what we already extract, instantly shareable.

2. **Staleness will kill trust faster than any missing feature.** The catalog is a
   snapshot; rule repos change weekly. Stale metadata is *worse* than none when an
   AI assistant answers from it confidently ("you already have a detection for
   that" — except it was deprecated last month). Even before full reconciliation:
   store a **content hash of each source file at catalog time and flag mismatches
   on read.** The assistant should know what it can't trust. (Expanded in section
   B — this is the deferred `adef sync` thread, reframed.)

3. **Journal placement fights the workflow.** DEs live in PRs. With journals in
   `~/work/adef-workspace/` and rules in the repo, journal updates never appear in
   review, never travel with the rule, and quietly stop happening. Consider a
   **journals-in-repo mode** (`journals/` inside the rules repo, or sidecar `.md`
   next to each rule) so rationale rides the same commit and reviewers see it. The
   workspace default is fine for the SIEM-stored crowd; for git-based teams,
   co-location is what makes the habit stick. **Incentive flip:** if the journal
   ID lands in deployed alert metadata, *responders* start reading journals — and
   journals that get read get written.

4. **Schema-from-queries has a built-in blind spot.** Inferring schema from
   existing rules only surfaces fields detections *already use* — precisely the
   wrong dataset for suggesting *new* detections, since gaps live in fields nobody
   queries yet. It's a fine bootstrap (and `--results -` sampling is the right
   complement), but frame it that way and consider layering in **known mappings
   (ECS, OCSF, Splunk CIM, Sysmon/Sentinel table docs)** so the schema knows what
   *could* exist, not just what's used. (Directly relevant to the schema-from-
   catalog work we just shipped, which is rules-only today.)

5. **Evolve needs a data seam.** Tuning/deprecation recommendations without FP
   rates, alert volumes, or outcome data are speculation. No connectors needed —
   reuse the paste/import pattern from schema sampling:
   `adef detection stats D-0042 --results alerts.csv`. That single seam makes the
   whole back half of FORGE real.

6. **The SIEM-only (less-mature) segment is where the pain is worst**, and we've
   deferred export-from-tool. Cheap bridge: **documented export recipes per SIEM**
   ("export Splunk `savedsearches.conf` like this, then `adef catalog`") — no
   code, just docs; our `.conf` sniffer already handles the result.

**Two smaller design notes (hardening):**
- Sequential `D-XXXX` IDs will **merge-conflict** when two engineers catalog
  concurrently.
- `rule_ref` **breaks on file renames**. A content hash or the rule's own UUID as
  a stable secondary key hardens both. (See the identity cascade in section B.)
- `adef detection list/show` (deferred, story 7393) is **table stakes** — people
  can't trust a catalog they can't browse.

### B. Sync / staleness strategy (reframe of the deferred `adef sync`)

The reframe: **ADEF must never require being in the write path.** The moment value
depends on engineers remembering to run `adef` when they edit a rule, we've lost.
Design ADEF to *observe* changes, not mediate them.

- **Catalog = disposable index; journals = the only durable data.** Catalog
  records are pure derivations of the source repo, so "staying current" is just
  "re-derive and reconcile," not state management. Re-running `catalog` / `sync`
  is cheap and safe. The only hard problem is **identity**: when a rule changes,
  which `D-XXXX` is it?
- **Identity matching cascade**, in order: (1) embedded rule UUID — Sigma rules
  carry `id:`, a gift; primary key when present. (2) content hash match →
  unchanged. (3) same path, new hash → modified. (4) fuzzy match on title/query
  for renamed+edited rules → attach with `needs_review`. (5) no match → new rule.
  (6) rule gone → mark journal **orphaned, never delete**. Same shape as
  detection-as-code / Terraform drift handling.
- **Lean on git — it solves most of this for free.** For repo-based teams, store
  the **commit SHA at catalog time**; staleness is one comparison against HEAD,
  and `git diff --name-status <sha>..HEAD` yields adds/modifies/deletes *and
  renames* (git's rename detection kills matching problem #4). Hash-diffing is the
  fallback for non-git sources (SIEM exports).
- **Every read path is staleness-aware.** CLI and especially the MCP server check
  the SHA per query and either auto-resync (cheap) or annotate: "catalog is 14
  commits behind." A confident AI answer from a stale catalog is the trust-killer.
- **Out-of-band edits become a feature.** When sync detects an external change,
  auto-append a journal entry: timestamp, diff summary, old/new hash — and pull
  the **git commit message(s) + PR reference** for that file into the entry.
  Commit messages are the "why" corpus teams already have; harvesting them means
  journals accumulate rationale even for teams who never manually journal. Later,
  an agent can draft an Evolve-stage note from the diff + commit message for human
  approval. Edits that bypass ADEF **don't lose value — ADEF becomes the change
  historian regardless of where the change happened.**
- **Close the loop with CI, not discipline.** One-step GitHub Action: `adef sync`
  on merge to main (commit the updated catalog), or `--check` mode that comments
  on PRs. Currency becomes automatic for the git crowd; the same seam works off a
  scheduled export for SIEM-stored rules.

Net effect: **humans are never the sync mechanism.** Journal entries are
enrichment on top of an automatically-current baseline, not the baseline itself.

### C. Usage scenarios we want to support

**Option 1 — Rules repo (git-based teams):**
1. Install ADEF into your repo; `adef catalog` + journal.
2. Journals live in git alongside PRs — history/rationale travels with the rule.
3. The pitch: having the history and reasoning *in git* is the value.

**Option 2 — No repo, SIEM-stored rules:**
1. Export rules from the SIEM → you now have a rules repo.
2. `adef catalog` + journal it.
3. CI/CD: TBD.
4. Sync: TBD (this is where section B's export + scheduled-sync seam applies).

These two shape the priorities: Option 1 wants **journals-in-repo + git-SHA sync +
CI**; Option 2 wants **export recipes + the disposable-index/re-derive model**.

### How this maps to what's already tracked

- Cold-start report (A.1) is new — no story yet; touches `adef catalog` output.
- Staleness/sync (A.2, B) = the deferred **`adef sync`** thread (Open threads #2).
- Browse commands (A.7) = **story 7393** (deferred, called out as table stakes).
- Schema blind spot (A.4) refines the **schema-from-catalog** work just shipped.
- Evolve data seam (A.5) and SIEM export recipes (A.6) are new seams to scope.
- ID collisions + `rule_ref` rename fragility (smaller notes) fold into B's
  identity cascade.

---

## Test corpora & what they revealed (2026-07-17)

Three open-source rule repos are cloned under `test-rules/` (gitignored — not
ours to commit) to exercise catalog/schema on real data:
- `panther-labs/panther-analysis` — Panther detections
- `palantir/osquery-configuration` — osquery configs
- `splunk/security_content` — Splunk ESCU detections

**Running `adef catalog --dry-run` against them exposed that our sniffer is
effectively Sigma-shaped-YAML-only, and brittle on `.conf`:**

| Repo | Result | Why |
|------|--------|-----|
| splunk/security_content | **0 found** (should be ~1000s) | Detections are `.yml` with a `search:` (SPL) + `mitre_attack_id` + `type` + `datamodel` — a **Splunk-YAML schema**, not Sigma. Our `.yml` sniff only matches Sigma (`detection:` + `logsource:`). |
| panther-labs/panther-analysis | **0 found** | `.yml` metadata (`AnalysisType`, `RuleID`, `LogTypes`) paired with a sibling `.py` holding the logic — **Panther schema**. Not Sigma; logic isn't even in the YAML. |
| palantir/osquery-configuration | **2 found, both false positives** | osquery `.conf` files matched our naive Splunk `.conf` sniff (just `[` + `search`). They're configs, not detections. |

**Takeaways for the roadmap:**
1. **Format coverage is the real gap, not polish.** "Multi-format" today means
   "Sigma YAML + raw .sql/.kql/.cql + a fragile .conf guess." The rule formats
   teams actually have (Splunk ESCU YAML, Panther YAML+py, Elastic, etc.) each
   have their *own* schema — the sniffer needs per-vendor recognizers, not one
   Sigma-YAML check. This is a pluggable-parser shape, not a one-off fix.
2. **YAML is ambiguous by extension.** `.yml` can be Sigma, Splunk ESCU, Panther,
   a pack/story file, or CI config. Sniffing must key on *content signature*
   (which keys are present), and we need a "recognized-but-unsupported" outcome
   distinct from "not a rule" so we can report coverage honestly.
3. **`.conf` false positives** mean the sniffer needs a stronger signal than
   `[` + `search` (osquery `.conf`, app `.conf`, and Splunk `savedsearches.conf`
   all differ).
4. **Logic-not-in-the-file** (Panther's sibling `.py`) breaks the assumption that
   query text lives in the catalogued file — affects both `rule_ref` and schema
   field extraction.

Reproduce: `ADEF_WORKSPACE=$(mktemp -d) .venv/bin/adef catalog test-rules/<repo> --dry-run`

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

### 2026-07-17 (later still) — Format-detection Phase 1 built (Jarrett + Claude)
- Implemented the recognizer registry + three-outcome `support` model + Splunk
  ESCU and Panther recognizers/extractors. `discover_rules` now uses `recognize()`
  and no longer silently drops recognized-but-unsupported rules.
- **Real-corpus result: Splunk `detections/` 0→2124, Panther `rules/` 0→877.**
- Full suite **139 passed** (+20). Guards green, ruff clean. `support` on
  `CatalogRecord` + YAML.
- Follow-up for Phase 2: Splunk platform inference is weak (most rules flag
  `needs_review` — no OS platform on a tstats query). Metadata-extraction polish.

### 2026-07-17 (later) — Test corpora + format-detection plan (Jarrett + Claude)
- Cloned 3 open-source rule repos into `test-rules/` (gitignored). `adef catalog`
  found ~0 in Splunk/Panther and false-positived on osquery → confirmed the
  sniffer is Sigma-shaped-YAML-only. Findings in "Test corpora" section above.
- Direction set (Jarrett): **format-agnostic detection is the foundation**;
  correct the Sigma bias; extension ≠ format.
- Wrote `docs/plans/2026-07-17-format-detection-plan.md` — content-signature
  recognizer registry, recognize-all/parse-incrementally, phased (framework →
  Splunk ESCU → Panther). **Proposed, awaiting co-worker review before building**
  (reshapes shared `rule_discovery` + likely `CatalogRecord`).

### 2026-07-17 — Strategic feedback captured (Jarrett + Claude)
- Recorded external design feedback + sync strategy + usage scenarios (Option 1
  repo / Option 2 SIEM) in the new "Strategic feedback & direction" section above,
  and a "Known adoption risks" summary in `docs/v0.1.0-current-state.md`.
- Framed as **input, not decisions** — drives upcoming design work; nothing in
  `ISA.md` yet. Next: triage which points become decisions + first work items
  (cold-start report, git-SHA sync + identity cascade, journals-in-repo mode).

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
