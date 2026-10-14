# ADEF CLI Reference

The `adef` command-line interface drives the FORGE detection lifecycle (Find →
Observe → Refine → Govern → Evolve) over a workspace of per-detection journals
and an enrichment catalog. This is the canonical, source-derived reference for
every command and option — a technical *reference*, not a walkthrough. For a
hands-on tutorial see `docs/quickstart.md`; for what is actually shipped and
working today see the [README](../README.md).

Commands are registered through the `adef.commands` entry-point group (see
`pyproject.toml`), so first-party and third-party plugins look identical. A
broken plugin logs to stderr and never crashes CLI startup.

Root flags: `adef --version` prints the version banner; `adef --help` lists all
discovered commands.

## Workspace resolution

Most commands resolve the workspace through `adef/core/workspace.py`
(`resolve_workspace`), in this order:

1. `--workspace PATH` (explicit flag), else
2. `ADEF_WORKSPACE` environment variable, else
3. the current directory, **only if** it contains a `catalog/` or `journals/`
   subdirectory, else
4. `~/work/adef-workspace`.

Read/browse commands (`detection list/show/search`, `coverage`) resolve without
scaffolding — they never create a workspace as a side effect.

`adef init` is the deliberate exception: it resolves explicit `PATH` →
`ADEF_WORKSPACE` → `~/work/adef-workspace`, with **no current-directory
fallback**, because it *creates* a workspace and must not infer its target from
cwd contents.

## Command index

| Command | Purpose |
|---|---|
| `adef init` | Scaffold an ADEF workspace |
| `adef doctor` | Check every piece of workspace state, with the next command where there is one |
| `adef detection new` | Create a detection journal at Find (optionally schema-grounded) |
| `adef detection observe` | Advance a detection to the Observe stage |
| `adef detection refine` | Advance to Refine; runs Similarity → Overlap → Verification |
| `adef detection govern` | Advance a detection to the Govern stage |
| `adef detection evolve` | Advance a detection to the Evolve stage |
| `adef detection list` | List catalogued detections with filters |
| `adef detection show` | Show one detection's record + journal tail |
| `adef detection search` | BM25 search over journals + catalog metadata |
| `adef detection tag-mitre` | Add validated ATT&CK technique IDs to a record |
| `adef hunt-promote` | Promote an upstream hunt to a draft detection |
| `adef catalog` | Walk a rule repo into the catalog (read-only on source) |
| `adef sync` | Reconcile the catalog with the source repo |
| `adef profile lint` | Validate an extraction profile against its schema |
| `adef reindex` | Rebuild `catalog/INDEX.yml` from the catalog records |
| `adef schema ingest` | Build schemas from a data-source declaration |
| `adef schema lint` | Validate a data-source declaration |
| `adef schema check` | Cross-reference rule field usage vs schemas |
| `adef schema list` | List declared schemas in the workspace |
| `adef schema show` | Display one declared schema |
| `adef schema recipe` | Print a SIEM field-extraction recipe |
| `adef schema reshape` | Reshape a raw SIEM export into a draft declaration |
| `adef attack info` | Active ATT&CK snapshot version + counts |
| `adef attack show` | Display an ATT&CK technique |
| `adef attack refresh` | Pull a fresh ATT&CK snapshot into the workspace |
| `adef coverage` | Coverage-quality report + optional Navigator layer |
| `adef ingest` | Ingest a detection-health capture document |
| `adef health show` | Read back ingested health + the metrics Evolve derives |
| `adef-mcp` | Start the FastMCP server (separate console script) |
| `adef install-skills` | Copy bundled skills into an agent's directory |

---

## Workspace & lifecycle

### adef init

**Synopsis:** `adef init [PATH] [--force] [--interactive/-i]`

Scaffold an ADEF workspace — `journals/`, `catalog/`, `schema/`, `config/`,
`templates/DETECTION_FORGE.md`, and an operator `AGENTS.md`. `PATH` defaults to
`~/work/adef-workspace/` (see workspace resolution — init has no cwd fallback).

| Option | Meaning |
|---|---|
| `PATH` (arg, optional) | Target directory; default `~/work/adef-workspace/`. |
| `--force` | Overwrite existing scaffolding files (config, AGENTS.md, template). |
| `--interactive`, `-i` | Guided setup: prompts where detections live (repo / SIEM-only / fresh), SIEM platform, and query languages; writes them to config, reports optional capabilities, and offers to chain into `install-skills`. |

Interactive mode prints (never runs) git-init durability guidance and an
`ADEF_WORKSPACE` export hint for non-default paths.

```bash
adef init
adef init /srv/detections/adef-workspace --interactive
```

### adef doctor

**Synopsis:** `adef doctor [--workspace PATH] [--report json]`

One answer to "is my workspace actually wired up?". Ten checks over the
workspace, each with the literal next command to run — the fix where one
command fixes it (`adef reindex`, `adef install-skills`), the triage entry
point where the work is a human's (`enrichment`), and none at all where no
command would help (`catalog` for a record whose YAML can't be parsed, `index`
when the expected INDEX can't even be built — `adef reindex` fails on the same
cause, so prescribing it would hand you a command that dies):

| Check | Reports |
|---|---|
| `workspace` | The resolved path exists *and* has `journals/` + `catalog/` — "the directory exists" is a different question, since workspace resolution falls back to the current directory. |
| `catalog` | Record count, and any record whose YAML cannot be parsed. |
| `index` | Whether `catalog/INDEX.yml` matches what the records imply, and which keys drifted. |
| `journals` | Journal count, and any record with no paired journal. |
| `schemas` | Declared data sources in `schema/`. |
| `att&ck` | Active snapshot version, technique count, and whether it is the shipped copy or a workspace refresh. |
| `enrichment` | The `needs_review` queue, summarized by reason (`3× no_mitre`). |
| `health` | Detections and telemetry sources with ingested captures. |
| `mcp` | Whether the `[mcp]` extra is importable. |
| `skills` | How many of ADEF's *own* bundled skills are installed, and which are missing. |

| Option | Meaning |
|---|---|
| `--workspace PATH` | Workspace to check (defaults per workspace resolution). |
| `--report json` | Machine-readable: every check plus `problems`/`warnings` counts. |

**Exit codes.** `0` when there are no *problems*, even with warnings; `1` when
any check is a problem. The split is deliberate: a warning is an optional
capability nobody has set up yet — no declared schemas, no ingested health, no
installed skills — which is the normal state of a workspace on day one, so
warnings stay safe in a CI job. A problem is state that makes another command
answer confidently from bad data: a missing workspace, a record every command
silently skips, a stale `INDEX.yml`.

The `index` check compares the stored INDEX against a freshly built one rather
than comparing ID sets or file mtimes, because the failure that matters leaves
every filename untouched — editing a record's `mitre` (what `adef detection
tag-mitre` does) changes `by_technique` and `by_tactic`, which is what
`adef coverage` and `adef detection list --tactic` read.

Read-only, including on the directory it is pointed at: nothing is created even
when the target turns out not to be a workspace at all.

```bash
adef doctor
adef doctor --workspace /srv/detections/adef-workspace
adef doctor --report json | jq '.checks[] | select(.status == "problem")'
```

### adef detection new

**Synopsis:** `adef detection new TITLE [--owner OWNER] [--rule-uuid UUID] [--source SCHEMA] [--workspace PATH]`

Create a new detection journal at the Find stage. With `--source`, also
scaffolds a draft catalog record grounded in that declared schema (platform,
query_language, and scope literals) — the starting point for authoring a
brand-new rule. The rule lands in ADEF's catalog; moving it to a rules repo is
the user's call.

| Option | Meaning |
|---|---|
| `TITLE` (arg, required) | Detection title; must not be empty. |
| `--owner` | Initial owner (default: empty). |
| `--rule-uuid` | Upstream rule UUID to pair (default: empty). |
| `--source` | Declared schema name to ground a new rule (e.g. `wineventlog_xml`); errors if the schema isn't declared. Omit for a journal only. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef detection new "Suspicious mshta.exe child process"
adef detection new "Suspicious mshta child" --source wineventlog_xml --owner alice
```

### adef detection observe / refine / govern / evolve

**Synopsis:** `adef detection <stage> DETECTION_ID [--note TEXT ...] [--back] [--workspace PATH]`

Advance a detection to the named FORGE stage. Appends a timestamped
`## [<ISO-8601>] Stage: <stage>` block to the journal and updates frontmatter
atomically. Re-advancing to the current stage is idempotent (appends the note
only, no duplicate block). Moving to an *earlier* stage is refused unless you
pass `--back`: FORGE is a loop, so going back is allowed, but it has to be
deliberate. The `find` stage is not a subcommand — it is the entry point of
`detection new`.

| Option | Meaning |
|---|---|
| `DETECTION_ID` (arg, required) | e.g. `D-0001`. |
| `--note TEXT` | Note appended to the stage block. Repeatable — several `--note`s render as a bullet list. |
| `--back` | Allow a move to an earlier stage (e.g. `observe` on a rule at refine). Without it the command errors and nothing changes. |
| `--chain` (refine and evolve) | Re-run that stage's chain even when already at the stage. On `refine`: Similarity → Overlap → Verification. On `evolve`: Health → Tuning → Deprecation — the one you usually want, since `adef ingest` brings fresh numbers between runs. |
| `--similarity-mode` (refine only) | How the Similarity step ranks: `bm25` (default) is deterministic and makes no network call; `agent` returns the target's and each candidate's query, MITRE IDs, platform, and data source for the caller to rank — both sides, since judging similarity needs something to compare against — also with no network call — unless an `ADEF_WRAPPER_*` override is configured, in which case the configured upstream class runs instead; `llm` reranks with an LLM judge and **sends detection content to the Anthropic API** (requires `ANTHROPIC_API_KEY` + the `llm` extra); `auto` picks `llm` when available, else `bm25`. |
| `--workspace` | Workspace path (see resolution). |

`refine` additionally runs the orchestration chain (Similarity → Overlap →
Verification) **on the transition into refine**, appending each result to the
journal (the chain does not abort on partial failure). Re-advancing to `refine`
does *not* re-run it — use `--chain` to force a re-run. Similarity ranking
defaults to `bm25` and stays there regardless of environment — an
`ANTHROPIC_API_KEY` no longer changes the default. Opt into an LLM rerank with
`--similarity-mode llm` (or `auto`), or hand the shortlist to your own assistant
with `--similarity-mode agent`.

The Verification step reports a `status`: `passed` (the engine and field
checks both ran clean), `failed` (either found a defect), or `partial` (the
field check couldn't run). `checks` shows each check, and
`fields_not_run_reason` says why the field check didn't run:
`no_schemas_declared`, `no_schema_matches` (no declared schema addresses the
rule's data source) or `unparseable_query`. `refine` prints one line when the
status isn't `passed`. Only fields a rule *filters on* can fail it: grouping
and projection columns (SPL `BY`, `SELECT` lists, KQL `project`) missing from
the schema are listed as `missing_grouping_fields` without failing. The older
`passed` flag is kept and means "no defect found", so it is also true for a
`partial` result; read `status`.

The Overlap step compares rules on the same technique (via `catalog/INDEX.yml`'s
`by_technique` map): a sub-technique and its parent technique (`T1219.002` and
`T1219`) are compared; sibling sub-techniques (`T1219.001` and `T1219.002`)
are not.

**`refine` and `adef detection search` answer "what is similar?" differently,
on purpose.** `refine`'s Similarity step runs three retrieval passes and fuses
them with reciprocal rank fusion: BM25 over `record_search_text` (for Sigma
rules its query part is the rule's `description`, `tags`, and `logsource` and
`detection` blocks), plus a second, language-agnostic field-set pass
(`adef/core/field_index.py`) that
matches rules on the telemetry fields their queries *filter on* (the
predicate — `WHERE`, search terms, a Sigma `detection:` block; not `BY`,
`table`, `project` or `SELECT` lists, and not routing such as `index`,
`sourcetype`, `datamodel` or CQL `#` tags), canonicalized through declared schema aliases — so a Sigma rule and a SQL
rule detecting the same behaviour can find each other even though they share
almost no words. A third pass (`adef/core/value_index.py`) needs no schema: it
proposes rules **in a different query language** that test the same
distinctive values (`bitsadmin.exe`, `EnableLUA`, a remote-access domain),
weighted by rarity, ignoring field names and values common to more than 5% of
the catalog. Each candidate reports `found_by` (`bm25`, `fields`, `values`)
and, for a value match, `value_score` and `shared_values`. `detection search`
(below) stays pure BM25 and never runs the field or value pass. This is a deliberate split, not an oversight: `refine`
already runs three agents and writes a journal entry, so a second full-corpus
pass is noise in its existing budget, and "does a rule like this already
exist?" is exactly the question extra recall serves. `search` is interactive
and latency-sensitive, and nobody has reported it missing cross-language
matches — the complaint has only ever been about `refine`. Wiring the field
pass into `search` remains open if that changes.

**Every Similarity run reports how well the field pass canonicalized**, via a
`field_matching` state. **The field pass only contributes to the shortlist in
`schema` state**, where declared aliases canonicalized the target's fields.
In every other state it could only compare literal field names — one language
only, which BM25 already covers through shared tokens — and in a mixed-language
catalog those literal matches crowd out the cross-language twin BM25 found, so
the pass is skipped. `refine` prints a warning naming the cause and the remedy
whenever it was skipped (nothing prints for `schema` — a working feature
doesn't announce itself):

| `field_matching` | Meaning | Remedy |
|---|---|---|
| `schema` | The rule matched a declared source, and that source's fields declare `aliases` — cross-language field matching is fully active. | — |
| `declared_no_aliases` | The rule matched a declared source, but that source's fields declare no `aliases`, so field names can only be compared literally (same language only) — the field pass is skipped. | Add `aliases` to that source's declared fields; `adef schema check` reports per-source alias coverage. |
| `unmatched` | The rule's literals (`data_source` plus query shape literals) match no declared source. | `adef schema ingest <declaration>`, then `adef schema check` to confirm the rule is no longer unmatched. |
| `unparseable` | No field extractor exists for the rule's format, it has no query to parse, or no event fields could be extracted from it (a malformed query, or a rule with no field conditions such as keyword-only Sigma). | Depends on the cause. **Unsupported format:** author an extraction profile and validate it with `adef profile lint` (nothing to do if the format is `recognized_unsupported` by design). **Malformed query:** fix it in the source repo, then `adef sync`. **No field conditions:** nothing to do — BM25 still covers the rule; there are simply no fields to match on. |

> **What leaves your machine in `llm`/`auto` mode.** When the LLM path
> actually runs, ADEF sends the Anthropic API the target detection's title
> (unbounded), MITRE technique IDs (unbounded count), and query (truncated to
> 500 characters; for Sigma, its logsource and detection blocks); plus, for
> each of at most `top_k` (default 5) shortlisted candidates, its detection
> ID, title (unbounded), and a snippet (up to 242 characters, built from
> both the journal body AND the catalog search text —
> title, MITRE IDs, platform, data source, format, query — see
> `record_search_text`; for Sigma rules the query part is the rule's
> `description`, `tags`, and `logsource` and `detection` blocks), so catalog
> and query content can be disclosed too, not just journal prose.
>
> **When a candidate matched via the field-set pass** (its `shared_fields`
> list is non-empty), the prompt additionally carries that full
> `shared_fields` list plus a bounded slice (≤200 characters; for Sigma, its
> logsource and detection blocks) of the candidate's own query — a
> field-only candidate has no BM25 snippet, so without this the judge would
> see an entry with no evidence attached at all. A candidate found only by the
> value pass (another query language, no `shared_fields`) likewise carries a
> ≤200-character slice of its query — not its `shared_values` — which is
> also **newly disclosed** in `llm` mode.
> Two points worth stating plainly rather than leaving to be discovered:
> `shared_fields` names are the rule's OWN literal field names AND, wherever
> canonicalization through a declared schema applied, their canonical form
> too — canonicalization adds to a rule's literal fields, it never replaces
> them — so this list can mix a raw name straight from a query (`Image`) with
> a canonical one drawn from your own declared schema (`process.name`), and
> either or both may appear. This still discloses schema vocabulary about
> your environment whenever a canonical name is present, not only rule
> content; and a field-only candidate could not reach the shortlist at all
> before the field-set pass existed, so its query slice is **newly disclosed
> data**, not a reshaping of egress that already happened. This same
> mixed-vocabulary `shared_fields` list is also what `--similarity-mode
> agent` hands back to its caller, unbounded — the ≤200-character query bound
> above is specific to the `llm` prompt.
>
> Nothing else from the workspace is transmitted. `--similarity-mode bm25`
> and `--similarity-mode agent` make no network call at all, unless an
> `ADEF_WRAPPER_*` override is configured — the configured upstream class
> runs instead, and this guarantee no longer applies.

**`evolve` runs its own chain — Health → Tuning → Deprecation.** On the
transition into `evolve` (and on `--chain`), ADEF reads the detection's
ingested health (`adef ingest`, see below), derives the ratios the two
heuristics consume, and appends all three blocks to the journal. Like the
Refine chain it never aborts on partial failure, and the verdicts also print
to stdout so a tuning call is visible without opening the journal.

With nothing ingested, the Health block says so and names `adef ingest` —
both recommenders then return `insufficient-data`, which is the honest answer,
not a failure. Counts become ratios here and only here:

| Derived | From | Rule |
|---|---|---|
| `fp_ratio` | `false_positive_count`, `true_positive_count` | Denominator is what was **adjudicated**, not `signal_count` — unlabeled signals are not known false positives, and dividing by every signal reports a detection as cleaner than the labelling supports. Omitted unless **both** counts are present — row contents aren't whitelisted at ingest, so FPs without TPs is a valid document, and defaulting the absent TP to zero reported `fp_ratio: 1.0` ("100% false positives") about a number nobody supplied. Also omitted when nothing was adjudicated (0 FP *and* 0 TP means nobody triaged, not "clean"). |
| `weekly_signal_volume` | `signal_count`, `window` | Normalized to a week by the document's declared window, so a 28-day capture isn't read as four times its traffic. Falls back to the raw count if the window is unreadable. |
| `days_since_true_positive` | `last_true_positive_at` | Computed at read time. Absent for a detection that has never had a true positive — see the note under `adef health show`. |

A key is emitted **only** when the counts behind it exist. Both recommenders
decide "insufficient data" on key *presence*, so a fabricated `0.0` would read
as a measured zero — the difference between "this detection is silent" and
"nobody told us anything about it". A non-numeric or **negative** count is
treated as absent on the same grounds: nothing happens a negative number of
times, and `false_positive_count: -5` against 10 TPs would otherwise derive a
plausible-looking `fp_ratio: -1.0`.

```bash
adef detection observe D-0001 --note "Checked 30d of process_create events"
adef detection refine  D-0001
adef detection govern  D-0001 --note "Owner: SOC-T2" --note "Gate: passed schema check"
adef detection evolve  D-0001
adef detection evolve  D-0001 --chain   # re-run after a fresh `adef ingest`
```

### adef hunt-promote

**Synopsis:** `adef hunt-promote (HUNT_ID | --gates PATH) [--dry-run] [--workspace PATH] [--rule-staging-root PATH] [--hunt-root PATH]`

Turn a finished ATHF hunt into draft ADEF detections. Two input modes, mutually
exclusive — `--gates` reads the hunt ID out of the document, so passing both a
`HUNT_ID` and `--gates` is an error rather than a silently ignored argument.

**`--gates` (primary).** Import an ATHF GATES document
(`hunt-promotion-analysis/H-XXXX_GATES.yaml`), which ATHF's `gates` skill wrote:
N candidate detections, each with a verdict, its BASE evidence, and — when
deployable — the query. Deployable candidates (`PROMOTE`/`CONDITIONAL`/`TIME_BOX`)
each get a catalog record with `origin: promoted` and a journal carrying the
reasoning; archival ones (`HOLD`/`DROP`/`RECURRING_HUNT`) are reported and nothing
is written. Re-import is idempotent on `hunt_ref` (`H-XXXX#<candidate-id>`), and
preserves your enrichment — `mitre`, `status`, `stage`, `owner`. A hunt whose
verdict is archival emits a `.md` narrative, which has nothing to import.

**`HUNT_ID`.** For a hunt that has *not* been through GATES: resolves the hunt,
calls a configured generator to draft a Sigma rule, writes it to a **staging**
directory (never any production rule directory), and creates a Find-stage journal
with intel sources populated. The generator dotted path is configured via
environment variable (`ADEF_HUNT_RULE_GENERATOR`); ADEF takes no opinion on the
upstream hunt system.

| Option | Meaning |
|---|---|
| `HUNT_ID` (arg) | Hunt to promote via the generator, e.g. `H-0042`. Omit with `--gates`. |
| `--gates` | Path to a GATES YAML document. Mutually exclusive with `HUNT_ID`. |
| `--dry-run` | With `--gates`: show what would be imported, write nothing. Not supported on the generator path. |
| `--workspace` | Workspace path (see resolution). |
| `--rule-staging-root` | Directory for the staging YAML draft (overrides `ADEF_RULE_STAGING_ROOT`). |
| `--hunt-root` | Directory where hunt artifacts live (overrides `ADEF_HUNT_ROOT`). |

```bash
adef hunt-promote --gates ~/athf-workspace/hunt-promotion-analysis/H-0041_GATES.yaml
adef hunt-promote --gates H-0041_GATES.yaml --dry-run
adef hunt-promote H-0042
adef hunt-promote H-0042 --hunt-root ~/athf/hunts --rule-staging-root ~/staging
```

---

## Cataloging & sync

### adef catalog

**Synopsis:** `adef catalog RULE_ROOT [--dry-run] [--report json] [-o/--output PATH] [--profile PATH] [--force] [--workspace PATH]`

Walk a directory of detection rules read-only and catalog each into
`catalog/<platform>/D-XXXX-<slug>.yml` with a paired skeleton journal, then
rebuild `catalog/INDEX.yml`. Infer-and-flag: rules whose platform/MITRE can't be
inferred are catalogued with `needs_review: true`. **Never writes to the source
repo.** A re-catalog of already-catalogued rules is refused (use `sync`) unless
`--force`.

| Option | Meaning |
|---|---|
| `RULE_ROOT` (arg, required) | Directory to walk (must exist). |
| `--dry-run` | Report what would be catalogued without writing. |
| `--report json` | Machine-readable outcome report (implies `--dry-run`; includes UNCLAIMED files and, with `--profile`, per-field extraction rates). |
| `--output`, `-o` | Write the `--report json` to a file instead of stdout (requires `--report json`). |
| `--profile PATH` | Candidate extraction profile to validate, checked ahead of all others. |
| `--force` | Catalog even when rules are already in the workspace (mints duplicate records). |
| `--workspace` | Workspace path (see resolution). |

```bash
adef catalog /path/to/rules --dry-run
adef catalog /path/to/rules --dry-run --report json -o report.json
adef catalog /path/to/rules
```

### adef sync

**Synopsis:** `adef sync RULE_ROOT [--dry-run] [--check] [--workspace PATH]`

Reconcile the catalog with the current source repo via the identity cascade
(`rule_uuid` → `source_hash` → `rule_ref` → new). On a match, **derived** fields
(query, platform, hashes) are refreshed while **enrichment** (`mitre`, `status`,
`stage`, `owner`, journal) is preserved. A file whose bytes haven't changed is
still refreshed when discovery now derives different values from it (an edited
extraction profile, or a newer ADEF). Missing source rules are marked
**orphaned, never deleted**. `authored` records are never touched. **Read-only on
the source repo** — writes only under `catalog/` and `journals/`.

| Option | Meaning |
|---|---|
| `RULE_ROOT` (arg, required) | Source repo to reconcile against (must exist). |
| `--dry-run` | Show the reconciliation plan; write nothing. |
| `--check` | CI/PR mode — report drift and exit non-zero if the catalog is behind; writes nothing. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef sync /path/to/rules --dry-run
adef sync /path/to/rules --check
adef sync /path/to/rules
```

### adef profile lint

**Synopsis:** `adef profile lint PROFILE_FILE`

Validate a declarative extraction profile against the v1 schema; exits 1 on
errors. Profiles teach ADEF's discovery engine a rule format without code and
live at `<workspace>/config/profiles/*.yml`.

| Option | Meaning |
|---|---|
| `PROFILE_FILE` (arg, required) | Profile YAML to validate (must exist). |

```bash
adef profile lint config/profiles/inhouse-yaml.yml
```

### adef reindex

**Synopsis:** `adef reindex [--workspace PATH]`

Rebuild `catalog/INDEX.yml` from the catalog records — the only safe way to
regenerate it (the INDEX is generated, never hand-edited). Use after any
out-of-band edit to catalog record files.

| Option | Meaning |
|---|---|
| `--workspace` | Workspace path (see resolution). |

```bash
adef reindex
```

---

## Browse

### adef detection list

**Synopsis:** `adef detection list [filters] [--report json] [--workspace PATH]`

List catalogued detections from the workspace catalog. Read-only. Closed-set
filters (`--engine`, `--status`, `--stage`, `--tactic`) reject typos with an
error rather than reporting zero coverage.

| Option | Meaning |
|---|---|
| `--platform` | Filter by platform (e.g. `windows`). |
| `--tactic` | Filter by ATT&CK tactic, resolved from technique IDs; accepts shortname (`execution`) or display name (`Execution`). |
| `--engine` | Internal engine: `sigma`, `sql`, `sch_sql`, `composite`. |
| `--rule-format` | Source format (`sigma`, `spl`, `<profile>`). |
| `--status` | `draft`, `ready`, `tuning`, `deprecated`. |
| `--stage` | FORGE stage (`find` … `evolve`). |
| `--origin` | `authored` (created in ADEF), `catalogued` (from a repo), or `promoted` (imported from an ATHF GATES document). |
| `--needs-review [REASON]` | Only detections needing review. Bare = the reasons worth surfacing unprompted (`malformed`, `external_logic`, `no_platform`, `invalid_mitre`, `gates_conditional`, `gates_time_box`); pass a reason (e.g. `no_mitre`, a queue to drain rather than a warning) to filter it specifically. |
| `--report json` | Machine-readable output; adds a derived `tactics` array per row. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef detection list --platform windows --status draft
adef detection list --tactic execution --report json
adef detection list --needs-review no_mitre
```

### adef detection show

**Synopsis:** `adef detection show DETECTION_ID [--workspace PATH]`

Show one detection: the catalog record (platform, format, engine, MITRE, derived
tactics, lifecycle, origin, source `rule_ref`, `support` note), its query, and
the tail of the paired journal. Read-only.

| Option | Meaning |
|---|---|
| `DETECTION_ID` (arg, required) | e.g. `D-0001`. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef detection show D-0001
```

### adef detection search

**Synopsis:** `adef detection search QUERY [--limit N] [--workspace PATH]`

BM25 search across the *why* (journal reasoning) and the *what* (catalog record
title, MITRE, platform, data source, query — for a Sigma rule, its
`description`, `tags`, and `logsource`/`detection` blocks, not the whole file).
Answers "have we looked at X before / do we cover Y?". Read-only. Unlike
`adef detection refine`'s Similarity step, this never runs the field-set
retrieval pass — pure BM25 only, deterministic, no per-run corpus-wide field
extraction. See the note
under `adef detection observe / refine / govern / evolve` for why the two
commands answer "what is similar?" differently.

| Option | Meaning |
|---|---|
| `QUERY` (arg, required) | Search text. |
| `--limit N` | Max results (default `10`). |
| `--workspace` | Workspace path (see resolution). |

```bash
adef detection search "mshta.exe public directory"
adef detection search "credential dumping" --limit 25
```

---

## Enrichment

### adef detection tag-mitre

**Synopsis:** `adef detection tag-mitre DETECTION_ID TECHNIQUE_ID [TECHNIQUE_ID ...] [--remove] [--workspace PATH]`

Add ATT&CK technique IDs to a catalog record, draining the `no_mitre` review
queue. Each ID is validated against the ATT&CK reference *this* workspace
resolves — its own `attack/enterprise.json` if `adef attack refresh` has written
one, else the shipped copy — so `--workspace` changes the verdict. An invalid ID
aborts without writing. Merges into the record's `mitre`, drops the `no_mitre`
reason, and rebuilds the INDEX. **Writes only to ADEF's catalog record — never
the source rule.** Revoked IDs are accepted with a note suggesting the
replacement.

| Option | Meaning |
|---|---|
| `DETECTION_ID` (arg, required) | e.g. `D-0007`. |
| `TECHNIQUE_IDS` (arg, one or more, required) | e.g. `T1547.001 T1055`. |
| `--remove` | Remove the listed IDs instead of adding them (the retag seam — Observe findings can invalidate a mapping). Emptying the mapping re-queues the record as `no_mitre`. To replace: `--remove` the old, then tag the new. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef detection tag-mitre D-0007 T1547.001 T1055
adef detection tag-mitre D-0007 T1055 --remove      # untag (retag seam)
```

---

## Schema

Declaration-driven: users provide a data-source declaration
(`adef-sources.yml`), and ADEF builds `schema/<source>.yml` (schema_version 2).
Rules are a schema *consumer* (via `check`), never a schema source.

### adef schema ingest

**Synopsis:** `adef schema ingest DECLARATION_FILE [--workspace PATH]`

Build one `schema/<source>.yml` per declared source. Re-ingest replaces declared
fields, preserves human `corrected` fields, and reports drift (added / removed /
type-changed).

| Option | Meaning |
|---|---|
| `DECLARATION_FILE` (arg, required) | Declaration YAML (must exist). |
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema ingest adef-sources.yml
```

### adef schema lint

**Synopsis:** `adef schema lint DECLARATION_FILE`

Validate a data-source declaration; exits 1 on errors (warnings are printed but
non-fatal).

| Option | Meaning |
|---|---|
| `DECLARATION_FILE` (arg, required) | Declaration YAML (must exist). |

```bash
adef schema lint adef-sources.yml
```

### adef schema check

**Synopsis:** `adef schema check [--detection ID ...] [--report json] [--workspace PATH]`

Cross-reference the fields catalogued rules actually use against the declared
schemas (names + aliases). Findings are advisory, never blocking: rule fields
missing from the matched schema, and declared fields no rule uses. Scope
matching keeps the most-specific source(s). Both the terminal report and
`--report json` include **per-source alias coverage** — how many of a
source's declared fields carry at least one `alias` — since aliases are what
switches on cross-language field matching in `adef detection refine` (see
`field_matching: declared_no_aliases` above); a source with 0 aliased fields
is called out explicitly. In `--report json`, `alias_coverage` maps each
source name to `{"with_aliases": N, "total": M}` (named keys, not a
positional pair, so a machine consumer can't misread which number is which).

| Option | Meaning |
|---|---|
| `--detection ID` | Scope to specific detection ID(s), e.g. `D-0001`. Repeatable; suppresses the unused-declared-fields section. |
| `--report json` | Machine-readable findings report. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema check
adef schema check --detection D-0001 --report json
```

### adef schema list

**Synopsis:** `adef schema list [--workspace PATH]`

List the declared schemas in the workspace, one line per source (source,
platform, query language, field count). Skips non-schema_version-2 files.

| Option | Meaning |
|---|---|
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema list
```

### adef schema show

**Synopsis:** `adef schema show SOURCE [--workspace PATH]`

Display a declared schema for `SOURCE`: platform, query language, declared date,
description, and every field with type, aliases, description, and enum values.
Corrected fields are marked. Exits 1 if the schema is missing or not v2.

| Option | Meaning |
|---|---|
| `SOURCE` (arg, required) | Schema source name (e.g. `wineventlog`). |
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema show wineventlog
```

### adef schema recipe

**Synopsis:** `adef schema recipe [PLATFORM] [--format markdown|json] [--workspace PATH]`

Print a SIEM-specific field-extraction recipe (the command to run in your SIEM
to produce a field export). If `PLATFORM` is omitted, reads the platform from
workspace config, else prompts. **Recipes are documentation, not connectors** —
ADEF ships no vendor API integration.

| Option | Meaning |
|---|---|
| `PLATFORM` (arg, optional) | e.g. `splunk`, `sentinel`, `elastic`. |
| `--format` | `markdown` (default) or `json`. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema recipe splunk
adef schema recipe elastic --format json
```

### adef schema reshape

**Synopsis:** `adef schema reshape EXPORT_FILE [--platform P] [--source NAME] [-o/--output PATH] [--no-fold FIELD ...] [--interactive/-i] [--append PATH] [--workspace PATH]`

Reshape a raw SIEM field export into a draft declaration by applying the five
reshape rules (internals filter, case-dupes to aliases, capped enum harvesting,
type inference, mixed-shape guard) and printing a transformation report. Approve
the transformations, then `adef schema ingest` the result. If `--platform` is
omitted, reads it from workspace config.

| Option | Meaning |
|---|---|
| `EXPORT_FILE` (arg, required) | Raw SIEM field export (must exist). |
| `--platform` | Export format: `splunk`, `sentinel`, `elastic` (others: one field per line). |
| `--source` | Declared source name (default: derived from sourcetype/filename). |
| `--output`, `-o` | Output declaration path (default `<source>-sources.yml`). |
| `--no-fold FIELD` | Exempt a field name from case-folding. Repeatable. |
| `--interactive`, `-i` | Walk each SUSPECT fold with value evidence and ask keep-or-split; also prompts for source platform + description. |
| `--append PATH` | Add this source to an existing declaration instead of writing a new file. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema reshape wineventlog-export.txt --platform splunk --interactive
adef schema reshape sysmon.csv --platform splunk --append adef-sources.yml
```

---

## ATT&CK & coverage

### adef attack info

**Synopsis:** `adef attack info`

Show the active ATT&CK snapshot's version and counts (techniques, tactics). No
options.

```bash
adef attack info
```

### adef attack show

**Synopsis:** `adef attack show TECHNIQUE_ID`

Display a technique: name, tactics, parent, and deprecated/revoked status (with
the superseding ID). Exits 1 for an invalid ID.

| Option | Meaning |
|---|---|
| `TECHNIQUE_ID` (arg, required) | e.g. `T1059.001`. |

```bash
adef attack show T1059.001
```

### adef attack refresh

**Synopsis:** `adef attack refresh [--workspace PATH]`

Pull a fresh ATT&CK snapshot from official STIX into
`<workspace>/attack/enterprise.json`, which wins over the shipped copy on read.
Network/parse failures report and exit 1 without touching package data.

| Option | Meaning |
|---|---|
| `--workspace` | Workspace to write into (default `$ADEF_WORKSPACE` or `~/work/adef-workspace`). |

```bash
adef attack refresh
```

### adef coverage

**Synopsis:** `adef coverage [--navigator PATH] [--name NAME] [--gaps] [--workspace PATH]`

Report coverage *quality* from the catalog with zero human input: **solid** vs
**fragile** techniques, log-source concentration, single points of failure,
fictional coverage (IDs absent from ATT&CK), a by-tactic rollup, and coverage
gaps (covered vs total ATT&CK techniques). Read-only.

| Option | Meaning |
|---|---|
| `--navigator PATH` | Also write a MITRE Navigator v4.5 layer scored by the quality tiers (solid=100, fragile=50). |
| `--name` | Layer name for the Navigator export (default `ADEF coverage`). |
| `--gaps` | Also list uncovered technique IDs grouped by tactic. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef coverage
adef coverage --gaps
adef coverage --navigator layer.json --name "Q3 coverage"
```

---

## Detection health

Document-driven: a producer hands ADEF a capture document describing what
deployed detections are doing; ADEF validates, routes on the document's own
`kind`, and stores it. ADEF never queries the environment those numbers came
from — producing the document is the user's side of the contract.

### adef ingest

**Synopsis:** `adef ingest DOCUMENT [--dry-run] [--workspace PATH]`

Ingest a detection-health capture document. The document declares its own
`kind` (`metrics`, `performance`, `deployment_drift`, `field_observations`,
`source_health`) and `schema_version`, so one command handles all five and
there is no flag to mismatch against the file. Detection rows are keyed by
`D-XXXX`; rows naming a detection the catalog does not have are reported and
skipped, never silently stored. `field_observations.fields[].sample_values` is
the one field that carries event-derived content — it is optional, and
including it puts that data at rest in the workspace.

| Option | Meaning |
|---|---|
| `DOCUMENT` (arg, required) | Capture document YAML (must exist). |
| `--dry-run` | Validate and report what would be written, without writing anything. |
| `--workspace` | Workspace path (see resolution). |

Stored under `<workspace>/health/`: `latest/D-XXXX.yml` (newest snapshot per
kind, by `captured_at` — backfilling an older capture adds it to history but
leaves `latest/` alone, and ingest says so), `history/D-XXXX.jsonl`
(append-only trend substrate; re-ingesting an identical document adds no
rows), and `sources/<source>.yml`.

```bash
adef ingest weekly-metrics.yml              # validate, store, report
adef ingest weekly-metrics.yml --dry-run    # validate and report only
```

Timestamps may be quoted or not, and must parse as ISO-8601 (`Z`, `+00:00`
and the compact `+0000` offset are all accepted); `window.start` must be
before `window.end`. `yaml.safe_load` resolves an unquoted
`2026-10-06T09:00:00Z` to a native datetime rather than a string, so ingest
normalizes YAML-native dates back to ISO-8601 at the document boundary.

### adef health show

**Synopsis:** `adef health show [DETECTION_ID] [--source NAME] [--report json] [--workspace PATH]`

Read back what `adef ingest` stored. Without this, the five capture kinds land
in `health/` with no way to see them short of opening the YAML, and "did my
document land on the detection I meant?" has no answer — ingest skips rows
naming an unknown detection, so a typo looks exactly like no data.

With neither argument, two listings: one row per detection that has any stored
health (which kinds, the newest `captured_at` across them, and the derived
numbers as a compact phrase — `fp 99%  240/wk  121d since TP`), then one row
per telemetry source. The numbers get the terminal width first and the columns
give way, so a narrow terminal trims the recoverable part rather than the
point of the row.

With a `DETECTION_ID`, each stored kind in full plus the derived metrics —
exactly what `adef detection evolve` will see, which makes this the thing to
check before trusting a tuning recommendation.

`source_health` and `field_observations` are keyed by a **free-form telemetry
source name**, not a `D-XXXX`, so they are reached with `--source NAME` rather
than positionally — there is no shape to dispatch on without guessing which
namespace you meant.

| Option | Meaning |
|---|---|
| `DETECTION_ID` (arg, optional) | e.g. `D-0001`. Must be `D-XXXX`-shaped; the id becomes a path component, so a malformed one is refused rather than resolved. |
| `--source NAME` | Show a telemetry source instead of a detection. Mutually exclusive with `DETECTION_ID`. A name that isn't usable as a filename is refused for the same reason. |
| `--report json` | Machine-readable output instead of the terminal rendering. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef health show                       # everything stored: detections, then sources
adef health show D-0001                # one detection, in full, + derived metrics
adef health show --source wineventlog  # one telemetry source
adef health show --report json         # machine-readable
```

> **A detection that has never fired a true positive carries no
> `last_true_positive_at`**, so `days_since_true_positive` stays absent and
> the deprecation arms (which need ≥ 90 / ≥ 180 days) cannot fire for it. The
> honest value is the earliest window start across history rows with no TP — a
> lower bound that grows as captures accumulate. Deferred until the history
> reader exists; deriving it from a single `latest` window would report ~7
> days forever, which is worse than absent.

> **Silence needs a week.** Both silence arms — Tune's `deprecate` suggestion
> (≥ 90 days since a TP) and the `deprecate` verdict (≥ 180) — also require the
> zero volume to have been measured over at least seven days (`window_days`,
> derived from the document's window; a date-only `end` counts as a whole day).
> Zero signals in one day says nothing about last week. A custom
> `ADEF_WRAPPER_METRICS` collector must report `window_days` for either arm to
> fire on its numbers.

A `report` subcommand (the coverage-peer view: decaying, drifted, telemetry
gaps, never-fired, failing runs) belongs beside `show` and is not built yet —
which is why `health` is a group rather than a bare command with flags.

---

## Interfaces

### adef-mcp

**Synopsis:** `adef-mcp`

Separate console script (`[project.scripts]` in `pyproject.toml`, not a
subcommand of `adef`). Builds and runs the FastMCP server so Claude Code /
Cursor / Copilot can drive ADEF. Takes no options; requires the optional
`.[mcp]` extra. Tools are auto-discovered via the `adef.mcp_tools` entry-point
group.

```bash
adef-mcp
```

### adef install-skills

**Synopsis:** `adef install-skills [--agent claude|codex|chatgpt] [--global] [--force]`

Copy ADEF's bundled skills (and agents) from the installed package
(`adef/data/claude-plugin/`, so a `pip install` carries them, not only a clone)
into an AI assistant's skills directory — an alternative to the plugin marketplace for
teams that want the skills committed into their own repo, or for assistants other
than Claude Code. Run bare, it **prompts** for the agent and project-vs-global;
passing `--agent` or `--global` skips the prompt (scriptable). Nothing is written
outside the chosen directory. Does not wire the `adef-mcp` server.

| Option | Meaning |
|---|---|
| `--agent` | `claude` → `.claude/skills/`; `codex`/`chatgpt` → `.agents/skills/`. Omit to be prompted. |
| `--global` | Install user-wide (`~/`) instead of project-local (`./`). Omit to be prompted. |
| `--force` | Overwrite skills/agents already installed. |

```bash
adef install-skills
adef install-skills --agent claude --global
```

---

## See also

- `docs/quickstart.md` — hands-on walkthrough (tutorial).
- `README.md` — what is shipped and working right now.
- `CLAUDE.md` — repo guidance, architecture, and hard rules.
