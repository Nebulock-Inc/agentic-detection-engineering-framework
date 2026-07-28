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
| `adef backfill journals` | Create skeleton journals for existing rules |
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

**Synopsis:** `adef detection <stage> DETECTION_ID [--note TEXT ...] [--workspace PATH]`

Advance a detection to the named FORGE stage. Appends a timestamped
`## [<ISO-8601>] Stage: <stage>` block to the journal and updates frontmatter
atomically. Re-advancing to the current stage is idempotent (appends the note
only, no duplicate block). The `find` stage is not a subcommand — it is the
entry point of `detection new`.

| Option | Meaning |
|---|---|
| `DETECTION_ID` (arg, required) | e.g. `D-0001`. |
| `--note TEXT` | Note appended to the stage block. Repeatable — several `--note`s render as a bullet list. |
| `--chain` (refine only) | Re-run the Similarity → Overlap → Verification chain even when already at refine (e.g. after wiring the wrapper agents). |
| `--workspace` | Workspace path (see resolution). |

`refine` additionally runs the orchestration chain (Similarity → Overlap →
Verification) **on the transition into refine**, appending each result to the
journal (the chain does not abort on partial failure). Re-advancing to `refine`
does *not* re-run it — use `--chain` to force a re-run.

```bash
adef detection observe D-0001 --note "Checked 30d of process_create events"
adef detection refine  D-0001
adef detection govern  D-0001 --note "Owner: SOC-T2" --note "Gate: passed schema check"
adef detection evolve  D-0001
```

### adef hunt-promote

**Synopsis:** `adef hunt-promote HUNT_ID [--workspace PATH] [--rule-staging-root PATH] [--hunt-root PATH]`

Promote an upstream ATHF hunt (e.g. `H-0042`) into a draft ADEF detection:
resolves the hunt, calls a configured generator to draft a Sigma rule, writes it
to a **staging** directory (never any production rule directory), and creates a
Find-stage journal with intel sources populated.

| Option | Meaning |
|---|---|
| `HUNT_ID` (arg, required) | Hunt to promote, e.g. `H-0042`. |
| `--workspace` | Workspace path (see resolution). |
| `--rule-staging-root` | Directory for the staging YAML draft (overrides `ADEF_RULE_STAGING_ROOT`). |
| `--hunt-root` | Directory where hunt artifacts live (overrides `ADEF_HUNT_ROOT`). |

The generator dotted path is configured via environment variable
(`ADEF_HUNT_RULE_GENERATOR`); ADEF takes no opinion on the upstream hunt system.

```bash
adef hunt-promote H-0042
adef hunt-promote H-0042 --hunt-root ~/athf/hunts --rule-staging-root ~/staging
```

### adef backfill journals

**Synopsis:** `adef backfill journals [--rule-root PATH] [--limit N] [--dry-run] [--workspace PATH]`

Create skeleton journals for every external rule that doesn't already have one,
so memory search is useful over an existing corpus.

| Option | Meaning |
|---|---|
| `--rule-root` | External rule-store root (overrides `ADEF_RULE_ROOT`). |
| `--limit N` | Backfill at most N rules (default `0` = all). |
| `--dry-run` | Print the plan without writing files. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef backfill journals --dry-run
adef backfill journals --rule-root ~/sigma/rules --limit 50
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
`stage`, `owner`, journal) is preserved; missing source rules are marked
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
| `--origin` | `authored` (created in ADEF) or `catalogued` (from a repo). |
| `--needs-review [REASON]` | Only detections needing review. Bare = structural reasons (malformed, external_logic, no_platform); pass a reason (e.g. `no_mitre`) to filter it specifically. |
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
title, MITRE, platform, data source, query). Answers "have we looked at X
before / do we cover Y?". Read-only.

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
queue. Each ID is validated against the shipped ATT&CK reference — an invalid ID
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
matching keeps the most-specific source(s).

| Option | Meaning |
|---|---|
| `--detection ID` | Scope to specific detection ID(s), e.g. `D-1470`. Repeatable; suppresses the unused-declared-fields section. |
| `--report json` | Machine-readable findings report. |
| `--workspace` | Workspace path (see resolution). |

```bash
adef schema check
adef schema check --detection D-1470 --report json
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

Copy ADEF's bundled skills (and agents) from the repo's `claude-plugin/` into an
AI assistant's skills directory — an alternative to the plugin marketplace for
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
- `docs/archive/ISA.md` — project system of record (decisions, changelog, verification).
