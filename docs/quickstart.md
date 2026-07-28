# Quickstart (local)

ADEF is on PyPI — `pip install agentic-detection-engineering-framework` — but
this quickstart runs from a **source checkout**, because it uses the bundled
demo (sample rules and data under `examples/`) that ships in the repo, not the
wheel. This walkthrough takes ~10 minutes and ends with a catalogued rules repo,
browsable detections, ingested data schemas, and a schema-check finding.

## 1. Install from source

```bash
git clone https://github.com/Nebulock-Inc/agentic-detection-engineering-framework.git
cd agentic-detection-engineering-framework

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip        # IMPORTANT: pip >= 21.3 needed for `pip install -e .`
pip install -e .                 # add ".[dev]" for pytest/ruff/mypy, ".[mcp]" for adef-mcp

adef --version                   # should print the version — if `adef` is not
                                 # found, the venv isn't activated
```

Requires Python **3.10+** (`python3 --version` to check).

Common gotchas from real attempts:

- **`No matching distribution found`** → you're on an unsupported Python (need
  3.10+) or a very old pip — upgrade pip. Note the demo needs the source
  checkout (`pip install -e .` from the repo root), not the published wheel.
- **`adef: command not found` after install** → the venv isn't activated, or
  the editable install silently failed on old pip. Upgrade pip and reinstall.
- Don't name your venv folder `adef` — it works, but makes `adef` vs `./adef/`
  confusion inevitable. `.venv` is the convention here.

## 2. Use a scratch workspace

ADEF keeps all of its state (catalog, journals, schemas) in a *workspace*,
default `~/work/adef-workspace/`. For testing, point it somewhere disposable:

```bash
export ADEF_WORKSPACE=$(mktemp -d)   # everything below writes here, nothing else
```

## 3. Run the bundled demo (no Splunk or data needed)

The repo ships a self-contained demo: a small mixed-format rules "repo"
(Splunk saved searches + a Sigma rule) and a matching data-source declaration
built from a real lab export.

```bash
# Ingest the data schemas FIRST — the catalog uses them to resolve platforms.
adef schema ingest examples/adef-sources-thrunt.yml

# Walk the demo rules repo (read-only) into the catalog + skeleton journals.
adef catalog examples/demo-rules

# Browse.
adef detection list
adef detection list --platform windows
adef detection list --needs-review           # structural problems only
adef detection list --needs-review no_mitre  # the ATT&CK enrichment queue
adef detection list --report json            # for scripts/agents
adef detection show D-0009                   # full record + query + journal

# Cross-reference: do the rules use fields that exist in the data?
adef schema check                            # finds the one deliberately-broken rule
adef schema show zeek_dns
```

What you should see: 9 detections catalogued; most platforms resolved
automatically from the declared schemas; exactly one ⚠ (`no_platform`) on the
deliberately-broad hunt rule; and `schema check` flagging `NotARealField` —
planted in `examples/demo-rules/broad_hunt_bogus_field.conf` so there's
always a finding to look at.

## 3a. Generate schemas for your own SIEM (recipe workflow)

The demo used a pre-built declaration (`adef-sources-thrunt.yml`). For your own
SIEM, ADEF can generate platform-specific recipes showing exactly what command
to run and how to convert the output.

```bash
# Interactive workspace setup (optional but helpful for first-time users)
adef init --interactive
# Prompts for:
#   - Which SIEM/platform? (splunk, sentinel, elastic, chronicle, sumo, qradar, other)
#   - Query language(s)? (spl, kql, sql, cql, etc.)
# Stores preferences in config/.adefconfig.yaml

# Generate recipe for your platform
adef schema recipe            # Uses platform from config
adef schema recipe splunk     # Explicit platform
adef schema recipe sentinel

# Recipe shows:
#   - Exact command to run in your SIEM (e.g., index=... | fieldsummary)
#   - How to export the results (CSV, JSON, etc.)
#   - The `adef schema reshape` invocation for that platform
```

**Workflow:**
1. Run the SIEM command from the recipe (e.g., Splunk `fieldsummary`)
2. Export the results as CSV/JSON
3. Convert deterministically: `adef schema reshape fields.csv --platform splunk`
   — prints a transformation report; `[SUSPECT]` merges show each spelling's
   values so you decide keep vs split (`--no-fold <name>`, or walk them with
   `--interactive`); `--append <decl.yml>` builds up a multi-source file
4. Set `platform:` (never inferred) and `description:` in the output YAML
5. Validate: `adef schema lint <platform>-sources.yml`
6. Ingest: `adef schema ingest <platform>-sources.yml`

Detailed per-SIEM guides: [`docs/siem-recipes.md`](./siem-recipes.md)

**Why this matters:** ADEF's schema system lets it suggest detections grounded
in what your data can actually express, and helps rules reference real field
names (not aliases, macros, or calculated fields).

## 3b. Teach ADEF an in-house format (extraction profiles)

Real repos almost always contain a format ADEF doesn't know — the first thing
you'll hit outside the demo. `examples/inhouse-rules/` is a made-up
"Nebulock hunt" format so you can experience the loop:

```bash
adef catalog examples/inhouse-rules
# → "3 structured files were NOT catalogued — no recognizer or profile
#    claims their format" ... nothing was added.

# Cluster the unclaimed files by shape (one key-set = one format = one profile):
adef catalog examples/inhouse-rules --dry-run --report json | grep top_level_keys

# A ready-made profile for this format ships in examples/profiles/.
# Validate it — the engine reports per-field extraction rates (the scoreboard):
adef profile lint examples/profiles/nebulock-hunt.yml
adef catalog examples/inhouse-rules --dry-run --profile examples/profiles/nebulock-hunt.yml
# → claimed 3; title 100%, query 100%, uuid 100%, mitre 100% ...

# Install it and catalog for real:
mkdir -p $ADEF_WORKSPACE/config/profiles
cp examples/profiles/nebulock-hunt.yml $ADEF_WORKSPACE/config/profiles/
adef catalog examples/inhouse-rules
adef detection list --rule-format nebulock-hunt
```

For your own formats, the profile is ~15 lines of YAML you write once —
full how-to: [`docs/creating-extraction-profiles.md`](creating-extraction-profiles.md).
(With the Claude plugin installed, the catalog-onboarding skill drafts and
validates profiles for you — see step 5b.)

## 4. The FORGE lifecycle (journals)

```bash
adef detection new "Suspicious svchost.exe child process"
adef detection observe D-0010 --note "Checked 30d of process_create events"
adef detection refine  D-0010
cat $ADEF_WORKSPACE/journals/D-0010.md
```

Every stage transition appends a timestamped block to the journal — that's
ADEF's durable memory.

## 5. Point it at real things

- **Your rules repo:** `adef catalog /path/to/your/rules --dry-run --report json`
  first to see what ADEF recognizes; unrecognized in-house formats are taught
  with an extraction profile — the how-to is
  [`docs/creating-extraction-profiles.md`](creating-extraction-profiles.md).
- **Your data:** write a declaration from any field inventory —
  [`docs/declaring-data-sources.md`](declaring-data-sources.md) has the format
  and worked Splunk/CrowdStrike examples — then `adef schema ingest` + `check`.
- **Claude Code / Cursor / Copilot:** `pip install -e ".[mcp]"` and run
  `adef-mcp` for the MCP tool surface (portable to all assistants).

## 5b. Install the skills (do this — it matters)

The skills and sub-agents are **inactive until they're installed** — sitting in
the repo does nothing. Without them your assistant can *describe* ADEF workflows
(it reads the repo docs) but won't *drive* them — e.g. it will diagnose
unclaimed rule formats and stop, instead of running the catalog-onboarding flow
that drafts and validates extraction profiles for you.

`adef install-skills` copies the skills into an assistant's skills directory —
so a team can **commit them into their shared detections repo** (everyone gets
them on clone, no per-person setup), and so users on **Claude, ChatGPT, or
Codex** get them.

Run it bare and it prompts for the agent and project-vs-global (it's a rare
one-time setup, so you don't have to memorize flags):

```
cd your-detections-repo
adef install-skills
#   Which AI assistant?
#     1) Claude Code
#     2) Codex (also ChatGPT) — .agents/
#   Install where?
#     1) This project only (./)
#     2) User-wide (~/)
git add .claude && git commit -m "Add ADEF skills"   # (or .agents/ for codex)
```

Flags skip the prompt: `adef install-skills --agent codex --global`. Claude →
`.claude/skills/`; Codex/ChatGPT → `.agents/skills/` (same skill files, each
agent's convention). `--force` overwrites edited local skills.

### Wire the MCP server

The skills drive ADEF's CLI; the `adef-mcp` server is the portable tool surface,
and it works in any MCP client (Claude, Cursor, Copilot, ChatGPT desktop):

```bash
pip install -e ".[mcp]"   # adef-mcp needs the mcp extra — the base install lacks it
adef-mcp                  # start the server; point your assistant's MCP config at it
```

> Solo Claude Code user? The repo doubles as a plugin marketplace, which bundles
> the skills **and** the MCP wiring in one step — `/plugin marketplace add
> Nebulock-Inc/agentic-detection-engineering-framework` then `/plugin install
> adef@adef-marketplace` and `/reload-plugins`. Still needs the `[mcp]` extra.

## 6. Developing

```bash
pip install -e ".[dev]"
pytest            # full suite
ruff check adef/
mypy adef/
```

CI-enforced hard rules live in `CLAUDE.md` / `AGENTS.md` — most importantly:
ADEF never writes inside any `detections/` tree in your rule repos.
