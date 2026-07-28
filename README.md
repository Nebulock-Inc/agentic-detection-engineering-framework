<p align="center">
  <img src="https://raw.githubusercontent.com/Nebulock-Inc/agentic-detection-engineering-framework/main/docs/assets/adef-logo.png" width="260" alt="ADEF logo: an anvil built from angular orange segments">
</p>

# Agentic Detection Engineering Framework (ADEF)

> Detection engineering with durable memory, a five-stage lifecycle, and an agentic surface — the sibling of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework).

ADEF gives every detection a journal, every transition a timestamp, and every lifecycle stage an agent surface that current and future engineers can read. Whether your rules live in a git repo, only in your SIEM, or don't exist yet, ADEF wraps them with durable memory: *why* the rule exists, *how* it evolved, and *when next* it needs attention.

**What you get:**

- **A catalog of every detection you have** — walked read-only from a repo or a one-time SIEM export, in any mix of Sigma, Splunk, Panther, KQL/SQL/CQL, or your in-house format
- **An honest coverage report** — solid vs. fragile ATT&CK coverage, single points of failure, and fictional technique IDs, exportable as a scored MITRE Navigator layer
- **Schema-grounded authoring** — new rules scaffolded against the fields and values that actually exist in your data, not guesses
- **A journal per detection** — the reasoning, tuning history, and review cadence that normally lives in chat threads and leaves with the person who wrote it

**The FORGE lifecycle.** A detection is never one-and-done — it's found, shaped against real data, deployed under review, then tuned or retired as the threat and your telemetry change. FORGE is ADEF's name for that arc and the five stages every detection moves through: **F**ind → **O**bserve → **R**efine → **G**overn → **E**volve. Each transition is journaled, so the *why* travels with the rule. Full walkthrough under [Work the FORGE lifecycle](#work-the-forge-lifecycle) and in [`docs/methodology.md`](docs/methodology.md).

## Install

Install from source — the full local walkthrough (a self-contained demo with
sample rules and data) is in [`docs/quickstart.md`](docs/quickstart.md).

```bash
git clone https://github.com/Nebulock-Inc/agentic-detection-engineering-framework.git
cd agentic-detection-engineering-framework
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip              # pip >= 21.3 required for editable installs
pip install -e .

adef --version                         # verify
adef init --interactive                # scaffold ~/work/adef-workspace/ + set your SIEM
```

`--interactive` is a guided setup: it asks where your detections live today
(repo / SIEM-only / starting fresh) and tailors your next steps, remembers
your SIEM and query language so later commands stop asking, surfaces the
optional layers (MCP server, AI-assistant skills — inactive until installed)
and offers to install the skills on the spot. Plain `adef init` works too.

ADEF publishes to PyPI with its public release — once it's out,
`pip install agentic-detection-engineering-framework` is all you need.

## Quick start — from zero to your first coverage report

ADEF meets you where your detections are. This is the linear path; each step
links to its deep-dive under [Building blocks](#building-blocks).

*Example IDs like `D-0001` are illustrative — ADEF assigns each detection its own `D-XXXX` when you catalog or author it.*

1. **Scaffold a workspace.**
   ```bash
   adef init --interactive
   ```
2. **Teach ADEF your data** — one SIEM export; ADEF never connects to your SIEM:
   ```bash
   adef schema recipe splunk          # or: adef schema recipe sentinel
   # …run the printed export in your SIEM, save the file, then:
   adef schema reshape fields.csv --platform splunk
   adef schema ingest splunk-sources.yml
   ```
3. **Bring in your detections — pick the line that's you:**
   - **Have a repo?** `adef catalog /path/to/rules` — read-only; add `--dry-run` to preview first.
   - **Only in your SIEM?** Export your rules to a folder, then `adef catalog /path/to/export`.
   - **Starting fresh?** `adef detection new "…" --source <schema>` to author against your declared data.
4. **See where you stand.**
   ```bash
   adef coverage --gaps
   ```
5. **Work a detection.** Cataloguing (and `detection new`) land a detection at **Find**, so you drive it forward from there: `adef detection show D-0001`, then `observe` → `refine` → `govern` → `evolve`.

Repo-only readers can catalog (step 3) before declaring schemas (step 2) — the
order above suits authoring and `schema check`. The full repo-less path is
[`docs/detection-home.md`](docs/detection-home.md).

## Building blocks

Each on-ramp and capability from the quick start, in depth. Dip in as needed.

### Teach ADEF your data

Detections are only as good as knowledge of the data they query. ADEF never
connects to your SIEM — you run one export, ADEF does the rest:

```bash
adef schema recipe splunk              # the exact field-export command for YOUR SIEM
adef schema reshape fields.csv --platform splunk   # export → draft declaration + report
adef schema ingest splunk-sources.yml  # → schema/<source>.yml per source
adef schema check                      # do your rules use fields that exist?
```

`recipe` knows Splunk, Sentinel, Elastic, Chronicle, Sumo Logic, and QRadar.
`reshape` converts the raw export deterministically — filters platform
internals, folds case-duplicate fields into aliases, harvests enum values,
infers types — and prints a transformation report so you approve the
transformations instead of hand-auditing YAML. Re-ingest anytime: your hand
corrections survive, drift is reported.

**Why the merge step matters.** SIEMs often expose one fact as two fields in two
value formats:

```
# Splunk — one logon failure, two fields
Status = 0xc000006d    raw field, NTSTATUS codes
status = failure       normalized field (CIM)
```

`reshape` merges such pairs into one declared field with `aliases:`, so a rule
written against either spelling passes `adef schema check`. It marks a pair
`[SUSPECT]` when it can't tell they're the same field — read the values it shows:

- **Same fact, two formats** (`SYSTEM` vs `NT AUTHORITY\SYSTEM`) → keep the merge.
- **Different fields colliding on spelling** → split with `--no-fold` (or `--interactive`).

With the Claude plugin, the `schema-declaration` skill drives this — the
keep-or-split call turns on knowing what a field *is*, exactly the domain
knowledge an agent session adds.

### Catalog & keep it current

Point ADEF at a detection repo — the repo is never modified:

```bash
adef catalog /path/to/rules --dry-run --report json   # see what ADEF recognizes first
adef catalog /path/to/rules      # walk read-only → catalog + skeleton journals
adef sync /path/to/rules         # later: refresh changed rules, keep your enrichment
adef sync /path/to/rules --check # CI mode: exit 1 if the catalog is behind
```

Sigma, Splunk ESCU / `savedsearches.conf`, Panther, raw KQL/SQL/CQL work out
of the box. In-house formats are taught with a small **extraction profile**
(YAML, no code) — draft one by hand or let the bundled agent draft it from
samples: `adef profile lint` validates, you approve, every future run uses it.

`sync` preserves everything you've added — MITRE tags, stage, owner, journal
entries survive a re-sync; rules edited outside ADEF get a journal note
instead of silent loss. Rules that vanish from the repo are marked orphaned,
never deleted.

### Author new rules

Rules authored in ADEF live in ADEF. Declare a data source first (above), then
scaffold new detections against it:

```bash
adef detection new "Suspicious mshta.exe child process" --source wineventlog_xml
adef detection list --origin authored     # your ADEF-native rules
```

`--source` grounds the draft in a declared schema: the record gets the real
platform, query language, and a starter query carrying your actual index and
sourcetype literals. Records carry an `origin` marker — `adef sync` never
touches rules authored in ADEF, so mixing authored rules with a catalogued
repo is safe. Using ADEF as your system of record with no repo at all is a
supported path: [`docs/detection-home.md`](docs/detection-home.md) covers
making the workspace durable under git.

### See your coverage — honestly

Coverage reads straight from your ATT&CK tags, so enrich first, then measure:

```bash
adef detection tag-mitre D-0007 T1547.001    # enrich, validated against ATT&CK
adef coverage                                # coverage QUALITY report
adef coverage --navigator layer.json         # scored MITRE Navigator layer
```

Not a vanity heatmap: `coverage` separates **solid** techniques (multiple
reviewed detections) from **fragile** ones (a single rule, or nothing but
unreviewed inferences), flags techniques riding a single log source, and
calls out *fictional coverage* — mapped technique IDs that don't exist in
ATT&CK. Every mapping is validated against a shipped ATT&CK snapshot
(`adef attack show T1059.001`; refresh it anytime with `adef attack refresh`).

### Work the FORGE lifecycle

ADEF detections move through five stages:

1. **Find** — a gap, a signal source, an intel report, a hunt outcome
2. **Observe** — characterize real telemetry behavior; understand normal before defining weird
3. **Refine** — iterate the rule with similarity, overlap, and verification feedback
4. **Govern** — deploy with quality gates, ownership, review cadence
5. **Evolve** — tune, deprecate, replace; detections never finish, they iterate

```bash
adef detection list --platform windows --needs-review no_mitre
adef detection show D-0042             # record + query + journal history
adef detection observe D-0042 --note "checked 30d of process_create events"
adef detection refine  D-0042          # similarity → overlap → verification chain
adef detection govern  D-0042
adef detection evolve  D-0042 --note "raised threshold, FP rate halved"
```

Every transition is a timestamped journal entry. Six months from now, the
next engineer reads *why* the threshold is what it is. See
[`docs/methodology.md`](docs/methodology.md) for the full FORGE walkthrough.

## Skills & MCP

ADEF ships the `adef-mcp` server, **eight task-specific Claude skills**
(cataloging, coverage, authoring, schema setup, FORGE-stage work, and more), and
the `profile-author` sub-agent. Which skill fronts which command:
[`docs/skills-reference.md`](docs/skills-reference.md).

Install the skills, then wire the MCP server:

```bash
adef install-skills       # copies skills into .claude/ (or .agents/ for Codex/ChatGPT)
pip install -e ".[mcp]"   # adef-mcp needs the mcp extra — the base install lacks it
adef-mcp                  # start the server; point your assistant's MCP config at it
```

`install-skills` prompts for the agent and project-vs-global on the first run;
commit the resulting `.claude/` (or `.agents/`) tree into your repo so your team
gets the skills too. With them in place, "help me set up schemas for my Splunk
environment" drives the whole recipe → reshape → ingest flow conversationally.
The MCP server is the portable layer — it works in any MCP client (Claude,
Cursor, Copilot, ChatGPT desktop).

## ADEF and ATHF — paired siblings, not successor

ADEF and ATHF are *paired siblings*, and the structural parallel is deliberate. ATHF runs the threat-hunting lifecycle (LOCK) to establish baseline visibility and answer "is this active in our environment?" ADEF runs the detection-engineering lifecycle (FORGE) to turn that insight into production alerts, answering "how do we codify this so it pages our security team?" Both are built on the same Click + entry-point + FastMCP foundation, so analysts and agents move between hunting and detection engineering without a learning curve.

## Maturity Model

| Level | Name | What you get |
|---|---|---|
| L0 | Ad-hoc | Rules in chat threads and tickets |
| L1 | Documented | Rules in a repo with metadata |
| L2 | Searchable | AI reads coverage, performance, overlap |
| L3 | Generative | AI proposes/drafts/backtests rules from intel or hunts |
| L4 | Agentic | Autonomous tuning, deprecation recommendations, scheduled gap sweeps |

See [`docs/maturity-model.md`](docs/maturity-model.md) for full descriptions and time-to-value estimates.

## Why ADEF

ADEF is for teams whose detection count has outgrown their ability to remember why each rule exists, whether it still earns its keep, and what changing it would cost. It's a memory-and-lifecycle layer *over* your existing detections — not a replacement for your SIEM, your rule repo, or your detection-as-code pipeline.

[`docs/why-adef.md`](docs/why-adef.md) is the full adoption guide: the problem it solves, where it fits in your stack, what you give up to use it, and how to bring it into an existing detection program.

## Credits

Built by the Detection Engineering & Threat Hunting (DE&TH) Team at [Nebulock, Inc.](https://nebulock.io):

- Eric Brown ([eric@nebulock.io](mailto:eric@nebulock.io))
- Joshua Hines ([josh@nebulock.io](mailto:josh@nebulock.io))
- Sydney Marrone ([sydney@nebulock.io](mailto:sydney@nebulock.io))
- Jarrett Polcari ([jarrett@nebulock.io](mailto:jarrett@nebulock.io))

## License

MIT — see [`LICENSE`](LICENSE).
