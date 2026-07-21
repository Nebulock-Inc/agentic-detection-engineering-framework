# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ADEF (Agentic Detection Engineering Framework)** is the detection-engineering sibling of ATHF (Agentic Threat Hunting Framework). It gives detection engineering durable memory and lifecycle structure through the **FORGE** methodology:

- **F**ind → **O**bserve → **R**efine → **G**overn → **E**volve

ADEF wraps existing detection rules (YAML) with sibling markdown journals (`journals/D-XXXX.md`) that capture *why*, *how*, and *when next* for every detection. Rules stay in their upstream repositories; ADEF never modifies upstream YAML.

**Key concepts:**
- **Journals**: Per-detection markdown files (`D-XXXX.md`) with YAML frontmatter + timestamped stage-transition blocks
- **Workspace**: `~/work/adef-workspace/` with `journals/`, `templates/`, `config/`
- **Paired sibling of ATHF**: Hunts graduate to detections via `adef hunt-promote H-XXXX`
- **Plugin architecture**: Click + entry-point groups + FastMCP (same shape as ATHF)

## Essential Commands

### Installation & Setup
```bash
pip install -e .                    # Editable install for development
pip install -e ".[dev]"             # Include dev dependencies (pytest, mypy, ruff)
pip install -e ".[mcp]"             # Include MCP server support

adef --version                      # Verify installation
adef --help                         # List all commands
```

### Workspace Initialization
```bash
adef init                           # Create workspace at ~/work/adef-workspace/
adef init --path /custom/path       # Create workspace at custom location
```

### Detection Lifecycle (FORGE)
```bash
# Create a new detection at Find stage
adef detection new "Suspicious mshta.exe child process"
adef detection new "Title" --owner alice --rule-uuid <UUID>

# Advance through FORGE stages
adef detection observe D-0001       # Stage 2: characterize telemetry
adef detection refine  D-0001       # Stage 3: runs Similarity → Overlap → Verification chain
adef detection govern  D-0001       # Stage 4: deployment gates, ownership
adef detection evolve  D-0001       # Stage 5: tuning, deprecation

# Add notes to any stage transition
adef detection observe D-0001 --note "Checked 30d of process_create events"

# Enrich a catalog record with ATT&CK technique IDs (drains the no_mitre queue)
adef detection tag-mitre D-0007 T1547.001 T1055   # validated vs the shipped reference
```
`tag-mitre` validates each ID against the ATT&CK reference (invalid ID aborts,
nothing written), merges into the record's `mitre`, drops the `no_mitre` review
reason, and rebuilds the INDEX. Writes only to ADEF's catalog record — never the
source rule. The `mitre-tagger` skill orchestrates this over the whole queue.

### Hunt Promotion (ATHF Integration)
```bash
adef hunt-promote H-0042            # Promote ATHF hunt to draft detection
```

### Cataloging Existing Rules
```bash
adef catalog /path/to/rules             # Walk a rule repo → catalog/ + INDEX.yml + skeleton journals
adef catalog /path/to/rules --dry-run   # Preview what would be catalogued (nothing written)
```
Cataloging is read-only on the source repo. It sniffs each file's format
(Sigma YAML, Splunk `.conf`, `.kql`, `.sql`, `.cql`), writes an enrichment
record to `catalog/<platform>/D-XXXX-<slug>.yml` that references the source via
`rule_ref`, and flags rules whose platform/MITRE couldn't be inferred with
`needs_review: true`. See `docs/plans/2026-07-15-catalog-design.md` for the spec.

### Backfilling
```bash
adef backfill journals              # Create journals for existing upstream rules
adef backfill journals --rule-root /path/to/rules
```

### Schema Management (declaration-driven)
```bash
adef schema ingest adef-sources.yml     # Build schemas from a data-source declaration
adef schema lint adef-sources.yml       # Validate a declaration (exit 1 on errors)
adef schema check                       # Cross-reference rule field usage vs schemas
adef schema show wineventlog            # Display a schema (schema_version 2)
```
Users provide a declaration document (sources + fields, produced from
`| fieldsummary` / `| getschema` / index mappings). Ingest writes
`schema/<source>.yml` with `declared | corrected` field provenance; re-ingest
preserves human corrections and reports drift. Rules are a schema *consumer*
(via `check`), never a schema *source*. See
`docs/plans/2026-07-20-schema-declaration-design.md`.

### ATT&CK Reference Layer
```bash
adef attack info                    # Active snapshot's ATT&CK version + counts
adef attack show T1059.001          # Technique name, tactics, parent, revoked→replacement
adef attack refresh                 # Pull a fresh snapshot from official STIX into the workspace
```
Compact ATT&CK snapshot (`adef/data/attack/enterprise.json`, distilled from
official STIX at build time by `adef/data/attack/_generate.py` — a dev-time
stdlib script, **never a runtime dep**). Consumers: catalog-time `invalid_mitre`
validation and true `by_tactic` INDEX resolution. `refresh` writes to
`$ADEF_WORKSPACE/attack/enterprise.json`, which wins over the shipped copy on read.

### MCP Server
```bash
adef-mcp                            # Start FastMCP server for Claude Code/Cursor/Copilot
```

### Testing
```bash
pytest                              # Run all tests
pytest -v                           # Verbose output
pytest -k test_journal              # Run specific test pattern
pytest -m unit                      # Run only unit tests (fast)
pytest -m integration               # Run integration tests (requires siblings)
pytest --cov=adef                   # Run with coverage report
```

### Code Quality
```bash
ruff check adef/                    # Lint with ruff
ruff format adef/                   # Format with ruff
mypy adef/                          # Type checking
```

## Architecture

### Package Structure
```
adef/
├── cli.py                      # Click root group + plugin discovery
├── plugin_system.py            # Entry-point discovery (adef.commands, adef.agents, adef.mcp_tools)
├── agents/
│   ├── hypothesis_from_intel.py      # ADEF-native: draft Find/Observe from CTI
│   ├── tune_recommender.py           # ADEF-native: tuning suggestions
│   ├── deprecation_recommender.py    # ADEF-native: keep/tune/deprecate
│   ├── hunt_promotion.py             # ADEF-native: ATHF hunt → ADEF detection
│   └── wrappers/                     # Thin wrappers around 12 upstream rule agents
├── commands/
│   ├── detection.py            # FORGE lifecycle commands (new, observe, refine, govern, evolve)
│   ├── init.py                 # Workspace scaffolding
│   ├── hunt_promote.py         # Hunt-to-detection promotion
│   └── backfill.py             # Bulk journal creation
├── core/
│   ├── journal.py              # Journal CRUD + stage advancement (NEVER writes to detections/)
│   ├── memory.py               # BM25 search over journals + upstream YAML
│   └── rule_bridge.py          # Read-only bridge to upstream rule metadata
├── data/
│   ├── templates/DETECTION_FORGE.md    # Journal template
│   └── prompts/                        # Stage-specific prompts (find.md, observe.md, etc.)
├── mcp/
│   ├── server.py               # FastMCP server + plugin tool discovery
│   └── tools/                  # lifecycle_tools, memory_tools, agent_tools, init_tools
└── orchestration/
    └── refine_chain.py         # Similarity → Overlap → Verification orchestration
```

### Plugin System (Entry Points)

ADEF uses Python entry points for extensibility (same as ATHF):

**Entry-point groups in `pyproject.toml`:**
- `adef.commands` → Click commands/groups attached to root CLI
- `adef.agents` → Agent classes for orchestration lookup
- `adef.mcp_tools` → Tool registration callables for FastMCP server

**Plugin discovery is defensive**: A broken plugin never kills CLI startup. Failures log to stderr and discovery continues.

### Journal Architecture

**Core invariant**: No `adef.*` code path ever writes to any path under a `detections/` directory. This is CI-enforced by `tests/test_schema_parity.py`.

**Journal lifecycle**:
1. `Journal.create(detection_id)` → writes `journals/D-XXXX.md` from template
2. `Journal.advance_stage(detection_id, stage, note)` → appends timestamped `## [ISO-8601] Stage: <stage>` block, updates frontmatter atomically (temp file + rename)
3. `Journal.read(detection_id)` → returns journal content + parsed frontmatter

**Frontmatter fields**: `id`, `status`, `current_stage`, `owner`, `created`, `updated`, `rule_uuid`

**Stage transitions are idempotent**: Re-advancing to the same stage appends only the note (if provided), no duplicate block.

### Upstream Decoupling via Environment Variables

ADEF never hardcodes upstream package names. Integration uses env vars:

```bash
# Wrapper bindings (12 upstream rule-engineering agents)
ADEF_WRAPPER_COVERAGE_ANALYSIS=package.module:CoverageAnalysisClass
ADEF_WRAPPER_RULE_OVERLAP=package.module:RuleOverlapClass
ADEF_WRAPPER_VERIFICATION=package.module:VerificationClass
# ... (9 more)

# Hunt promotion
ADEF_HUNT_RULE_GENERATOR=athf_package.module:HuntRuleGeneratorClass

# Paths
ADEF_RULE_ROOT=/path/to/upstream/rules      # Read-only rule YAML directory
ADEF_HUNT_ROOT=/path/to/upstream/hunts      # Read-only hunt artifacts directory
ADEF_WORKSPACE=/path/to/adef-workspace      # Override default workspace location
```

If a binding is missing or import fails, the wrapper raises `WrapperUnavailable` → orchestration logs error to journal and continues.

### The Refine Chain

When `adef detection refine D-XXXX` runs:
1. Advances stage to `refine`
2. Invokes `orchestration/refine_chain.py`
3. Runs **three upstream agents in sequence**:
   - **RuleSimilarity**: Does a rule like this already exist?
   - **RuleOverlap**: Do triggers heavily overlap with another rule?
   - **Verification**: Would the rule pass schema validation + four-engine constraint?
4. Each result is appended to the detection's journal under `### Refine / <step>` heading
5. Chain does NOT abort on failure; partial results are valuable

## Hard Rules (CI-Enforced Anti-Goals)

These are tested and will fail CI if violated:

1. **`tests/test_schema_parity.py`**: Never write inside any `detections/` tree. ADEF is read-only for upstream YAML.
2. **`tests/test_no_new_engine_types.py`**: Only four engines allowed: `sigma`, `sql`, `sch_sql`, `composite`. No new engine types.
3. **`tests/test_no_vendor_connectors.py`**: Never add vendor API connectors (CrowdStrike, Splunk, SentinelOne, etc.). Connectors live in adapter packages.
4. **`tests/test_no_web_ui_deps.py`**: No web UI dependencies (`flask`, `fastapi`, `starlette`, `django`, `next`, `react`). v0.1.0 is CLI + MCP only.

## ISA.md — System of Record

`ISA.md` at repo root uses **Algorithm v6.3.0** and is the authoritative project document:
- All decisions go in `## Decisions`
- All conjectures/refutations go in `## Changelog`
- All verification facts go in `## Verification`

When making architectural changes, update `ISA.md` first, then implement.

## Key Documentation

Read these to understand the framework:
- **`docs/methodology.md`**: The FORGE lifecycle explained with examples
- **`docs/maturity-model.md`**: L0 (Ad-hoc) → L4 (Agentic) progression
- **`docs/why-adef.md`**: Adoption guide, ADEF vs ATHF relationship
- **`AGENTS.md`**: AI agent briefing for working in this repo
- **`ISA.md`**: Project ISA (system of record)

## ADEF and ATHF Relationship

ADEF and ATHF are **paired siblings, not successors**:

| Framework | Lifecycle | Unit of Work | Purpose |
|-----------|-----------|--------------|---------|
| **ATHF** | LOCK (Learn → Observe → Check → Keep) | Hunt (`H-XXXX`) | "Is this happening?" — exploratory |
| **ADEF** | FORGE (Find → Observe → Refine → Govern → Evolve) | Detection (`D-XXXX`) | "Codify this so it pages someone" — production rules |

Hunts graduate to detections via `adef hunt-promote H-XXXX`. Both frameworks share Click + entry-point + FastMCP architecture.

## Development Patterns

### Adding a New CLI Command

1. Create command in `adef/commands/<name>.py` as a Click group or command
2. Register in `pyproject.toml`:
   ```toml
   [project.entry-points."adef.commands"]
   my-command = "adef.commands.my_command:my_command"
   ```
3. Test with `adef --help` (should appear in list)
4. Plugin discovery is automatic via `PluginRegistry.register_commands(cli)` in `adef/cli.py`

### Adding a New Agent

1. Create agent in `adef/agents/<name>.py`
2. Register in `pyproject.toml`:
   ```toml
   [project.entry-points."adef.agents"]
   my-agent = "adef.agents.my_agent:MyAgentClass"
   ```
3. Ensure agent has a `.run()` method compatible with orchestration

### Adding MCP Tools

1. Create tools module in `adef/mcp/tools/<name>.py`
2. Define a `register_mcp_tools(server)` function
3. Register in `pyproject.toml`:
   ```toml
   [project.entry-points."adef.mcp_tools"]
   my-tools = "adef.mcp.tools.my_tools:register_mcp_tools"
   ```
4. Tools are auto-discovered when `adef-mcp` starts

### Working with Journals

```python
from adef.core.journal import Journal, workspace_journals_dir

journals_dir = workspace_journals_dir(None)  # Uses ADEF_WORKSPACE or default
journal = Journal(journals_dir)

# Create
journal.create(detection_id="D-0042", title="My Detection", owner="alice")

# Advance stage
result = journal.advance_stage(detection_id="D-0042", stage="observe", note="Analyzed 30d")

# Read
content = journal.read(detection_id="D-0042")
```

### Memory Search

```python
from adef.core.memory import MemoryIndex

index = MemoryIndex(workspace_path="/path/to/workspace", rule_root="/path/to/rules")
results = index.search("mshta.exe public directory")  # BM25 over journals + YAML
```

## Common Patterns

### Atomic File Writes
All journal writes use temp file + `os.replace()` for POSIX atomicity:
```python
from adef.core.journal import _atomic_write
_atomic_write(target_path, content)
```

### Defensive Plugin Loading
All entry-point loads are wrapped to never crash:
```python
from adef.plugin_system import PluginRegistry
commands = PluginRegistry.register_commands(cli)  # Broken plugins log to stderr, don't crash
```

### Stage Prompt Rendering
Stage prompts are markdown files in `adef/data/prompts/`:
```python
from importlib import resources
prompt = resources.files("adef.data").joinpath("prompts/observe.md").read_text()
```

## Version

Current version: **v0.1.0**

Update version in `adef/__init__.py`:
```python
__version__ = "0.1.0"
```
