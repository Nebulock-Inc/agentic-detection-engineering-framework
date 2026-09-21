# Decision 008: ATHF-Inspired CLI Commands for ADEF

**Status:** Planning  
**Created:** 2026-06-25  
**Purpose:** Identify CLI commands from ATHF that should be adapted for ADEF detection engineering

---

## Executive Summary

ATHF has **30+ CLI commands** across hunt management, research, integrations, and analytics. Many patterns can be adapted for ADEF's detection engineering workflow while respecting the "paired siblings" relationship.

**Key Finding:** ATHF already has `athf detect` command group with 14 subcommands — this is the **primary overlap** that needs consolidation per meeting notes.

---

## ATHF Command Inventory

### Core Commands (Already in ADEF)
| ATHF Command | ADEF Equivalent | Status |
|--------------|-----------------|--------|
| `athf init` | `adef init` | ✅ Implemented |
| `athf hunt new` | `adef detection new` | ✅ Implemented (different lifecycle) |
| `athf hunt list` | ❌ Missing | Need `adef detection list` |
| `athf hunt search` | ❌ Missing | Need `adef detection search` |
| `athf hunt stats` | ❌ Missing | Need `adef detection stats` |
| `athf hunt validate` | ❌ Missing | Need `adef detection validate` |
| `athf hunt coverage` | ❌ Missing | Need `adef detection coverage` |

### ATHF Research Commands (Inspiration for ADEF Research)
| Command | Purpose | ADEF Adaptation |
|---------|---------|-----------------|
| `athf research new --topic "LSASS dumping"` | Deep pre-hunt research | `adef research new --topic "LSASS dumping"` (CTI → detection drafts) |
| `athf research list` | List research docs | `adef research list` |
| `athf research view R-0001` | Show research doc | `adef research view R-0001` |

**Research Methodology (ATHF):**
1. System Research — How does tech normally work?
2. Adversary Tradecraft — How do adversaries abuse it? (web search)
3. Telemetry Mapping — What OCSF fields capture this?
4. Related Work — What past hunts are relevant?
5. Synthesis — Key findings, gaps, focus areas

**ADEF Adaptation:**
1. System Research — Same
2. Adversary Tradecraft — Same (CTI sources)
3. Telemetry Mapping → **Schema Discovery** — What fields exist in our environment?
4. Related Work → **Coverage Analysis** — What detections already exist?
5. Synthesis → **Detection Drafts** — Generate Find/Observe/Refine starters

---

## ATHF Detect Commands — THE OVERLAP

### Commands We Should Consolidate into ADEF

#### 🔴 **Direct Overlap (Deprecate in ATHF, Move to ADEF)**

**1. `athf detect new`**
- Creates detection rule interactively
- **ADEF:** `adef detection new` (already exists)
- **Action:** Deprecate `athf detect new`, point to ADEF

**2. `athf detect list`**
- Lists detection rules from ClickHouse
- **ADEF:** Need `adef detection list` (currently missing)
- **Note:** ATHF reads from ClickHouse; ADEF reads from journals dir

**3. `athf detect show <RULE_ID>`**
- Shows detailed rule information
- **ADEF:** Need `adef detection show D-XXXX`
- **Implementation:** Read journal + render rich display

**4. `athf detect validate`**
- Validates rule syntax, structure, MITRE mapping
- **ADEF:** Already in Refine stage, could expose as standalone
- **Implementation:** `adef detection validate D-XXXX`

**5. `athf detect coverage`**
- Analyzes ATT&CK coverage across rules
- **ADEF:** Need `adef detection coverage` (high value)
- **Note:** ATHF queries ClickHouse; ADEF queries journals + YAML

**6. `athf detect gaps`**
- Shows prioritized coverage gaps
- **ADEF:** Need `adef detection gaps` (research input)
- **Integration:** Feeds into `adef research` workflow

**7. `athf detect similar --query "process injection"`**
- Semantic search for rules
- **ADEF:** Already have `memory_search` MCP tool
- **Action:** Expose as CLI: `adef detection search "process injection"`

---

#### 🟡 **Partial Overlap (Adapt, Don't Duplicate)**

**8. `athf detect overlap`**
- Detects overlapping/redundant rules
- **ADEF:** Already in Refine chain (RuleOverlap agent)
- **Action:** Expose as standalone: `adef detection overlap D-XXXX`

**9. `athf detect decision`**
- Update existing rule vs. create new?
- **ADEF:** Similar to Evolve stage logic
- **Action:** Could be part of `adef detection evolve`

**10. `athf detect to-query`**
- Converts rule to executable query
- **ADEF:** Out of scope (ADEF doesn't execute queries in v0.1)
- **Action:** Defer to product or v0.2

**11. `athf detect generate --hunt H-0042`**
- Generates detection from hunt
- **ADEF:** Already have `adef hunt-promote H-0042`
- **Action:** Keep ADEF version, deprecate ATHF version

---

#### 🟢 **Product-Specific (Keep in ATHF or Defer)**

**12. `athf detect performance`**
- Analyzes rule performance from signals table
- **ADEF:** Gray-zone (product feature - requires signal stream)
- **Action:** Document as product-only in gray-zone doc

**13. `athf detect metrics`**
- MTTD, MTTR, triage times
- **ADEF:** Gray-zone (product feature)
- **Action:** Keep in ATHF or move to product

**14. `athf detect findings`**
- Findings analysis and inspection
- **ADEF:** Gray-zone (requires finding store)
- **Action:** Keep in ATHF or defer to product

**15. `athf detect review-detections`**
- Review rules for quality degradation
- **ADEF:** Gray-zone (requires live signal data)
- **Action:** Document as product feature

**16. `athf detect hunting-triggers`**
- Hunting trigger analysis and noise profiling
- **ADEF:** ATHF-specific (hunt workflow)
- **Action:** Keep in ATHF

**17. `athf detect forge-next`**
- Forge rules for top-N priority gaps
- **ADEF:** Could be `adef research forge --top 5`
- **Action:** Consider for v0.2 research workflow

---

## Recommended ADEF CLI Commands (Inspired by ATHF)

### Phase 1: Essential Commands (v0.1.1)

#### Detection Lifecycle (Extend Existing)
```bash
# Already exists
adef detection new "Title"
adef detection {observe,refine,govern,evolve} D-XXXX

# ADD THESE:
adef detection list                          # List all detections
adef detection list --stage refine           # Filter by stage
adef detection list --owner alice            # Filter by owner
adef detection list --technique T1003.001    # Filter by MITRE

adef detection show D-XXXX                   # Rich display of detection

adef detection search "mshta.exe"            # Full-text search journals

adef detection validate D-XXXX               # Schema + YAML validation

adef detection assign D-XXXX --owner bob     # Change owner

adef detection approve D-XXXX                # Mark approved (Govern stage)
```

#### Coverage & Gap Analysis
```bash
adef detection coverage                      # ATT&CK coverage heatmap
adef detection coverage --tactic execution   # Filter by tactic
adef detection coverage --export coverage.json

adef detection gaps                          # Prioritized gaps
adef detection gaps --format json            # For scripting

adef detection stats                         # Program metrics
# Output: Total detections, by stage, by owner, coverage %
```

#### Detection Comparison
```bash
adef detection overlap D-XXXX                # Find overlapping rules
adef detection similar D-XXXX                # Find similar rules
adef detection diff D-0001 D-0002            # Compare two detections
```

---

### Phase 2: Research Commands (v0.2)

#### Research Workflow (New Command Group)
```bash
adef research new --topic "LSASS dumping"    # CTI → detection drafts
adef research new --cti-url https://...     # From URL
adef research new --cve CVE-2024-1234        # From CVE
adef research new --technique T1003.001      # From technique

adef research list                           # List research docs
adef research show R-0001                    # Show research doc
adef research export R-0001 --format json    # Export structured data

# Research creates detection drafts:
# R-0001.md contains:
#  - MITRE mapping
#  - Coverage gaps
#  - 3-5 prioritized detection drafts
# Then: adef detection new --from-research R-0001 --draft 1
```

---

### Phase 3: Schema Commands (v0.2)

Already proposed in meeting plan, adding ATHF-inspired enhancements:

```bash
# Core schema discovery (from meeting plan)
adef schema discover --connector splunk --source security-logs
adef schema list
adef schema show splunk-security
adef schema delete splunk-security

# ADD THESE (ATHF-inspired):
adef schema validate D-XXXX                  # Validate rule against schema
adef schema drift splunk-security            # Compare current vs previous
adef schema refresh splunk-security          # Re-run discovery

# Schema-aware detection authoring
adef detection new "Title" --schema splunk-security
# Prompts with available fields during interactive creation
```

---

### Phase 4: Integration Commands (v0.3+)

ATHF has rich integration commands. ADEF could have similar:

```bash
# Splunk integration (read-only for schema/validation)
adef splunk test                             # Test connection
adef splunk query "index=main | head 10"    # Execute query (for validation)
adef splunk fields --sourcetype WinEventLog  # List available fields

# ClickHouse integration (if used for signal storage)
adef clickhouse test
adef clickhouse query "SELECT * FROM signals LIMIT 10"

# Generic connector test
adef connector test splunk
adef connector list                          # Show configured connectors
```

---

## Command Mapping: ATHF → ADEF

| ATHF Command | ADEF Command | Status | Priority |
|--------------|--------------|--------|----------|
| `athf init` | `adef init` | ✅ Exists | — |
| `athf hunt new` | `adef detection new` | ✅ Exists (different model) | — |
| `athf hunt list` | `adef detection list` | ❌ Missing | 🔴 HIGH |
| `athf hunt search` | `adef detection search` | ❌ Missing | 🔴 HIGH |
| `athf hunt stats` | `adef detection stats` | ❌ Missing | 🟡 MEDIUM |
| `athf hunt validate` | `adef detection validate` | ⚠️ Partial (in Refine) | 🟡 MEDIUM |
| `athf hunt coverage` | `adef detection coverage` | ❌ Missing | 🔴 HIGH |
| `athf research new` | `adef research new` | ❌ Missing | 🔴 HIGH |
| `athf research list` | `adef research list` | ❌ Missing | 🟡 MEDIUM |
| `athf detect new` | `adef detection new` | ✅ Exists | — |
| `athf detect list` | `adef detection list` | ❌ Missing | 🔴 HIGH |
| `athf detect show` | `adef detection show` | ❌ Missing | 🟡 MEDIUM |
| `athf detect coverage` | `adef detection coverage` | ❌ Missing | 🔴 HIGH |
| `athf detect gaps` | `adef detection gaps` | ❌ Missing | 🔴 HIGH |
| `athf detect similar` | `adef detection search/similar` | ⚠️ MCP only | 🟡 MEDIUM |
| `athf detect overlap` | `adef detection overlap` | ⚠️ Refine chain only | 🟡 MEDIUM |
| `athf detect validate` | `adef detection validate` | ⚠️ Refine stage only | 🟡 MEDIUM |
| `athf detect decision` | Part of `adef detection evolve` | ❌ Missing | 🟢 LOW |
| `athf detect to-query` | Out of scope (v0.1) | ⏸️ Deferred | 🟢 LOW |
| `athf detect performance` | Product-only (gray-zone) | ⏸️ Deferred | 🟢 LOW |
| `athf detect metrics` | Product-only (gray-zone) | ⏸️ Deferred | 🟢 LOW |

---

## Implementation Priority

### Sprint 1 (Week 1-2): Essential Parity
1. ✅ `adef detection list` — List/filter detections
2. ✅ `adef detection search` — Full-text search
3. ✅ `adef detection coverage` — ATT&CK heatmap
4. ✅ `adef detection gaps` — Coverage gaps

### Sprint 2 (Week 3-4): Research Workflow
5. ✅ `adef research new` — CTI → detection drafts
6. ✅ `adef research list/show` — Research management
7. ✅ `adef detection stats` — Program metrics

### Sprint 3 (Week 5-6): Quality & Validation
8. ✅ `adef detection show` — Rich detail view
9. ✅ `adef detection validate` — Standalone validation
10. ✅ `adef detection overlap/similar` — Comparison tools

### Sprint 4+ (v0.2): Advanced Features
11. ⏳ `adef detection assign/approve` — Governance
12. ⏳ `adef schema` commands — Schema discovery integration
13. ⏳ `adef connector` commands — Data source integration

---

## Code Reuse Opportunities

### 1. HuntManager → DetectionManager Pattern
ATHF has `athf/core/hunt_manager.py` that:
- Lists hunts from filesystem
- Parses YAML frontmatter
- Generates next hunt ID
- Filters by status/tactic/technique

**ADEF already has this!** → `adef/core/journal.py` (Journal class)

**Enhancement needed:** Add filtering/listing methods to Journal class:
```python
# adef/core/journal.py additions
class Journal:
    def list_detections(
        self,
        stage: Optional[str] = None,
        owner: Optional[str] = None,
        technique: Optional[str] = None
    ) -> List[JournalEntry]:
        """List detections with optional filters."""
        pass

    def get_stats(self) -> Dict[str, Any]:
        """Get program statistics."""
        pass
```

---

### 2. Coverage Analysis Pattern
ATHF has coverage analysis in `athf/commands/hunt.py`:
- Scans hunt files for MITRE techniques
- Builds ATT&CK matrix
- Identifies gaps
- Outputs rich table or JSON

**ADEF can reuse the pattern:**
```python
# New: adef/core/coverage.py
def analyze_coverage(journals_dir: Path) -> CoverageReport:
    """Scan journals, extract techniques, build matrix."""
    pass

def identify_gaps(coverage: CoverageReport, priority: str) -> List[Gap]:
    """Compare coverage to full ATT&CK matrix."""
    pass
```

---

### 3. Rich Display Patterns
ATHF uses Rich library extensively for:
- Tables with filtering/sorting
- Panels for detailed views
- Progress spinners for long operations
- Color-coded status indicators

**ADEF already uses Rich!** Can copy display patterns directly.

---

### 4. Search Implementation
ATHF's `athf hunt search` does:
- Full-text search across markdown files
- Grep-based initially, could upgrade to vector search
- Returns ranked results with snippets

**ADEF already has this!** → `adef/core/memory.py` (MemoryIndex with BM25)

**Enhancement:** Expose as CLI command:
```python
# New: adef/commands/detection.py
@detection.command()
@click.argument("query")
def search(query: str):
    """Full-text search across detection journals."""
    from adef.core.memory import MemoryIndex
    index = MemoryIndex(workspace_path=..., rule_root=...)
    results = index.search(query)
    # Display with Rich table
```

---

## Connector Architecture Insight from ATHF

ATHF has connectors in `athf/integrations/`:
- `splunk.py` — Splunk REST API
- `clickhouse.py` — ClickHouse driver
- Each has test/list/query commands

**Pattern for ADEF:**
```
adef/connectors/
  ├── base.py          # SchemaConnector ABC (already planned)
  ├── splunk.py        # Splunk schema discovery
  ├── clickhouse.py    # ClickHouse schema discovery
  └── generic_sql.py   # Generic SQL (Postgres, MySQL, etc.)
```

ATHF connectors have:
- `test()` — Connection validation
- `query()` — Execute query
- `fields()` — List available fields

ADEF connectors should have:
- `discover()` — Schema discovery (already in plan)
- `validate_query()` — Check query against schema (already in plan)
- **ADD:** `test()` — Connection test
- **ADD:** `sample()` — Get sample data (for Observe stage)

---

## Migration Path from ATHF Detect Commands

### Phase 1: Deprecation Warnings (ATHF v0.X)
Add deprecation messages to ATHF detect commands:
```python
# In athf/commands/detect.py
@detect.command()
def new(...):
    console.print("[yellow]Warning: 'athf detect new' is deprecated.[/yellow]")
    console.print("[yellow]Use 'adef detection new' instead.[/yellow]")
    console.print("[yellow]ATHF will focus on hunting; ADEF handles detections.[/yellow]\n")
    # ... existing logic
```

### Phase 2: Command Aliases (Transition Period)
ATHF can shell out to ADEF:
```python
# athf/commands/detect.py
@detect.command()
def new(...):
    console.print("[yellow]Forwarding to ADEF...[/yellow]")
    import subprocess
    subprocess.run(["adef", "detection", "new", ...])
```

### Phase 3: Full Removal (ATHF v1.0+)
Remove `athf detect` command group entirely.

---

## Next Steps

1. **Decision Required:** Confirm consolidation strategy (deprecate athf detect)
2. **Implementation:** Add missing ADEF commands (list, search, coverage, gaps, stats)
3. **Documentation:** Update both ATHF and ADEF docs with migration guide
4. **Testing:** Ensure feature parity before deprecating ATHF commands
5. **Coordination:** Work with ATHF team on deprecation timeline

---

## Open Questions

1. **Timeline:** When can we start deprecating `athf detect` commands?
2. **Feature Parity:** Which commands must reach parity before deprecation?
3. **Data Migration:** Do existing detection rules need migration from ATHF format to ADEF journals?
4. **Connector Sharing:** Should connectors be extracted to shared library (Decision 002)?
5. **User Communication:** How do we communicate the transition to users?
