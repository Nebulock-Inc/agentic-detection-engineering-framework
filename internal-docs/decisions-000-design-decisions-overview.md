# Design Decisions Overview — ADEF Meeting Requirements

**Status:** Planning  
**Created:** 2026-06-25  
**Purpose:** Identify and prioritize major design decisions needed before implementation

---

## Critical Design Decisions (Blocking Implementation)

These decisions must be made **before** we can confidently implement the meeting requirements. They affect architecture, integration patterns, and user experience.

---

### Decision 1: Interface Shape — CLI vs Skills vs Both

**Status:** 🔴 UNRESOLVED (Blocking)

**Question:** What is ADEF's primary user interface?

**Options:**
- **A) CLI-first** — Current state, scriptable, automation-friendly
- **B) Skills-first** — Conversational, Claude Code native, reduces CLI surface
- **C) Both** — CLI for automation, skills for exploration (Recommended)

**Why it matters:**
- Affects development effort (build both vs. one)
- Determines user onboarding story ("install adef" vs "use this skill")
- Influences ATHF integration pattern (see Decision 2)

**Blocking:**
- Research skill design (Task 6)
- MCP tool surface area
- Documentation structure

**Decision Doc:** `docs/decisions/001-interface-shape.md`

---

### Decision 2: ATHF Integration Pattern — Connectors & Data Access

**Status:** 🔴 UNRESOLVED (Blocking)

**Question:** How does ADEF leverage ATHF's existing connectors and data access infrastructure?

**Context:**
ATHF already has:
- Data source connectors (Splunk, EDR, cloud providers)
- Query execution infrastructure
- Authentication/credential management
- Schema awareness (implicit in connector implementations)

ADEF needs similar capabilities for:
- Schema discovery (querying data sources to reverse-engineer field schemas)
- Detection validation (testing rules against real data)
- Signal/finding access (reading detection outputs for Evolve stage)

**Options:**

#### Option A: Shared Connector Library
**Pattern:** Extract ATHF connectors into separate package, both frameworks import it

```
adef-connectors/  (new package)
├── splunk_connector.py
├── edr_connector.py
└── cloud_connector.py

athf/  imports adef-connectors
adef/  imports adef-connectors
```

**Pros:**
- DRY — one implementation, two consumers
- Consistent auth/config between frameworks
- Bug fixes benefit both

**Cons:**
- Requires refactoring ATHF to extract connectors
- Introduces shared dependency (coupling)
- Breaking change for ATHF users if API shifts

---

#### Option B: ADEF Calls ATHF via API
**Pattern:** ADEF shells out to ATHF CLI or calls ATHF as library

```python
# In ADEF schema discovery
import athf
result = athf.query(source="splunk", query="| metadata type=sources")
```

**Pros:**
- No extraction needed, ATHF stays intact
- ADEF gets all ATHF connectors immediately
- Clear dependency direction (ADEF depends on ATHF, not vice versa)

**Cons:**
- Tight coupling — ADEF requires ATHF installed
- Breaks "paired siblings" independence (can't use ADEF without ATHF)
- ATHF API changes break ADEF

---

#### Option C: Parallel Connector Implementations (Accept Duplication)
**Pattern:** ADEF builds own connectors, duplicates ATHF's implementations

```
athf/connectors/  (hunt-optimized)
adef/schema/connectors/  (schema-discovery-optimized)
```

**Pros:**
- True independence — ADEF works without ATHF
- Each framework optimizes for its use case (hunt queries ≠ schema queries)
- No coordination needed for changes

**Cons:**
- Duplication (violates DRY)
- Auth/config setup duplicated (user does twice)
- Bug fixes must be applied to both

---

#### Option D: Hybrid — Plugin Registry for Connectors
**Pattern:** Both frameworks use entry-point plugin system for connectors. Users install connector plugins separately.

```
# User installs
pip install adef athf splunk-connector

# splunk-connector registers with both
[project.entry-points."athf.connectors"]
splunk = "splunk_connector:SplunkConnector"

[project.entry-points."adef.schema_connectors"]
splunk = "splunk_connector:SplunkSchemaConnector"
```

**Pros:**
- Loose coupling — frameworks stay independent
- Third-party connectors possible
- User installs only what they need

**Cons:**
- More complex onboarding (install 3 packages)
- Connector authors must support both frameworks
- No connectors ship out-of-box (ATHF currently has built-in)

---

**Recommendation:** **Option D (Hybrid Plugin Registry)** with migration path:

1. **v0.1-0.2:** ADEF uses Option C (parallel implementations) for Splunk only (reference impl)
2. **v0.3:** Extract ATHF connectors to plugins, register via entry points
3. **v0.4+:** Third-party connector ecosystem

**Rationale:**
- Preserves "paired siblings" independence (doesn't break ISA principle)
- Allows ADEF to ship with one reference connector immediately
- Creates path to shared connector ecosystem without forcing tight coupling
- Aligns with existing plugin architecture (commands, agents, mcp_tools already use entry points)

**Action Items:**
1. Coordinate with ATHF team on connector extraction timeline
2. Design `SplunkSchemaConnector` as reference implementation
3. Document connector plugin interface for third parties

**Decision Doc:** `docs/decisions/002-athf-integration.md`

---

### Decision 3: Schema Storage Format — YAML vs SQLite vs JSON

**Status:** 🟡 NEEDS DECISION

**Question:** How does ADEF persist discovered schemas?

**Context:**
Schema discovery produces field metadata (name, type, population rate, sample values). This needs to be:
- Persisted to workspace
- Queryable ("does field X exist in source Y?")
- Version-controlled (schemas drift over time)
- Human-readable (analysts review schemas)

**Options:**

#### Option A: YAML Files (Proposed in Plan)
```yaml
# config/schemas/splunk-security.yaml
source: splunk-security
discovered_at: 2026-06-25T10:00:00Z
fields:
  - name: EventCode
    type: integer
    population_rate: 1.0
```

**Pros:** Human-readable, version-control friendly, no DB setup
**Cons:** Slow queries for large schemas, no indexing

#### Option B: SQLite Database
```sql
CREATE TABLE schemas (source TEXT, discovered_at TEXT);
CREATE TABLE fields (schema_id INT, name TEXT, type TEXT, pop_rate REAL);
```

**Pros:** Fast queries, indexing, relational joins
**Cons:** Binary file (harder to diff), requires DB management

#### Option C: JSON Lines (JSONL)
```jsonl
{"source": "splunk-security", "field": "EventCode", "type": "int", "pop_rate": 1.0}
{"source": "splunk-security", "field": "CommandLine", "type": "str", "pop_rate": 0.68}
```

**Pros:** Append-only (good for streaming), greppable, version-control friendly
**Cons:** Redundant data, no native indexing

**Recommendation:** **Option A (YAML)** for v0.1-0.2, migrate to SQLite if query performance becomes issue.

**Rationale:**
- Matches existing ADEF patterns (journals are markdown, config is YAML)
- Human-readability matters for schema review
- Premature optimization — schema files are small (<1MB typically)
- Easy to migrate later (just add `SchemaManager.migrate_to_sqlite()`)

**Decision Doc:** `docs/decisions/003-schema-storage.md`

---

### Decision 4: ADEF Research Skill — Standalone vs MCP Tool

**Status:** 🟡 NEEDS DECISION

**Question:** Should ADEF research be a Claude Code skill or an MCP tool?

**Context:**
Meeting notes call for "ADEF research skill, parallel to ATHF research." Two implementation paths:

#### Option A: Skill (Markdown with Instructions)
- Lives in `skills/adef-research.md`
- Claude Code reads it, follows instructions conversationally
- Uses existing MCP tools + web search
- Produces markdown report

#### Option B: MCP Tool (Programmatic)
- Lives in `adef/mcp/tools/research_tools.py`
- Structured input/output (URL → detection drafts JSON)
- Called by skill OR directly by Claude
- Less conversational, more deterministic

**Recommendation:** **Both (Skill wraps MCP tool)**

**Pattern:**
```markdown
# skills/adef-research.md
When user provides CTI URL:
1. Call mcp__adef__research_cti(url) -> returns structured detection drafts
2. Format results as markdown report
3. Guide user through `adef detection new` commands
```

```python
# adef/mcp/tools/research_tools.py
@server.tool()
def research_cti(url: str) -> dict:
    """Extract detection opportunities from CTI source."""
    # Fetch, parse, map to ATT&CK, check coverage, draft rules
    return {"detections": [...], "coverage_gaps": [...]}
```

**Rationale:**
- MCP tool is reusable (other agents, automation, CI/CD can call it)
- Skill provides conversational wrapper (better UX for exploratory work)
- Aligns with Decision 1 Option C (both CLI-like tools and skills)

**Decision Doc:** `docs/decisions/004-research-implementation.md`

---

### Decision 5: Detection Validation — Syntax-Only vs Live Test

**Status:** 🟡 NEEDS DECISION

**Question:** What does `adef detection refine` validate?

**Context:**
Refine stage chains RuleSimilarity → RuleOverlap → Verification. Current "Verification" agent checks:
- Schema validation (YAML structure)
- Four-engine constraint (sigma/sql/sch_sql/composite only)

Should it also:
- **Syntax check** — Does the query compile? (e.g., Sigma-to-SPL transpilation succeeds)
- **Live test** — Run query against real data, show sample results?

**Options:**

#### Option A: Syntax-Only (Fast, Deterministic)
- Validate YAML structure
- Check field references against discovered schema
- Transpile Sigma (if applicable) to target language
- Don't execute queries

**Pros:** Fast, no data access needed, CI-friendly
**Cons:** Doesn't catch runtime errors (missing fields, wrong data types)

#### Option B: Live Test (Comprehensive, Slow)
- Everything in Option A, plus:
- Execute query against data source
- Return sample matching events (first 10)
- Measure query performance

**Pros:** Catches real issues, provides feedback on results
**Cons:** Requires data access (auth, network), slow, non-deterministic

**Recommendation:** **Option A for Refine stage, Option B as separate command**

```bash
adef detection refine D-XXXX    # Syntax validation only (fast)
adef detection test D-XXXX      # Live test (requires --connector) (v0.2+)
```

**Rationale:**
- Refine stage should be fast and repeatable (CI-friendly)
- Live testing is exploratory, happens in Observe stage or manual testing
- Separating concerns keeps Refine deterministic

**Decision Doc:** `docs/decisions/005-validation-depth.md`

---

### Decision 6: Journal-to-Rule Mapping — UUID in Frontmatter vs Filename Convention

**Status:** 🟢 RESOLVED (Current: UUID in frontmatter)

**Current State:**
Journals have `rule_uuid:` in frontmatter. Detection ID (`D-XXXX`) is independent of upstream rule UUID.

**Why this is correct:**
- Upstream rules may not exist yet (draft detections)
- One journal may evolve into multiple rules (rule splitting)
- One rule may have multiple journals (refactor history)

**No change needed.** Document in architecture decisions as resolved.

**Decision Doc:** `docs/decisions/006-journal-rule-mapping.md`

---

### Decision 7: Governance Fields — Frontmatter vs Separate File

**Status:** 🟡 NEEDS DECISION

**Question:** Where do governance fields (owner, reviewers, approval status) live?

**Options:**

#### Option A: Journal Frontmatter (Proposed in Plan)
```yaml
---
id: D-0042
owner: alice@example.com
reviewers:
  - bob@example.com
  - carol@example.com
approved_at: 2026-06-25T14:00:00Z
deployed_at: null
---
```

**Pros:** All detection metadata in one file, simple
**Cons:** Frontmatter gets large, mixing lifecycle state with governance

#### Option B: Separate Governance File
```yaml
# governance/D-0042.yaml
owner: alice@example.com
reviewers: [bob, carol]
approval_history:
  - approver: bob
    approved_at: 2026-06-25T14:00:00Z
```

**Pros:** Separates concerns, scales better for audit logging
**Cons:** Two files per detection, more complex

**Recommendation:** **Option A (frontmatter) for v0.1-0.2**, extract to separate file if governance becomes complex.

**Rationale:**
- Gray-zone decision already says governance is "hybrid" (framework models, product implements workflows)
- Framework only needs owner/approved_at (simple fields)
- Product can add audit logging, RBAC, approval workflows (separate files/DB)

**Decision Doc:** `docs/decisions/007-governance-storage.md`

---

## Decision Priority Matrix

| # | Decision | Blocks | Priority | Effort |
|---|----------|--------|----------|--------|
| 1 | Interface Shape | Research skill, docs | 🔴 CRITICAL | Low (doc only) |
| 2 | ATHF Integration | Schema discovery, connectors | 🔴 CRITICAL | High (coordination) |
| 3 | Schema Storage | Schema CLI implementation | 🟡 HIGH | Low (impl detail) |
| 4 | Research Skill Type | Research skill implementation | 🟡 HIGH | Medium (both paths viable) |
| 5 | Validation Depth | Refine stage scope | 🟡 MEDIUM | Low (doc only) |
| 6 | Journal-Rule Mapping | — | 🟢 RESOLVED | None |
| 7 | Governance Storage | Govern stage implementation | 🟡 LOW | Low (defer to v0.2) |

---

## Recommended Decision Order

### Week 1 (Pre-Implementation)
1. **Decision 1** (Interface Shape) — 1 hour, just needs your confirmation
2. **Decision 2** (ATHF Integration) — 2-4 hours, coordinate with ATHF team
3. **Decision 4** (Research Skill Type) — 1 hour, follows from Decision 1

### Week 2 (During Implementation)
4. **Decision 3** (Schema Storage) — 30 min, implementation detail
5. **Decision 5** (Validation Depth) — 30 min, scope clarification

### Week 3+ (Post-MVP)
6. **Decision 7** (Governance Storage) — Defer to v0.2 when product needs emerge

---

## Next Steps

1. **Review this document** — Do these match your understanding of critical decisions?
2. **Add/remove decisions** — Are we missing any? Any that don't matter?
3. **Make Decision 1** — Interface shape (CLI vs Skills vs Both)
4. **Schedule ATHF coordination** — Decision 2 needs input from ATHF team
5. **Update implementation plan** — Prepend decision-making phase before current tasks

---

## Open Questions for Discussion

1. **ATHF Integration:** Do you have access to ATHF codebase? Can we coordinate with that team?
2. **Connector Priority:** Which data source connector should be reference implementation? (Splunk? Generic SQL? Other?)
3. **Timeline:** Do critical decisions need to be made this week, or can some wait?
4. **Product Boundary:** Are there Nebulock product features we should explicitly NOT design for in framework?
