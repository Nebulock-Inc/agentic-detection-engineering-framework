# ADEF Command Summary for Team Discussion

**Date:** 2026-06-25  
**Purpose:** Share proposed CLI commands for feedback and prioritization

---

## Currently Implemented (v0.1.0) ✅

### Core Lifecycle
- `adef init` — Initialize workspace structure
- `adef detection new "Title"` — Create detection journal at Find stage
- `adef detection observe D-XXXX` — Advance to Observe stage
- `adef detection refine D-XXXX` — Advance to Refine stage, run orchestration chain
- `adef detection govern D-XXXX` — Advance to Govern stage
- `adef detection evolve D-XXXX` — Advance to Evolve stage
- `adef hunt-promote H-XXXX` — Promote ATHF hunt to ADEF detection
- `adef backfill journals` — Bulk-create journals for existing rules

---

## Proposed Additions

### Phase 1: Discovery & Visibility (P0 — 2 weeks)

#### Detection Management
- `adef detection list` — List all detections with filtering
  - `--stage refine` — Filter by current FORGE stage
  - `--owner alice` — Filter by owner
  - `--technique T1003.001` — Filter by MITRE technique
  - `--format json` — JSON output for scripting

- `adef detection search "keyword"` — Full-text search across journals

- `adef detection show D-XXXX` — Display detection details with stage history

#### Coverage Analysis
- `adef detection coverage` — ATT&CK technique coverage heatmap
  - `--tactic execution` — Filter by tactic
  - `--export coverage.json` — Export for reporting

- `adef detection gaps` — Identify uncovered techniques
  - `--top 10` — Show top priority gaps
  - `--tactic credential-access` — Filter by tactic

- `adef detection stats` — Program metrics (total detections, by stage, by owner)

#### Research Workflow
- `adef research new --cti-url <URL>` — Extract detection drafts from threat intel
- `adef research new --cve CVE-2024-1234` — Generate detections for CVE
- `adef research new --topic "LSASS dumping"` — Research topic for detection ideas
- `adef research list` — List research documents
- `adef research show R-0001` — Display research findings

#### Schema (declaration-driven — SHIPPED 2026-07-20, replaced connector-based discovery)
- `adef schema ingest adef-sources.yml` — ✅ Build schemas from a user-provided declaration (drift reported on re-ingest)
- `adef schema lint adef-sources.yml` — ✅ Validate a declaration
- `adef schema check` — ✅ Cross-reference rule field usage vs declared schemas
- `adef schema show wineventlog` — ✅ Display schema details
- `adef schema list` — List ingested schemas (still roadmap)
- `adef schema fields wineventlog --search "process"` — Search available fields (still roadmap)

---

### Phase 2: Analytics & Comparison (P1 — 4 weeks)

#### Detection Comparison
- `adef detection overlap D-XXXX` — Find overlapping rules
- `adef detection similar D-XXXX` — Find similar rules via semantic search
- `adef detection validate D-XXXX` — Standalone validation (schema + syntax)

#### Enhanced Research
- `adef research export R-0001 --format json` — Export research for integration
- `adef detection new --from-research R-0001` — Create detection from research draft

#### Schema Integration
- `adef schema validate D-XXXX` — Validate one detection against its declared schema (`schema check` already does this repo-wide)

#### Hunt Promotion Enhancements
- `adef hunt-promote list` — Show promotable hunts from ATHF
- `adef hunt-promote status H-0042` — Check if hunt is ready to promote
- `adef hunt-promote --preview H-0042` — Preview what will be created

---

### Phase 3: Governance & Automation (P2 — 8+ weeks)

#### Governance
- `adef detection assign D-XXXX --owner bob` — Change detection owner
- `adef detection approve D-XXXX` — Mark detection as approved
- `adef detection deploy D-XXXX --environment prod` — Mark as deployed
- `adef detection archive D-XXXX` — Archive deprecated detection

#### Metrics & Reporting
- `adef metrics program` — Overall program health metrics
- `adef metrics velocity` — Detections created/deployed per week
- `adef metrics coverage --trend` — Coverage trend over time

#### Connector Management
- `adef connector list` — List configured data source connectors
- `adef connector test splunk` — Test connector configuration
- `adef connector configure splunk --interactive` — Configure connector

#### Bulk Operations
- `adef detection export --stage refine --format json` — Export filtered detections
- `adef detection bulk-update --owner alice --new-owner bob` — Bulk reassignment

---

## Command Organization by Use Case

### For Detection Engineers
```bash
# Day-to-day workflow
adef detection new "Title"
adef detection observe D-XXXX
adef detection refine D-XXXX
adef detection list --stage refine
adef detection show D-XXXX
```

### For Threat Researchers
```bash
# CTI → Detection pipeline
adef research new --cti-url <URL>
adef research show R-0001
adef detection new --from-research R-0001
adef detection coverage --tactic execution
```

### For Detection Managers
```bash
# Program oversight
adef detection stats
adef detection coverage
adef detection gaps --top 10
adef detection list --owner alice
adef metrics program
```

### For Platform Teams
```bash
# Data source integration (declaration-driven — no connectors, by design)
adef schema ingest adef-sources.yml   # ✅ shipped
adef schema check                     # ✅ shipped
adef schema show wineventlog          # ✅ shipped
adef schema validate D-XXXX           # roadmap
```

---

## Questions for Discussion

### Priority
1. Does the P0/P1/P2 priority alignment make sense?
2. Are there must-have commands missing from P0?
3. Any P2 commands that should be P0?

### Interface
4. CLI-first vs. Skills-first vs. Both?
5. Should commands output Rich tables by default, or plain text?
6. How important is JSON output for automation?

### ATHF Integration
7. Consolidation plan for `athf detect` commands?
8. Timeline for deprecating overlapping commands?
9. Should connectors be shared between ATHF and ADEF?

### Scope
10. Which commands belong in framework vs. product?
11. Should governance commands (assign/approve/deploy) be in v0.1.1 or later?
12. How much automation should Observe/Refine stages have?

---

## Next Steps

1. **Team review** — Gather feedback on proposed commands
2. **Prioritize** — Finalize P0 command list
3. **Design decisions** — Resolve open questions (interface, ATHF integration)
4. **Implementation plan** — Sprint planning for P0 commands
5. **Prototype** — Build 2-3 P0 commands to validate approach

---

## Additional Context

**Full documentation:**
- `docs/cli-commands-roadmap.md` — Complete 120+ command catalog
- `docs/existing-vs-roadmap.md` — How new commands integrate with existing FORGE
- `docs/whats-real-vs-proposed.md` — What's implemented vs. proposed
- `docs/decisions/008-athf-inspired-cli-commands.md` — ATHF command overlap analysis
- `docs/forge-commands-explained.md` — Detailed explanation of existing commands

**Estimated scope:**
- P0: ~20 commands (2 weeks)
- P1: ~25 commands (4 weeks total)
- P2: ~35 commands (8+ weeks total)
- Total potential: 120+ commands across all phases
