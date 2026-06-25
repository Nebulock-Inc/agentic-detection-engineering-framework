# ADEF CLI Commands Roadmap

**Status:** Planning  
**Updated:** 2026-06-25

---

## Legend

- ✅ **Implemented** — Already exists in v0.1.0
- 🔴 **P0 (Critical)** — Essential for feature parity, high value
- 🟡 **P1 (High)** — Important for completeness
- 🟢 **P2 (Medium)** — Nice to have, v0.2+
- ⚪ **P3 (Low)** — Future consideration
- 💡 **Idea** — Potential future command

---

## Core Commands

### `adef init`
✅ **Implemented** — Initialize workspace

```bash
adef init
adef init --path /custom/path
```

---

## Detection Lifecycle (`adef detection`)

### ✅ Implemented

```bash
adef detection new "Title"
adef detection new "Title" --owner alice --rule-uuid UUID-123

adef detection observe D-XXXX
adef detection observe D-XXXX --note "Checked 30d of logs"

adef detection refine D-XXXX
adef detection refine D-XXXX --note "Fixed false positives"

adef detection govern D-XXXX
adef detection govern D-XXXX --note "Security team approved"

adef detection evolve D-XXXX
adef detection evolve D-XXXX --note "Tuned threshold"
```

---

### 🔴 P0 (Critical Priority)

#### List & Filter
```bash
adef detection list
adef detection list --stage refine
adef detection list --stage refine,govern
adef detection list --owner alice
adef detection list --technique T1003.001
adef detection list --tactic credential-access
adef detection list --status active
adef detection list --format json
adef detection list --format table
```

#### Search
```bash
adef detection search "mshta.exe"
adef detection search "process injection" --format json
```

#### Coverage Analysis
```bash
adef detection coverage
adef detection coverage --tactic execution
adef detection coverage --technique T1003
adef detection coverage --export coverage.json
adef detection coverage --format heatmap
```

#### Gap Analysis
```bash
adef detection gaps
adef detection gaps --tactic credential-access
adef detection gaps --priority high
adef detection gaps --top 10
adef detection gaps --format json
```

---

### 🟡 P1 (High Priority)

#### Statistics
```bash
adef detection stats
adef detection stats --by-stage
adef detection stats --by-owner
adef detection stats --by-tactic
adef detection stats --format json
```

#### Detail View
```bash
adef detection show D-XXXX
adef detection show D-XXXX --format json
adef detection show D-XXXX --include-history
```

#### Comparison
```bash
adef detection overlap D-XXXX
adef detection overlap D-XXXX --show-rules

adef detection similar D-XXXX
adef detection similar D-XXXX --top 5

adef detection diff D-0001 D-0002
```

#### Validation
```bash
adef detection validate D-XXXX
adef detection validate D-XXXX --schema splunk-security
adef detection validate D-XXXX --strict
```

---

### 🟢 P2 (Medium Priority)

#### Governance
```bash
adef detection assign D-XXXX --owner bob
adef detection assign D-XXXX --owner bob --note "Reassigned to EMEA team"

adef detection approve D-XXXX
adef detection approve D-XXXX --approver alice

adef detection deploy D-XXXX
adef detection deploy D-XXXX --environment production

adef detection archive D-XXXX
adef detection archive D-XXXX --reason "Deprecated per Q2 review"
```

#### Bulk Operations
```bash
adef detection bulk-update --owner alice --new-owner bob
adef detection bulk-update --stage find --advance-to observe

adef detection export --stage refine --format json > refine-detections.json
adef detection import detections.json
```

---

### ⚪ P3 (Low Priority)

#### Advanced Analysis
```bash
adef detection dependencies D-XXXX
adef detection dependencies D-XXXX --show-graph

adef detection timeline D-XXXX
adef detection timeline D-XXXX --format gantt

adef detection owners
adef detection owners --show-workload
```

---

### 💡 Ideas (Future)

```bash
adef detection clone D-XXXX --title "New variant"
adef detection merge D-0001 D-0002 --into D-0003
adef detection split D-XXXX --into 2
adef detection recommend-stage D-XXXX  # AI suggests next stage
adef detection health-check  # Check all detections for issues
```

---

## Research (`adef research`)

### 🔴 P0 (Critical Priority)

```bash
adef research new --topic "LSASS memory dumping"
adef research new --topic "Credential Access" --technique T1003.001

adef research new --cti-url https://example.com/threat-report
adef research new --cti-url https://... --depth advanced

adef research new --cve CVE-2024-1234
adef research new --actor APT29
```

---

### 🟡 P1 (High Priority)

```bash
adef research list
adef research list --topic "credential"
adef research list --technique T1003
adef research list --format json

adef research show R-0001
adef research show R-0001 --format json
adef research show R-0001 --section coverage-gaps

adef research export R-0001 --format json
adef research export R-0001 --format markdown
```

---

### 🟢 P2 (Medium Priority)

```bash
adef research gaps R-0001  # Show coverage gaps from research
adef research drafts R-0001  # List detection drafts from research

adef detection new --from-research R-0001
adef detection new --from-research R-0001 --draft 2

adef research update R-0001  # Re-run research with latest data
adef research archive R-0001
```

---

### 💡 Ideas (Future)

```bash
adef research auto --watch-feeds  # Auto-research new CTI
adef research compare R-0001 R-0002  # Compare two research docs
adef research merge R-0001 R-0002  # Merge research findings
```

---

## Schema Discovery (`adef schema`)

### 🔴 P0 (Critical Priority)

```bash
adef schema discover --connector splunk --source security-logs
adef schema discover --connector splunk --source security-logs --time-window 30d
adef schema discover --connector splunk --source security-logs --sample-size 1000000

adef schema list
adef schema list --format json

adef schema show splunk-security
adef schema show splunk-security --field process_name
adef schema show splunk-security --format json

adef schema delete splunk-security
adef schema delete splunk-security --force
```

---

### 🟡 P1 (High Priority)

```bash
adef schema validate D-XXXX
adef schema validate D-XXXX --schema splunk-security
adef schema validate D-XXXX --show-missing-fields

adef schema fields splunk-security
adef schema fields splunk-security --type string
adef schema fields splunk-security --min-population 0.8
adef schema fields splunk-security --search "process"
```

---

### 🟢 P2 (Medium Priority)

```bash
adef schema refresh splunk-security
adef schema refresh splunk-security --time-window 7d

adef schema drift splunk-security
adef schema drift splunk-security --compare-to 2026-06-01

adef schema export splunk-security --format yaml
adef schema export splunk-security --format json
adef schema import schema.yaml

adef schema merge splunk-security edr-security --into combined
```

---

### 💡 Ideas (Future)

```bash
adef schema recommend D-XXXX  # Suggest best schema for detection
adef schema coverage  # Show which detections use which schemas
adef schema health  # Check schema freshness across all sources
adef schema auto-discover  # Discover all available sources
```

---

## Hunt Promotion (`adef hunt-promote`)

### ✅ Implemented

```bash
adef hunt-promote H-0042
adef hunt-promote H-0042 --workspace /path/to/workspace
adef hunt-promote H-0042 --rule-staging-root /path/to/staging
```

---

### 🟡 P1 (High Priority)

```bash
adef hunt-promote H-0042 --preview  # Show what would be created
adef hunt-promote H-0042 --dry-run

adef hunt-promote list  # Show promotable hunts
adef hunt-promote list --status completed
adef hunt-promote list --technique T1003.001

adef hunt-promote status H-0042  # Check if hunt is ready to promote
```

---

### 💡 Ideas (Future)

```bash
adef hunt-promote bulk H-0042,H-0043,H-0044
adef hunt-promote auto --min-confidence high  # Auto-promote high-quality hunts
adef hunt-promote recommend  # Suggest hunts ready for promotion
```

---

## Backfill (`adef backfill`)

### ✅ Implemented

```bash
adef backfill journals
adef backfill journals --workspace /path/to/workspace
adef backfill journals --rule-root /path/to/rules
adef backfill journals --limit 100
adef backfill journals --dry-run
```

---

### 🟡 P1 (High Priority)

```bash
adef backfill journals --filter "technique=T1003*"
adef backfill journals --filter "severity=critical"
adef backfill journals --since 2026-01-01

adef backfill status  # Show backfill progress
adef backfill validate  # Check which rules need backfill
```

---

### 💡 Ideas (Future)

```bash
adef backfill enrich  # Enhance existing journals with new metadata
adef backfill migrate  # Migrate journals to new template version
adef backfill resume  # Resume interrupted backfill
```

---

## Connector Management (`adef connector`)

### 🟢 P2 (Medium Priority)

```bash
adef connector list
adef connector list --type schema
adef connector list --available

adef connector test splunk
adef connector test splunk --verbose

adef connector configure splunk
adef connector configure splunk --host https://splunk.example.com
adef connector configure splunk --interactive

adef connector remove splunk
```

---

### 💡 Ideas (Future)

```bash
adef connector install adef-splunk-connector
adef connector install adef-splunk-connector --from-git https://...
adef connector upgrade splunk-connector
adef connector health  # Check all connector health
```

---

## Configuration (`adef config`)

### 🟢 P2 (Medium Priority)

```bash
adef config show
adef config show --key workspace_path

adef config set workspace_path /path/to/workspace
adef config set rule_root /path/to/rules
adef config set hunt_root /path/to/hunts

adef config validate
adef config reset
adef config export > adef-config.yaml
```

---

## Metrics & Reporting (`adef metrics`)

### 🟢 P2 (Medium Priority)

```bash
adef metrics program  # Overall program health
adef metrics program --since 2026-01-01
adef metrics program --format json

adef metrics velocity  # Detections per stage per week
adef metrics velocity --by-owner
adef metrics velocity --chart

adef metrics coverage  # Coverage over time
adef metrics coverage --trend

adef metrics quality  # Quality metrics
adef metrics quality --show-degraded
```

---

### 💡 Ideas (Future)

```bash
adef metrics drift  # Detect quality drift
adef metrics forecast  # Predict coverage trends
adef metrics benchmark --compare-to industry-standard
```

---

## Integration Commands

### 🟢 P2 (Medium Priority)

#### Splunk
```bash
adef splunk test
adef splunk query "index=main | head 10"
adef splunk fields --sourcetype WinEventLog:Security
adef splunk validate-query query.spl
```

#### ClickHouse
```bash
adef clickhouse test
adef clickhouse query "SELECT * FROM signals LIMIT 10"
adef clickhouse schema detections
```

#### Git Integration
```bash
adef git status  # Show workspace git status
adef git sync  # Sync journals with remote
adef git commit --stage refine  # Commit all refine-stage changes
```

---

## Utility Commands

### 🟢 P2 (Medium Priority)

```bash
adef version
adef version --check-updates

adef doctor  # Health check for workspace
adef doctor --fix  # Auto-fix common issues

adef workspace info
adef workspace validate
adef workspace migrate  # Migrate to new version

adef clean  # Clean up temporary files
adef clean --journals  # Remove archived journals
adef clean --dry-run
```

---

### 💡 Ideas (Future)

```bash
adef upgrade  # Upgrade ADEF itself
adef plugin list
adef plugin install <name>
adef plugin remove <name>

adef notebook generate  # Generate Jupyter notebook from detection
adef notebook run D-XXXX  # Execute detection in notebook

adef ai chat  # Interactive AI assistant
adef ai suggest  # Get AI suggestions for current context
```

---

## Summary by Priority

### 🔴 P0 — Essential (Target: v0.1.1, Sprint 1-2)
- `adef detection list` + filters
- `adef detection search`
- `adef detection coverage`
- `adef detection gaps`
- `adef research new`
- `adef schema discover/list/show/delete`

**Total: ~20 commands**

---

### 🟡 P1 — Important (Target: v0.2, Sprint 3-4)
- `adef detection stats/show/overlap/similar/validate`
- `adef research list/show/export`
- `adef schema validate/fields`
- `adef hunt-promote list/status`
- `adef backfill` filters

**Total: ~25 commands**

---

### 🟢 P2 — Nice to Have (Target: v0.3+)
- Governance commands (assign/approve/deploy)
- Connector management
- Configuration management
- Metrics & reporting
- Integration commands (splunk/clickhouse)
- Utility commands (doctor/clean)

**Total: ~35 commands**

---

### ⚪ P3 + 💡 Ideas — Future
- Advanced analysis (dependencies/timeline)
- Bulk operations (export/import)
- Auto-promotion
- AI-assisted features
- Plugin management
- Notebook generation

**Total: ~30+ potential commands**

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
Focus: Detection list/search, coverage/gaps, schema basics
- 6 command groups
- ~20 total commands
- Achieves feature parity with ATHF essentials

### Phase 2: Completeness (Weeks 3-4)
Focus: Research workflow, enhanced schema, hunt promotion
- 8 command groups
- ~25 additional commands
- Full research-to-detection pipeline

### Phase 3: Quality of Life (Weeks 5-8)
Focus: Governance, metrics, integrations
- 5 command groups
- ~35 additional commands
- Production-ready tooling

### Phase 4: Innovation (v0.3+)
Focus: AI assistance, automation, advanced analytics
- 3+ command groups
- ~30+ potential commands
- Competitive differentiation

---

## Command Count Summary

| Priority | Commands | Timeline | Status |
|----------|----------|----------|--------|
| ✅ Implemented | ~10 | v0.1.0 | Done |
| 🔴 P0 Critical | ~20 | v0.1.1 (2 weeks) | Planning |
| 🟡 P1 High | ~25 | v0.2 (4 weeks) | Planning |
| 🟢 P2 Medium | ~35 | v0.3+ (8+ weeks) | Future |
| ⚪ P3 + 💡 Ideas | ~30+ | v0.4+ | Exploratory |

**Total Potential: 120+ commands** across 15+ command groups
