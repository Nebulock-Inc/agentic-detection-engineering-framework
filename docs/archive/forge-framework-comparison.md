# FORGE Framework Comparison

**Date:** 2026-06-18  
**Purpose:** Compare ADEF's FORGE methodology against industry-standard detection lifecycle frameworks

## Frameworks Compared

1. **ADEF FORGE** (Find → Observe → Refine → Govern → Evolve)
2. **Snowflake Detection Development Lifecycle** (6 phases)
3. **Palantir Alerting and Detection Strategy (ADS)** Framework

---

## Framework Overview Comparison

| Aspect | ADEF FORGE | Snowflake Lifecycle | Palantir ADS |
|--------|------------|---------------------|--------------|
| **Total Phases** | 5 stages | 6 phases | Strategy-first approach |
| **Lifecycle Shape** | Iterative loop | Linear with feedback loops | Front-loaded design |
| **Memory Model** | Per-detection markdown journals | DIRs + version control | ADS documentation |
| **Primary Artifact** | Journal (D-XXXX.md) | Detection code + metadata | ADS strategy doc |
| **Deployment Gate** | Govern stage | Testing & Deployment phase | Review checkpoints |
| **Maintenance** | Evolve stage | Monitoring + Continuous Testing | Review cycles |

---

## Phase-by-Phase Mapping

### Phase 1: Initiation / Requirements

| ADEF: **Find** | Snowflake: **Requirements Gathering** | Palantir ADS |
|----------------|--------------------------------------|--------------|
| **Purpose:** Capture *why* | **Purpose:** Single point of entry with risk-based prioritization | **Purpose:** Define detection goal |
| **Inputs:** Gap, intel, hunt, IR request | **Inputs:** Product/Corporate Security, Threat Intel, IR, Audit, Red Team | **Inputs:** Threat model, use cases |
| **Outputs:** Hypothesis, MITRE mapping, motivation | **Outputs:** Prioritized backlog, technical details | **Outputs:** Clear detection goal |
| **Key Activities:** | **Key Activities:** | **Key Activities:** |
| • Record signal source | • Collect technical details from stakeholders | • Define goal |
| • Draft one-sentence hypothesis | • Risk-based prioritization | • Threat modeling |
| • Initial ATT&CK mapping | • Track coverage metrics | • Stakeholder alignment |
| • Note paired rule UUID | • Engage early for new features | |

**Coverage Assessment:**
- ✅ ADEF captures motivation well
- ⚠️ Snowflake's explicit **risk-based prioritization** is stronger
- ⚠️ Snowflake's **stakeholder engagement protocol** is more structured
- ⚠️ Snowflake's **coverage metrics tracking** is explicit

**Gap:** ADEF Find doesn't explicitly mention prioritization or stakeholder engagement protocol.

---

### Phase 2: Telemetry Characterization

| ADEF: **Observe** | Snowflake: (Implicit in Design/Development) | Palantir ADS |
|-------------------|---------------------------------------------|--------------|
| **Purpose:** Characterize telemetry before defining "weird" | **Purpose:** (Embedded in Design) | **Purpose:** (Part of strategy) |
| **Inputs:** Data sources, production logs | **Inputs:** Production logs, data sources | **Inputs:** Available data sources |
| **Outputs:** Field population rates, volume estimates, baseline normal | **Outputs:** Detection design document | **Outputs:** Detection strategy |
| **Key Activities:** | **Key Activities:** | **Key Activities:** |
| • Identify data sources | • (Part of Design phase) | • Data source identification |
| • Check field population | | • Data quality assessment |
| • Estimate volume/cardinality | | |
| • Sample queries | | |
| • Characterize baseline normal | | |

**Coverage Assessment:**
- ✅ ADEF's dedicated **Observe stage** is unique and valuable
- ✅ Explicit baseline characterization ("what's normal?") before detection logic
- ⚠️ Neither Snowflake nor Palantir dedicates a full phase to this
- ✅ ADEF prevents "jump straight to query" anti-pattern

**Strength:** ADEF's Observe stage is a unique contribution — forcing telemetry characterization before query logic.

---

### Phase 3: Detection Design & Development

| ADEF: **Refine** | Snowflake: **Design** + **Development** | Palantir ADS |
|------------------|----------------------------------------|--------------|
| **Purpose:** Iterate rule with structured feedback | **Purpose:** Design strategy → Build code | **Purpose:** Document detection strategy |
| **Inputs:** Telemetry characterization | **Inputs:** Requirements, design patterns | **Inputs:** Detection goal, threat model |
| **Outputs:** Refined rule with similarity/overlap/verification checks | **Outputs:** Code + metadata tags | **Outputs:** ADS document |
| **Key Activities:** | **Key Activities:** | **Key Activities:** |
| • RuleSimilarity check | • Use ADS Framework for design | • Define detection strategy |
| • RuleOverlap analysis | • Share with IR for triage playbooks | • Document assumptions |
| • Verification (schema + constraints) | • Standardized templates | • Enable IR playbook creation |
| • Append results to journal | • MITRE + metadata tagging | • Share with IR team |
| | • Detection-as-Code | |

**Coverage Assessment:**
- ✅ ADEF's **automated chain** (Similarity → Overlap → Verification) is strong
- ⚠️ Snowflake's **IR triage playbook alignment** in Design phase is explicit
- ⚠️ Snowflake's **standardized templates** ensure consistency
- ⚠️ Palantir's **front-loaded strategy documentation** prevents rework
- ⚠️ Neither ADEF nor competitors explicitly mention **MITRE sub-technique granularity**

**Gaps:**
1. **IR playbook alignment**: ADEF doesn't explicitly mention triage runbook creation during Refine
2. **Standardized templates**: ADEF has templates but doesn't enforce template usage for rule syntax

---

### Phase 4: Testing & Validation

| ADEF: (Embedded in Refine) | Snowflake: **Testing and Deployment** | Palantir ADS |
|-----------------------------|----------------------------------------|--------------|
| **Purpose:** (Part of Refine verification) | **Purpose:** Validate before production | **Purpose:** (Part of deployment) |
| **Inputs:** Draft rule | **Inputs:** Detection code | **Inputs:** Detection code |
| **Outputs:** Verified rule | **Outputs:** Production-ready detection | **Outputs:** Deployed detection |
| **Key Activities:** | **Key Activities:** | **Key Activities:** |
| • Schema validation (in Refine) | • **Historical testing** (backtest) | • Testing |
| • Four-engine constraint check | • **Real-time testing** (test queue) | • Peer review |
| | • Validate acceptance criteria | • Deployment |
| | • Atomic Red Team / Red Team testing | |
| | • **Peer review** | |
| | • Version control | |

**Coverage Assessment:**
- ⚠️ ADEF doesn't have explicit **historical backtesting**
- ⚠️ ADEF doesn't have explicit **real-time test queue**
- ⚠️ ADEF doesn't mention **acceptance criteria definition** (FP rate, alert volume)
- ⚠️ ADEF doesn't mention **peer review** requirement
- ⚠️ ADEF doesn't mention **Red Team / Atomic Red Team validation**

**Critical Gap:** ADEF conflates validation into Refine. Snowflake's separate Testing & Deployment phase with explicit backtesting, test queues, and acceptance criteria is more rigorous.

---

### Phase 5: Deployment & Ownership

| ADEF: **Govern** | Snowflake: **Testing and Deployment** (part 2) | Palantir ADS |
|------------------|------------------------------------------------|--------------|
| **Purpose:** Deploy with quality gates, ownership, review cadence | **Purpose:** Production deployment | **Purpose:** Operationalize |
| **Inputs:** Verified rule | **Inputs:** Tested detection | **Inputs:** Tested detection |
| **Outputs:** Production rule with owner, rotation, cadence | **Outputs:** Deployed detection | **Outputs:** Production detection |
| **Key Activities:** | **Key Activities:** | **Key Activities:** |
| • Name engine type | • Version control | • Assign ownership |
| • Set severity / risk score / RBA | • Peer review | • Define escalation |
| • Assign owner | • Deploy to production | • Set alert routing |
| • Name on-call rotation | | |
| • Set review cadence | | |
| • Record deployment gate evidence | | |

**Coverage Assessment:**
- ✅ ADEF's **explicit review cadence** is strong
- ✅ ADEF's **on-call rotation naming** is explicit
- ✅ ADEF's **deployment gate evidence** requirement is clear
- ⚠️ Snowflake's **version control** is explicit (ADEF has it but doesn't emphasize)
- ⚠️ Snowflake's **peer review** is a hard gate (ADEF mentions "deployment gate evidence" but not peer review specifically)

**Minor Gap:** ADEF should explicitly mention peer review as a deployment gate.

---

### Phase 6: Maintenance & Tuning

| ADEF: **Evolve** | Snowflake: **Monitoring** + **Continuous Testing** | Palantir ADS |
|------------------|-----------------------------------------------------|--------------|
| **Purpose:** Tune, deprecate, replace | **Purpose:** Monitor performance + validate effectiveness | **Purpose:** Continuous improvement |
| **Inputs:** Production metrics | **Inputs:** Alert data, performance metrics | **Inputs:** Alert data |
| **Outputs:** Tuning decisions, deprecation rationale | **Outputs:** DIRs, decommission requests | **Outputs:** Updated detections |
| **Key Activities:** | **Key Activities:** | **Key Activities:** |
| • Record tuning decisions | • **Detection Improvement Requests (DIRs)** | • Performance review |
| • Track performance trends | • Track DIR metrics (quality indicator) | • Tuning |
| • Document replacement rationale | • **Decommission requests** (temp/permanent) | • Deprecation |
| • Name successor rules | • **Annual detection reviews** | |
| | • **Purple Teaming / Red Team exercises** | |
| | • Partner with Red Team | |

**Coverage Assessment:**
- ✅ ADEF captures tuning and deprecation well
- ⚠️ Snowflake's **Detection Improvement Request (DIR)** workflow is more structured
- ⚠️ Snowflake's **DIR metrics as quality indicators** is explicit
- ⚠️ Snowflake's **annual review cadence** is explicit (ADEF has "review cadence" in Govern but not annual reviews in Evolve)
- ⚠️ Snowflake's **Purple Teaming / Red Team partnership** for continuous validation is explicit
- ⚠️ Snowflake's **temporary vs. permanent decommission** distinction is more nuanced

**Gap:** ADEF Evolve should explicitly mention structured improvement request workflow and Purple Team validation.

---

## Gap Analysis Summary

### What ADEF Does Better

1. ✅ **Observe stage**: Unique, dedicated telemetry characterization before query logic
2. ✅ **Journal-based memory**: Durable, version-controlled markdown journals (stronger than Snowflake's DIRs)
3. ✅ **Automated Refine chain**: Similarity → Overlap → Verification orchestration
4. ✅ **Explicit review cadence**: Set in Govern, enforced in Evolve
5. ✅ **Hunt-to-detection promotion**: `adef hunt-promote` from ATHF

### What ADEF Is Missing or Weak On

#### Critical Gaps (Should Address)

1. ❌ **Historical backtesting** (Snowflake Testing phase)
   - Recommendation: Add to **Refine** or create sub-stage "Refine → Test"
2. ❌ **Real-time test queue** (Snowflake Testing phase)
   - Recommendation: Mention in **Govern** or **Refine**
3. ❌ **Acceptance criteria definition** (Snowflake Testing phase)
   - FP rate thresholds, alert volume targets
   - Recommendation: Add to **Refine** or **Govern**
4. ❌ **Peer review requirement** (Snowflake Testing phase)
   - Recommendation: Explicitly add to **Govern** deployment gates
5. ❌ **Structured improvement workflow** (Snowflake DIR process)
   - Recommendation: Add to **Evolve** with explicit DIR-like tracking

#### Important Gaps (Should Consider)

6. ⚠️ **Risk-based prioritization** (Snowflake Requirements)
   - Recommendation: Add to **Find** stage
7. ⚠️ **Stakeholder engagement protocol** (Snowflake Requirements)
   - Recommendation: Mention in **Find** (who requested, why)
8. ⚠️ **IR triage playbook alignment** (Snowflake Design)
   - Recommendation: Add to **Govern** (pair detection with runbook)
9. ⚠️ **Purple Team / Red Team validation** (Snowflake Continuous Testing)
   - Recommendation: Add to **Evolve** as periodic validation gate
10. ⚠️ **Annual detection review** (Snowflake Monitoring)
    - Recommendation: Clarify in **Evolve** (not just review cadence, but annual deep review)

#### Nice-to-Have

11. ⚠️ **Detection coverage metrics tracking** (Snowflake Requirements)
12. ⚠️ **Temporary vs. permanent decommission** (Snowflake Monitoring)
13. ⚠️ **Version control emphasis** (Snowflake everywhere)
14. ⚠️ **Atomic Red Team integration** (Snowflake Testing)

---

## Proposed FORGE Enhancements

### Option 1: Expand Existing Stages (Minimal Change)

Keep the FORGE acronym but expand guidance within stages:

**Find** → Add:
- Risk-based prioritization guidance
- Stakeholder engagement protocol
- Detection coverage gap tracking

**Observe** → No changes (already unique strength)

**Refine** → Add:
- Historical backtesting requirement
- Real-time test queue mention
- Acceptance criteria definition (FP rate, alert volume)
- IR triage playbook alignment

**Govern** → Add:
- Peer review as explicit deployment gate
- Version control requirement
- IR runbook pairing

**Evolve** → Add:
- Detection Improvement Request (DIR) workflow
- Purple Team / Red Team validation
- Annual deep review requirement
- Temp vs. permanent decommission distinction

### Option 2: Expand Acronym (Moderate Change)

Insert a new stage between **Refine** and **Govern**:

**F**ind → **O**bserve → **R**efine → **T**est → **G**overn → **E**volve

FORTGE is awkward, but could become:
- **FORGED** → **F**ind → **O**bserve → **R**efine → **G**overn → **E**volve → **D**eploy (but this breaks the loop)
- **FORGED** → **F**ind → **O**bserve → **R**efine → **T**est → **G**overn → **E**volve (but no good acronym)

**Not recommended** — awkward acronym.

### Option 3: Reframe a Letter (Creative Change)

Reframe **R**efine to **R**eady or **R**eview:

**F**ind → **O**bserve → **R**eady → **G**overn → **E**volve

**Ready** = Refine + Test in one stage:
- Similarity / Overlap / Verification (current Refine)
- Historical backtesting
- Real-time test queue
- Peer review
- Acceptance criteria validation

This keeps FORGE, expands Refine semantically to include testing/validation.

### Option 4: Sub-Stage Expansion (Recommended)

Keep FORGE acronym but introduce **sub-stages** in documentation:

**Refine**:
- Refine.1: Draft & Iterate (similarity, overlap, verification)
- Refine.2: Test & Validate (backtest, test queue, acceptance criteria)
- Refine.3: Review (peer review, IR playbook alignment)

This preserves the memorable acronym while adding rigor.

---

## Recommendations

### Short-Term (v0.1.0 Documentation Updates)

1. **Expand Find stage guidance** to include:
   - Risk-based prioritization
   - Stakeholder engagement protocol

2. **Expand Refine stage guidance** to include:
   - Historical backtesting
   - Real-time test queue
   - Acceptance criteria (FP rate, alert volume targets)
   - Peer review requirement

3. **Expand Govern stage guidance** to include:
   - IR triage runbook pairing
   - Explicit peer review as deployment gate

4. **Expand Evolve stage guidance** to include:
   - Detection Improvement Request (DIR) workflow
   - Purple Team / Red Team validation cadence
   - Annual deep review

### Medium-Term (v0.2.0 Feature Additions)

5. **Add CLI support**:
   - `adef detection backtest D-XXXX --window 30d`
   - `adef detection test-queue D-XXXX`
   - `adef detection review D-XXXX --peer @alice`

6. **Add MCP tools**:
   - `detection_backtest(detection_id, window)`
   - `detection_acceptance_criteria(detection_id)`
   - `detection_review_request(detection_id, reviewer)`

### Long-Term (v0.3.0+)

7. **Detection Improvement Request (DIR) system**:
   - `adef dir create D-XXXX --type tuning`
   - Track DIR metrics as quality indicators

8. **Purple Team / Red Team integration**:
   - `adef detection validate D-XXXX --atomic-red-team`

---

## Conclusion

**ADEF's FORGE methodology is strong** and introduces unique value (especially the Observe stage). However, it lacks some rigor compared to Snowflake's Detection Development Lifecycle, particularly around:

1. Testing & validation (backtesting, test queues, acceptance criteria)
2. Peer review as a hard gate
3. Structured improvement workflows (DIRs)
4. Purple Team / Red Team validation

**Recommended path forward:**
- Keep the FORGE acronym (it's memorable and differentiated)
- Expand guidance within existing stages (especially Refine, Govern, Evolve)
- Add sub-stages in documentation (Refine.1 Draft, Refine.2 Test, Refine.3 Review)
- Roadmap CLI/MCP tools for backtesting and peer review workflows in v0.2.0

This preserves ADEF's unique strengths while incorporating industry best practices.
