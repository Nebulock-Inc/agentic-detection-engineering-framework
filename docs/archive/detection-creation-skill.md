# Detection Creation Skill — The Missing Core Skill

**Status:** 🔴 Critical Gap Identified  
**Priority:** P0 — Should be the FIRST skill  
**Purpose:** AI-assisted detection creation through the entire FORGE lifecycle

---

## The Problem

**Current state:** All proposed skills help you navigate, analyze, or monitor detections. **None help you actually create one.**

This is backwards. The core workflow is:
1. **Create a detection** (missing!)
2. Then list/search/analyze it (covered by other skills)

---

## Detection Creation Skill

### Core Purpose
Guide users through creating a detection from initial hypothesis to deployment-ready rule, with AI assistance at every FORGE stage.

---

## Skill Triggers

### Initial Creation
- "Create a detection for LSASS dumping"
- "Build a detection for T1003.001"
- "I want to detect mshta.exe abuse"
- "Help me write a detection rule"
- "Guide me through creating a detection"

### From Research
- "Create a detection from research R-0005"
- "Build detection from draft #2 in R-0005"
- "Turn this CTI into a detection: [URL]"

### From Hunt
- "Promote hunt H-0042 to detection"
- "Convert this hunt to a detection"

---

## Stage 1: Find — Hypothesis Generation

### User Intent
```
User: Create a detection for LSASS dumping
```

### Skill Response
```
Skill: I'll help you create an LSASS dumping detection. Let me start by researching this technique.

[Runs: adef research new --technique T1003.001]

**Research Summary (T1003.001 - LSASS Memory):**

Common methods:
1. rundll32.exe + comsvcs.dll (most common)
2. Mimikatz + sekurlsa::minidump
3. Procdump -ma lsass.exe
4. Task Manager memory dump

**Coverage Check:**
[Runs: adef detection list --technique T1003.001]

Found 2 existing detections:
- D-0023: Mimikatz via process creation
- D-0034: Procdump targeting LSASS

**Gap identified:** No coverage for comsvcs.dll method.

I recommend creating a detection for:
**"LSASS memory dumping via comsvcs.dll"**

This would cover the most common technique (rundll32 + comsvcs) that's currently not detected.

Shall I create this detection?
```

### User Confirmation
```
User: Yes, create it

Skill: Creating detection...
[Runs: adef detection new "LSASS memory dumping via comsvcs.dll" --technique T1003.001]

Created **D-0101** at Find stage.

Let me help you document the hypothesis...
```

---

## Stage 2: Observe — Telemetry Analysis

### AI Assistance: Schema Discovery + Sample Queries

```
Skill: Now let's move to Observe stage to characterize the telemetry.

**Step 1: Verify data source availability**
[Runs: adef schema list]

Available schemas:
- splunk-security (Sysmon + Windows Event Logs)
- crowdstrike-edr (EDR telemetry)

Which data source should I check?

User: Splunk

Skill: Checking schema...
[Runs: adef schema show splunk-security --search "process"]

**Required fields for this detection:**
✅ process_name (98% populated)
✅ command_line (68% populated) ⚠️ Some events missing
✅ parent_process (88% populated)
⚠️ parent_command_line (45% populated) - Low coverage

**Detection logic:**
```
process_name = "rundll32.exe"
AND command_line CONTAINS "comsvcs.dll"
AND command_line CONTAINS "MiniDump"
```

**Step 2: Estimate volume**

I can generate a sample query to estimate baseline volume. Here's a Splunk query:

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| where process_name="rundll32.exe"
| where like(command_line, "%comsvcs.dll%")
| stats count by _time span=1d, user, host
```

**Expected baseline:** <5 events/day (mostly legitimate COM registration)

**Suspicious indicators:**
- "MiniDump" in command_line (malicious)
- Parent process from Office/browser (malicious)
- Run from temp directories (malicious)

Should I document this in the Observe stage and advance?

User: Yes

Skill: Documenting and advancing...
[Edits journal with findings]
[Runs: adef detection observe D-0101 --note "Verified fields available in Splunk, baseline <5/day"]

D-0101 advanced to **Observe stage** ✅

Ready for Refine stage. Should I draft the detection rule?
```

---

## Stage 3: Refine — Rule Drafting + Iteration

### AI Assistance: Generate Detection Rule

```
Skill: Let me draft the detection rule based on what we learned.

**Detection Format:** Which format should I use?
1. Sigma (vendor-neutral)
2. Splunk SPL
3. KQL (Microsoft Sentinel)
4. Generic SQL

User: Sigma

Skill: Generating Sigma rule...

**Draft Detection Rule:**

```yaml
title: LSASS Memory Dumping via comsvcs.dll
id: a1b2c3d4-5678-90ab-cdef-1234567890ab
status: experimental
description: Detects LSASS memory dumping using rundll32.exe and comsvcs.dll MiniDump technique
author: AI-Assisted (Human: Alice)
date: 2026-06-25
references:
  - https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  selection_target:
    CommandLine|contains: 'lsass'
  condition: selection_process and selection_target
falsepositives:
  - Legitimate system administration (rare)
level: high
```

**Rule Explanation:**
- **Process:** rundll32.exe (common LOLBin for DLL execution)
- **DLL:** comsvcs.dll (Windows component DLL with MiniDump export)
- **Target:** lsass (Local Security Authority Subsystem Service)
- **Technique:** Combines all three indicators = high confidence

**Validation Checks:**
[Runs: adef schema validate D-0101]
✅ All fields exist in schema
⚠️ CommandLine has 68% population (some events may lack details)

**Overlap Check:**
[Runs: adef detection overlap D-0101]
Checking against 50 existing detections...
✅ No significant overlap detected

**Similarity Check:**
[Runs: adef detection similar D-0101]
Found similar detections:
- D-0023 (Mimikatz) - 30% similar (different process)
- D-0034 (Procdump) - 25% similar (different technique)

✅ Distinct enough to warrant separate detection

Should I:
1. Save this rule to the journal?
2. Run the Refine orchestration chain?
3. Make adjustments first?

User: Save and run Refine

Skill: Saving rule and advancing...
[Saves Sigma YAML to detection artifacts or journal]
[Runs: adef detection refine D-0101]

**Refine Orchestration Results:**

### Similarity Check
✅ No duplicate rules found

### Overlap Check
✅ No overlapping triggers with existing rules

### Verification
✅ Schema validation passed
✅ Four-engine constraint satisfied (sigma)
✅ MITRE mapping valid (T1003.001)

D-0101 advanced to **Refine stage** ✅

The detection rule is ready for testing. 

**Next steps:**
1. Backtest against 30 days of data
2. Document true positives / false positives
3. Tune thresholds if needed

Should I generate backtest queries?
```

---

## Stage 4: Govern — Deployment Preparation

### AI Assistance: Deployment Checklist + Rule Metadata

```
Skill: Let's prepare D-0101 for deployment.

**Governance Checklist:**

**1. Severity Assessment**
Based on MITRE ATT&CK T1003.001:
- Tactic: Credential Access
- Impact: Critical (credentials stolen)
- Prevalence: Common in real attacks
- **Recommended Severity:** High

**2. Ownership Assignment**
Who should own this detection?
- Current owner: (none)
- Typical owner: SOC Tier 2 or Detection Engineering team

User: Assign to me

Skill: [Runs: adef detection assign D-0101 --owner alice@example.com]
✅ Owner set to alice@example.com

**3. On-Call Rotation**
Which rotation responds when this fires?
- SOC Primary
- Incident Response
- Detection Engineering

User: SOC Primary

Skill: Documenting...

**4. False Positive Review**
Expected FP rate: Very Low (<1%)

Legitimate scenarios:
- System diagnostics (rare)
- Security tools (antivirus memory scanning)

Recommended exclusions:
- Parent process = known security tools
- User = SYSTEM (depends on environment)

**5. Deployment Evidence**
Required approvals:
- ☐ Peer review (detection engineering)
- ☐ SOC team review
- ☐ Security manager approval

Should I mark this for review?

User: Yes

Skill: Advancing to Govern stage...
[Runs: adef detection govern D-0101 --note "Ready for peer review, awaiting approvals"]

D-0101 advanced to **Govern stage** ✅

**Summary:**
- Detection: D-0101 (LSASS via comsvcs.dll)
- Severity: High
- Owner: alice@example.com
- Stage: Govern (awaiting approvals)

Once approvals are complete, I can help you deploy to production.
```

---

## Stage 5: Evolve — Tuning + Monitoring

### AI Assistance: Performance Analysis + Tuning Recommendations

```
User: D-0101 has been running for 30 days, help me tune it

Skill: Let me analyze D-0101's performance over the past 30 days.

[Queries signal data from SIEM/SOAR - if available]
[Or prompts user for data]

**Option 1: If signal data available (product/gray zone)**
Signal summary (30 days):
- Total signals: 12
- True positives: 10 (83%)
- False positives: 2 (17%)
- Avg time to triage: 15 minutes

**True Positive Analysis:**
- 8 from known red team exercises
- 2 from actual incidents (confirmed)
- All involved rundll32 + comsvcs + lsass pattern

**False Positive Analysis:**
FP #1: Security tool (CrowdStrike memory scanner)
- Parent: csagent.exe
- Recommendation: Add exclusion for parent=csagent.exe

FP #2: System diagnostic by IT admin
- User: corp\sysadmin
- Time: During maintenance window
- Recommendation: Consider excluding specific admin accounts OR time-based suppression

**Tuning Recommendation:**
Add these exclusions to reduce FP rate to near-zero:

```yaml
falsepositives:
  - Security tools (EDR memory scanning)
  - Authorized system administration
filter:
  ParentImage|endswith:
    - '\csagent.exe'        # CrowdStrike
    - '\taniumclient.exe'   # Tanium EDR
  User|startswith: 'NT AUTHORITY\'  # System processes
```

Should I update the rule with these exclusions?

User: Yes

Skill: Updating rule and documenting...
[Updates detection rule/journal]
[Runs: adef detection evolve D-0101 --note "Tuned: Added EDR exclusions, FP rate reduced from 17% to <1%"]

D-0101 tuning complete ✅

**Updated Performance (projected):**
- FP rate: <1%
- TP rate: 100% (maintained)
- Ready to continue monitoring

I'll check back in 30 days to see if further tuning is needed.

---

**Option 2: If no signal data (framework-only)**

Skill: I don't have access to signal data from your SIEM. Let me guide you through manual tuning.

**Questions to document:**

1. How many signals fired in 30 days?
2. How many were true positives?
3. How many were false positives?
4. What patterns did you notice in FPs?

[Interactive Q&A to gather data]

Based on your answers, here are tuning recommendations...
[Continues with similar analysis]
```

---

## Complete Workflow Example

### End-to-End: Idea → Deployed Detection

```
User: I want to detect lateral movement via WMI

Skill: I'll help you create a WMI lateral movement detection.

**Step 1: Research** (Auto)
[Researches T1047 - WMI Execution]
Found gap: No coverage for WMI remote process creation
Recommended: "Remote WMI process creation"

**Step 2: Create Detection** (Auto)
[Creates D-0102 at Find stage]

**Step 3: Observe** (Assisted)
[Checks schema: WinEventLog:Security Event 4648 + 4688]
[Generates sample query]
[Estimates volume: ~10 events/day]
Data source confirmed ✅

**Step 4: Refine** (AI-Generated)
[Drafts Sigma rule for WMI process creation]
[Validates against schema]
[Checks for overlaps]
Rule validated ✅

**Step 5: Govern** (Assisted)
[Sets severity: Medium]
[Assigns owner: alice]
[Documents deployment checklist]
Ready for approval ✅

**Step 6: Deploy** (Manual - CLI or product)
User deploys to production

**Step 7: Evolve** (Assisted)
[After 30 days]
[Analyzes performance: 5 TP, 1 FP]
[Recommends tuning: Exclude parent=sccm.exe]
Detection optimized ✅

---

**Total time:** 15 minutes (vs. 2-3 hours manual)
**AI assistance:** 80% of work automated
**Human decisions:** Approval, deployment timing, environment-specific tuning
```

---

## Skill Capabilities Summary

### What This Skill Does

**1. Hypothesis Generation**
- Research TTPs from MITRE ATT&CK
- Check existing coverage
- Identify gaps
- Recommend specific detections

**2. Schema Discovery**
- Check data source availability
- Validate required fields
- Estimate field population
- Flag low-coverage fields

**3. Sample Query Generation**
- Generate baseline queries (Splunk/KQL/SQL)
- Estimate normal volume
- Identify suspicious indicators

**4. Detection Rule Drafting**
- Generate Sigma/Splunk/KQL/SQL rules
- Include proper metadata (MITRE, severity, author)
- Add false positive guidance
- Provide rule explanations

**5. Validation**
- Schema validation (fields exist)
- Overlap detection (duplicates)
- Similarity checks (related rules)
- Syntax validation

**6. Governance Guidance**
- Severity assessment
- Ownership assignment
- Deployment checklist
- Approval workflow

**7. Tuning Recommendations**
- Analyze signal performance (if data available)
- Identify FP patterns
- Suggest exclusions
- Update rules

---

## CLI Commands Used

Throughout the workflow:
1. `adef research new --technique T1003.001`
2. `adef detection list --technique T1003.001`
3. `adef detection new "Title" --technique T1003.001`
4. `adef schema list`
5. `adef schema show splunk-security`
6. `adef schema validate D-0101`
7. `adef detection observe D-0101`
8. `adef detection overlap D-0101`
9. `adef detection similar D-0101`
10. `adef detection refine D-0101`
11. `adef detection assign D-0101 --owner alice`
12. `adef detection govern D-0101`
13. `adef detection evolve D-0101`

**Skill orchestrates the entire FORGE lifecycle.**

---

## Why This is the #1 Priority Skill

### Current Skills (Proposed)
1. Detection Explorer — **Find existing detections**
2. Coverage Analyst — **Analyze what's missing**
3. Detection Researcher — **Research what to build**
4. Schema Discovery — **Check data availability**
5. Stage Advisor — **Guide through stages**
6. Quality Checker — **Validate detections**
7. Hunt Promotion — **Convert hunts**

**Missing:** Actually CREATE the detection!

### This Skill (Detection Creation)
**Does:** Guide from idea → deployed detection in one conversation

**This should be Skill #1.** Everything else supports it.

---

## Implementation Priority

### Phase 0 (Before P0)
- ✅ **Detection Creation Skill** — The core workflow

### Phase 1 (P0)
- Schema Discovery Assistant (supports creation)
- Coverage Analyst (identifies what to create)
- Detection Explorer (manage created detections)

### Phase 2 (P1)
- Detection Researcher (alternative creation path)
- Stage Advisor (supports creation process)
- Quality Checker (validates created detections)

---

## Updated Skill Roadmap

| Priority | Skill | Purpose |
|----------|-------|---------|
| **P0** | Detection Creation | ⭐ Create detections end-to-end |
| P0 | Schema Discovery | Support creation with field data |
| P0 | Coverage Analyst | Identify what to create |
| P0 | Detection Explorer | Manage created detections |
| P1 | Detection Researcher | Alternative creation (CTI-driven) |
| P1 | Stage Advisor | Guide creation process |
| P1 | Quality Checker | Validate created detections |
| P1 | Hunt Promotion | Convert hunts to detections |

---

## Key Insight

**You were absolutely right.** A detection engineering framework without a detection creation assistant is like:
- A text editor without a "new file" command
- A build system without a "compile" command
- A package manager without an "install" command

**Detection Creation Skill is the CORE skill.** Everything else is supporting infrastructure.

---

## Next Steps

1. **Implement Detection Creation Skill FIRST**
2. Test with real workflows (idea → deployed detection)
3. Validate it reduces time from hours to minutes
4. Then add supporting skills (explorer, coverage, etc.)

**This skill is the 80% use case. Start here.**
