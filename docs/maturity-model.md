# ADEF Detection Engineering Maturity Model

> Five levels of how your team writes, ships, and remembers detections. Where you are today is fine; what matters is the next step.

ADEF's maturity model is shaped to match the gap most teams actually face: not "we don't have detections," but **"our detections have no memory."** The levels below describe the substrate underneath the detection program — what's written down, what's searchable, what's automatable — not the count of rules deployed.

The framework treats every level as a stable plateau a team can rest on. You don't have to reach L4 to benefit. You have to *know which level you're on* and pick the next one deliberately.

---

## L0 — Ad-hoc

**What you get.** Detections live as YAML or platform-saved searches. Tribal knowledge lives in DMs, sticky notes, and the heads of two senior engineers. New rules are added when someone has time. There's no consistent place for *why* a rule exists; if the author leaves, that context is gone.

**Signs you're here.** Asked "why is this rule the way it is?" the team's first move is `git blame`. Someone tunes a rule, breaks something, and a peer says "ah, that filter was there for a reason — I think."

**Time to next level.** **1–2 weeks** of deliberate work. Pick a per-detection markdown file format and start writing the *why* down. Even ungenerously rough notes beat empty files.

---

## L1 — Documented

**What you get.** Every production detection has a sibling markdown journal capturing the FORGE-stage notes — at minimum: hypothesis, intel sources, why this isn't a duplicate, deployment decision. Onboarding a new detection engineer takes a fraction of the time it used to. Tuning decisions don't surprise anyone six months later because the rationale is in the journal.

**Signs you're here.** A detection engineer can read a rule's journal cold and answer "should I tune this, and why?" without asking the original author. `adef detection new` and `adef detection observe/refine/govern/evolve` are part of the team's habit loop.

**Time to next level.** **1–2 months.** L1 → L2 is mostly an indexing problem.

---

## L2 — Searchable

**What you get.** Journal corpora and YAML metadata are indexed and queryable in one call. *"Have we hunted this technique before?"*, *"Which rules cover T1218.*?"*, *"Show me deprecated detections in cloud control plane"* are answered in seconds, not afternoons. ADEF's `memory_search` MCP tool serves both human queries and agent context.

**Signs you're here.** Onboarding includes "search before you write." Nobody ships a rule until they've checked for overlap. Detection reviewers have evidence of prior decisions to cite, not just opinions.

**Time to next level.** **3–6 months.** L2 → L3 requires you to trust the index enough to seed agent input.

---

## L3 — Generative

**What you get.** Agents augment the human at every FORGE stage. `adef hunt-promote H-XXXX` produces a draft detection from a hunt. `HypothesisFromIntelAgent` turns a CTI URL into a draft Find/Observe block. `RuleSimilarityWrapper` and `RuleOverlapWrapper` flag duplicates before review. `TuneRecommenderAgent` proposes specific tuning actions from performance metrics. Humans still author and approve — agents draft, deduplicate, and de-risk.

**Signs you're here.** Every new detection starts as an agent-drafted journal entry that a human refines, not a blank file. Refine-stage chains run as part of the normal review flow. The team measures *agent-suggested* vs. *human-shipped* divergence and uses it to improve prompts.

**Time to next level.** **6–12 months** for most teams. L3 → L4 is mostly governance, observability, and trust.

---

## L4 — Agentic

**What you get.** Long-running orchestration daemons monitor detection health, propose deprecations, and ship low-risk tuning PRs autonomously. The team's role shifts from *writing detections* to *governing the system that writes detections*. Humans set policy, review proposals, and intervene on the ones that matter; routine tuning becomes a queue of agent-proposed PRs to approve.

**Signs you're here.** Most tuning PRs are opened by an agent and approved (or rejected with rationale that feeds back into the agent's prompt). Detection deprecation is a regular, evidence-backed event, not a quarterly cleanup. The team can answer "what is the agent uncertain about right now?" because the agents surface their own uncertainty.

**v0.1.0 honesty.** L4 is on the roadmap, not in this release. The Tune/Deprecation recommenders ship in v0.1.0 as *advisory* agents — they suggest, they don't act. v0.2+ adds the daemon and the autonomous PR loop. See [roadmap.md](./roadmap.md).

---

## Choosing your next level

A few notes from the field:

- **L0 → L1 is the highest-ROI step.** Most teams that "don't get value from detection engineering frameworks" are stuck at L0 not because frameworks are broken, but because journals were never the unit of work.
- **Don't skip L2.** Generative AI on top of un-indexed journals produces confident-sounding hallucinations. Search first, then layer agents on top of search.
- **L3 is a culture shift, not a tooling shift.** You can install ADEF in an afternoon. Getting your team to *use* the agent-drafted journals takes longer.
- **L4 is a governance problem.** It's also a year of trust-building. Plan accordingly.

ADEF v0.1.0 ships everything you need to operate at L0–L3 today, and the foundation for L4 in v0.2+.
