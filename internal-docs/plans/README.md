# ADEF Design Plans

Design specs for shipped and in-progress features — the *why* behind the
implementation, kept as internal engineering reference (not part of the
public, user-facing doc set). For the earlier brainstorming/meeting artifacts
(June–early July 2026) that shaped v1, see the parent `docs/archive/`.

## Current specs

- **[2026-07-15-catalog-design.md](2026-07-15-catalog-design.md)** — the catalog
  artifact: records, INDEX, discovery, `support` model.
- **[2026-07-17-format-detection-plan.md](2026-07-17-format-detection-plan.md)** —
  content-signature recognizer registry; recognize-all / parse-incrementally.
- **[2026-07-20-claude-plugin-design.md](2026-07-20-claude-plugin-design.md)** —
  the Claude plugin: skills, sub-agents, extraction profiles.
- **[2026-07-20-schema-declaration-design.md](2026-07-20-schema-declaration-design.md)** —
  the declaration-driven schema model (`adef schema *`) + scope.
- **[2026-07-22-adef-sync-design.md](2026-07-22-adef-sync-design.md)** —
  `adef sync`: staleness detection, the identity/reconciliation cascade, and
  out-of-band journal harvesting. *Steps 1–3 shipped.*
- **[2026-07-22-adef-as-detection-home-design.md](2026-07-22-adef-as-detection-home-design.md)** —
  repo-less teams using ADEF as their detection system of record: the
  `origin: authored|catalogued` marker, sync-exclusion for authored records,
  git-friendly workspace. (`adef export` considered and deferred.)
  *Steps 1–2 shipped; `adef export` deferred.*
- **[2026-07-22-unify-on-profiles-design.md](2026-07-22-unify-on-profiles-design.md)** —
  analysis of whether built-in extractors should collapse into shipped profiles
  (they can't without turning the profile format into a DSL). Decision record
  for when the question recurs. *Analysis; P1/P2 shipped, keep-the-split holds.*

## Where else to look

- **What's shipped:** the `README.md` at the repo root
- **Decisions (system of record):** `../ISA.md`
- **Branch state + roadmap (archived dev notes):** `../HANDOFF.md`
- **Framework context:** `../../methodology.md`, `../../why-adef.md`,
  `../forge-framework-comparison.md`
