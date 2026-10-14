"""Field-set retrieval — find rules that filter on the same telemetry fields.

BM25 compares words, so a Sigma rule and a SQL rule detecting the same
behaviour score near zero against each other: they share almost no tokens.
But they read the same *fields*. This module indexes each detection by the
field names its query *filters on* — the predicate, via
``PREDICATE_FIELD_EXTRACTORS``; grouping and projection columns say nothing
about what a rule detects — and scores pairs on weighted overlap, which is
language-agnostic by construction.

Canonicalization through declared schema aliases is what makes it truly
cross-language (`Image` -> `process.name`). Without declared aliases the
comparison is literal — same language only, which BM25 already covers through
shared tokens — so ``RuleSimilarity`` fuses these hits only when the target's
state is ``schema``; every result reports the state either way.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Optional

from adef.core.corpus import CorpusEntry
from adef.core.declaration import address_literals, declared_aliases, read_schema_v2
from adef.core.rule_discovery import shape_literals
from adef.core.rule_parser import (
    PREDICATE_FIELD_EXTRACTORS as _EXTRACTORS,
    field_extractor_key as _extractor_key,
    routing_fields,
)

FieldMatching = Literal["schema", "declared_no_aliases", "unmatched", "unparseable"]

# The floor of `log(1 + N/df)` as df -> N: a field present in *every*
# detection contributes exactly `log(2)`, never more, regardless of corpus
# size. `idf(f) > _UBIQUITOUS_FLOOR` iff `df(f) < N` strictly — "clears the
# floor" and "is not universal" are the same predicate for one field, since
# idf is a strictly decreasing function of df and log(2) is its value
# exactly at df == N. The match-gate in `candidates()` requires the shared
# *set* to contain at least one field clearing this floor — not merely a
# summed weight above it. A pure containment ratio can't reject a match
# built entirely from universal fields any other way: two identical sets
# always score 1.0 regardless of weighting, because the ratio's numerator
# and denominator are the same value, and summing weights doesn't fix this —
# two universal fields together sum to `2 * log(2)`, comfortably above a
# single-field floor, even though neither carries any signal alone. A
# per-field floor with an "any" quantifier is what actually rejects it,
# generalizing to any number of universal fields at once. Fixed, not
# derived from the live `_idf` dict, so disabling IDF (weights all 1.0)
# makes every field's weight exceed this floor instead of tracking it down
# — which is exactly the "plain containment saturates" failure IDF fixes.
_UBIQUITOUS_FLOOR = math.log(2)


@dataclass(frozen=True)
class FieldHit:
    detection_id: str
    score: float
    shared_fields: list[str]


def _fields_for(record: dict) -> Optional[set[str]]:
    """Referenced event field names, or None when nothing can be extracted.

    Routing pseudo-fields (`index`, `sourcetype`, ...) are dropped, as `schema
    check` drops them: every SPL rule pins them, so in a mixed-language corpus
    they clear the ubiquitous floor and would field-match every SPL rule to
    every other on routing alone. An empty result is None too — the
    extractors swallow their own parse errors and return an empty set, so
    that is what "malformed" actually looks like here, and an empty set kept
    in the index would count toward N and hold every field's df below it.
    """
    key = _extractor_key(record)
    query = str(record.get("query") or "")
    if not key or not query:
        return None
    try:
        routing = routing_fields(key)
        fields = {f for f in _EXTRACTORS[key](query)
                  if f and f.lower() not in routing}
    except Exception:  # noqa: BLE001 — a malformed query is data, not a crash
        return None
    return fields or None


def _build_alias_maps(
    workspace: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, set[str]], set[str], set[str]]:
    """(source -> {alias -> canonical}, literal -> source names, sources with
    aliases, alias/canonical keys that mean DIFFERENT things in different sources).

    One alias map *per source*, not a single map shared across all of them.
    A global map is the bug this module originally shipped with: source
    `aaa` and source `wineventlog` can both declare `Image` as an alias for
    different canonical fields, and if they're merged into one dict, whichever
    source sorts first wins the collision *for every rule in the corpus* —
    including a rule that only ever addresses `wineventlog` and never
    touches `aaa`. That silently breaks the one thing this feature exists to
    deliver: a rule's fields must canonicalize through the alias map of the
    source *that rule matched*, never a source it didn't.

    Sorted iteration of schema files so that, within one source's own field
    list, a same-named alias declared twice resolves the same way on every
    run instead of flipping with directory order.

    The 4th return value guards `build_field_index`'s literal-fallback union
    (CodeRabbit finding, final whole-branch review fix wave): a casefolded
    alias-or-canonical key that resolves to more than one distinct canonical
    field ACROSS different sources' declarations (e.g. `Image` -> `process.name`
    in one source, `Image` -> `different.canonical` in another) is one this
    module has been explicitly told means two different things depending on
    source. Adding it as a bare literal for BOTH rules would let them match
    each other directly through it, silently overriding what their own
    declared schemas disagree about — the same cross-source bleed the
    per-source scoping above exists to prevent, reopened through the literal
    side-channel instead of the alias-map side-channel.
    """
    alias_maps: dict[str, dict[str, str]] = {}
    addressed_by: dict[str, set[str]] = {}
    with_aliases: set[str] = set()
    schema_dir = workspace / "schema"
    if not schema_dir.is_dir():
        return alias_maps, addressed_by, with_aliases, set()
    for path in sorted(schema_dir.glob("*.yml")):
        data = read_schema_v2(path)
        if not data:  # not v2, or unparseable — skip this file, keep the rest
            continue
        name = data.get("source")
        if not name:
            continue
        name = str(name)
        for literal in address_literals(data):
            addressed_by.setdefault(literal, set()).add(name)
        source_map = alias_maps.setdefault(name, {})
        for fld in data.get("fields", []) or []:
            if not isinstance(fld, dict):  # a malformed entry, not a malformed file
                continue
            canonical = str(fld.get("name") or "")
            if not canonical:
                continue
            aliases = declared_aliases(fld)
            if aliases:
                with_aliases.add(name)
            for alias in aliases:
                source_map.setdefault(alias.casefold(), canonical)
            source_map.setdefault(canonical.casefold(), canonical)
    # Conflicts are derived from the RESOLVED per-source maps, comparing
    # across distinct sources -- not from every raw field declaration seen
    # while building them. A source that (mistakenly, or via a malformed
    # hand-edit) declares the same alias twice for two different fields
    # already resolves to one canonical via `setdefault`'s first-field-wins
    # above; counting the raw declarations instead would flag that as a
    # "conflict" too, needlessly suppressing the literal fallback for every
    # rule using that alias corpus-wide, including rules whose sources have
    # no disagreement at all (CodeRabbit finding, round 2, same fix wave).
    key_canonicals: dict[str, set[str]] = {}
    for source_map in alias_maps.values():
        for key, canonical in source_map.items():
            key_canonicals.setdefault(key, set()).add(canonical)
    conflicting_keys = {k for k, canons in key_canonicals.items() if len(canons) > 1}
    return alias_maps, addressed_by, with_aliases, conflicting_keys


def _effective_alias_map(alias_maps: dict[str, dict[str, str]], sources: set[str]) -> dict[str, str]:
    """Merge the alias maps of exactly the sources one rule matched.

    A rule that matches a single source (the common case) just gets that
    source's own map — no cross-source collision is even possible. A rule
    whose address literal happens to match more than one declared source
    (e.g. two sources sharing a `scope` value) has more than one candidate
    map; the precedence for that case is: sort the *matched* sources
    alphabetically and let the earliest one win any alias-key collision
    between THEM. This is the same tie-break the schema-file loop already
    uses for determinism, just correctly scoped to the sources this rule is
    actually about, instead of every source in the workspace.
    """
    merged: dict[str, str] = {}
    for source in sorted(sources):
        for key, canonical in alias_maps.get(source, {}).items():
            merged.setdefault(key, canonical)
    return merged


class FieldIndex:
    def __init__(
        self,
        fields: dict[str, frozenset[str]],
        matching: dict[str, FieldMatching],
    ) -> None:
        self._fields = fields
        self._matching = matching
        n = len(fields)
        df: Counter[str] = Counter()
        for fs in fields.values():
            df.update(fs)
        # log(1 + N/df): a field in every detection approaches log(2) rather
        # than 0, so it still ranks below a rare one without vanishing.
        self._idf = {f: math.log(1 + n / c) for f, c in df.items()} if n else {}

    def matching_for(self, detection_id: str) -> FieldMatching:
        return self._matching.get(detection_id, "unparseable")

    def _weight(self, fs: Iterable[str]) -> float:
        return sum(self._idf.get(f, 0.0) for f in fs)

    def candidates(self, detection_id: str, top_k: int) -> list[FieldHit]:
        target = self._fields.get(detection_id)
        if not target:
            return []
        target_w = self._weight(target)
        hits: list[FieldHit] = []
        for other_id, other in self._fields.items():
            if other_id == detection_id or not other:
                continue
            shared = target & other
            if not shared:
                continue
            # At least one shared field must be non-universal (df < N), or
            # the match rests entirely on fields that carry zero signal
            # regardless of how many of them there are.
            if not any(self._idf.get(f, 0.0) > _UBIQUITOUS_FLOOR for f in shared):
                continue
            shared_w = self._weight(shared)
            denom = min(target_w, self._weight(other))
            if denom <= 0:
                continue
            score = shared_w / denom
            if score <= 0:
                continue
            hits.append(FieldHit(other_id, round(score, 4), sorted(shared)))
        # Deterministic: score descending, id ascending on ties.
        hits.sort(key=lambda h: (-h.score, h.detection_id))
        return hits[:top_k]


def build_field_index(entries: Iterable[CorpusEntry], workspace: Path) -> FieldIndex:
    alias_maps, addressed_by, with_aliases, conflicting_keys = _build_alias_maps(workspace)
    fields: dict[str, frozenset[str]] = {}
    matching: dict[str, FieldMatching] = {}
    for entry in entries:
        record = entry.record
        if not record:
            matching[entry.detection_id] = "unparseable"
            continue
        raw = _fields_for(record)
        if raw is None:
            matching[entry.detection_id] = "unparseable"
            continue

        # Match this rule to a declared source the same way `schema check`
        # does (`adef/commands/schema.py`) — by literal-match *count*, not a
        # plain union. A broad container literal (a `data_source` string)
        # and a specific shape literal (SPL `sourcetype=`) can each address a
        # different source; unioning both would let the broad source's
        # alias map compete with the specific source's for this rule, and
        # alphabetical precedence could then pick the wrong one. Keeping
        # only the source(s) tied at the highest literal-match count mirrors
        # `schema check`'s specificity heuristic exactly.
        literals = {str(record.get("data_source") or "").strip()} - {""}
        literals.update(shape_literals(str(record.get("query") or ""),
                                        _extractor_key(record)))
        match_counts: dict[str, int] = {}
        for literal in literals:
            for source in addressed_by.get(literal, ()):
                match_counts[source] = match_counts.get(source, 0) + 1
        sources: set[str] = set()
        if match_counts:
            best = max(match_counts.values())
            sources = {s for s, n in match_counts.items() if n == best}

        if not sources:
            matching[entry.detection_id] = "unmatched"
            fields[entry.detection_id] = frozenset(f.casefold() for f in raw)
            continue
        if not (sources & with_aliases):
            matching[entry.detection_id] = "declared_no_aliases"
            fields[entry.detection_id] = frozenset(f.casefold() for f in raw)
            continue
        matching[entry.detection_id] = "schema"
        effective = _effective_alias_map(alias_maps, sources)
        # Union, not replacement (I-1, final whole-branch review): a rule
        # whose source is declared-with-aliases must keep its own literal
        # field names in the index ALONGSIDE the canonical form, not swap one
        # for the other. Replacing lost the literal namespace entirely, so a
        # rule with no schema for its own source (still literal, correctly)
        # could no longer intersect with one that had a schema declared --
        # `adef schema ingest`, this feature's own remedy for `unmatched`,
        # made field retrieval strictly worse than declaring nothing. The
        # union means canonicalization can only ever ADD recall -- EXCEPT for
        # a literal that's a conflicting alias key (CodeRabbit finding, same
        # fix wave): when different declared sources map the same spelling
        # to two DIFFERENT canonical fields, keeping the bare literal for
        # both would let them match each other directly through it, silently
        # overriding what their own schemas explicitly disagree about. That
        # one literal is dropped; every other literal -- an alias declared by
        # at most one source, or not aliased at all, the overwhelmingly
        # common case -- still gets the union.
        fields[entry.detection_id] = frozenset(
            {f.casefold() for f in raw if f.casefold() not in conflicting_keys}
            | {effective.get(f.casefold(), f).casefold() for f in raw}
        )
    return FieldIndex(fields, matching)


__all__ = ["FieldHit", "FieldIndex", "FieldMatching", "build_field_index"]
