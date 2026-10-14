"""Native, vendor-free duplicate/complementary/redundant classification.

Deterministic (hashlib/difflib, stdlib only) — no LLM call. Compares the target against
rules on the same MITRE technique: a sub-technique and its parent technique
are compared; sibling sub-techniques are not. Uses `catalog/INDEX.yml`'s
`by_technique` map (built by `Catalog.rebuild_index()`) rather than
re-deriving grouping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from adef.core.catalog import NoCatalogRecordError
from adef.core.corpus import build_corpus
from adef.core.corpus_text import _sigma_doc, record_language, record_mitre, record_query_logic
from adef.core.journal import workspace_journals_dir
from adef.core.rule_parser import field_extractor_key, spl_filter_text

_DUPLICATE_NEAR_THRESHOLD = 0.85  # near-identical, not byte-identical, query logic


@dataclass
class Overlap:
    other_id: str
    overlap_type: str  # duplicate | complementary | redundant | unassessed
    confidence: float
    reasoning: str


def _normalize_query(query_text: str) -> str:
    if not query_text:
        return ""
    normalized = query_text.lower()
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"\s*([=<>!(),])\s*", r"\1", normalized)
    return normalized.strip()


def _similarity(query_a: str, query_b: str) -> float:
    if not query_a or not query_b:
        return 0.0
    return SequenceMatcher(None, _normalize_query(query_a), _normalize_query(query_b)).ratio()


# One token per predicate: a quoted value (with any `field=` prefix) stays whole,
# so `CommandLine="foo AND bar"` is one token, not an `and` operator.
_SPL_TOKEN_RE = re.compile(r'[^\s()|"]*"(?:[^"\\]|\\.)*"[^\s()|"]*|[()|]|[^\s()|"]+')
_SPL_STRUCTURE = frozenset({"or", "not", "(", ")"})


_QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_SPL_KEYWORDS = frozenset({"and", "or", "not"})


def _spl_tokens(text: str) -> list[str]:
    """Predicate and operator tokens of an SPL filter, normalized only where
    that can't change meaning: whitespace and operator spacing *outside*
    quotes, and the case of the ``and``/``or``/``not`` keywords and stage
    commands. Quoted text (a regex pattern, a value with spaces) and field
    names and values keep their case — SPL field names, ``CASE()`` terms and
    PCRE patterns are case-sensitive — so a case-only difference reads as
    different rules: a recall cost, never a false duplicate. ``and`` is
    dropped: SPL ANDs adjacent terms implicitly."""
    pieces: list[str] = []
    pos = 0
    for m in _QUOTED_RE.finditer(text):
        pieces.append(re.sub(r"\s*([=<>!(),])\s*", r"\1", re.sub(r"\s+", " ", text[pos:m.start()])))
        pieces.append(m.group(0))
        pos = m.end()
    pieces.append(re.sub(r"\s*([=<>!(),])\s*", r"\1", re.sub(r"\s+", " ", text[pos:])))
    out: list[str] = []
    at_command = False
    for tok in _SPL_TOKEN_RE.findall("".join(pieces).strip()):
        if tok == "|":
            out.append(tok)
            at_command = True
            continue
        if at_command or tok.lower() in _SPL_KEYWORDS:
            tok = tok.lower()
        at_command = False
        if tok != "and":
            out.append(tok)
    return out


def _spl_canonical(tokens: list[str]) -> str:
    """Order-insensitive within each AND run, order-sensitive across ``or``,
    parens and stage pipes; ``not`` stays bound to the predicate (or group) it
    negates. Two filters with the same canonical form select the same events."""
    out: list[str] = []
    run: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "not" and i + 1 < len(tokens):
            if tokens[i + 1] == "(":
                out.extend(sorted(run))
                run.clear()
                out.append("not(")
            else:
                run.append(f"not {tokens[i + 1]}")
            i += 2
            continue
        if tok in _SPL_STRUCTURE or tok == "|":
            out.extend(sorted(run))
            run.clear()
            out.append(tok)
        else:
            run.append(tok)
        i += 1
    out.extend(sorted(run))
    return " ".join(out)


def _classify_spl_pair(filt_a: str, filt_b: str, same_source: bool, id_a: str, id_b: str) -> Overlap:
    """Compare two SPL rules on their filter stages (``spl_filter_text``).

    A duplicate is an identical canonical form, never a Jaccard threshold: in a
    plain conjunction, two rules that each carry a predicate the other lacks
    narrow differently (13 shared predicates plus ``cmd.exe`` vs
    ``powershell.exe`` is 0.87 Jaccard and disjoint events). Containment —
    a predicate superset is a narrower rule — is claimed only for a plain
    conjunction; once ``or``/``not``/parens appear the same tokens can select
    disjoint events (``a=1 AND b=2 OR c=3`` vs ``a=1 OR b=2 AND c=3``).
    Jaccard is reported as the confidence of a ``complementary`` verdict.
    """
    tok_a, tok_b = _spl_tokens(filt_a), _spl_tokens(filt_b)
    set_a, set_b = set(tok_a) - {"|"}, set(tok_b) - {"|"}
    jaccard = len(set_a & set_b) / len(set_a | set_b) if set_a and set_b else 0.0
    if tok_a and _spl_canonical(tok_a) == _spl_canonical(tok_b):
        return Overlap(id_b, "duplicate", 1.0, "Identical filter logic after normalization")
    if not (_SPL_STRUCTURE & set_a or _SPL_STRUCTURE & set_b):
        if same_source and set_a < set_b:
            return Overlap(
                id_b, "redundant", len(set_a) / len(set_b),
                f"{id_b}'s filter adds predicates to {id_a}'s — "
                f"{id_b} fires on a subset of what {id_a} already covers",
            )
        if same_source and set_b < set_a:
            return Overlap(
                id_b, "redundant", len(set_b) / len(set_a),
                f"{id_a}'s filter adds predicates to {id_b}'s — "
                f"{id_a} fires on a subset of what {id_b} already covers",
            )
    return Overlap(
        id_b, "complementary", jaccard,
        "Related technique, distinct detection logic — different coverage angle",
    )


_BOUNDARY_CONTINUATION_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789._"
)


def _is_clean_substring(needle: str, haystack: str) -> bool:
    """True if ``needle`` occurs in ``haystack`` at a clause boundary, not as
    a partial token — e.g. "event.code=1" is a raw Python substring of
    "event.code=10", but the two are unrelated comparisons, not a superset
    relation. Reject a match whose neighboring character continues an
    identifier or number (found live via CodeRabbit review).

    Every occurrence is tested, not just the first: a broader rule can mention the
    narrower one's predicate twice — once inside a longer token and once on its own
    (``event.code=10 and event.code=1``) — and judging only the first occurrence
    reported a genuinely redundant pair as ``complementary``, which ships the
    duplicate.
    """
    idx = haystack.find(needle)
    while idx != -1:
        end = idx + len(needle)
        before = haystack[idx - 1] if idx > 0 else ""
        after = haystack[end] if end < len(haystack) else ""
        if (
            before not in _BOUNDARY_CONTINUATION_CHARS
            and after not in _BOUNDARY_CONTINUATION_CHARS
        ):
            return True
        idx = haystack.find(needle, idx + 1)
    return False


_SigmaLogic = tuple[tuple[str, ...], frozenset[str]]  # (logsource key, detection tokens)


def _leaf_tokens(node: Any, key: str) -> list[str]:
    """``field|modifier=value`` tokens for every leaf under ``node``; a list
    contributes one token per element, a bare string list (Sigma keywords)
    ``keyword=<value>``. Values are lowercased unless the key's modifier chain
    carries ``cased`` or ``re`` — there, case is part of the match."""
    if isinstance(node, dict):
        return [t for k, v in node.items() for t in _leaf_tokens(v, str(k).lower())]
    if isinstance(node, list):
        return [t for v in node for t in _leaf_tokens(v, key)]
    value = str(node)
    if not {"cased", "re"} & set(key.split("|")[1:]):
        value = value.lower()
    return [f"{key}={value}"]


def _canonical_condition(tokens: list[str]) -> str:
    """Condition tokens joined back into text, with each flat chain of only
    ``and`` or only ``or`` at one parenthesis level sorted (``not`` stays with
    its operand). Mixed and/or chains keep their order — precedence is not
    re-derived. Anything that doesn't parse (e.g. ``| count() > 5``) is
    returned as written."""
    pos = 0

    def operand() -> str:
        nonlocal pos
        if pos >= len(tokens) or tokens[pos] in ("and", "or", ")"):
            raise ValueError
        tok = tokens[pos]
        pos += 1
        if tok == "not":
            return "not " + operand()
        if tok != "(":
            return tok
        inner = chain()
        if pos >= len(tokens) or tokens[pos] != ")":
            raise ValueError
        pos += 1
        return f"({inner})"

    def chain() -> str:
        nonlocal pos
        operands, ops = [operand()], []
        while pos < len(tokens) and tokens[pos] in ("and", "or"):
            ops.append(tokens[pos])
            pos += 1
            operands.append(operand())
        if len(set(ops)) == 1:
            operands.sort()
        return operands[0] + "".join(f" {op} {o}" for op, o in zip(ops, operands[1:]))

    try:
        text = chain()
        if pos != len(tokens):
            raise ValueError
        return text
    except ValueError:
        return " ".join(tokens)


def _sigma_logic(record: dict) -> _SigmaLogic | None:
    """(logsource key, detection token set) for a Sigma record with a
    ``detection`` mapping, else ``None``.

    Selection names and file order are arbitrary, so each selection's
    placeholder comes from its CONTENT: selections are sorted by their leaf
    token signature and numbered ``S1``, ``S2``…. The placeholder prefixes the
    selection's leaf tokens and replaces its name in the one ``condition=``
    token, where ``1 of``/``all of <pattern>`` (and ``them``) are expanded to
    the sorted placeholder group they match and commutative chains are sorted
    — so which values sit under ``not`` still matters, but naming and operand
    order do not.
    """
    doc = _sigma_doc(record)
    detection = doc.get("detection") if doc else None
    if not isinstance(detection, dict):
        return None
    leaves = {
        str(k).lower(): sorted(_leaf_tokens(v, "keyword")) for k, v in detection.items() if k != "condition"
    }
    # ponytail: identical-content selections tie-break by name; their tokens are identical anyway.
    order = sorted(leaves, key=lambda n: (leaves[n], n))
    placeholder = {name: f"S{i}" for i, name in enumerate(order, 1)}
    tokens = {f"{placeholder[name]}:{t}" for name, toks in leaves.items() for t in toks}
    cond = detection.get("condition")
    cond_text = " ".join(map(str, cond)) if isinstance(cond, list) else str(cond or "")
    cond_tokens = []
    for tok in re.findall(r"\(|\)|(?:1|all) of [^\s()]+|[^\s()]+", cond_text.lower()):
        group = re.fullmatch(r"(1|all) of (\S+)", tok)
        if group:
            pattern = "*" if group[2] == "them" else group[2]
            members = [placeholder[n] for n in order if fnmatchcase(n, pattern)]
            tok = f"{group[1]} of ({' '.join(members)})"
        cond_tokens.append(placeholder.get(tok, tok))
    tokens.add(f"condition={_canonical_condition(cond_tokens)}")
    logsource = doc.get("logsource") if doc else None
    ls = logsource if isinstance(logsource, dict) else {}
    ls_key = tuple(str(ls.get(k) or "").lower() for k in ("category", "product", "service"))
    return ls_key, frozenset(tokens)


def _classify_sigma_pair(
    logic_a: _SigmaLogic,
    logic_b: _SigmaLogic,
    id_a: str, id_b: str,
) -> Overlap:
    """Set comparison of two Sigma detections: Jaccard over detection tokens.

    Text similarity over dumped YAML scores two single-selection rules as
    near-identical (mshta vs regsvr32: 0.956) because the structure is
    shared; the tokens are not. ``duplicate`` needs the same logsource and
    the same canonical condition.
    Never ``redundant``: a token superset is not coverage containment — an
    extra list value (OR) broadens a rule, an extra field (AND) narrows it,
    and the token sets cannot tell which.
    """
    (ls_a, tok_a), (ls_b, tok_b) = logic_a, logic_b
    jaccard = len(tok_a & tok_b) / len(tok_a | tok_b)
    # The condition is one token among many leaves, so Jaccard barely feels it:
    # `sel and not filter` vs `sel and filter` fire on disjoint events yet score
    # 0.87 with a 12-value selection. A duplicate must share the condition.
    same_condition = {t for t in tok_a if t.startswith("condition=")} == {
        t for t in tok_b if t.startswith("condition=")
    }
    if ls_a == ls_b and same_condition and jaccard >= _DUPLICATE_NEAR_THRESHOLD:
        return Overlap(
            id_b, "duplicate", jaccard,
            f"Near-identical detection logic ({jaccard:.0%} of field/value tokens shared)",
        )
    return Overlap(
        id_b, "complementary", jaccard,
        "Related technique, distinct detection logic — different coverage angle",
    )


def classify_pair(record_a: dict, record_b: dict, id_a: str, id_b: str) -> Overlap:
    """Classify the relationship of ``record_b`` relative to ``record_a``.

    ``other_id`` on the returned ``Overlap`` is always ``id_b`` — callers
    build one ``Overlap`` per (target, cluster-mate) pair.
    """
    # Different query languages: nothing below compares logic across them —
    # every path is same-language token or text matching, so a true
    # Sigma/CQL twin scored ~0.01 "complementary", which reads as a verdict.
    # Say so instead.
    lang_a, lang_b = record_language(record_a), record_language(record_b)
    if lang_a and lang_b and lang_a != lang_b:
        return Overlap(
            id_b, "unassessed", 0.0,
            f"Different query languages ({lang_a} vs {lang_b}) — logic not compared. "
            "Judge the pair from Similarity's shortlist; a text score across "
            "languages says nothing about overlap",
        )

    sigma_a, sigma_b = _sigma_logic(record_a), _sigma_logic(record_b)
    if sigma_a is not None and sigma_b is not None:
        return _classify_sigma_pair(sigma_a, sigma_b, id_a, id_b)

    query_a, query_b = record_query_logic(record_a), record_query_logic(record_b)
    same_source = bool(record_a.get("data_source")) and record_a.get("data_source") == record_b.get("data_source")
    if field_extractor_key(record_a) == field_extractor_key(record_b) == "spl":
        # Compare what the rules filter on, not ESCU's shared scaffolding: two
        # unrelated tstats rules scored 0.74 on the boilerplate alone.
        # When a filter can't be isolated (it tests an `eval`-built field), the
        # whole query is compared the same structure-aware way — never by a
        # character ratio, which called `process="powershell.exe"` vs
        # `process="cmd.exe"` 91% alike.
        filt_a, filt_b = spl_filter_text(query_a), spl_filter_text(query_b)
        if not (filt_a and filt_b):
            filt_a, filt_b = query_a, query_b
        return _classify_spl_pair(filt_a, filt_b, same_source, id_a, id_b)
    norm_a, norm_b = _normalize_query(query_a), _normalize_query(query_b)

    # Strip one layer of outer wrapping parens before *any* comparison —
    # a WHERE-only predicate convention that wraps the whole condition in
    # `(...)` otherwise defeats both the identity check below and substring
    # matching (export-shaped fixtures).
    # ponytail: lstrip/rstrip strip a *character set*, not one matched
    # pair — correct for the single-outer-paren case real queries use,
    # but would corrupt a query with nested parens immediately at its
    # outer edge (e.g. `((a) and (b))`). Upgrade to a real matched-pair
    # strip if a fixture ever needs that shape.
    norm_a_stripped = norm_a.lstrip("(").rstrip(")")
    norm_b_stripped = norm_b.lstrip("(").rstrip(")")

    # Compared stripped, not raw: `(x)` vs `((x))` is the same logic, and
    # comparing the raw forms fell through to the substring arm below, which
    # then reported the pair as `redundant` at confidence 1.0 with reasoning
    # claiming each side was both a superset and a subset of the other.
    if norm_a_stripped and norm_a_stripped == norm_b_stripped:
        return Overlap(id_b, "duplicate", 1.0, "Identical query logic after normalization")

    # Substring/redundant check runs before the near-duplicate ratio threshold:
    # a substring relation (e.g. one rule adds a single extra clause) can score
    # >= _DUPLICATE_NEAR_THRESHOLD on SequenceMatcher, but the narrower rule is
    # "redundant" (rule 2), not a "duplicate" (rule 1) — the substring test is
    # the more specific signal and must win.

    # The stripped halves, not the raw ones, are what has to be non-empty: a
    # placeholder query (`()` — a stub candidate, or a GATES document with the logic
    # left out) normalizes non-empty and strips to nothing, and the confidence below
    # divides by its length. That `ZeroDivisionError` reached the user as a traceback
    # in the journal, via `run_refine_chain`'s catch-all. Equality is already
    # handled above, so the two sides here always differ.
    if same_source and norm_a_stripped and norm_b_stripped:
        if _is_clean_substring(norm_a_stripped, norm_b_stripped):
            return Overlap(
                id_b, "redundant", len(norm_a_stripped) / len(norm_b_stripped),
                f"{id_b}'s query is a strict superset of {id_a}'s predicate — "
                f"{id_b} fires on a subset of what {id_a} already covers",
            )
        if _is_clean_substring(norm_b_stripped, norm_a_stripped):
            return Overlap(
                id_b, "redundant", len(norm_b_stripped) / len(norm_a_stripped),
                f"{id_a}'s query is a strict superset of {id_b}'s predicate — "
                f"{id_a} fires on a subset of what {id_b} already covers",
            )

    ratio = _similarity(query_a, query_b)
    if ratio >= _DUPLICATE_NEAR_THRESHOLD:
        return Overlap(id_b, "duplicate", ratio, f"Near-identical query logic ({ratio:.0%} similar)")

    return Overlap(
        id_b, "complementary", ratio,
        "Related technique, distinct detection logic — different coverage angle",
    )


class RuleOverlapAgent:
    """Native replacement for the upstream RuleOverlap wrapper agent."""

    def run(self, detection_id: str, workspace: Path | None = None, **ctx: Any) -> dict[str, Any]:
        journals_dir = workspace_journals_dir(workspace, create=False)
        ws = journals_dir.parent

        # Same membership resolver as Similarity — the two agents disagreeing
        # about what the catalog holds is the bug this replaced. Entries with
        # no query are skipped here rather than absent: `classify_pair` needs
        # logic on both sides, so a journal-only draft is in the corpus and
        # simply not comparable.
        records: dict[str, dict] = {
            e.detection_id: e.record
            for e in build_corpus(ws)
            if e.record is not None and (e.record.get("query") or "")
        }
        target = records.get(detection_id)
        if target is None:
            raise NoCatalogRecordError(f"No catalog record found for {detection_id}")

        index_path = ws / "catalog" / "INDEX.yml"
        by_technique: dict[str, list[str]] = {}
        if index_path.exists():
            index = yaml.safe_load(index_path.read_text(encoding="utf-8")) or {}
            by_technique = {
                k: v for k, v in (index.get("by_technique") or {}).items() if isinstance(k, str)
            }

        # A candidate technique C matches a target technique T iff C == T, or
        # C's parent is T, or T's parent is C — so T1219.002 (Sigma) and T1219
        # (Splunk ESCU) meet, but sibling sub-techniques (T1219.001 vs
        # T1219.002) do not: pulling every sibling floods the comparison.
        by_parent: dict[str, set[str]] = {}
        for technique, ids in by_technique.items():
            parent = technique.split(".", 1)[0]
            if parent != technique:
                by_parent.setdefault(parent, set()).update(ids)
        cluster_ids: set[str] = set()
        techniques = record_mitre(target)
        for technique in techniques:
            cluster_ids.update(by_technique.get(technique, ()))
            parent = technique.split(".", 1)[0]
            if parent != technique:
                cluster_ids.update(by_technique.get(parent, ()))
            cluster_ids.update(by_parent.get(technique, ()))
        cluster_ids.discard(detection_id)

        overlaps = [
            classify_pair(target, records[other_id], detection_id, other_id)
            for other_id in sorted(cluster_ids)
            if other_id in records
        ]
        # Most-relevant-first for the journal reader. Display ordering only —
        # nothing is filtered or capped (that's a product call, not this
        # agent's); `other_id` breaks ties so the output stays deterministic.
        overlaps.sort(key=lambda o: (-o.confidence, o.other_id))

        return {
            "detection_id": detection_id,
            "techniques": techniques,
            "overlaps": [
                {
                    "other_id": o.other_id,
                    "overlap_type": o.overlap_type,
                    "confidence": round(o.confidence, 4),
                    "reasoning": o.reasoning,
                }
                for o in overlaps
            ],
        }


__all__ = ["RuleOverlapAgent", "Overlap", "classify_pair"]
