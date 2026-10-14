"""Value retrieval — find rules in *other* languages that test the same literals.

BM25 compares words and the field pass compares field names, so a Sigma rule
and a CrowdStrike CQL rule for the same behaviour meet on neither: their
syntax shares no tokens, and without a declared schema their field names
(``Image`` vs ``ImageFileName``) don't line up either. What they do share is
the *values* they test — ``bitsadmin.exe``, ``EnableLUA``, ``mshta.exe``,
a remote-access tool's domain. In trials, agents built exactly this pass by
hand, and it found twins Similarity missed.

Each record is indexed by the distinctive value tokens of its logic (Sigma
``detection`` leaves; quoted strings, regex literals and unquoted comparison
operands elsewhere — never field names). Candidates are restricted to a
*different* query language: same-language value overlap is already BM25's
job, and letting it in would crowd the cross-language twin out of the
shortlist (the field pass's lesson, learned in a trial run). Tokens
present in more than a small share of the corpus (``cmd.exe``,
``powershell.exe``) carry no weight.

This is a recall signal for Similarity's shortlist, not an overlap verdict:
shared values say two rules look at the same thing, not that they select the
same events.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from adef.core.corpus import CorpusEntry
from adef.core.corpus_text import _sigma_doc, record_language
from adef.core.rule_discovery import _strip_sql_comments
from adef.core.rule_parser import mask_literals

# A token in more than this share of the corpus is too common to identify
# behaviour. Never below 2, so a pair can share a token in a tiny corpus.
_MAX_DF_SHARE = 0.05

_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')
_REGEX_LITERAL_RE = re.compile(r'(?<![\w)])/((?:[^/\\\n]|\\.)+)/[a-z]*')
# The operand of a comparison, unquoted: `Image=*\mshta.exe`, `EventCode=4688`.
# `:=` is an assignment, not a test, and is excluded.
# Range operands count too: a Sigma `EventID|gte: 4946` leaf is indexed, so
# leaving `EventID >= 4946` out would make the pass lopsided across languages.
_UNQUOTED_OPERAND_RE = re.compile(
    r'(?<![:!<>=])(?:==|!=|>=|<=|=|>|<)\s*([^\s|()"\',=<>/][^\s|()"\',]*)'
)
# An assignment's right-hand side (`x := "EnableLUA"`, up to the next pipe or
# line) names what the query computes, not what it tests. Matched against the
# query with quoted text blanked, so `CommandLine="x := mshta.exe"` (a tested
# value that merely contains `:=`) is left alone.
_ASSIGNMENT_RE = re.compile(r'[A-Za-z_][\w.]*\s*:=[^|\n]*')
# Members of an `IN (...)` list (`EventID IN (4946, 4948)`); quoted members
# are already caught by _QUOTED_RE, so only bare ones are taken here.
_IN_LIST_RE = re.compile(r'\bin~?\s*\(([^()]*)\)', re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]*[a-z0-9]")
_NOISE = frozenset({"true", "false", "null", "none"})
# `powershell.exe` in one language is `/powershell/i` in another: index the
# bare name of an executable-style token too.
_BINARY_SUFFIX_RE = re.compile(r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr|sh|py)$")


@dataclass(frozen=True)
class ValueHit:
    detection_id: str
    score: float
    shared_values: list[str]


def _sigma_values(node: Any, out: list[str]) -> None:
    if isinstance(node, dict):
        for value in node.values():
            _sigma_values(value, out)
    elif isinstance(node, list):
        for value in node:
            _sigma_values(value, out)
    elif node is not None and not isinstance(node, bool):
        out.append(str(node))


def _strip_comments(query: str, language: str) -> str:
    if language == "sql":
        return _strip_sql_comments(query)
    return mask_literals(query, language, strings=False)


def _raw_values(record: dict) -> list[str]:
    doc = _sigma_doc(record)
    if doc is not None:
        detection = doc.get("detection")
        out: list[str] = []
        if isinstance(detection, dict):
            for name, block in detection.items():
                if name != "condition":
                    _sigma_values(block, out)
        return out
    # Comments say nothing about what a rule tests: `// Image="mshta.exe"` in
    # a CQL rule that doesn't test mshta.exe must not become a value.
    query = _strip_comments(str(record.get("query") or ""), record_language(record))
    masked = _QUOTED_RE.sub(lambda m: " " * len(m.group(0)), query)
    for m in reversed(list(_ASSIGNMENT_RE.finditer(masked))):
        query = query[:m.start()] + " " * (m.end() - m.start()) + query[m.end():]
    out = [a or b for a, b in _QUOTED_RE.findall(query)]
    out += _REGEX_LITERAL_RE.findall(query)
    unquoted = _QUOTED_RE.sub(" ", query)
    out += _UNQUOTED_OPERAND_RE.findall(unquoted)
    for members in _IN_LIST_RE.findall(unquoted):
        out += [m.strip() for m in members.split(",") if m.strip()]
    return out


def value_tokens(record: dict) -> frozenset[str]:
    """Lowercased value tokens of a record's logic: path segments, file names,
    domains, flags — split on separators, wildcards and regex syntax."""
    tokens: set[str] = set()
    for raw in _raw_values(record):
        # `\.` is a regex-escaped dot (`/mshta\.exe/`): keep `mshta.exe` whole.
        text = raw.lower().replace("\\\\", "\\").replace("\\.", ".")
        for tok in _TOKEN_RE.findall(text):
            if len(tok) >= 3 and tok not in _NOISE:
                tokens.add(tok)
                stem = _BINARY_SUFFIX_RE.sub("", tok)
                if stem != tok and len(stem) >= 3:
                    tokens.add(stem)
    return frozenset(tokens)


class ValueIndex:
    def __init__(self, tokens: dict[str, frozenset[str]], languages: dict[str, str]) -> None:
        self._tokens = tokens
        self._languages = languages
        n = len(tokens)
        df: Counter[str] = Counter()
        for toks in tokens.values():
            df.update(toks)
        max_df = max(2, math.ceil(_MAX_DF_SHARE * n))
        self._idf = {t: math.log(1 + n / c) for t, c in df.items() if c <= max_df}

    def candidates(self, detection_id: str, top_k: int) -> list[ValueHit]:
        """Other-language records sharing distinctive values with the target,
        scored by the share of the target's distinctive weight they cover."""
        target = {t for t in self._tokens.get(detection_id, ()) if t in self._idf}
        lang = self._languages.get(detection_id, "")
        if not target or not lang:
            return []
        total = sum(self._idf[t] for t in target)
        hits: list[ValueHit] = []
        for other_id, other in self._tokens.items():
            other_lang = self._languages.get(other_id, "")
            if other_id == detection_id or not other_lang or other_lang == lang:
                continue
            shared = target & other
            if shared:
                hits.append(ValueHit(
                    other_id,
                    sum(self._idf[t] for t in shared) / total,
                    sorted(shared, key=lambda t: (-self._idf[t], t)),
                ))
        hits.sort(key=lambda h: (-h.score, h.detection_id))
        return hits[:top_k]


def build_value_index(corpus: Iterable[CorpusEntry]) -> ValueIndex:
    tokens: dict[str, frozenset[str]] = {}
    languages: dict[str, str] = {}
    for entry in corpus:
        if entry.record is None or not entry.record.get("query"):
            continue
        tokens.setdefault(entry.detection_id, value_tokens(entry.record))
        languages.setdefault(entry.detection_id, record_language(entry.record))
    return ValueIndex(tokens, languages)


__all__ = ["ValueHit", "ValueIndex", "build_value_index", "value_tokens"]
