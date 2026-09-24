"""``MemoryIndex`` — read-only BM25 index over the workspace corpus.

Builds a small in-memory inverted index over ``CorpusEntry`` objects (see
``adef.core.corpus``) and scores each entry's ``index_text``. Search returns
ranked entries with a snippet so the caller (CLI, MCP, agent) can reason about
prior detection work without re-reading every journal or catalog record.

The implementation is deliberately self-contained: no external BM25 dependency
(``rank_bm25`` etc.). v0.1.0 prefers zero added install surface; we can swap
later if corpora grow large enough to matter.

This module no longer reads the filesystem or knows what a journal block is:
membership (which detections exist, and from which artifacts) belongs to
``adef.core.corpus``, and block/provenance structure belongs to
``adef.core.journal``.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from adef.core.corpus import CorpusEntry


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_BM25_K1 = 1.5
_BM25_B = 0.75


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text)]


@dataclass
class SearchHit:
    """A single ranked search result."""

    detection_id: str
    score: float
    title: str
    current_stage: str
    snippet: str
    path: Path


@dataclass
class _Doc:
    entry: "CorpusEntry"
    tokens: list[str]
    text: str = ""
    tf: Counter = field(default_factory=Counter)
    length: int = 0


class MemoryIndex:
    """BM25 index over the workspace corpus.

    Takes ``CorpusEntry`` objects and scores ``entry.index_text``. It no longer
    reads the filesystem or knows what a journal block is: membership belongs to
    ``adef.core.corpus`` and block structure to ``adef.core.journal``.
    """

    def __init__(self) -> None:
        self._docs: list[_Doc] = []
        self._df: Counter[str] = Counter()
        self._avgdl: float = 0.0
        self._built = False

    def build(self, entries: Iterable["CorpusEntry"]) -> None:
        """Build the index over a corpus."""
        self._docs = []
        self._df = Counter()
        total_len = 0
        for entry in entries:
            text = entry.index_text
            tokens = _tokenize(text)
            tf = Counter(tokens)
            doc = _Doc(entry=entry, tokens=tokens, text=text, tf=tf, length=len(tokens))
            for term in tf:
                self._df[term] += 1
            total_len += doc.length
            self._docs.append(doc)
        # Empty documents (a template-only journal with no record) must not
        # divide by zero or drag `avgdl` toward zero and inflate every score.
        scored = [d for d in self._docs if d.length > 0]
        self._avgdl = (total_len / len(scored)) if scored else 0.0
        self._built = True

    def _idf(self, term: str) -> float:
        n = len(self._docs)
        df = self._df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log(1 + (n - df + 0.5) / (df + 0.5))

    def _score(self, doc: _Doc, query_terms: list[str]) -> float:
        if doc.length == 0 or self._avgdl == 0:
            return 0.0
        score = 0.0
        for term in query_terms:
            f = doc.tf.get(term, 0)
            if f == 0:
                continue
            idf = self._idf(term)
            denom = f + _BM25_K1 * (1 - _BM25_B + _BM25_B * doc.length / self._avgdl)
            score += idf * (f * (_BM25_K1 + 1)) / denom
        return score

    def _snippet(self, text: str, query_terms: list[str], width: int = 240) -> str:
        # `text` is already `CorpusEntry.index_text`: template scaffolding,
        # machine-generated blocks, and housekeeping are gone before it gets
        # here, so no second cleaning pass is needed.
        if not query_terms:
            return text[:width].strip().replace("\n", " ")
        lowered = text.lower()
        for term in query_terms:
            idx = lowered.find(term)
            if idx >= 0:
                start = max(0, idx - width // 2)
                end = min(len(text), start + width)
                snippet = text[start:end].strip().replace("\n", " ")
                return ("…" if start > 0 else "") + snippet + ("…" if end < len(text) else "")
        return text[:width].strip().replace("\n", " ")

    def search(self, query: str, limit: int = 10) -> list[SearchHit]:
        """Return up to ``limit`` ranked hits for ``query``."""
        if not self._built:
            self.build([])
        query_terms = _tokenize(query)
        if not query_terms or not self._docs:
            return []
        scored: list[tuple[float, _Doc]] = []
        for doc in self._docs:
            s = self._score(doc, query_terms)
            if s > 0:
                scored.append((s, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        out: list[SearchHit] = []
        for score, doc in scored[:limit]:
            entry = doc.entry
            out.append(
                SearchHit(
                    detection_id=entry.detection_id,
                    score=round(score, 4),
                    title=entry.title,
                    current_stage=entry.current_stage,
                    snippet=self._snippet(doc.text, query_terms),
                    path=entry.path,
                )
            )
        return out


__all__ = ["MemoryIndex", "SearchHit"]
