"""``MemoryIndex`` — read-only BM25 index over journal markdown.

Builds a small in-memory inverted index across every ``D-XXXX.md`` file in a
journals directory. Search returns ranked entries with the matched stage block
truncated to a snippet so the caller (CLI, MCP, agent) can reason about prior
detection work without re-reading every journal.

The implementation is deliberately self-contained: no external BM25 dependency
(``rank_bm25`` etc.). v0.1.0 prefers zero added install surface; we can swap
later if corpora grow large enough to matter.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from adef.core.journal import Journal, JournalEntry


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_BM25_K1 = 1.5
_BM25_B = 0.75


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text)]


# The first timestamped stage block marks the end of the static template
# preamble — everything before it is fill-in scaffolding, not reasoning.
_STAGE_BLOCK_RE = re.compile(r"^## \[.+?\] Stage:", re.MULTILINE)


def _clean_for_snippet(text: str) -> str:
    """Drop journal chrome so a snippet shows matched reasoning, not scaffolding:
    the static-template preamble (up to the first ``## [ts] Stage:`` block), stage
    headings, blockquotes, the echoed title, and 'Catalogued from…' housekeeping.
    """
    m = _STAGE_BLOCK_RE.search(text)
    if m:
        text = text[m.start():]  # keep only the real stage blocks (+ appended record text)
    keep: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(">"):  # stage headings / blockquote
            continue
        if line.startswith("**Title:**"):                 # the echoed title
            continue
        if "Catalogued from" in line and "adef" in line:   # housekeeping note
            continue
        keep.append(line)
    return "\n".join(keep)


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
    entry: JournalEntry
    tokens: list[str]
    text: str = ""  # the searchable text (journal body + any extra record text)
    tf: Counter = field(default_factory=Counter)
    length: int = 0


class MemoryIndex:
    """BM25 index over journal markdown bodies.

    The index is built lazily on first ``search``; callers can pass an explicit
    iterable of entries to skip filesystem traversal (used by tests).
    """

    def __init__(self, journals_dir: Optional[Path] = None) -> None:
        self._journals_dir = journals_dir
        self._docs: list[_Doc] = []
        self._df: Counter[str] = Counter()
        self._avgdl: float = 0.0
        self._built = False

    def _iter_source_entries(self) -> Iterable[JournalEntry]:
        if self._journals_dir is None:
            return iter(())
        return Journal(self._journals_dir).iter_entries()

    def build(
        self,
        entries: Optional[Iterable[JournalEntry]] = None,
        extra_text_for: Optional["Callable[[JournalEntry], str]"] = None,
    ) -> None:
        """Build the index over journal bodies.

        ``extra_text_for(entry) -> str`` (optional) supplies extra searchable
        text per detection — the catalog record's title/mitre/platform/query —
        so a detection is findable by *what it detects*, not only what its
        journal says. The command layer fills this from the catalog (keeping
        this module decoupled from ``Catalog``).
        """
        source = list(entries) if entries is not None else list(self._iter_source_entries())
        self._docs = []
        self._df = Counter()
        total_len = 0
        for entry in source:
            text = entry.body
            if extra_text_for is not None:
                extra = extra_text_for(entry)
                if extra:
                    text = f"{text}\n{extra}"
            tokens = _tokenize(text)
            tf = Counter(tokens)
            doc = _Doc(entry=entry, tokens=tokens, text=text, tf=tf, length=len(tokens))
            for term in tf:
                self._df[term] += 1
            total_len += doc.length
            self._docs.append(doc)
        self._avgdl = (total_len / len(self._docs)) if self._docs else 0.0
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

    def _snippet(self, body: str, query_terms: list[str], width: int = 240) -> str:
        # Snippet from a *cleaned* view: drop the empty template scaffolding
        # (unfilled `- **Field:**` lines, the `## Stage` headers, the blockquote
        # header) and housekeeping ("Catalogued from…") so the snippet shows the
        # actual matched reasoning, not boilerplate. (ISA 2026-07-22.)
        text = _clean_for_snippet(body)
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
            self.build()
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
                    title=entry.frontmatter.get("title", ""),
                    current_stage=entry.current_stage,
                    snippet=self._snippet(doc.text or entry.body, query_terms),
                    path=entry.path,
                )
            )
        return out


__all__ = ["MemoryIndex", "SearchHit"]
