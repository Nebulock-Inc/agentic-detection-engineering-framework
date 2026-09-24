"""The corpus — every detection in a workspace, however it is represented.

A detection has up to two artifacts, stored separately and joined only by its
``D-XXXX`` id: a **journal** (``journals/D-XXXX.md``, append-only history) and
a **catalog record** (``catalog/<platform>/D-XXXX-<slug>.yml``, current state).
Either can be absent — ``detection new`` without ``--source`` writes a journal
and no record; a deleted journal leaves a record alone.

Before this module, ``RuleSimilarityAgent`` walked journals and
``RuleOverlapAgent`` walked the catalog, so the same Refine run could report a
rule as a 98% duplicate and as not existing. ``build_corpus`` is the single
membership answer both use.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from adef.core.corpus_text import record_search_text
from adef.core.journal import Journal, JournalEntry, narrative_text


@dataclass(frozen=True)
class CorpusEntry:
    """One detection, with whichever of its two artifacts exist."""

    detection_id: str
    record: Optional[dict] = None
    record_path: Optional[Path] = None
    journal: Optional[JournalEntry] = None

    @property
    def title(self) -> str:
        """Record wins: `sync` refreshes it from source, the journal's is set once."""
        if self.record:
            title = str(self.record.get("title") or "")
            if title:
                return title
        if self.journal is not None:
            return str(self.journal.frontmatter.get("title", "") or "")
        return ""

    @property
    def current_stage(self) -> str:
        """Journal wins: it owns the stage machine — `advance_stage` writes it."""
        if self.journal is not None:
            return self.journal.current_stage
        if self.record:
            return str(self.record.get("stage") or "find")
        return "find"

    @property
    def path(self) -> Path:
        """Whichever artifact exists. Never fabricated."""
        if self.journal is not None:
            return self.journal.path
        assert self.record_path is not None, "a CorpusEntry has at least one artifact"
        return self.record_path

    @property
    def index_text(self) -> str:
        """What retrieval scores: the record projection plus human journal prose.

        Both artifacts, working together. A human's Observe note is legitimate
        evidence for "does a rule like this already exist?" and can never feed
        back, because nothing automated writes it. Machine-generated blocks are
        already gone — `narrative_text` drops them by provenance.
        """
        parts = []
        if self.record:
            parts.append(record_search_text(self.record))
        if self.journal is not None:
            parts.append(narrative_text(self.journal.body))
        return "\n".join(p for p in parts if p)


def build_corpus(workspace: Path) -> list[CorpusEntry]:
    """Every detection in ``workspace`` — it exists if it has a record OR a journal.

    Exactly one entry per detection id, sorted by id. Creates nothing: a
    read path must not mkdir, and ``Catalog.__init__`` does (the same reason
    ``catalog.known_detection_ids`` exists).
    """
    from adef.core.catalog import Catalog, catalog_dir

    records: dict[str, tuple[Path, dict]] = {}
    if catalog_dir(workspace).is_dir():
        for det_id, path, data in Catalog(workspace).iter_records():
            # First one wins, and iter_records sorts by path, so a duplicate id
            # under two platform dirs resolves deterministically.
            records.setdefault(str(det_id), (path, data))

    journals: dict[str, JournalEntry] = {}
    journals_dir = workspace / "journals"
    if journals_dir.is_dir():
        for entry in Journal(journals_dir).iter_entries():
            journals.setdefault(entry.detection_id, entry)

    return [
        CorpusEntry(
            detection_id=det_id,
            record=records.get(det_id, (None, None))[1],
            record_path=records.get(det_id, (None, None))[0],
            journal=journals.get(det_id),
        )
        for det_id in sorted(set(records) | set(journals))
    ]


__all__ = ["CorpusEntry", "build_corpus"]
