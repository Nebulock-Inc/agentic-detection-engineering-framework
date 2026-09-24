# tests/test_memory_corpus.py
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.corpus import build_corpus
from adef.core.journal import Journal
from adef.core.memory import MemoryIndex


def _rec(rid: str, title: str, query: str) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"],
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat, journal = Catalog(w), Journal(w / "journals")
    r = _rec("D-0001", "mshta child process", "process.name = 'mshta.exe'")
    cat.write_raw(w / "catalog" / "D-0001.yml", r.to_yaml_dict())
    journal.create(detection_id="D-0001", title=r.title)
    cat.rebuild_index()
    return w


def _search(ws: Path, q: str):
    index = MemoryIndex()
    index.build(build_corpus(ws))
    return index.search(q, limit=10)


def test_a_record_only_detection_is_searchable(ws: Path):
    # The headline bug: catalogued, journal missing, invisible to retrieval.
    cat = Catalog(ws)
    cat.write_raw(
        ws / "catalog" / "D-0002.yml",
        _rec("D-0002", "rundll32 abuse", "process.name = 'RUNDLLMARKER'").to_yaml_dict(),
    )
    cat.rebuild_index()
    assert "D-0002" in [h.detection_id for h in _search(ws, "RUNDLLMARKER")]


def test_a_record_only_hit_reports_the_record_path(ws: Path):
    cat = Catalog(ws)
    cat.write_raw(
        ws / "catalog" / "D-0002.yml",
        _rec("D-0002", "rundll32 abuse", "process.name = 'RUNDLLMARKER'").to_yaml_dict(),
    )
    cat.rebuild_index()
    hit = next(h for h in _search(ws, "RUNDLLMARKER") if h.detection_id == "D-0002")
    # Path comparisons must resolve both sides: `catalog_dir()` calls
    # `.expanduser().resolve()` while `tmp_path` may not be resolved, and on
    # macOS `/tmp` symlinks to `/private/tmp`.
    assert hit.path.resolve() == (ws / "catalog" / "D-0002.yml").resolve()
    assert hit.current_stage == "find"


def test_human_journal_prose_is_indexed(ws: Path):
    Journal(ws / "journals").advance_stage(
        detection_id="D-0001", stage="observe", note="HUMANBASELINE three per day"
    )
    assert "D-0001" in [h.detection_id for h in _search(ws, "HUMANBASELINE")]


def test_a_generated_block_earns_no_score(ws: Path):
    # The feedback loop, asserted end-to-end against the real pipeline.
    Journal(ws / "journals").append_block(
        "D-0001", "Refine / Similarity", "- **candidates:** MACHINEONLYTOKEN", generated=True
    )
    assert _search(ws, "MACHINEONLYTOKEN") == []


def test_a_legacy_unmarked_refine_block_earns_no_score(ws: Path):
    Journal(ws / "journals").append_block(
        "D-0001", "Refine / Overlap", "- **overlaps:** LEGACYONLYTOKEN"
    )
    assert _search(ws, "LEGACYONLYTOKEN") == []


def test_an_unadvanced_journal_does_not_break_scoring(ws: Path):
    # Review Focus 4: template-only journal, no record → zero-length document.
    Journal(ws / "journals").create(detection_id="D-0009", title="bare draft")
    hits = _search(ws, "mshta")            # must not raise ZeroDivisionError
    assert "D-0001" in [h.detection_id for h in hits]
