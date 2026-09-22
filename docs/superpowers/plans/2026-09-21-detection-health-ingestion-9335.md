# Detection Health Capture — Ingestion and Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a producer hand ADEF a file describing what its catalogued detections are doing in a live environment, and have ADEF validate, route, and store it — without ADEF ever contacting that environment.

**Architecture:** Five versioned, self-describing document kinds are parsed and validated by a pure core module (`adef/core/health_docs.py`), then written by a second pure module (`adef/core/health_store.py`) into `<workspace>/health/` as a latest-snapshot-per-kind plus an append-only JSON Lines history. A thin Click command (`adef ingest`) and an MCP tool sit on top, both calling the same core functions. No analysis in this plan — trend, drift comparison, and the Evolve chain are story 10097.

**Tech Stack:** Python 3.10+, Click, PyYAML, `dataclasses`, stdlib `json`. No new runtime dependencies.

**Spec:** `internal-docs/plans/2026-09-21-vendor-capture-design.md`

## Global Constraints

- **No vendor API connectors anywhere in `adef/`.** CI-enforced by `tests/test_no_vendor_connectors.py`. Every input in this plan is a file the user supplies.
- **No write path may contain `detections/`.** CI-enforced by `tests/test_schema_parity.py`. Write only under `<workspace>/health/`.
- **Four engines only** (`sigma`, `sql`, `sch_sql`, `composite`). CI-enforced by `tests/test_no_new_engine_types.py`. Not touched by this plan.
- **No web-UI dependencies.** CI-enforced by `tests/test_no_web_ui_deps.py`.
- **`schema_version: 1`** is present and validated on every document from day one.
- **Metrics are counts, never ratios** — `signal_count`, `true_positive_count`, `false_positive_count`, `unlabeled_count`. A ratio cannot be re-aggregated across windows.
- **`last_true_positive_at` is an absolute timestamp**, never a stored `days_since_true_positive`.
- **`window` is required** for `metrics`, `performance`, `field_observations`, `source_health`; it is a **validation error** on `deployment_drift` (point-in-time), not silently ignored.
- **Unmatched `detection_id`s are reported, never silently dropped** — the infer-and-flag principle the catalog already follows.
- **Standalone-first.** No private or in-house codebase is a reference corpus, a justification, or an interface shape. See `CLAUDE.md` → "Direction of Integration".
- Python 3.10+ syntax. `from __future__ import annotations` at the top of every new module, matching every existing `adef/core/` module.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `adef/core/health_docs.py` | new | The five document kinds: dataclass, lint, load. Pure — no I/O beyond reading the given path, no catalog knowledge. Mirrors `adef/core/declaration.py`. |
| `adef/core/health_store.py` | new | Storage only: merge into `latest/`, append to `history/`, write `sources/`. Pure — takes a parsed doc plus a set of known IDs, returns a result object. |
| `adef/commands/ingest.py` | new | Thin Click command. Resolves the workspace, reads known IDs from the catalog, calls the two core modules, renders the report. |
| `adef/mcp/tools/health_tools.py` | new | `health_ingest` MCP tool over the same core functions. |
| `adef/mcp/register.py` | modify | Register the new tool module. |
| `pyproject.toml` | modify | `adef.commands` entry point for `ingest`. |
| `docs/cli-reference.md` | modify | Canonical per-command reference — every command must appear here. |
| `CLAUDE.md` | modify | Commands section + package structure tree. |
| `tests/test_health_docs.py` | new | Validation matrix per kind. |
| `tests/test_health_store.py` | new | Latest merge, history append, unmatched reporting. |
| `tests/test_ingest_command.py` | new | CLI routing, `--dry-run`, exit codes, output. |

`health_docs` and `health_store` are separate because they fail differently and are reviewed differently: one is a validation matrix, the other is filesystem behavior. Story 10097 adds `adef/core/health.py` (analysis) as a third peer; keeping parsing and storage apart now means that module has clean inputs to consume.

---

## Task 1: Document model, lint, and load

**Files:**
- Create: `adef/core/health_docs.py`
- Test: `tests/test_health_docs.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `SCHEMA_VERSION: int = 1`
  - `KINDS: frozenset[str]` — `{"metrics", "performance", "deployment_drift", "field_observations", "source_health"}`
  - `WINDOWED_KINDS: frozenset[str]` — every kind except `deployment_drift`
  - `class HealthDocError(ValueError)`
  - `@dataclass HealthDoc` with fields `kind: str`, `schema_version: int`, `captured_at: str`, `environment: str`, `window: dict[str, str] | None`, `detections: list[dict]`, `sources: list[dict]`, `source: str`, `fields: list[dict]`
  - `lint_health_doc(data: dict) -> list[str]` — returns error strings, never raises
  - `load_health_doc(path: Path) -> HealthDoc` — raises `HealthDocError` on any lint error

- [ ] **Step 1: Write the failing tests**

Create `tests/test_health_docs.py`:

```python
"""Tests for detection-health capture documents (adef/core/health_docs.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.health_docs import (
    KINDS,
    SCHEMA_VERSION,
    HealthDocError,
    lint_health_doc,
    load_health_doc,
)


def _metrics_doc() -> dict:
    return {
        "schema_version": 1,
        "kind": "metrics",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "detections": [
            {
                "detection_id": "D-0042",
                "signal_count": 143,
                "true_positive_count": 4,
                "false_positive_count": 131,
                "unlabeled_count": 8,
                "last_true_positive_at": "2026-08-30T11:04:00Z",
            }
        ],
    }


def _drift_doc() -> dict:
    return {
        "schema_version": 1,
        "kind": "deployment_drift",
        "captured_at": "2026-09-21T14:00:00Z",
        "environment": "prod-siem",
        "detections": [{"detection_id": "D-0042", "deployed_status": "enabled"}],
    }


def test_valid_metrics_doc_lints_clean():
    assert lint_health_doc(_metrics_doc()) == []


def test_the_five_kinds_are_the_closed_set():
    assert KINDS == {
        "metrics",
        "performance",
        "deployment_drift",
        "field_observations",
        "source_health",
    }


def test_unknown_kind_is_an_error():
    doc = _metrics_doc()
    doc["kind"] = "made_up"
    errors = lint_health_doc(doc)
    assert any("kind" in e and "made_up" in e for e in errors)


def test_wrong_schema_version_is_an_error():
    doc = _metrics_doc()
    doc["schema_version"] = 2
    errors = lint_health_doc(doc)
    assert any("schema_version" in e for e in errors)


def test_window_required_for_windowed_kinds():
    doc = _metrics_doc()
    del doc["window"]
    errors = lint_health_doc(doc)
    assert any("window" in e and "required" in e for e in errors)


def test_window_forbidden_on_deployment_drift():
    # Point-in-time: captured_at is the whole of its temporal meaning. A window
    # here means the producer misunderstood the format — say so, don't ignore it.
    doc = _drift_doc()
    doc["window"] = {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"}
    errors = lint_health_doc(doc)
    assert any("window" in e and "deployment_drift" in e for e in errors)


def test_deployment_drift_without_window_lints_clean():
    assert lint_health_doc(_drift_doc()) == []


def test_missing_captured_at_is_an_error():
    doc = _metrics_doc()
    del doc["captured_at"]
    errors = lint_health_doc(doc)
    assert any("captured_at" in e for e in errors)


def test_detection_row_without_id_is_an_error():
    doc = _metrics_doc()
    del doc["detections"][0]["detection_id"]
    errors = lint_health_doc(doc)
    assert any("detection_id" in e for e in errors)


def test_empty_detections_is_an_error():
    doc = _metrics_doc()
    doc["detections"] = []
    errors = lint_health_doc(doc)
    assert any("detections" in e for e in errors)


def test_unknown_top_level_key_is_an_error():
    doc = _metrics_doc()
    doc["enviroment"] = "typo-prod"          # realistic misspelling
    errors = lint_health_doc(doc)
    assert any("enviroment" in e for e in errors)


def test_source_health_requires_named_sources():
    doc = {
        "schema_version": 1,
        "kind": "source_health",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "sources": [{"event_count": 240000000}],   # no name
    }
    errors = lint_health_doc(doc)
    assert any("name" in e for e in errors)


def test_field_observations_requires_source_and_fields():
    doc = {
        "schema_version": 1,
        "kind": "field_observations",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "fields": [{"name": "process.name", "null_rate": 0.02}],
    }
    errors = lint_health_doc(doc)
    assert any("source" in e for e in errors)


def test_load_returns_typed_doc(tmp_path: Path):
    path = tmp_path / "metrics.yml"
    path.write_text(yaml.safe_dump(_metrics_doc()), encoding="utf-8")
    doc = load_health_doc(path)
    assert doc.kind == "metrics"
    assert doc.schema_version == SCHEMA_VERSION
    assert doc.environment == "prod-siem"
    assert doc.detections[0]["detection_id"] == "D-0042"
    assert doc.window is not None


def test_load_raises_on_invalid_doc(tmp_path: Path):
    doc = _metrics_doc()
    doc["kind"] = "made_up"
    path = tmp_path / "bad.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(HealthDocError, match="made_up"):
        load_health_doc(path)


def test_load_raises_on_unparseable_yaml(tmp_path: Path):
    path = tmp_path / "broken.yml"
    path.write_text("kind: [unclosed\n", encoding="utf-8")
    with pytest.raises(HealthDocError):
        load_health_doc(path)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_health_docs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'adef.core.health_docs'`

- [ ] **Step 3: Write the implementation**

Create `adef/core/health_docs.py`:

```python
"""Detection-health capture documents — the producer-side contract.

A producer (a person, a scheduled job, or an assistant session with its own
tooling) describes what catalogued detections are doing in a live environment
and hands ADEF the file. ADEF never queries that environment; see the
no-vendor-connector anti-goal.

Documents are self-describing: each declares its own ``kind`` and
``schema_version``, so ingestion routes on content rather than on a CLI flag a
producer could mismatch against the file they are passing.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1

KINDS = frozenset(
    {"metrics", "performance", "deployment_drift", "field_observations", "source_health"}
)

#: Kinds whose numbers are counts over an interval. A count without a
#: denominator is uninterpretable, and trend comparison needs comparable spans.
#: ``deployment_drift`` is excluded: it is a point-in-time observation, so
#: ``captured_at`` carries all of its temporal meaning.
WINDOWED_KINDS = KINDS - {"deployment_drift"}

#: Kinds whose rows are keyed by an ADEF detection ID.
DETECTION_KEYED_KINDS = frozenset({"metrics", "performance", "deployment_drift"})

_COMMON_KEYS = {"schema_version", "kind", "captured_at", "window", "environment"}
_KEYS_BY_KIND = {
    "metrics": _COMMON_KEYS | {"detections"},
    "performance": _COMMON_KEYS | {"detections"},
    "deployment_drift": _COMMON_KEYS | {"detections"},
    "field_observations": _COMMON_KEYS | {"source", "fields"},
    "source_health": _COMMON_KEYS | {"sources"},
}


class HealthDocError(ValueError):
    """Raised when a capture document cannot be read or fails validation."""


@dataclass
class HealthDoc:
    """A parsed, validated capture document."""

    kind: str
    schema_version: int
    captured_at: str
    environment: str
    window: dict[str, str] | None = None
    detections: list[dict] = dataclass_field(default_factory=list)
    sources: list[dict] = dataclass_field(default_factory=list)
    source: str = ""
    fields: list[dict] = dataclass_field(default_factory=list)


def _lint_rows(rows: Any, where: str, id_key: str, errors: list[str]) -> None:
    """Every row must be a mapping carrying a non-empty ``id_key``.

    Row *contents* are deliberately not whitelisted: a producer may carry extra
    context alongside the documented fields, and storage preserves it verbatim.
    Only the key that makes a row addressable is required here. Do not tighten
    this into a per-kind field whitelist — the analysis in story 10097 reads the
    specific keys it needs and ignores the rest.
    """
    if not isinstance(rows, list) or not rows:
        errors.append(f"{where}: required non-empty list")
        return
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"{where}[{i}]: must be a mapping")
            continue
        value = row.get(id_key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{where}[{i}].{id_key}: required non-empty string")


def lint_health_doc(data: Any) -> list[str]:
    """Return a list of validation errors for ``data``. Never raises."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["document: must be a mapping"]

    kind = data.get("kind")
    if kind not in KINDS:
        errors.append(f"kind: {kind!r} not one of {', '.join(sorted(KINDS))}")
        return errors  # every remaining rule is kind-dependent

    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        errors.append(f"schema_version: expected {SCHEMA_VERSION}, got {version!r}")

    captured_at = data.get("captured_at")
    if not isinstance(captured_at, str) or not captured_at.strip():
        errors.append("captured_at: required non-empty string (ISO-8601)")

    unknown = set(data) - _KEYS_BY_KIND[kind]
    if unknown:
        errors.append(f"unknown keys for kind {kind!r}: {', '.join(sorted(unknown))}")

    window = data.get("window")
    if kind in WINDOWED_KINDS:
        if not isinstance(window, dict) or not window.get("start") or not window.get("end"):
            errors.append(
                f"window: required for kind {kind!r} with 'start' and 'end' "
                "(a count without a denominator cannot be interpreted)"
            )
    elif window is not None:
        errors.append(
            f"window: not allowed on kind {kind!r} — it is a point-in-time "
            "observation, so captured_at carries its temporal meaning"
        )

    if kind in DETECTION_KEYED_KINDS:
        _lint_rows(data.get("detections"), "detections", "detection_id", errors)
    elif kind == "source_health":
        _lint_rows(data.get("sources"), "sources", "name", errors)
    else:  # field_observations
        source = data.get("source")
        if not isinstance(source, str) or not source.strip():
            errors.append("source: required non-empty string")
        _lint_rows(data.get("fields"), "fields", "name", errors)

    return errors


def load_health_doc(path: Path) -> HealthDoc:
    """Parse and validate the capture document at ``path``."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        raise HealthDocError(f"{path}: could not be read as YAML ({exc})") from exc

    errors = lint_health_doc(data)
    if errors:
        raise HealthDocError(f"{path}: " + "; ".join(errors))

    return HealthDoc(
        kind=str(data["kind"]),
        schema_version=int(data["schema_version"]),
        captured_at=str(data["captured_at"]),
        environment=str(data.get("environment", "")),
        window=data.get("window"),
        detections=list(data.get("detections", [])),
        sources=list(data.get("sources", [])),
        source=str(data.get("source", "")),
        fields=list(data.get("fields", [])),
    )


__all__ = [
    "SCHEMA_VERSION",
    "KINDS",
    "WINDOWED_KINDS",
    "DETECTION_KEYED_KINDS",
    "HealthDoc",
    "HealthDocError",
    "lint_health_doc",
    "load_health_doc",
]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_health_docs.py -v`
Expected: PASS — 16 tests

- [ ] **Step 5: Run the full suite and the linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass, no regressions

- [ ] **Step 6: Commit**

```bash
git add adef/core/health_docs.py tests/test_health_docs.py
git commit -m "feat(health): capture document model, lint, and load"
```

---

## Task 2: Storage — latest snapshot and append-only history

**Files:**
- Create: `adef/core/health_store.py`
- Test: `tests/test_health_store.py`

**Interfaces:**
- Consumes: `HealthDoc`, `DETECTION_KEYED_KINDS` from `adef.core.health_docs`
- Produces:
  - `@dataclass IngestResult` with fields `kind: str`, `matched: list[str]`, `unmatched: list[str]`, `paths_written: list[Path]`
  - `health_dir(workspace: Path | None) -> Path` — `<workspace>/health`
  - `store_health_doc(doc: HealthDoc, health_root: Path, known_ids: set[str], dry_run: bool = False) -> IngestResult`

`known_ids` is passed in rather than read from the catalog inside this module, so storage stays pure and testable without building a catalog fixture. The command layer supplies it.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_health_store.py`:

```python
"""Tests for detection-health storage (adef/core/health_store.py)."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from adef.core.health_docs import HealthDoc
from adef.core.health_store import health_dir, store_health_doc


def _metrics(captured_at: str = "2026-09-21T14:00:00Z", signal_count: int = 143) -> HealthDoc:
    return HealthDoc(
        kind="metrics",
        schema_version=1,
        captured_at=captured_at,
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        detections=[{"detection_id": "D-0042", "signal_count": signal_count}],
    )


def test_health_dir_is_under_the_workspace(tmp_path: Path):
    assert health_dir(tmp_path) == tmp_path / "health"


def test_writes_latest_snapshot_keyed_by_kind(tmp_path: Path):
    root = tmp_path / "health"
    result = store_health_doc(_metrics(), root, known_ids={"D-0042"})
    stored = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert stored["metrics"]["signal_count"] == 143
    assert stored["metrics"]["captured_at"] == "2026-09-21T14:00:00Z"
    assert stored["metrics"]["environment"] == "prod-siem"
    assert result.matched == ["D-0042"]
    assert result.unmatched == []


def test_second_ingest_replaces_latest_but_appends_history(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_metrics(signal_count=143), root, known_ids={"D-0042"})
    store_health_doc(
        _metrics(captured_at="2026-09-28T14:00:00Z", signal_count=7),
        root,
        known_ids={"D-0042"},
    )

    stored = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert stored["metrics"]["signal_count"] == 7      # latest wins

    lines = (root / "history" / "D-0042.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2                              # history keeps both
    assert [json.loads(line)["signal_count"] for line in lines] == [143, 7]
    assert json.loads(lines[0])["kind"] == "metrics"


def test_a_second_kind_merges_into_the_same_latest_file(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_metrics(), root, known_ids={"D-0042"})
    perf = HealthDoc(
        kind="performance",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        detections=[{"detection_id": "D-0042", "avg_runtime_seconds": 12.4}],
    )
    store_health_doc(perf, root, known_ids={"D-0042"})

    stored = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert stored["metrics"]["signal_count"] == 143     # not clobbered
    assert stored["performance"]["avg_runtime_seconds"] == 12.4


def test_unmatched_detection_ids_are_reported_not_dropped(tmp_path: Path):
    root = tmp_path / "health"
    doc = _metrics()
    doc.detections.append({"detection_id": "D-9999", "signal_count": 1})
    result = store_health_doc(doc, root, known_ids={"D-0042"})

    assert result.matched == ["D-0042"]
    assert result.unmatched == ["D-9999"]
    assert not (root / "latest" / "D-9999.yml").exists()


def test_dry_run_writes_nothing_but_still_reports(tmp_path: Path):
    root = tmp_path / "health"
    result = store_health_doc(_metrics(), root, known_ids={"D-0042"}, dry_run=True)
    assert result.matched == ["D-0042"]
    assert result.paths_written == []
    assert not root.exists()


def test_source_health_is_stored_by_source_name(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="source_health",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        sources=[{"name": "wineventlog", "event_count": 240000000}],
    )
    result = store_health_doc(doc, root, known_ids=set())

    stored = yaml.safe_load(
        (root / "sources" / "wineventlog.yml").read_text(encoding="utf-8")
    )
    assert stored["event_count"] == 240000000
    assert result.matched == ["wineventlog"]
    assert result.unmatched == []       # source names are not checked against the catalog


def test_field_observations_are_stored_by_source_name(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="field_observations",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        source="wineventlog",
        fields=[{"name": "process.name", "null_rate": 0.02}],
    )
    store_health_doc(doc, root, known_ids=set())
    stored = yaml.safe_load(
        (root / "sources" / "wineventlog.yml").read_text(encoding="utf-8")
    )
    assert stored["fields"][0]["name"] == "process.name"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_health_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'adef.core.health_store'`

- [ ] **Step 3: Write the implementation**

Create `adef/core/health_store.py`:

```python
"""Storage for detection-health capture documents.

Hybrid by design: ``latest/`` answers "what is true now" in a single read,
``history/`` is the append-only substrate the trend analysis in story 10097
consumes. History rows are the document's own per-detection rows plus a
timestamp and kind — small, so growth is bounded by ingest cadence rather than
by document size.

Pure: ``known_ids`` is supplied by the caller rather than read from the catalog
here, so this module is testable without building a catalog fixture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path

import yaml

from adef.core.health_docs import DETECTION_KEYED_KINDS, HealthDoc
from adef.core.workspace import resolve_workspace


@dataclass
class IngestResult:
    """What one ``store_health_doc`` call did."""

    kind: str
    matched: list[str] = dataclass_field(default_factory=list)
    unmatched: list[str] = dataclass_field(default_factory=list)
    paths_written: list[Path] = dataclass_field(default_factory=list)


def health_dir(workspace: Path | None = None) -> Path:
    """Workspace health dir via the canonical resolver (honors --workspace, env,
    cwd, default), matching ``_get_workspace_schema_dir``'s behavior."""
    return resolve_workspace(workspace) / "health"


def _merge_latest(path: Path, kind: str, payload: dict) -> None:
    """Replace this kind's entry in ``path``, leaving other kinds intact."""
    existing: dict = {}
    if path.exists():
        existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    existing[kind] = payload
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(existing, sort_keys=True), encoding="utf-8")


def _append_history(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def store_health_doc(
    doc: HealthDoc,
    health_root: Path,
    known_ids: set[str],
    dry_run: bool = False,
) -> IngestResult:
    """Write ``doc`` under ``health_root``; report matched and unmatched keys.

    Rows whose ``detection_id`` is absent from ``known_ids`` are reported in
    ``unmatched`` and never written — the same infer-and-flag principle the
    catalog follows, so a typo'd or stale ID is visible rather than silently
    creating an orphan record.
    """
    result = IngestResult(kind=doc.kind)
    envelope = {
        "captured_at": doc.captured_at,
        "environment": doc.environment,
        "window": doc.window,
    }

    if doc.kind in DETECTION_KEYED_KINDS:
        for row in doc.detections:
            det_id = str(row["detection_id"])
            if det_id not in known_ids:
                result.unmatched.append(det_id)
                continue
            result.matched.append(det_id)
            if dry_run:
                continue
            payload = {**row, **envelope}
            latest_path = health_root / "latest" / f"{det_id}.yml"
            _merge_latest(latest_path, doc.kind, payload)
            history_path = health_root / "history" / f"{det_id}.jsonl"
            _append_history(history_path, {"kind": doc.kind, **row, "captured_at": doc.captured_at})
            result.paths_written.extend([latest_path, history_path])
        return result

    # Source-keyed kinds. Source names are free-form labels describing the
    # producer's telemetry, not ADEF identities, so there is nothing to match
    # them against — `unmatched` stays empty by construction.
    if doc.kind == "source_health":
        rows = [(str(row["name"]), dict(row)) for row in doc.sources]
    else:  # field_observations
        rows = [(doc.source, {"fields": list(doc.fields)})]

    for name, payload in rows:
        result.matched.append(name)
        if dry_run:
            continue
        path = health_root / "sources" / f"{name}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump({**payload, **envelope}, sort_keys=True), encoding="utf-8"
        )
        result.paths_written.append(path)

    return result


__all__ = ["IngestResult", "health_dir", "store_health_doc"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_health_store.py -v`
Expected: PASS — 8 tests

- [ ] **Step 5: Run the full suite and the linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass, no regressions

- [ ] **Step 6: Commit**

```bash
git add adef/core/health_store.py tests/test_health_store.py
git commit -m "feat(health): latest-snapshot and append-only history storage"
```

---

## Task 3: The `adef ingest` command

**Files:**
- Create: `adef/commands/ingest.py`
- Modify: `pyproject.toml` (add to `[project.entry-points."adef.commands"]`)
- Modify: `docs/cli-reference.md`
- Modify: `CLAUDE.md`
- Test: `tests/test_ingest_command.py`

**Interfaces:**
- Consumes: `load_health_doc`, `HealthDocError` from `adef.core.health_docs`; `health_dir`, `store_health_doc` from `adef.core.health_store`; `Catalog` from `adef.core.catalog`; `resolve_workspace` from `adef.core.workspace`
- Produces: Click command `ingest`, importable as `adef.commands.ingest:ingest`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ingest_command.py`:

```python
"""Tests for `adef ingest` (adef/commands/ingest.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.ingest import ingest as ingest_cli
from adef.core.catalog import Catalog, CatalogRecord


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    cat = Catalog(ws)
    rec = CatalogRecord(
        id="D-0042", title="mshta child", rule_ref="r/d42.yml",
        original_path="/tmp/d42.yml", platform="windows", kind="atomic",
        engine="sigma", format="sigma", query="process.name='mshta.exe'",
    )
    cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def _write_doc(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _metrics_doc(detection_id: str = "D-0042") -> dict:
    return {
        "schema_version": 1,
        "kind": "metrics",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "detections": [{"detection_id": detection_id, "signal_count": 143}],
    }


def test_ingest_writes_and_reports(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc())
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "metrics" in result.output
    assert "D-0042" in result.output or "1 matched" in result.output
    stored = yaml.safe_load(
        (workspace / "health" / "latest" / "D-0042.yml").read_text(encoding="utf-8")
    )
    assert stored["metrics"]["signal_count"] == 143


def test_ingest_routes_on_the_documents_own_kind(workspace: Path, tmp_path: Path):
    # No --kind flag exists; the file says what it is.
    drift = {
        "schema_version": 1,
        "kind": "deployment_drift",
        "captured_at": "2026-09-21T14:00:00Z",
        "environment": "prod-siem",
        "detections": [{"detection_id": "D-0042", "deployed_status": "enabled"}],
    }
    doc = _write_doc(tmp_path / "d.yml", drift)
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    stored = yaml.safe_load(
        (workspace / "health" / "latest" / "D-0042.yml").read_text(encoding="utf-8")
    )
    assert stored["deployment_drift"]["deployed_status"] == "enabled"


def test_dry_run_writes_nothing(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc())
    result = CliRunner().invoke(
        ingest_cli, [str(doc), "--workspace", str(workspace), "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    assert not (workspace / "health").exists()


def test_unmatched_ids_are_reported_in_output(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc(detection_id="D-9999"))
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "D-9999" in result.output
    assert "unmatched" in result.output.lower()


def test_invalid_document_is_a_clean_error_not_a_traceback(workspace: Path, tmp_path: Path):
    bad = _metrics_doc()
    bad["kind"] = "made_up"
    doc = _write_doc(tmp_path / "bad.yml", bad)
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code != 0
    assert "made_up" in result.output
    assert "Traceback" not in result.output


def test_missing_file_is_a_clean_error(workspace: Path, tmp_path: Path):
    result = CliRunner().invoke(
        ingest_cli, [str(tmp_path / "nope.yml"), "--workspace", str(workspace)]
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ingest_command.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'adef.commands.ingest'`

- [ ] **Step 3: Write the implementation**

Create `adef/commands/ingest.py`:

```python
"""`adef ingest` — take a detection-health capture document into the workspace.

One command for every document kind: the file declares its own ``kind``, so
there is no flag for a producer to mismatch against the file they are passing.
ADEF never contacts the environment the numbers came from.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from adef.core.catalog import Catalog
from adef.core.health_docs import HealthDocError, load_health_doc
from adef.core.health_store import health_dir, store_health_doc
from adef.core.workspace import resolve_workspace

console = Console()


@click.command()
@click.argument(
    "document",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Validate and report what would be written, without writing anything.",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE, current dir, or ~/work/adef-workspace/).",
)
def ingest(document: Path, dry_run: bool, workspace: Path | None) -> None:
    """Ingest a detection-health capture document (metrics, performance, drift…).

    The document declares its own ``kind`` and ``schema_version``; ingestion
    routes on that. Rows naming a detection the catalog does not know are
    reported and skipped, never silently stored.
    """
    try:
        doc = load_health_doc(document)
    except HealthDocError as exc:
        raise click.ClickException(str(exc)) from exc

    ws = resolve_workspace(workspace)
    known_ids = {det_id for det_id, _path, _data in Catalog(ws).iter_records()}

    result = store_health_doc(
        doc, health_dir(workspace), known_ids=known_ids, dry_run=dry_run
    )

    prefix = "[cyan]Would ingest[/cyan]" if dry_run else "[green]Ingested[/green]"
    console.print(
        f"{prefix} {result.kind} from {document.name} — "
        f"{len(result.matched)} matched"
    )
    if result.unmatched:
        console.print(
            f"  [yellow]unmatched:[/yellow] {len(result.unmatched)} row(s) name a "
            f"detection the catalog does not have: {', '.join(result.unmatched)}"
        )


__all__ = ["ingest"]
```

- [ ] **Step 4: Register the command**

In `pyproject.toml`, add one line to `[project.entry-points."adef.commands"]`, after the `sync` line:

```toml
ingest = "adef.commands.ingest:ingest"
```

Then reinstall so the entry point is discoverable:

Run: `.venv/bin/python -m pip install -e . --quiet`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ingest_command.py -v && .venv/bin/adef ingest --help`
Expected: PASS — 6 tests; `adef ingest --help` prints the command's help text

- [ ] **Step 6: Document the command**

In `docs/cli-reference.md`, add a section following the shape of the existing `adef schema ingest` entry:

````markdown
## `adef ingest`

Ingest a detection-health capture document produced from a live environment.

```bash
adef ingest health-metrics.yml              # validate, store, report
adef ingest health-metrics.yml --dry-run    # validate and report only
```

The document declares its own `kind` (`metrics`, `performance`,
`deployment_drift`, `field_observations`, `source_health`) and
`schema_version`, so one command handles all five and there is no flag to
mismatch against the file. Detection rows are keyed by `D-XXXX`; rows naming a
detection the catalog does not have are reported and skipped.

Stored under `<workspace>/health/`: `latest/D-XXXX.yml` (newest snapshot per
kind), `history/D-XXXX.jsonl` (append-only trend substrate), and
`sources/<source>.yml`.

ADEF never queries the environment these numbers describe — producing the
document is the user's side of the contract. See
`internal-docs/plans/2026-09-21-vendor-capture-design.md`.
````

In `CLAUDE.md`, add to the Essential Commands section, after the Schema Management block:

````markdown
### Detection Health Capture
```bash
adef ingest health-metrics.yml           # ingest a capture document (routes on its own `kind`)
adef ingest health-metrics.yml --dry-run # validate and report, write nothing
```
Five self-describing document kinds — `metrics`, `performance`,
`deployment_drift`, `field_observations`, `source_health` — bulk, keyed by
`D-XXXX`. Stored under `<workspace>/health/` as a latest snapshot per kind plus
an append-only `.jsonl` history. ADEF never queries the environment the numbers
came from; the producer hands over a file. Design:
`internal-docs/plans/2026-09-21-vendor-capture-design.md`.
````

And in `CLAUDE.md`'s Package Structure tree, add under `commands/`:

```
│   ├── ingest.py              # `adef ingest` — detection-health capture documents
```

and under `core/`:

```
│   ├── health_docs.py          # capture document model, lint, load
│   ├── health_store.py         # latest snapshot + append-only history
```

- [ ] **Step 7: Run the full suite and the linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass, no regressions

- [ ] **Step 8: Commit**

```bash
git add adef/commands/ingest.py tests/test_ingest_command.py pyproject.toml docs/cli-reference.md CLAUDE.md
git commit -m "feat(health): adef ingest command for capture documents"
```

---

## Task 4: The `health_ingest` MCP tool

**Files:**
- Create: `adef/mcp/tools/health_tools.py`
- Modify: `adef/mcp/register.py`
- Test: `tests/test_health_mcp_tools.py`

**Interfaces:**
- Consumes: `load_health_doc`, `HealthDocError` from `adef.core.health_docs`; `health_dir`, `store_health_doc` from `adef.core.health_store`; `Catalog`; `resolve_workspace`
- Produces: `register(server)` in `adef.mcp.tools.health_tools`, exposing the `health_ingest` tool

- [ ] **Step 1: Write the failing test**

Create `tests/test_health_mcp_tools.py`:

```python
"""Tests for the health MCP tools (adef/mcp/tools/health_tools.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.catalog import Catalog, CatalogRecord


class _FakeServer:
    """Minimal stand-in for a FastMCP server — captures @server.tool() callables."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    cat = Catalog(ws)
    rec = CatalogRecord(
        id="D-0042", title="mshta child", rule_ref="r/d42.yml",
        original_path="/tmp/d42.yml", platform="windows", kind="atomic",
        engine="sigma", format="sigma", query="process.name='mshta.exe'",
    )
    cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def test_health_ingest_tool_stores_and_reports(workspace: Path, tmp_path: Path):
    from adef.mcp.tools import health_tools

    doc_path = tmp_path / "m.yml"
    doc_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "kind": "metrics",
                "captured_at": "2026-09-21T14:00:00Z",
                "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
                "environment": "prod-siem",
                "detections": [{"detection_id": "D-0042", "signal_count": 143}],
            }
        ),
        encoding="utf-8",
    )

    server = _FakeServer()
    health_tools.register(server)
    out = server.tools["health_ingest"](
        document_path=str(doc_path), workspace=str(workspace)
    )

    assert out["kind"] == "metrics"
    assert out["matched"] == ["D-0042"]
    assert out["unmatched"] == []
    stored = yaml.safe_load(
        (workspace / "health" / "latest" / "D-0042.yml").read_text(encoding="utf-8")
    )
    assert stored["metrics"]["signal_count"] == 143


def test_health_ingest_tool_returns_error_instead_of_raising(workspace: Path, tmp_path: Path):
    from adef.mcp.tools import health_tools

    doc_path = tmp_path / "bad.yml"
    doc_path.write_text(yaml.safe_dump({"kind": "made_up"}), encoding="utf-8")

    server = _FakeServer()
    health_tools.register(server)
    out = server.tools["health_ingest"](
        document_path=str(doc_path), workspace=str(workspace)
    )

    assert "error" in out
    assert "made_up" in out["error"]


def test_register_mcp_tools_includes_health_tools():
    from adef.mcp.register import register_mcp_tools

    server = _FakeServer()
    register_mcp_tools(server)
    assert "health_ingest" in server.tools
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_health_mcp_tools.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'adef.mcp.tools.health_tools'`

- [ ] **Step 3: Write the implementation**

Create `adef/mcp/tools/health_tools.py`:

```python
"""MCP tools — detection-health capture ingestion.

Same core functions the `adef ingest` CLI uses. This is what "MCP-driven
tuning" means in practice: an assistant session that already has its own
tooling connected fetches the numbers, writes a capture document, and calls
this tool with it. ADEF still makes no call to the environment itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from adef.core.catalog import Catalog
from adef.core.health_docs import HealthDocError, load_health_doc
from adef.core.health_store import health_dir, store_health_doc
from adef.core.workspace import resolve_workspace


def register(server: Any) -> None:
    """Register health tools on ``server``."""

    @server.tool()
    def health_ingest(
        document_path: str,
        dry_run: bool = False,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Ingest a detection-health capture document. Routes on its own `kind`."""
        ws_arg = Path(workspace) if workspace else None
        try:
            doc = load_health_doc(Path(document_path))
        except HealthDocError as exc:
            # A malformed document is expected user input, not an exceptional
            # condition — return it so the assistant can show and fix it.
            return {"error": str(exc)}

        ws = resolve_workspace(ws_arg)
        known_ids = {det_id for det_id, _path, _data in Catalog(ws).iter_records()}
        result = store_health_doc(
            doc, health_dir(ws_arg), known_ids=known_ids, dry_run=dry_run
        )
        return {
            "kind": result.kind,
            "matched": result.matched,
            "unmatched": result.unmatched,
            "dry_run": dry_run,
            "paths_written": [str(p) for p in result.paths_written],
        }


__all__ = ["register"]
```

- [ ] **Step 4: Register the tool module**

In `adef/mcp/register.py`, add `health_tools` to both the import and the call list:

```python
def register_mcp_tools(server: Any) -> None:
    """Register every built-in tool module against ``server``."""
    from adef.mcp.tools import (
        agent_tools,
        health_tools,
        init_tools,
        lifecycle_tools,
        memory_tools,
        schema_tools,
    )

    lifecycle_tools.register(server)
    memory_tools.register(server)
    agent_tools.register(server)
    init_tools.register(server)
    schema_tools.register(server)
    health_tools.register(server)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_health_mcp_tools.py -v`
Expected: PASS — 3 tests

- [ ] **Step 6: Document the tool**

In `CLAUDE.md`, in the MCP Server section, add below the `adef-mcp` code block:

```markdown
Tools include `health_ingest` — the MCP twin of `adef ingest`, over the same
core. An assistant session with its own environment tooling connected can fetch
the numbers, shape a capture document, and ingest it without a file round-trip
through the CLI.
```

- [ ] **Step 7: Run the full suite and the linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass, no regressions

- [ ] **Step 8: Commit**

```bash
git add adef/mcp/tools/health_tools.py adef/mcp/register.py tests/test_health_mcp_tools.py CLAUDE.md
git commit -m "feat(health): health_ingest MCP tool"
```

---

## Done when

- `adef ingest <file>` validates and stores all five document kinds, routing on the document's own `kind`.
- `--dry-run` validates and reports without writing.
- Unmatched `detection_id`s appear in the output and are not written.
- `<workspace>/health/` holds `latest/`, `history/`, and `sources/` as specified.
- `health_ingest` is reachable through `adef-mcp`.
- `adef ingest` appears in `docs/cli-reference.md` and `CLAUDE.md`.
- Full suite green, ruff clean, mypy clean, all four anti-goal guards passing.

Story 10097 picks up from here: `adef/core/health.py` (EWMA trend and the
source-health correlation), `adef health`, the deployment-drift comparison, the
Evolve chain, and the `ADEF_WRAPPER_PERFORMANCE_METRICS` → `ADEF_WRAPPER_METRICS`
rename.
