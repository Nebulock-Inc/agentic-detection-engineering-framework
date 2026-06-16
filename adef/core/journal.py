"""Per-detection markdown journal — the core memory primitive of ADEF.

A *journal* is a markdown file at ``<workspace>/journals/D-XXXX.md`` paired
with an upstream detection rule (or pending — Find stage may exist before a
rule is written). It carries YAML frontmatter for machine-readable state and
one ``## [<ISO-8601>] Stage: <stage>`` block per FORGE transition.

Hard invariant: ``Journal`` never opens or writes any path that resolves
under a ``detections/`` directory. A journal lives in the ADEF workspace;
upstream rules live in their own repository. The two are paired by
``rule_uuid`` in frontmatter.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

import yaml


FORGE_STAGES: tuple[str, ...] = ("find", "observe", "refine", "govern", "evolve")
"""The five FORGE lifecycle stages, in order."""


_DETECTION_ID_RE = re.compile(r"^D-(\d{4,})$")
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
_STAGE_BLOCK_RE = re.compile(r"^## \[([^\]]+)\] Stage: (\w+)$", re.MULTILINE)


class JournalError(RuntimeError):
    """Base error for journal operations."""


class HardInvariantViolation(JournalError):
    """Raised if a journal path would resolve inside a rule ``detections/`` tree."""


@dataclass(frozen=True)
class StageAdvanceResult:
    """Outcome of ``Journal.advance_stage``."""

    detection_id: str
    stage: str
    was_idempotent: bool
    timestamp: str


def _now_iso() -> str:
    """Return current time as an ISO-8601 string with second precision and TZ."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _atomic_write(target: Path, content: str) -> None:
    """Write ``content`` to ``target`` via a temp file + rename (POSIX atomic)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".adef-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _check_not_under_detections(path: Path) -> None:
    """Raise if ``path`` resolves anywhere under a rule ``detections/`` tree.

    ADEF journals live in the workspace ``journals/`` directory. Any path that
    sits inside an upstream rule repository (whose convention is a top-level
    ``detections/`` directory) is read-only for ADEF — the journal layer must
    never write there.
    """
    parts = path.resolve().parts
    if "detections" in parts:
        raise HardInvariantViolation(
            f"adef.core.journal refused to touch {path} — paths under any "
            "rule 'detections/' directory are read-only for ADEF."
        )


def workspace_journals_dir(workspace: Optional[Path]) -> Path:
    """Resolve the journals directory for ``workspace``.

    Resolution order:

    1. Explicit ``workspace`` argument.
    2. ``ADEF_WORKSPACE`` environment variable.
    3. Current working directory if it contains a ``journals/`` subdirectory.
    4. Default ``~/work/adef-workspace/`` (creating ``journals/`` on demand).
    """
    if workspace is not None:
        ws = workspace
    elif env := os.environ.get("ADEF_WORKSPACE"):
        ws = Path(env)
    elif (Path.cwd() / "journals").is_dir():
        ws = Path.cwd()
    else:
        ws = Path.home() / "work" / "adef-workspace"

    ws = ws.expanduser().resolve()
    journals = ws / "journals"
    journals.mkdir(parents=True, exist_ok=True)
    return journals


def next_detection_id(journals_dir: Path) -> str:
    """Return ``D-<next>`` where ``<next>`` is one greater than the max existing index."""
    max_idx = 0
    for child in journals_dir.glob("D-*.md"):
        m = _DETECTION_ID_RE.match(child.stem)
        if m:
            max_idx = max(max_idx, int(m.group(1)))
    return f"D-{max_idx + 1:04d}"


def _load_template_text() -> str:
    """Return the package-data DETECTION_FORGE.md template as a string."""
    return (
        resources.files("adef.data.templates")
        .joinpath("DETECTION_FORGE.md")
        .read_text(encoding="utf-8")
    )


def _load_prompt(stage: str) -> str:
    """Return the stage-prompt body for ``stage`` (empty string if absent)."""
    try:
        return (
            resources.files("adef.data.prompts")
            .joinpath(f"{stage}.md")
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError):
        return ""


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split markdown ``text`` into (frontmatter dict, body string)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    fm = yaml.safe_load(m.group(1)) or {}
    body = text[m.end() :]
    return fm, body


def _join_frontmatter(fm: dict, body: str) -> str:
    """Re-serialize ``fm`` + ``body`` into a frontmatter+markdown document."""
    head = yaml.safe_dump(fm, sort_keys=False).strip()
    return f"---\n{head}\n---\n{body}" if not body.startswith("\n") else f"---\n{head}\n---{body}"


@dataclass
class JournalEntry:
    """In-memory representation of a single journal."""

    path: Path
    frontmatter: dict
    body: str

    @property
    def detection_id(self) -> str:
        return self.frontmatter.get("id", self.path.stem)

    @property
    def current_stage(self) -> str:
        return self.frontmatter.get("current_stage", "find")

    @property
    def rule_uuid(self) -> str:
        return self.frontmatter.get("rule_uuid", "") or ""


class Journal:
    """File-system-backed CRUD for ``D-XXXX.md`` journal files.

    Each ``Journal`` instance is bound to a journals directory. Operations on
    individual detections take their id; the class never holds per-detection
    state across calls.
    """

    def __init__(self, journals_dir: Path) -> None:
        _check_not_under_detections(journals_dir)
        self._dir = journals_dir.expanduser().resolve()
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def _path_for(self, detection_id: str) -> Path:
        candidate = self._dir / f"{detection_id}.md"
        _check_not_under_detections(candidate)
        return candidate

    def create(
        self,
        detection_id: str,
        title: str,
        owner: str = "",
        rule_uuid: str = "",
        note: str = "",
    ) -> JournalEntry:
        """Create a new journal at the Find stage. Returns the populated entry."""
        path = self._path_for(detection_id)
        if path.exists():
            raise JournalError(f"Journal {path} already exists.")

        template = _load_template_text()
        fm_template, body_template = _split_frontmatter(template)
        ts = _now_iso()
        fm = {
            **fm_template,
            "id": detection_id,
            "title": title,
            "status": "draft",
            "current_stage": "find",
            "owner": owner,
            "rule_uuid": rule_uuid,
            "created": ts,
            "updated": ts,
        }
        find_prompt = _load_prompt("find")
        find_block = (
            f"\n## [{ts}] Stage: find\n\n"
            f"**Title:** {title}\n\n"
            + (f"{find_prompt.strip()}\n\n" if find_prompt else "")
            + (f"_Note:_ {note}\n" if note else "")
        )
        text = _join_frontmatter(fm, body_template.rstrip() + "\n" + find_block)
        _atomic_write(path, text)
        return JournalEntry(path=path, frontmatter=fm, body=body_template + find_block)

    def read(self, detection_id: str) -> JournalEntry:
        """Read an existing journal."""
        path = self._path_for(detection_id)
        if not path.exists():
            raise JournalError(f"Journal {path} not found.")
        text = path.read_text(encoding="utf-8")
        fm, body = _split_frontmatter(text)
        return JournalEntry(path=path, frontmatter=fm, body=body)

    def advance_stage(
        self,
        detection_id: str,
        stage: str,
        note: str = "",
    ) -> StageAdvanceResult:
        """Advance the journal to ``stage``, append a stage block, return outcome.

        Idempotent: re-advancing to the same stage emits a stderr warning and
        does not append a duplicate block (a note, if given, is still added as
        a sub-block within the existing stage).
        """
        if stage not in FORGE_STAGES:
            raise JournalError(f"Unknown stage {stage!r}. Expected one of {FORGE_STAGES}.")

        entry = self.read(detection_id)
        ts = _now_iso()
        was_idempotent = entry.current_stage == stage

        if was_idempotent:
            print(
                f"[adef.journal] {detection_id} already at stage {stage}; "
                f"appending note only.",
                file=sys.stderr,
            )
            new_body = entry.body
            if note:
                new_body = entry.body.rstrip() + f"\n\n_Note ({ts}):_ {note}\n"
        else:
            prompt = _load_prompt(stage)
            block = (
                f"\n## [{ts}] Stage: {stage}\n\n"
                + (f"{prompt.strip()}\n\n" if prompt else "")
                + (f"_Note:_ {note}\n" if note else "")
            )
            new_body = entry.body.rstrip() + "\n" + block

        new_fm = {
            **entry.frontmatter,
            "current_stage": stage,
            "updated": ts,
        }
        _atomic_write(entry.path, _join_frontmatter(new_fm, new_body))
        return StageAdvanceResult(
            detection_id=detection_id,
            stage=stage,
            was_idempotent=was_idempotent,
            timestamp=ts,
        )

    def append_block(self, detection_id: str, heading: str, body: str) -> None:
        """Append an arbitrary ``### heading``-level block under the current stage.

        Used by orchestration (Refine chain) to record agent results.
        """
        entry = self.read(detection_id)
        ts = _now_iso()
        block = f"\n### {heading} ({ts})\n\n{body.strip()}\n"
        new_fm = {**entry.frontmatter, "updated": ts}
        _atomic_write(entry.path, _join_frontmatter(new_fm, entry.body.rstrip() + "\n" + block))

    def iter_entries(self) -> Iterable[JournalEntry]:
        """Yield every journal in the directory."""
        for child in sorted(self._dir.glob("D-*.md")):
            text = child.read_text(encoding="utf-8")
            fm, body = _split_frontmatter(text)
            yield JournalEntry(path=child, frontmatter=fm, body=body)

    def find_by_rule_uuid(self, rule_uuid: str) -> Optional[JournalEntry]:
        """Return the journal paired with ``rule_uuid``, or ``None``."""
        if not rule_uuid:
            return None
        for entry in self.iter_entries():
            if entry.rule_uuid == rule_uuid:
                return entry
        return None

    def max_detection_index(self) -> int:
        """Return the highest existing D-XXXX index, or 0."""
        max_idx = 0
        for child in self._dir.glob("D-*.md"):
            m = _DETECTION_ID_RE.match(child.stem)
            if m:
                max_idx = max(max_idx, int(m.group(1)))
        return max_idx


__all__ = [
    "FORGE_STAGES",
    "Journal",
    "JournalEntry",
    "JournalError",
    "HardInvariantViolation",
    "StageAdvanceResult",
    "next_detection_id",
    "workspace_journals_dir",
]
