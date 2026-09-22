"""The catalog artifact — ADEF's enrichment record over a user's rule repo.

A *catalog record* lives at ``<workspace>/catalog/<platform>/D-XXXX-<slug>.yml``.
It **references** a rule in the user's repository (``rule_ref`` + absolute
``original_path``) and layers ADEF's value-add on top: platform, MITRE, kind,
lifecycle status/stage, and slim-ADS strategy fields. The user's repo stays the
source of truth for the query logic; ADEF never writes to it.

A generated ``<workspace>/catalog/INDEX.yml`` gives O(1) lookup by ID plus
reverse maps (by_platform / by_technique / by_engine / by_status).

Hard invariant (CI-enforced by ``tests/test_schema_parity.py``): no path this
module writes ever contains a ``detections/`` segment. Catalog output is always
under ``catalog/``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from adef.core.journal import _atomic_write, _check_not_under_detections
from adef.core.rule_discovery import DiscoveredRule


class CatalogError(Exception):
    """A catalog write would corrupt state (e.g. a duplicate-ID clobber)."""


class NoCatalogRecordError(ValueError):
    """Raised by a native Refine agent when `detection_id` has no catalog record yet (still journal-only)."""


class _CatalogDumper(yaml.SafeDumper):
    """SafeDumper that renders multi-line strings as literal block scalars.

    A detection ``query`` is the field humans most want to read; block style
    (``query: |``) keeps it legible instead of an escaped one-line string. Scoped
    to catalog writes so it never affects other modules' YAML output.
    """


def _represent_str(dumper: yaml.Dumper, data: str):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_CatalogDumper.add_representer(str, _represent_str)


def _dump_catalog_yaml(data: dict) -> str:
    return str(yaml.dump(data, Dumper=_CatalogDumper, sort_keys=False, allow_unicode=True))

_DETECTION_ID_RE = re.compile(r"^D-(\d{4,})$")
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9]+")

# Platform used when discovery can't infer one — the "multi-platform" escape
# hatch from the repo-design doc (platform is the one single-valued axis, but
# unknown is still possible for raw SQL/CQL).
_UNKNOWN_PLATFORM = "multi-platform"


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _slugify(title: str, fallback: str) -> str:
    slug = _SLUG_STRIP_RE.sub("-", title.lower()).strip("-")
    return slug or fallback


def catalog_dir(workspace: Path) -> Path:
    """Return the catalog directory for ``workspace`` (``<workspace>/catalog``)."""
    return Path(workspace).expanduser().resolve() / "catalog"


def git_head_sha(directory: Path) -> str:
    """Repo HEAD SHA if ``directory`` is inside a git work tree, else ``""``.

    Stamped on records as ``catalog_sha`` so `adef sync` can do a one-shot
    staleness check (`git rev-parse HEAD` vs. this) and diff. No git → empty,
    and sync falls back to per-file hashing. Never raises.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


@dataclass
class CatalogRecord:
    """One ADEF catalog record — the enrichment layer over a source rule.

    ``engine`` is ADEF's internal four-value taxonomy; ``format`` preserves the
    true source language losslessly (see ``rule_discovery``).
    """

    id: str
    title: str
    rule_ref: str          # pointer to the source file, relative to the rule root
    original_path: str     # absolute path to the source file (provenance)
    platform: str
    kind: str              # atomic | correlation | composite
    engine: str            # sigma | sql | sch_sql | composite (internal taxonomy)
    format: str            # sigma | spl | kql | cql | sql | <profile name> (true source format)
    rule_uuid: str = ""    # embedded rule UUID (Sigma `id:`, profile uuid) — the
                           # primary identity key for `adef sync` reconciliation
                           # (survives file renames); empty when the format has none.
    source_hash: str = ""  # SHA-256 of the source file's bytes at catalog time —
                           # `adef sync` unchanged/modified signal + identity
                           # fallback for UUID-less formats. Empty for authored rules.
    catalog_sha: str = ""  # repo HEAD SHA at catalog time (git repos only) — the
                           # one-shot staleness check + `git diff` base for sync.
    origin: str = "catalogued"  # authored (created in ADEF — ADEF owns the durable
                           # copy) | catalogued (derived from a source repo). `adef
                           # sync` skips `authored` records (no upstream to
                           # reconcile). ISA 2026-07-22.
    query_language: str = ""  # language of `query` (spl|kql|cql|sql) — drives `schema check`
    query: str = ""        # the detection query/logic, verbatim (empty if external, e.g. Panther .py)
    data_source: str = ""  # raw table/index/logsource literal (schema prioritization + `schema check` key)
    support: str = "supported"  # supported | recognized_unsupported (how well we parse the format)
    mitre: list[str] = dataclass_field(default_factory=list)
    status: str = "draft"  # draft | ready | tuning | deprecated
    stage: str = "find"    # find | observe | refine | govern | evolve
    owner: str = ""
    needs_review: bool = False
    # Why (REVIEW_* constants from rule_discovery); needs_review == bool(reasons).
    review_reasons: list[str] = dataclass_field(default_factory=list)
    created: str = ""
    updated: str = ""

    def to_yaml_dict(self) -> dict:
        """Serialize to the on-disk catalog YAML shape (ordered, no None noise)."""
        ts = _now_iso()
        return {
            "id": self.id,
            "title": self.title,
            "rule_ref": self.rule_ref,
            "original_path": self.original_path,
            "rule_uuid": self.rule_uuid,
            "source_hash": self.source_hash,
            "catalog_sha": self.catalog_sha,
            "origin": self.origin,
            "query": self.query,
            "platform": self.platform,
            "kind": self.kind,
            "engine": self.engine,
            "format": self.format,
            "query_language": self.query_language,
            "data_source": self.data_source,
            "support": self.support,
            "mitre": list(self.mitre),
            "status": self.status,
            "stage": self.stage,
            "owner": self.owner,
            "needs_review": self.needs_review,
            "review_reasons": list(self.review_reasons),
            "created": self.created or ts,
            "updated": self.updated or ts,
        }


def record_from_discovered(
    detection_id: str,
    disc: DiscoveredRule,
    workspace: Path,
    rule_root: Path | None = None,
    catalog_sha: str = "",
) -> CatalogRecord:
    """Build a ``CatalogRecord`` from a ``DiscoveredRule``.

    Applies the infer-and-flag rule: an unknown platform falls back to the
    ``multi-platform`` escape hatch and preserves ``needs_review``.

    ``rule_ref`` is relative to the *rule root* when one is given
    (``<root-name>/<path-inside-root>``) — portable regardless of where the
    workspace lives. The workspace-relative form is only a fallback for
    callers that don't know the root (found by the 2026-07-21 E2E test, where
    a distant workspace produced ``../../..``-style refs).
    """
    ws = Path(workspace).expanduser().resolve()
    abs_path = disc.path.expanduser().resolve()
    rule_ref = ""
    if rule_root is not None:
        root = Path(rule_root).expanduser().resolve()
        try:
            rule_ref = str(Path(root.name) / abs_path.relative_to(root))
        except ValueError:
            rule_ref = ""  # not under the given root — fall through
    if not rule_ref:
        try:
            rule_ref = str(abs_path.relative_to(ws.parent))
        except ValueError:
            # Source repo lives outside the workspace parent — relative walk.
            import os

            rule_ref = os.path.relpath(abs_path, ws)

    platform = disc.platform or _UNKNOWN_PLATFORM
    title = disc.title or abs_path.stem
    return CatalogRecord(
        id=detection_id,
        title=title,
        rule_ref=rule_ref,
        original_path=str(abs_path),
        rule_uuid=disc.rule_uuid,
        source_hash=disc.source_hash,
        catalog_sha=catalog_sha,
        query=disc.query_text,
        platform=platform,
        kind=disc.kind,
        engine=disc.engine,
        format=disc.format,
        query_language=disc.query_language,
        data_source=disc.data_source,
        support=disc.support,
        mitre=list(disc.mitre),
        needs_review=disc.needs_review or disc.platform is None,
        review_reasons=list(disc.review_reasons),
    )


def _starter_query(query_language: str, scope: dict[str, str]) -> str:
    """A skeleton query grounded in the schema's scope, in the source language.

    Not runnable logic — a scaffold that gets the *addressing* right (real
    index/sourcetype/table literals) so the author fills in behavior, not
    boilerplate. Empty when there's nothing to ground on.
    """
    if not scope:
        return ""
    ql = query_language.lower()
    if ql == "spl":
        prefix = " ".join(f"{k}={v}" for k, v in scope.items())
        return f"{prefix}\n| where <condition>" if prefix else ""
    if ql in ("kql", "cql"):
        # Lead table is the container literal; prefer an explicit table/source.
        table = scope.get("table") or scope.get("source") or next(iter(scope.values()))
        return f"{table}\n| where <condition>"
    if ql == "sql":
        table = scope.get("table") or next(iter(scope.values()))
        return f"SELECT * FROM {table}\nWHERE <condition>"
    return ""


def draft_record_from_schema(
    workspace: Path,
    detection_id: str,
    title: str,
    source: str,
) -> "CatalogRecord":
    """Build a draft catalog record grounded in a declared schema.

    Pulls ``platform`` / ``query_language`` / scope from ``schema/<source>.yml``
    so a newly-authored detection starts with correct addressing instead of
    guesses. ``data_source`` is the schema's canonical ``source`` name — the
    identity ``adef schema check`` matches on. Raises ``FileNotFoundError`` if
    the schema isn't declared (author against a real source, not a guess).
    """
    from adef.core.declaration import read_schema_v2

    schema_path = Path(workspace).expanduser().resolve() / "schema" / f"{source}.yml"
    data = read_schema_v2(schema_path) if schema_path.is_file() else None
    if not data:
        raise FileNotFoundError(
            f"no schema '{source}' in the workspace — run `adef schema ingest` "
            f"first, or `adef schema show` to list declared sources"
        )

    query_language = str(data.get("query_language", ""))
    scope = {str(k): str(v) for k, v in (data.get("scope") or {}).items()}
    return CatalogRecord(
        id=detection_id,
        title=title,
        rule_ref="",           # authored in ADEF, not (yet) in the user's repo
        original_path="",
        platform=str(data.get("platform") or _UNKNOWN_PLATFORM),
        kind="atomic",
        engine="sql" if query_language in ("sql", "spl", "kql", "cql") else "sigma",
        format=query_language or "sql",
        query_language=query_language,
        query=_starter_query(query_language, scope),
        data_source=source,
        support="supported",
        origin="authored",  # created in ADEF — sync must never orphan it
    )


class Catalog:
    """File-system-backed catalog writer + INDEX generator for a workspace."""

    def __init__(self, workspace: Path) -> None:
        self._ws = Path(workspace).expanduser().resolve()
        self._dir = self._ws / "catalog"
        _check_not_under_detections(self._dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def _path_for(self, rec: CatalogRecord) -> Path:
        slug = _slugify(rec.title, rec.id.lower())
        candidate = self._dir / rec.platform / f"{rec.id}-{slug}.yml"
        _check_not_under_detections(candidate)
        return candidate

    def write(self, rec: CatalogRecord) -> Path:
        """Write a catalog record to ``catalog/<platform>/D-XXXX-<slug>.yml``.

        Defense in depth against the duplicate-ID clobber (ISA 2026-07-22): if a
        record with this ``id`` already exists at a *different* path (a different
        detection minted the same ID), refuse rather than silently overwrite it.
        Re-writing the same record — same ID, whether the slug/path changed or
        not — is fine (sync MODIFIED, catalog re-slug); a stale same-ID sibling
        at the old path is removed so the ID never has two files.
        """
        path = self._path_for(rec)
        existing = self.find_record(rec.id)
        if existing is not None:
            old_path, old_data = existing
            if old_path.resolve() != path.resolve() and old_data.get("id") == rec.id:
                # Same ID, different file. If the *slug* changed for the same
                # detection (title edit), migrate: remove the stale sibling. But
                # we can't tell "same detection, renamed" from "two detections,
                # same ID" purely by ID — so treat a differing rule_ref as a
                # genuine collision and refuse; otherwise migrate the slug.
                same_detection = (old_data.get("rule_ref") or "") == (rec.rule_ref or "")
                if same_detection:
                    old_path.unlink()  # re-slug of the same rule; drop the old file
                else:
                    raise CatalogError(
                        f"refusing to write {rec.id}: a different detection already "
                        f"holds that ID at {old_path.name}. This would clobber it."
                    )
        content = _dump_catalog_yaml(rec.to_yaml_dict())
        _atomic_write(path, content)
        return path

    def find_record(self, detection_id: str) -> tuple[Path, dict] | None:
        """Return ``(path, data)`` for one record by ID, or None if absent."""
        for det_id, path, data in self.iter_records():
            if det_id == detection_id:
                return path, data
        return None

    def write_raw(self, path: Path, data: dict) -> Path:
        """Write an already-shaped record dict back to ``path`` (in place).

        Unlike ``write`` this does not re-derive the filename from the record,
        so it preserves the existing file location — used by enrichment paths
        that mutate a record without moving it.
        """
        _check_not_under_detections(path)
        _atomic_write(path, _dump_catalog_yaml(data))
        return path

    def iter_records(self):
        """Yield ``(detection_id, path, data)`` for every catalog YAML on disk."""
        for path in sorted(self._dir.rglob("D-*.yml")):
            if path.name == "INDEX.yml":
                continue
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            det_id = data.get("id") or path.stem.split("-")[0]
            yield det_id, path, data

    def max_index(self) -> int:
        """Highest ``D-XXXX`` index present in the catalog, or 0.

        Filenames are ``D-XXXX-<slug>.yml``, so the ID is the leading token.
        """
        max_idx = 0
        for path in self._dir.rglob("D-*.yml"):
            lead = re.match(r"(D-\d{4,})", path.stem)
            if lead:
                max_idx = max(max_idx, int(lead.group(1)[2:]))
        return max_idx

    def journals_max_index(self) -> int:
        """Highest ``D-XXXX`` index present in ``journals/``, or 0.

        Public because sync's reconcile needs the journal floor too (shared ID
        space) — a NEW id must clear journal-only detections, not just catalog
        records (ISA 2026-07-22).
        """
        journals = self._ws / "journals"
        if not journals.is_dir():
            return 0
        max_idx = 0
        for child in journals.rglob("D-*.md"):
            m = _DETECTION_ID_RE.match(child.stem)
            if m:
                max_idx = max(max_idx, int(m.group(1)))
        return max_idx

    def next_id(self) -> str:
        """Next ``D-XXXX`` clearing both catalog and journal IDs (shared space)."""
        nxt = max(self.max_index(), self.journals_max_index()) + 1
        return f"D-{nxt:04d}"

    def rebuild_index(self) -> Path:
        """Regenerate ``catalog/INDEX.yml`` from every catalog record on disk."""
        from adef.core.attack import attack_reference

        ref = attack_reference()

        detections: dict[str, str] = {}
        by_platform: dict[str, list[str]] = {}
        by_technique: dict[str, list[str]] = {}
        # by_tactic resolves each mapped technique to its tactic(s) via the
        # shipped ATT&CK reference; a technique with two tactics lands under
        # both. Techniques absent from the reference contribute to
        # by_technique but not by_tactic (they're flagged `invalid_mitre`).
        by_tactic: dict[str, list[str]] = {}
        by_engine: dict[str, list[str]] = {}
        by_status: dict[str, list[str]] = {}
        by_data_source: dict[str, list[str]] = {}

        for det_id, path, data in self.iter_records():
            rel = str(path.relative_to(self._dir))
            detections[det_id] = rel
            by_platform.setdefault(data.get("platform", _UNKNOWN_PLATFORM), []).append(det_id)
            by_engine.setdefault(data.get("engine", ""), []).append(det_id)
            by_status.setdefault(data.get("status", "draft"), []).append(det_id)
            for technique in data.get("mitre") or []:
                by_technique.setdefault(technique, []).append(det_id)
                for tactic in ref.tactics_for(technique):
                    by_tactic.setdefault(tactic, []).append(det_id)
            src = data.get("data_source") or ""
            if src:
                by_data_source.setdefault(src, []).append(det_id)

        # dedupe: a rule mapping two techniques in the same tactic appears once.
        index = {
            "generated": True,
            "detections": dict(sorted(detections.items())),
            "by_platform": {k: sorted(v) for k, v in sorted(by_platform.items())},
            "by_tactic": {k: sorted(set(v)) for k, v in sorted(by_tactic.items())},
            "by_technique": {k: sorted(v) for k, v in sorted(by_technique.items())},
            "by_engine": {k: sorted(v) for k, v in sorted(by_engine.items())},
            "by_status": {k: sorted(v) for k, v in sorted(by_status.items())},
            "by_data_source": {k: sorted(v) for k, v in sorted(by_data_source.items())},
        }
        index_path = self._dir / "INDEX.yml"
        _atomic_write(index_path, yaml.safe_dump(index, sort_keys=False, allow_unicode=True))
        return index_path


def known_detection_ids(workspace: Path) -> set[str]:
    """Detection IDs already in the workspace catalog, without creating it.

    `Catalog.__init__` mkdirs `catalog/`, which a read-only caller must not
    do — `adef ingest --dry-run` has to write nothing at all. Constructing
    the catalog only when its directory already exists keeps that true while
    still reusing `iter_records`' parsing.
    """
    catalog_dir_path = Path(workspace).expanduser().resolve() / "catalog"
    if not catalog_dir_path.is_dir():
        return set()
    return {det_id for det_id, _path, _data in Catalog(workspace).iter_records()}


__all__ = [
    "Catalog",
    "CatalogRecord",
    "NoCatalogRecordError",
    "catalog_dir",
    "known_detection_ids",
    "record_from_discovered",
]
