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

from adef.core.corpus_text import record_mitre
from adef.core.journal import _atomic_write, _check_not_under_detections
from adef.core.rule_discovery import (
    PLATFORM_MAX_BYTES,
    REVIEW_INVALID_MITRE,
    REVIEW_NO_MITRE,
    REVIEW_NO_PLATFORM,
    DiscoveredRule,
    mitre_review_reasons,
    safe_platform,
)


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
# hatch (platform is the one single-valued axis, but
# unknown is still possible for raw SQL/CQL).
_UNKNOWN_PLATFORM = "multi-platform"


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _slugify(title: str, fallback: str) -> str:
    slug = _SLUG_STRIP_RE.sub("-", title.lower()).strip("-")
    # The slug is a *filename*, so an untruncated one is an `OSError` from the
    # write — and the title arrives from outside ADEF (a source rule, or a GATES
    # candidate `name` an agent wrote). Uncapped, a long name made `hunt-promote`
    # traceback mid-loop with part of the document already imported, while
    # `--dry-run` reported it fine: `record_path` only resolves, and resolving an
    # overlong component succeeds. 80 leaves room for `D-XXXX-` + `.yml` inside
    # every filesystem's 255-byte limit.
    return slug[:80].rstrip("-") or fallback


def _as_list(value: object) -> list:
    """A list field's value, tolerating the scalar a hand-edit leaves behind.

    Hand-editing a record *is* the enrichment workflow, and `references:
    https://x` (no dash) is what that produces. `list()` on a string iterates
    characters, so the typo turns into 17 references — or seven platforms — on the
    next write. One entry instead, which is what was meant.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set)):
        return [value]
    return list(value)


def as_str_list(value: object) -> list[str]:
    """``_as_list`` for a list *of strings* — platforms, references, MITRE IDs.

    Separate from ``_as_list`` because the two shapes disagree about a mapping. A
    bare mapping where a list of mappings belongs (``entities: {name: …}``) is one
    entry, but `platforms:` followed by indented `windows:`/`macos:` lines — the
    other half of the missing-dash typo — is two *keys*, which is what `list()`
    gave before and what the INDEX needs. Wrapping that one would file the
    stringified dict as a platform.
    """
    if isinstance(value, dict):
        return [text for text in (str(k).strip() for k in value) if text]
    # `None` entries dropped, everything else stringified. A bare `-` with nothing
    # after it parses to `None`, and `str()` would file `"None"` as a technique in
    # `by_technique` — an empty item carries nothing to report, so there is no
    # signal lost by dropping it. A non-string that *does* carry text (an unquoted
    # number) is kept so `invalid_mitre` can surface it to a human instead.
    return [
        text
        for text in (str(v).strip() for v in _as_list(value) if v is not None)
        if text
    ]


def declared_platforms(data: dict) -> list[str]:
    """A record's ``platforms``, read the one way that survives a scalar.

    `platforms` is hand-editable on disk, and a comprehension over the string
    ``windows`` iterates *characters* — which reached the INDEX as seven bogus
    ``by_platform`` keys, each matching `--platform w`. The same corruption
    `gates._str_list` was written to stop on the document side, arriving through
    the other door; every reader of the field goes through here instead.
    """
    return as_str_list(data.get("platforms"))


def record_platforms(data: dict) -> list[str]:
    """Every platform a record covers: its bucket plus any declared constituents.

    One answer for the ``--platform`` filter and the ``by_platform`` INDEX, so a
    cross-platform detection can't be findable through one and invisible through
    the other. The bucket stays in the list — ``--platform multi-platform`` is how
    you ask for exactly the cross-platform ones.
    """
    bucket = str(data.get("platform") or _UNKNOWN_PLATFORM)
    declared = declared_platforms(data)
    return list(dict.fromkeys([bucket, *declared]))


def catalog_dir(workspace: Path) -> Path:
    """Return the catalog directory for ``workspace`` (``<workspace>/catalog``)."""
    return Path(workspace).expanduser().resolve() / "catalog"


def refresh_mitre_review(rec: CatalogRecord, workspace: Path | None = None) -> None:
    """Re-derive ``rec``'s MITRE review reasons from the mapping it ends up with.

    ``review_reasons`` is computed while the record is built — from the source rule
    or the GATES document — but ``mitre`` is *enrichment*, grafted back on
    afterwards. So a detection someone mapped with ``adef detection tag-mitre``
    came out of the next ``adef sync`` or GATES re-import carrying its mapping
    *and* ``no_mitre``: correct mapping, wrong queue, re-filled on every re-run.
    Recomputed here, as ``core/tag.py`` does after a tag. The other reasons are
    the source's to say and stay. ``reconcile._merge`` never needs this — it
    starts from the existing record and recomputes neither field; every path that
    *re-derives* one does.

    ``workspace`` selects the ATT&CK snapshot ``invalid_mitre`` is judged
    against — pass the one the record lives in, or a `--workspace` whose
    refreshed snapshot differs from ``$ADEF_WORKSPACE`` gets the wrong verdict
    written to disk.
    """
    # Normalized first: the graft that hands us `mitre` hands over the raw on-disk
    # value, and a hand-edited `mitre: T1218.011` (no dash) would otherwise be read
    # as nine one-character techniques — nine `by_technique` buckets, and
    # `invalid_mitre` instead of the clean mapping it is.
    rec.mitre = as_str_list(rec.mitre)
    rec.review_reasons = mitre_review_reasons(rec.mitre, workspace) + [
        r for r in rec.review_reasons if r not in (REVIEW_NO_MITRE, REVIEW_INVALID_MITRE)
    ]
    rec.needs_review = bool(rec.review_reasons)


def record_path(catalog_directory: Path, rec: CatalogRecord) -> Path:
    """Where ``rec`` belongs: ``<catalog>/<platform>/D-XXXX-<slug>.yml``.

    Module-level and side-effect free so a caller that must not touch the disk —
    ``hunt-promote --gates --dry-run``, which has to predict what the real run
    would reject — can validate a planned path without constructing a ``Catalog``
    (whose ``__init__`` creates the directory).
    """
    # Length first. This function refuses *by reason*, and `safe_platform` now
    # answers the composite question (charset AND length, so that no producer
    # hands the writer a value it will reject) — so asking it first answered an
    # overlong platform with the charset message, naming a charset the value
    # never violated. Ordered this way, the comparison below is still exactly
    # the charset test: anything reaching it has already passed the bound.
    if len(rec.platform.encode("utf-8", "surrogatepass")) > PLATFORM_MAX_BYTES:
        # Worse than a path escape, which `resolve()` below catches: resolving an
        # overlong component succeeds, so nothing fails until the write — a bare
        # `OSError` halfway through an import, with earlier records already on
        # disk. Named here instead, and both dry runs (`hunt-promote --gates`,
        # `adef catalog`) vet the whole plan through this function before writing
        # anything. Not truncated: the directory and the record's `platform` have
        # to stay the same string or the INDEX points nowhere.
        raise CatalogError(
            f"Refused to write {rec.id}: platform "
            f"{rec.platform[:40]!r}… is too long to be a directory name."
        )
    # Narrowest check next, and the only one that rejects a platform the path
    # checks below would wave through: `windows/sub` resolves *inside* the catalog
    # but nests the record a level deeper than the INDEX looks for, and `Windows`
    # makes a second directory for a platform that already has one. Both are a
    # single plain segment away from correct, so refuse rather than guess.
    if safe_platform(rec.platform) != rec.platform:
        raise CatalogError(
            f"{rec.id}: platform {rec.platform!r} is not a single plain path "
            "segment (lowercase letters, digits, '-' or '_')"
        )
    slug = _slugify(rec.title, rec.id.lower())
    candidate = catalog_directory / rec.platform / f"{rec.id}-{slug}.yml"
    _check_not_under_detections(candidate)
    # `platform` becomes a directory name, and it arrives from outside ADEF: a
    # source rule's `logsource.product` or a GATES document's `platforms`. A value
    # like `../../etc` would put the record outside the workspace entirely.
    # Checked here because every writer routes through this, so no caller has to
    # remember to sanitize.
    # Both sides resolved, or the comparison is between two different spellings of
    # the same directory: `catalog_dir()` resolves, but this is a module-level helper
    # and a caller passing `/tmp/ws/catalog` on macOS — where `/tmp` is a symlink —
    # would have every legitimate record refused.
    if catalog_directory.resolve() not in candidate.resolve().parents:
        raise CatalogError(
            f"Refused to write {rec.id} to {candidate}: platform "
            f"{rec.platform!r} resolves outside {catalog_directory}."
        )
    return candidate


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
    # The platforms actually declared, when `platform` had to collapse to the
    # `multi-platform` bucket (`platform` is a directory name, so it stays
    # single-valued). Empty for a single-platform detection — `platform` already
    # says it. Lets `--platform windows` and `by_platform` see through the bucket.
    platforms: list[str] = dataclass_field(default_factory=list)
    rule_uuid: str = ""    # embedded rule UUID (Sigma `id:`, profile uuid) — the
                           # primary identity key for `adef sync` reconciliation
                           # (survives file renames); empty when the format has none.
    source_hash: str = ""  # SHA-256 of the source file's bytes at catalog time —
                           # `adef sync` unchanged/modified signal + identity
                           # fallback for UUID-less formats. Empty for authored rules.
    catalog_sha: str = ""  # repo HEAD SHA at catalog time (git repos only) — the
                           # one-shot staleness check + `git diff` base for sync.
    origin: str = "catalogued"  # authored (created in ADEF — ADEF owns the durable
                           # copy) | catalogued (derived from a source repo) |
                           # promoted (imported from an ATHF GATES document). `adef
                           # sync` skips `authored` and `promoted` records — neither
                           # has an upstream rule repo to reconcile.
    query_language: str = ""  # language of `query` (spl|kql|cql|sql) — drives `schema check`
    query: str = ""        # the detection query/logic, verbatim (empty if external, e.g. Panther .py)
    data_source: str = ""  # raw table/index/logsource literal (schema prioritization + `schema check` key)
    support: str = "supported"  # supported | recognized_unsupported (how well we parse the format)
    mitre: list[str] = dataclass_field(default_factory=list)
    status: str = "draft"  # draft | ready | tuning | deprecated
    stage: str = "find"    # find | observe | refine | govern | evolve
    owner: str = ""
    # --- enrichment: human/agent-supplied, never derived from the source rule.
    # `adef sync` preserves every field below (see reconcile.py); they are only
    # written on the way in (catalog/promote) or by a human afterwards. Omitted
    # from the YAML entirely when empty, so catalogued records stay terse.
    description: str = ""  # what it detects and how, in prose (cf. Sigma `description`)
    alert: dict = dataclass_field(default_factory=dict)  # {severity, throttle:{entity,duration}}
    entities: list[dict] = dataclass_field(default_factory=list)  # [{name,type}] correlation keys
    observables: list[dict] = dataclass_field(default_factory=list)  # [{name,type}] other artifacts
    references: list[str] = dataclass_field(default_factory=list)
    hunt_ref: str = ""     # `H-XXXX#<gates-detection-id>` for promoted records —
                           # provenance, and the stable identity key that makes
                           # re-importing a GATES document idempotent.
    needs_review: bool = False
    # Why (REVIEW_* constants from rule_discovery); needs_review == bool(reasons).
    review_reasons: list[str] = dataclass_field(default_factory=list)
    created: str = ""
    updated: str = ""

    def to_yaml_dict(self) -> dict:
        """Serialize to the on-disk catalog YAML shape (ordered, no None noise)."""
        ts = _now_iso()
        data = {
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
            # `mitre` goes through the same coercion as the enrichment block below:
            # it is in `_ENRICHMENT_FIELDS`, so every re-derive path grafts the raw
            # on-disk value onto it, and it has more downstream consumers than any
            # other list here (`by_technique`, coverage, the search text).
            "mitre": as_str_list(self.mitre),
            "status": self.status,
            "stage": self.stage,
            "owner": self.owner,
            "needs_review": self.needs_review,
            "review_reasons": list(self.review_reasons),
            "created": self.created or ts,
            "updated": self.updated or ts,
        }
        # Omitted when empty: enrichment is opt-in (a rule catalogued from a repo
        # has none of it) and `platforms` only applies to a cross-platform
        # detection, so emitting the empty keys would bloat every file in the tree.
        # Every list here is coerced and `alert` is copied only when it really is a
        # mapping: these fields arrive from a hand-edited file (via the
        # `sync`/re-import graft, which restores the raw YAML value), so
        # `list()`/`dict()` on a scalar typo either corrupted the field or raised
        # mid-write, leaving the tree half-synced behind a stale INDEX.
        for key, value in (
            ("platforms", as_str_list(self.platforms)),
            ("description", self.description),
            ("alert", dict(self.alert) if isinstance(self.alert, dict) else self.alert),
            ("entities", _as_list(self.entities)),
            ("observables", _as_list(self.observables)),
            ("references", as_str_list(self.references)),
            ("hunt_ref", self.hunt_ref),
        ):
            if value:
                data[key] = value
        return data


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
    # Through `safe_platform` for the same reason the GATES importer and the
    # declaration-inheritance pass do: the schema's `platform` is free text the
    # user wrote, and it becomes a directory name. `platform: Windows` made
    # `adef detection new --source` die at write time on a `record_path` refusal
    # the user cannot act on from the command they ran.
    platform = safe_platform(data.get("platform"))
    return CatalogRecord(
        id=detection_id,
        title=title,
        rule_ref="",           # authored in ADEF, not (yet) in the user's repo
        original_path="",
        platform=platform or _UNKNOWN_PLATFORM,
        review_reasons=[] if platform else [REVIEW_NO_PLATFORM],
        needs_review=not platform,
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
        # The one place every write resolves its path. All four refusals —
        # charset, `detections/`, escape, length — live in `record_path`, which
        # the two dry-run pre-flights call directly; nothing is checked only here.
        return record_path(self._dir, rec)

    def write(self, rec: CatalogRecord) -> Path:
        """Write a catalog record to ``catalog/<platform>/D-XXXX-<slug>.yml``.

        Defense in depth against the duplicate-ID clobber: if a
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
                # `rule_ref` is per-*file*, and every candidate promoted from one
                # GATES document shares it — so there it can't tell two detections
                # apart, and the migration branch below would unlink a sibling
                # candidate's record instead of refusing. `hunt_ref` is the
                # per-candidate identity; prefer it when both records carry one.
                if (new_hunt := rec.hunt_ref) and (old_hunt := old_data.get("hunt_ref")):
                    same_detection = new_hunt == old_hunt
                else:
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
            except (yaml.YAMLError, UnicodeDecodeError, OSError):
                # Not just `YAMLError`: `read_text(encoding="utf-8")` raises
                # `UnicodeDecodeError` before the parser ever sees the bytes,
                # and that is a `ValueError` — so a record saved as UTF-16 (or
                # a half-written one) tracebacked out of *every* caller of this
                # method, `adef doctor` included. One guard here rather than at
                # eighteen call sites, and the skip is already visible: `doctor`'s
                # catalog check diffs the files on disk against the paths this
                # yielded and names what it dropped. `OSError` for the same
                # reason — a record whose permissions were changed is the same
                # "the file is there and cannot be turned into data" answer.
                continue
            # Coerced here, at the one boundary every reader of a record goes
            # through (`find_record`, `rebuild_index`, `coverage`, `detection
            # list/show`, the search corpus, both enrichment grafts): a record is
            # hand-edited by design, and `mitre: T1218.011` without the dash is a
            # *string*, which every one of those consumers then iterates per
            # character — nine techniques in `by_technique`, nine in coverage.
            # `to_yaml_dict` coerces on the way out too, for records built in
            # process; this is for the record that is only ever edited. All four
            # list-of-string fields a record has — `review_reasons` included, where
            # the per-character read made `coverage` count a record flagged
            # `invalid_mitre` as solid and dropped it from `--needs-review`.
            for key in ("mitre", "platforms", "references", "review_reasons"):
                if key in data:
                    data[key] = as_str_list(data[key])
            # `str` for the same reason: `id: 1470` without the `D-` prefix is an
            # *int*, and the ID is used as a dict key (`INDEX.yml`'s `detections`
            # map gained an int key) and sorted and joined alongside IDs read from
            # journal filenames, which are always strings — `sorted({1470,
            # "D-0002"})` and `", ".join(...)` both raise `TypeError`. That took
            # down `adef doctor`, the one command whose job is to report a broken
            # workspace, on the exact input it exists to find.
            det_id = str(data.get("id") or path.stem.split("-")[0])
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
        records.
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

    def build_index(self) -> dict:
        """The INDEX this catalog's records imply, without writing it.

        Split out of ``rebuild_index`` so a reader can compare the stored INDEX
        against the one the records *should* produce — an exact staleness
        answer. The alternative (comparing ID sets, or file mtimes) misses the
        case that matters most: a record whose ``mitre`` was edited leaves
        every filename untouched while ``by_technique`` and ``by_tactic`` go
        wrong, which is the stale-INDEX bug that has reached a real workspace
        before.
        """
        from adef.core.attack import attack_reference

        # This workspace's snapshot, not whatever `$ADEF_WORKSPACE` names:
        # `by_tactic` is *persisted* into `INDEX.yml` and then read by `adef
        # coverage` and `--tactic`, so `adef reindex --workspace /srv/ws`
        # wrote tactic resolution from a different ATT&CK release than the
        # records it indexed.
        ref = attack_reference(self._ws)

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
            # Name the record in the failure. A record hand-edited to
            # `engine: [sigma]` raises a bare "unhashable" `TypeError` from the
            # `setdefault` below — accurate and useless in a 400-record
            # catalog, because nothing in it says which file. Both commands
            # that report this to a user print the exception text and nothing
            # else (`adef reindex`, and `adef doctor`'s index check, which
            # deliberately offers no `fix`), so naming it here fixes both for
            # one line. The file, not the field: only three values are used as
            # keys and the message names the offending type, which is enough to
            # find it once you know which file to open.
            try:
                rel = str(path.relative_to(self._dir))
                detections[det_id] = rel
                for plat in record_platforms(data):
                    by_platform.setdefault(plat, []).append(det_id)
                by_engine.setdefault(data.get("engine", ""), []).append(det_id)
                by_status.setdefault(data.get("status", "draft"), []).append(det_id)
                for technique in record_mitre(data):
                    by_technique.setdefault(technique, []).append(det_id)
                    for tactic in ref.tactics_for(technique):
                        by_tactic.setdefault(tactic, []).append(det_id)
                src = data.get("data_source") or ""
                if src:
                    by_data_source.setdefault(src, []).append(det_id)
            except (TypeError, AttributeError) as exc:
                # Same type back out, not a wrapper: callers catch broadly, and
                # `adef detection tag-mitre`'s tests assert on `TypeError`.
                raise type(exc)(f"{path.name}: {exc}") from exc

        # dedupe: a rule mapping two techniques in the same tactic appears once.
        return {
            "generated": True,
            "detections": dict(sorted(detections.items())),
            "by_platform": {k: sorted(v) for k, v in sorted(by_platform.items())},
            "by_tactic": {k: sorted(set(v)) for k, v in sorted(by_tactic.items())},
            "by_technique": {k: sorted(v) for k, v in sorted(by_technique.items())},
            "by_engine": {k: sorted(v) for k, v in sorted(by_engine.items())},
            "by_status": {k: sorted(v) for k, v in sorted(by_status.items())},
            "by_data_source": {k: sorted(v) for k, v in sorted(by_data_source.items())},
        }

    def rebuild_index(self) -> Path:
        """Regenerate ``catalog/INDEX.yml`` from every catalog record on disk."""
        index = self.build_index()
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
    if not catalog_dir(workspace).is_dir():
        return set()
    return {det_id for det_id, _path, _data in Catalog(workspace).iter_records()}


__all__ = [
    "Catalog",
    "CatalogRecord",
    "NoCatalogRecordError",
    "catalog_dir",
    "known_detection_ids",
    "record_from_discovered",
    "record_path",
    "record_platforms",
]
