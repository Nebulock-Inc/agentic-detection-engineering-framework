"""A catalog write can never land outside ``<workspace>/catalog/``.

``platform`` becomes a path segment (``catalog/<platform>/D-XXXX-slug.yml``).
A profile can pull it from rule content (``platform.path``), so a crafted rule
must not be able to steer a write — ``../`` or an absolute value (which makes
``Path.__truediv__`` discard the base entirely).
"""

from __future__ import annotations

import json

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog
from adef.core.catalog import Catalog, CatalogError, CatalogRecord


def _rec(platform: str) -> CatalogRecord:
    return CatalogRecord(
        id="D-0001", title="t", rule_ref="r/x.yml", original_path="/tmp/x.yml",
        platform=platform, kind="atomic", engine="sql", format="sql", query="x=1",
    )


@pytest.mark.parametrize("platform", ["../escaped", "../../escaped", "a/../../b", "ABSOLUTE", ".."])
def test_catalog_write_refuses_a_platform_that_is_not_one_path_segment(tmp_path, platform):
    if platform == "ABSOLUTE":  # an absolute path makes `dir / platform` discard `dir`;
        platform = str(tmp_path / "abs-escape")  # kept inside tmp_path so a regression can't write elsewhere
    ws = tmp_path / "ws"
    ws.mkdir()
    before = {p for p in tmp_path.rglob("*")}
    with pytest.raises(CatalogError, match="platform"):
        Catalog(ws).write(_rec(platform))
    written = {p for p in tmp_path.rglob("*")} - before
    assert not [p for p in written if p.is_file()], written


def test_profile_platform_from_rule_content_cannot_escape_the_catalog(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "config" / "profiles").mkdir(parents=True)
    (ws / "config" / "profiles" / "p.yml").write_text(yaml.safe_dump({
        "name": "evil-export", "version": 1,
        "signature": {"container": "json", "all_keys": ["name", "q", "plat"]},
        "query_language": "sql",
        "map": {"title": "name", "query": "q"},
        "platform": {"path": "plat"},
    }), encoding="utf-8")
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "r.json").write_text(json.dumps({"name": "t", "q": "x=1", "plat": "../../escaped"}))

    result = CliRunner().invoke(catalog, [str(repo)])
    assert result.exit_code == 0, result.output
    assert not (tmp_path / "escaped").exists()
    [(_rid, path, data)] = list(Catalog(ws).iter_records())
    assert path.resolve().is_relative_to((ws / "catalog").resolve())
    assert data["platform"] == "multi-platform"
    assert "no_platform" in data["review_reasons"]


def test_a_symlinked_platform_directory_cannot_redirect_a_write(tmp_path):
    # A valid segment can still escape if catalog/<platform> is a symlink out.
    ws = tmp_path / "ws"
    outside = tmp_path / "outside"
    outside.mkdir()
    (ws / "catalog").mkdir(parents=True)
    (ws / "catalog" / "windows").symlink_to(outside, target_is_directory=True)
    # `windows` passes the plain-segment check, so this is the one case that
    # reaches the resolve guard — the reason both guards exist.
    with pytest.raises(CatalogError, match="resolves outside"):
        Catalog(ws).write(_rec("windows"))
    assert list(outside.iterdir()) == []
