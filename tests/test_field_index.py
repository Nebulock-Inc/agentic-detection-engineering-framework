# tests/test_field_index.py
from pathlib import Path

import yaml

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.corpus import build_corpus, CorpusEntry
from adef.core.field_index import _build_alias_maps, build_field_index
from adef.core.journal import Journal


def _rec(rid: str, title: str, query: str, lang: str, fmt: str, source: str) -> CatalogRecord:
    r = CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format=fmt,
        query=query, mitre=["T1218.005"],
        query_language=lang, data_source=source,
    )
    return r


def _ws(tmp_path: Path, records, schema: dict | None = None) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in records:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()
    if schema is not None:
        (ws / "schema").mkdir()
        (ws / "schema" / f"{schema['source']}.yml").write_text(
            yaml.safe_dump(schema), encoding="utf-8"
        )
    return ws


SIGMA = """
detection:
  selection:
    Image|endswith: '\\mshta.exe'
    ParentImage|endswith: '\\excel.exe'
  condition: selection
"""

# Backtick-quoted: in SQL an unquoted `process.name` is a qualified
# reference (table `process`, column `name`), so the parser would silently
# lose the dotted field name; a quoted identifier is one column.
SQL = "SELECT * FROM wineventlog WHERE `process.name` = 'mshta.exe' AND `parent.name` = 'excel.exe'"


def _schema_with_aliases() -> dict:
    return {
        "schema_version": 2,
        "source": "wineventlog",
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            {"name": "parent.name", "type": "string", "aliases": ["ParentImage"]},
        ],
    }


def _schema_without_aliases() -> dict:
    s = _schema_with_aliases()
    for f in s["fields"]:
        f["aliases"] = []
    return s


def test_cross_language_match_when_aliases_declared(tmp_path):
    # The headline case: same behaviour, two languages, zero shared tokens.
    # A noise record with an unrelated field keeps the corpus above 2
    # detections so `process.name`/`parent.name` aren't trivially
    # "universal" (df == N) — a degenerate 2-detection corpus can't
    # distinguish "these two are related" from "everything here is
    # universal because there's nothing else to compare against."
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "mshta sql", SQL, "sql", "sql", "wineventlog"),
        _rec("D-0003", "noise", "SELECT * FROM t WHERE `noise.field` = 'x'",
             "sql", "sql", "unrelated"),
    ], schema=_schema_with_aliases())
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    assert "D-0002" in [h.detection_id for h in idx.candidates("D-0001", top_k=5)]


def test_no_cross_language_match_without_aliases_and_it_says_so(tmp_path):
    # Same pair, schema declared but alias-less: `Image` and `process.name`
    # share nothing. The state must be reported, not silently degraded.
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "mshta sql", SQL, "sql", "sql", "wineventlog"),
    ], schema=_schema_without_aliases())
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "declared_no_aliases"
    assert idx.candidates("D-0001", top_k=5) == []


def test_unmatched_when_no_schema_addresses_the_source(tmp_path):
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "mshta sql", SQL, "sql", "sql", "wineventlog"),
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "unmatched"


def test_same_language_structural_match_still_works_unmatched(tmp_path):
    # Degrading to raw names is not degrading to useless: two SQL rules over
    # the same fields still find each other with no schema at all. Noise
    # record keeps N > 2 so the shared fields aren't trivially "universal".
    other = "SELECT * FROM wineventlog WHERE `process.name` = 'rundll32.exe' AND `parent.name` = 'word.exe'"
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sql", SQL, "sql", "sql", "wineventlog"),
        _rec("D-0002", "rundll sql", other, "sql", "sql", "wineventlog"),
        _rec("D-0003", "noise", "SELECT * FROM t WHERE `noise.field` = 'z'",
             "sql", "sql", "unrelated"),
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert "D-0002" in [h.detection_id for h in idx.candidates("D-0001", top_k=5)]


def test_a_ubiquitous_field_does_not_by_itself_create_matches(tmp_path):
    # The IDF property. Every rule reads process.name; that must carry almost
    # no weight, or every Windows rule matches every other.
    recs = [
        _rec(f"D-000{i}", f"r{i}",
             f"SELECT * FROM t WHERE `process.name` = 'p{i}.exe'", "sql", "sql", "t")
        for i in range(1, 6)
    ]
    ws = _ws(tmp_path, recs, schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.candidates("D-0001", top_k=5) == []


def test_two_universal_fields_together_still_do_not_create_a_match(tmp_path):
    # Generalizes the property above from one field to a *set*. The old
    # gate compared the SUMMED shared weight against a single-field floor,
    # so two universal fields together (2 * log(2)) cleared a one-field
    # floor even though neither carries any signal alone — e.g. a
    # Windows-only Sigma corpus where every rule reads both `Image` and
    # `EventID`. Every one of 5 rules here reads exactly `process.name`
    # AND `event.id`; both are universal (df == N == 5).
    recs = [
        _rec(f"D-000{i}", f"r{i}",
             f"SELECT * FROM t WHERE `process.name` = 'p{i}.exe' AND `event.id` = '{i}'",
             "sql", "sql", "t")
        for i in range(1, 6)
    ]
    ws = _ws(tmp_path, recs, schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.candidates("D-0001", top_k=5) == []


def test_a_rare_shared_field_does_create_a_match(tmp_path):
    # Control for the test above: same shape, but the shared field is rare.
    recs = [
        _rec("D-0001", "a", "SELECT * FROM t WHERE `process.name`='x' AND `rare.field`='y'",
             "sql", "sql", "t"),
        _rec("D-0002", "b", "SELECT * FROM t WHERE `process.name`='z' AND `rare.field`='w'",
             "sql", "sql", "t"),
    ] + [
        _rec(f"D-001{i}", f"n{i}", f"SELECT * FROM t WHERE `process.name`='n{i}'", "sql", "sql", "t")
        for i in range(1, 5)
    ]
    ws = _ws(tmp_path, recs, schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert "D-0002" in [h.detection_id for h in idx.candidates("D-0001", top_k=5)]


def test_superset_rule_surfaces_against_its_subset(tmp_path):
    # The containment property: B is A plus extra conditions.
    a = "SELECT * FROM t WHERE `alpha.one`='x' AND `beta.two`='y'"
    b = "SELECT * FROM t WHERE `alpha.one`='x' AND `beta.two`='y' AND `gamma.three`='z' AND `delta.four`='w'"
    noise = [
        _rec(f"D-010{i}", f"n{i}", f"SELECT * FROM t WHERE `other.{i}`='v'", "sql", "sql", "t")
        for i in range(1, 5)
    ]
    ws = _ws(tmp_path, [
        _rec("D-0001", "narrow", a, "sql", "sql", "t"),
        _rec("D-0002", "broad", b, "sql", "sql", "t"),
    ] + noise, schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert "D-0002" in [h.detection_id for h in idx.candidates("D-0001", top_k=5)]


def test_single_detection_corpus_does_not_divide_by_zero(tmp_path):
    # Review Focus 1.
    ws = _ws(tmp_path, [_rec("D-0001", "only", SQL, "sql", "sql", "t")], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.candidates("D-0001", top_k=5) == []


def test_a_query_with_no_extractable_fields_scores_nothing(tmp_path):
    # Review Focus 2: parses fine, yields an empty field set.
    ws = _ws(tmp_path, [
        _rec("D-0001", "empty", "SELECT 1", "sql", "sql", "t"),
        _rec("D-0002", "real", SQL, "sql", "sql", "t"),
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.candidates("D-0001", top_k=5) == []


def test_unparseable_format_is_reported_not_fatal(tmp_path):
    ws = _ws(tmp_path, [
        _rec("D-0001", "weird", "some text", "", "unknown-format", "t"),
        _rec("D-0002", "real", SQL, "sql", "sql", "t"),
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "unparseable"
    assert idx.candidates("D-0001", top_k=5) == []


def test_conflicting_aliases_across_sources_resolve_deterministically(tmp_path, monkeypatch):
    # Review Focus 3, revised: two sources claim the same alias ("Image")
    # for different canonical names. The original version of this test only
    # asserted that two calls to build_field_index *agreed with each
    # other* — which is satisfied even by a wrong answer, as long as it's
    # the same wrong answer every time. That's exactly what the old global
    # alias map did: whichever source sorted first won "Image" for every
    # rule in the corpus, including rules that never addressed that source.
    #
    # The fix scopes alias resolution per source, so there is no shared
    # namespace left for the two sources to collide in at all: each keeps
    # its OWN "Image" mapping, correctly, independent of the other. Assert
    # that directly — the right answer for both, not mere agreement — with
    # the schema-file glob order reversed as a belt-and-suspenders check
    # that nothing here depends on directory listing order.
    ws = _ws(tmp_path, [_rec("D-0001", "a", SQL, "sql", "sql", "wineventlog")],
             schema=_schema_with_aliases())
    (ws / "schema" / "otherlog.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "otherlog",
        "fields": [{"name": "different.canonical", "type": "string", "aliases": ["Image"]}],
    }), encoding="utf-8")

    real_glob = Path.glob

    def reversed_glob(self, pattern, *args, **kwargs):
        return list(reversed(list(real_glob(self, pattern, *args, **kwargs))))

    monkeypatch.setattr(Path, "glob", reversed_glob)
    for _ in range(2):
        alias_maps = _build_alias_maps(ws)[0]
        assert alias_maps["wineventlog"]["image"] == "process.name"
        assert alias_maps["otherlog"]["image"] == "different.canonical"


def test_a_malformed_schema_does_not_abort_the_alias_map(tmp_path):
    # Review Focus 4.
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "mshta sql", SQL, "sql", "sql", "wineventlog"),
    ], schema=_schema_with_aliases())
    (ws / "schema" / "broken.yml").write_text("{{{ not yaml", encoding="utf-8")
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"


def test_unmatched_source_alias_does_not_contaminate_cross_language_match(tmp_path):
    # An unrelated source that happens to declare the same alias for a
    # different canonical field must never influence a rule that never
    # addressed it. Before the fix, `_build_alias_map` merged every source's
    # aliases into one global dict keyed only on the alias string, so `aaa`
    # (sorting before `wineventlog`) silently won the `Image` collision for
    # a rule that only ever addressed `wineventlog` — losing the
    # cross-language match this feature exists to deliver. Noise record
    # keeps N > 2 so process.name/parent.name aren't trivially "universal".
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "mshta sql", SQL, "sql", "sql", "wineventlog"),
        _rec("D-0003", "noise", "SELECT * FROM t WHERE `noise.field` = 'q'",
             "sql", "sql", "somethingelse"),
    ], schema=_schema_with_aliases())
    (ws / "schema" / "aaa.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "aaa",
        "fields": [{"name": "wrong.field", "type": "string", "aliases": ["Image"]}],
    }), encoding="utf-8")
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    assert "D-0002" in [h.detection_id for h in idx.candidates("D-0001", top_k=5)]


def test_multi_source_match_resolves_alias_by_precedence(tmp_path):
    # A rule whose address literal matches TWO declared sources at once
    # (both scope the same literal), each claiming the same alias for a
    # different canonical field. Precedence: sorted alphabetically among
    # the sources this rule actually matched, earliest wins — same
    # tie-break rule as the single-source collision case, just correctly
    # scoped to only the sources in play for this rule.
    ws = _ws(tmp_path, [
        _rec("D-0001", "multi", "SELECT * FROM t WHERE `Foo` = 'x'", "sql", "sql", "shared"),
        _rec("D-0002", "alpha-direct", "SELECT * FROM t WHERE `alpha.canonical` = 'x'",
             "sql", "sql", "alpha"),
        _rec("D-0003", "beta-direct", "SELECT * FROM t WHERE `beta.canonical` = 'x'",
             "sql", "sql", "beta"),
    ], schema=None)
    (ws / "schema").mkdir()
    for source_name, canonical in [("alpha", "alpha.canonical"), ("beta", "beta.canonical")]:
        (ws / "schema" / f"{source_name}.yml").write_text(yaml.safe_dump({
            "schema_version": 2, "source": source_name,
            "scope": {"index": "shared"},
            "fields": [{"name": canonical, "type": "string", "aliases": ["Foo"]}],
        }), encoding="utf-8")
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    # "alpha" sorts before "beta", so alpha's declaration wins the
    # collision: `Foo` resolves to `alpha.canonical`, matching D-0002 (which
    # reads that canonical name directly) and NOT D-0003 (beta's).
    hit_ids = [h.detection_id for h in idx.candidates("D-0001", top_k=5)]
    assert "D-0002" in hit_ids
    assert "D-0003" not in hit_ids


def test_most_specific_source_wins_over_a_broader_container_match(tmp_path):
    # `schema check` (adef/commands/schema.py) selects sources by literal-
    # match *count*, keeping only the ones tied at the max, not a plain
    # union — a specificity heuristic. This is the only SPL test in this
    # suite: a rule's broad `data_source` container literal addresses
    # `aaawide` (1 literal match), while its SPL `sourcetype=` shape literal
    # is more specific and addresses `zzzspecific` alone — but `zzzspecific`
    # ALSO shares the broad container literal, so it accumulates 2 matches
    # to `aaawide`'s 1. Naming the sources so the WRONG (broad) one sorts
    # first alphabetically makes this decisive: a union+alphabetical
    # resolution would pick `aaawide`, count-based selection picks
    # `zzzspecific`.
    ws = _ws(tmp_path, [
        _rec("D-0001", "spl multi", "search sourcetype=specific:sourcetype Foo=1",
             "spl", "spl", "broadcontainer"),
        _rec("D-0002", "specific-direct", "SELECT * FROM t WHERE `right.field` = 'x'",
             "sql", "sql", "zzzspecific"),
        _rec("D-0003", "wide-direct", "SELECT * FROM t WHERE `wrong.field` = 'x'",
             "sql", "sql", "aaawide"),
    ], schema=None)
    (ws / "schema").mkdir()
    (ws / "schema" / "aaawide.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "aaawide",
        "scope": {"index": "broadcontainer"},
        "fields": [{"name": "wrong.field", "type": "string", "aliases": ["Foo"]}],
    }), encoding="utf-8")
    (ws / "schema" / "zzzspecific.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "zzzspecific",
        "scope": {"index": "broadcontainer", "sourcetype": "specific:sourcetype"},
        "fields": [{"name": "right.field", "type": "string", "aliases": ["Foo"]}],
    }), encoding="utf-8")
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    hit_ids = [h.detection_id for h in idx.candidates("D-0001", top_k=5)]
    assert "D-0002" in hit_ids       # Foo -> right.field, via zzzspecific
    assert "D-0003" not in hit_ids   # NOT aaawide's wrong.field


SIGMA_MIXED = """
detection:
  selection:
    Image|endswith: '\\mshta.exe'
    CommandLine|contains: 'suspicious'
  condition: selection
"""


def _schema_mixed_with_aliases() -> dict:
    return {
        "schema_version": 2,
        "source": "wineventlog",
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            {"name": "process.command_line", "type": "string", "aliases": ["CommandLine"]},
        ],
    }


def test_mixed_vocabulary_schema_target_still_matches_unmatched_candidate(tmp_path):
    # I-1 (final whole-branch review). Two byte-identical Sigma rules reading
    # Image + CommandLine: one's source has a schema+aliases declared
    # (state `schema`), the other's source is undeclared (state `unmatched`).
    # Before the fix, the declared rule's fields were REPLACED by their
    # canonical form (`process.name`/`process.command_line`), losing `image`/
    # `commandline` entirely -- so it shared nothing with the undeclared
    # rule's still-literal fields, even though they read the identical
    # literal names. `adef schema ingest` (the feature's own remedy for
    # `unmatched`) made this pair's field retrieval strictly worse than
    # declaring nothing. The fix indexes the union of literal and canonical
    # forms, so canonicalization can only ever ADD recall.
    ws = _ws(tmp_path, [
        _rec("D-0001", "declared", SIGMA_MIXED, "", "sigma", "wineventlog"),
        _rec("D-0002", "undeclared, byte-identical fields", SIGMA_MIXED, "", "sigma", "elsewhere"),
        _rec("D-0003", "noise", "SELECT * FROM t WHERE `noise.field` = 'q'",
             "sql", "sql", "unrelated"),
    ], schema=_schema_mixed_with_aliases())
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    assert idx.matching_for("D-0002") == "unmatched"
    hits = {h.detection_id: h for h in idx.candidates("D-0001", top_k=5)}
    assert "D-0002" in hits
    # The match must ride the literal form -- D-0002 never learned the
    # canonical names, so `process.name`/`process.command_line` can't be
    # what's shared.
    assert set(hits["D-0002"].shared_fields) & {"image", "commandline"}


def test_conflicting_alias_declarations_do_not_bleed_through_the_literal_fallback(tmp_path):
    # CodeRabbit finding against the I-1 fix above, same fix wave: the union
    # (literal + canonical) must not reopen the exact cross-source bleed
    # `_build_alias_maps` scopes per-source. Two DIFFERENT declared sources
    # each alias `Image` to a DIFFERENT canonical field -- an explicit,
    # first-class disagreement about what the spelling means. Keeping the
    # bare literal `image` in both rules' index regardless would let them
    # match each other directly through it, silently overriding what their
    # own schemas say. Each rule also carries a distinct rare field so the
    # match-or-no-match verdict rests entirely on whether `image` itself
    # was allowed to carry the match.
    ws = _ws(tmp_path, [
        _rec("D-0001", "wineventlog rule",
             "SELECT * FROM t WHERE `Image` = 'x' AND `rare1.field`='a'",
             "sql", "sql", "wineventlog"),
        _rec("D-0002", "otherlog rule",
             "SELECT * FROM t WHERE `Image` = 'y' AND `rare2.field`='b'",
             "sql", "sql", "otherlog"),
    ] + [
        _rec(f"D-050{i}", f"noise{i}", f"SELECT * FROM t WHERE `noise{i}.field`='z'",
             "sql", "sql", "unrelated")
        for i in range(1, 4)
    ], schema={
        "schema_version": 2, "source": "wineventlog",
        "fields": [{"name": "process.name", "type": "string", "aliases": ["Image"]}],
    })
    (ws / "schema" / "otherlog.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "otherlog",
        "fields": [{"name": "different.canonical", "type": "string", "aliases": ["Image"]}],
    }), encoding="utf-8")
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    assert idx.matching_for("D-0002") == "schema"
    hit_ids = [h.detection_id for h in idx.candidates("D-0001", top_k=5)]
    assert "D-0002" not in hit_ids


def test_a_within_source_duplicate_alias_is_not_a_cross_source_conflict(tmp_path):
    # CodeRabbit finding, round 2, same fix wave: the conflict check above
    # must compare RESOLVED per-source mappings across DIFFERENT sources,
    # not raw field declarations. A single source that (mistakenly) declares
    # the same alias for two different fields already resolves to one
    # canonical via `_build_alias_maps`'s first-field-wins; that is not a
    # cross-source disagreement, and must not suppress the literal fallback
    # for an unrelated, undeclared rule elsewhere reading the same spelling
    # -- the exact I-1 case this whole fix wave restores.
    ws = _ws(tmp_path, [
        _rec("D-0001", "wineventlog rule",
             "SELECT * FROM t WHERE `Image` = 'x' AND `rare1.field`='a'",
             "sql", "sql", "wineventlog"),
        _rec("D-0002", "undeclared, same literal",
             "SELECT * FROM t WHERE `Image` = 'y' AND `rare2.field`='b'",
             "sql", "sql", "elsewhere"),
    ] + [
        _rec(f"D-060{i}", f"noise{i}", f"SELECT * FROM t WHERE `noise{i}.field`='z'",
             "sql", "sql", "unrelated")
        for i in range(1, 4)
    ], schema={
        "schema_version": 2, "source": "wineventlog",
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            # Duplicate declaration of the SAME alias for a DIFFERENT field,
            # within this one source -- resolves to `process.name` (first
            # field wins), not a genuine conflict.
            {"name": "other.thing", "type": "string", "aliases": ["Image"]},
        ],
    })
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"
    assert idx.matching_for("D-0002") == "unmatched"
    hit_ids = [h.detection_id for h in idx.candidates("D-0001", top_k=5)]
    assert "D-0002" in hit_ids


def test_containment_ratio_is_exactly_one_for_a_subset_target(tmp_path):
    # m-1: ADEF uses IDF-weighted containment (shared weight / the
    # SMALLER side's weight) over two named alternatives -- Jaccard and plain
    # (unweighted) containment -- specifically because a strict
    # subset/superset pair scores exactly 1.0 from the narrower side. Nothing
    # before this test distinguished that from `max` (denominator = the
    # LARGER side): membership in top-5 is satisfied by all of min/max/
    # Jaccard/unweighted-containment alike, so swapping `min` for `max` in
    # `field_index.py:208` kept every prior test green. Asserting the exact
    # ratio value is the only assertion `max` fails.
    a = "SELECT * FROM t WHERE `alpha.one`='x' AND `beta.two`='y'"
    b = "SELECT * FROM t WHERE `alpha.one`='x' AND `beta.two`='y' AND `gamma.three`='z' AND `delta.four`='w'"
    noise = [
        _rec(f"D-010{i}", f"n{i}", f"SELECT * FROM t WHERE `other.{i}`='v'", "sql", "sql", "t")
        for i in range(1, 5)
    ]
    ws = _ws(tmp_path, [
        _rec("D-0001", "narrow", a, "sql", "sql", "t"),
        _rec("D-0002", "broad", b, "sql", "sql", "t"),
    ] + noise, schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    hit = next(h for h in idx.candidates("D-0001", top_k=5) if h.detection_id == "D-0002")
    assert hit.score == 1.0


def test_a_malformed_query_does_not_abort_the_whole_run(tmp_path, monkeypatch):
    # m-5: `_fields_for`'s `except Exception: return None` runs over every
    # record on every refine. Its docstring promises a malformed query is
    # "data, not a crash" -- pin that a raising extractor degrades only the
    # one record it hit, not the whole build.
    import adef.core.field_index as fi

    real_sql = fi._EXTRACTORS["sql"]

    def flaky(query: str):
        if "BOOM" in query:
            raise ValueError("simulated malformed-query failure")
        return real_sql(query)

    monkeypatch.setitem(fi._EXTRACTORS, "sql", flaky)
    ws = _ws(tmp_path, [
        _rec("D-0001", "bad", "SELECT * FROM t WHERE BOOM", "sql", "sql", "t"),
        _rec("D-0002", "good", SQL, "sql", "sql", "wineventlog"),
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)  # must not raise
    assert idx.matching_for("D-0001") == "unparseable"
    assert idx.matching_for("D-0002") != "unparseable"


def test_extractor_routing_matches_schema_checks_query_language_precedence(tmp_path):
    # m-6: `adef schema check`'s routing (`data.get("query_language") or
    # data.get("format", "")`) only falls back to `format` when
    # `query_language` is absent -- never merely because it names something
    # unrecognized. A record tagged `query_language: eql, format: sigma` is
    # `unparseable` there; `_extractor_key` must agree, not silently fall
    # through to the sigma extractor and disagree with the command this
    # feature's own remedies send users to.
    ws = _ws(tmp_path, [
        _rec("D-0001", "eql-tagged", SIGMA, "eql", "sigma", "wineventlog"),
        _rec("D-0002", "real sql", SQL, "sql", "sql", "wineventlog"),
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "unparseable"


def _entry(rid: str, query: str, source: str = "t") -> CorpusEntry:
    return CorpusEntry(
        detection_id=rid,
        record={
            "id": rid, "title": rid, "engine": "sql", "format": "sql",
            "query_language": "sql", "query": query, "data_source": source,
            "platform": "windows", "mitre": [],
        },
    )


def test_candidates_tie_break_is_by_detection_id_not_insertion_order(tmp_path):
    # m-7 (part 1): two candidates score identically against the target;
    # the declared tie-break is `(-score, detection_id)`, but `build_corpus`
    # always hands `build_field_index` entries pre-sorted by id, so a
    # corpus-driven fixture can never tell "the explicit id tie-break did
    # it" apart from "the input just happened to already be alphabetical".
    # Calling `build_field_index` directly with entries in a DELIBERATELY
    # non-alphabetical order defeats that: Python's stable sort would
    # otherwise preserve the (wrong) insertion order for the tie.
    target_q = "SELECT * FROM t WHERE `a.rare`='x' AND `b.rare`='y'"
    same_q = "SELECT * FROM t WHERE `a.rare`='p' AND `b.rare`='q'"
    entries = [
        _entry("D-0009", same_q),
        _entry("D-0001", target_q),
        _entry("D-0002", same_q),
        _entry("D-0301", "SELECT * FROM t WHERE `n1.f`='v'"),
        _entry("D-0302", "SELECT * FROM t WHERE `n2.f`='v'"),
    ]
    idx = build_field_index(entries, tmp_path / "no-such-workspace")
    hits = idx.candidates("D-0001", top_k=5)
    tied = [h for h in hits if h.detection_id in {"D-0002", "D-0009"}]
    assert len(tied) == 2
    assert tied[0].score == tied[1].score
    assert [h.detection_id for h in tied] == ["D-0002", "D-0009"]


def test_shared_fields_are_alphabetically_sorted(tmp_path):
    # m-7 (part 2): `FieldHit.shared_fields` is `sorted(shared)`, not
    # `list(shared)` -- a plain frozenset's iteration order isn't
    # alphabetical, and this is user-visible (`agent` output, the LLM
    # prompt) as well as feeding RRF rank order.
    names = ["zzz.rare", "yyy.rare", "xxx.rare", "www.rare", "aaa.rare"]

    def q(id_char: str) -> str:
        return "SELECT * FROM t WHERE " + " AND ".join(
            f"`{n}`='{id_char}'" for n in names
        )

    ws = _ws(tmp_path, [
        _rec("D-0001", "target", q("1"), "sql", "sql", "t"),
        _rec("D-0002", "match", q("2"), "sql", "sql", "t"),
    ] + [
        _rec(f"D-040{i}", f"noise{i}", f"SELECT * FROM t WHERE `n{i}.f`='v'", "sql", "sql", "t")
        for i in range(1, 3)
    ], schema=None)
    idx = build_field_index(build_corpus(ws), ws)
    hit = next(h for h in idx.candidates("D-0001", top_k=5) if h.detection_id == "D-0002")
    assert hit.shared_fields == sorted(names)


def test_a_malformed_field_entry_does_not_abort_the_alias_map(tmp_path):
    # A schema file that IS valid v2 YAML (so `read_schema_v2` accepts it)
    # but whose `fields` list has a non-mapping entry, e.g. a stray `- ` in
    # hand-edited YAML producing a null. Unlike the whole-file-unparseable
    # case above, `read_schema_v2` can't filter this out for us.
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "mshta sql", SQL, "sql", "sql", "wineventlog"),
    ], schema=_schema_with_aliases())
    (ws / "schema" / "alsobad.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "alsobad",
        "fields": [None, {"name": "process.name", "aliases": ["Image"]}],
    }), encoding="utf-8")
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") == "schema"


def test_spl_routing_pseudo_fields_are_not_shared_fields(tmp_path):
    # `index`/`sourcetype` are pinned by every SPL rule; in a mixed-language
    # corpus they are not universal (df < N), so without the routing filter
    # two unrelated SPL rules field-match on routing alone.
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", "index=win sourcetype=sec EventCode=4688", "spl", "spl", "win"),
        _rec("D-0002", "b", "index=win sourcetype=sec LogonType=10", "spl", "spl", "win"),
        _rec("D-0003", "c", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0004", "d", SQL, "sql", "sql", "wineventlog"),
    ])
    assert build_field_index(build_corpus(ws), ws).candidates("D-0001", 10) == []


def test_empty_extraction_is_unparseable_and_does_not_disable_the_ubiquitous_gate(tmp_path):
    # Real extractors never raise on bad input — they return an empty set.
    # Malformed SQL and keyword-only Sigma must report `unparseable`, and must
    # not count toward N (which would make the universal `Image` look rare).
    img = "detection:\n  s:\n    Image|endswith: '{}'\n  condition: s\n"
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", img.format("x.exe"), "", "sigma", "w"),
        _rec("D-0002", "b", img.format("y.exe"), "", "sigma", "w"),
        _rec("D-0003", "kw", "detection:\n  keywords:\n    - mimikatz\n  condition: keywords\n",
             "", "sigma", "w"),
        _rec("D-0004", "bad", "SELECT * FROM w WHERE ((( `process.name` =", "sql", "sql", "w"),
    ])
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0003") == "unparseable"
    assert idx.matching_for("D-0004") == "unparseable"
    assert idx.candidates("D-0001", 10) == []


def test_a_scalar_alias_is_one_alias_not_its_characters(tmp_path):
    ws = _ws(tmp_path, [_rec("D-0001", "a", SIGMA, "", "sigma", "wineventlog")], schema={
        "schema_version": 2, "source": "wineventlog",
        "fields": [{"name": "process.name", "type": "string", "aliases": "Image"}],
    })
    source_map = _build_alias_maps(ws)[0]["wineventlog"]
    assert source_map.get("image") == "process.name"
    assert "i" not in source_map


# --- The field pass reads PREDICATE fields: what a rule filters on, not what it
# groups or projects. Found by the 2026-09-28 trial on Splunk ESCU: every
# `tstats ... BY <same datamodel columns>` rule scored 1.0 against every other.

ESCU = """| tstats `summariesonly` count min(_time) as firstTime FROM datamodel=Endpoint.Processes
  WHERE Processes.{field}={value}
  BY Processes.action Processes.dest Processes.user
     Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`"""


def _escu_ws(tmp_path, where_fields):
    # Three ESCU rules sharing one BY list, plus two non-SPL rules so the BY
    # columns sit in 3 of 5 detections — rare enough to pass the ubiquitous
    # gate, so the OLD extractor really does match on them (not a degenerate
    # corpus where the gate hides the bug).
    recs = [_rec(f"D-000{i}", f"escu {i}", ESCU.format(field=f, value="x.exe"),
                 "spl", "splunk-escu", "Sysmon EventID 1")
            for i, f in enumerate(where_fields, start=1)]
    recs += [_rec("D-0008", "sigma", SIGMA, "", "sigma", "wineventlog"),
             _rec("D-0009", "sql", SQL, "sql", "sql", "wineventlog")]
    return _ws(tmp_path, recs)


def test_shared_group_by_columns_are_not_shared_logic(tmp_path):
    ws = _escu_ws(tmp_path, ["parent_process_name", "original_file_name", "process_hash"])
    hits = build_field_index(build_corpus(ws), ws).candidates("D-0001", 10)
    assert [h.detection_id for h in hits] == [], [(h.detection_id, h.shared_fields) for h in hits]


def test_shared_predicate_field_still_matches_across_different_group_by(tmp_path):
    ws = _escu_ws(tmp_path, ["parent_process_name", "parent_process_name", "process_hash"])
    hits = build_field_index(build_corpus(ws), ws).candidates("D-0001", 10)
    assert [(h.detection_id, h.shared_fields) for h in hits] == [
        ("D-0002", ["processes.parent_process_name"])]


def test_predicate_extractors_drop_projections_outputs_and_routing():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    spl = ('index=win sourcetype=sec EventCode=4688 New_Process_Name="*mshta.exe" '
           '| eval p=lower(New_Process_Name) | stats count by host, user | table host user')
    assert P["spl"](spl) == {"EventCode", "New_Process_Name", "index", "sourcetype"}
    assert P["spl"](ESCU.format(field="parent_process_name", value="x")) == {
        "Processes.parent_process_name"}
    kql = ('DeviceProcessEvents | where FileName =~ "mshta.exe" and InitiatingProcessFileName == "x" '
           '| extend lc = tolower(ProcessCommandLine) | project DeviceName, AccountName '
           '| summarize n = count() by DeviceName')
    assert P["kql"](kql) == {"FileName", "InitiatingProcessFileName"}
    sql = ("SELECT user, host, count(*) AS n FROM w WHERE `process.name` = 'mshta.exe' "
           "GROUP BY user, host HAVING count(*) > 5")
    assert P["sql"](sql) == {"process.name"}
    assert P["sql"]("`process.name` = 'x' AND `parent.name` LIKE '%y%'") == {
        "process.name", "parent.name"}
    cql = '#event_simpleName=ProcessRollup2 ImageFileName=/mshta/i | groupBy([ComputerName])'
    assert P["cql"](cql) == {"ImageFileName"}


def test_datamodel_is_routing_not_a_field():
    from adef.core.rule_parser import routing_fields

    assert {"datamodel", "nodename"} <= routing_fields("spl")


def test_spl_in_list_is_a_predicate_for_both_extractors():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS, extract_spl_fields

    q = "| tstats count FROM datamodel=Endpoint.Processes WHERE Processes.process IN (*create*, *addfile*) BY Processes.dest"
    assert PREDICATE_FIELD_EXTRACTORS["spl"](q) == {"Processes.process"}
    assert "Processes.process" in extract_spl_fields(q)  # schema check sees it too


# --- Stage-aware predicate extraction (CodeRabbit). A comparison is a
# predicate only in a FILTER stage, and a name is an output only if a stage
# BEFORE the filter assigned it.

def test_later_assignment_does_not_erase_an_earlier_filter():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["spl"]("ProcessName=evil | eval ProcessName=lower(ProcessName)") == {"ProcessName"}
    assert P["kql"]('T | where FileName == "mshta.exe" | extend FileName = tolower(FileName)') == {"FileName"}
    # ...while a name assigned BEFORE the filter is still an output, not an event field
    assert P["spl"]('a=1 | eval p=lower(a) | where p="x"') == {"a"}
    assert P["kql"]('T | where A == 1 | extend lc = tolower(X) | where lc == "a"') == {"A"}


def test_comparisons_inside_computed_outputs_are_not_predicates():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["kql"]('T | where A == 1 | extend flag = iff(DeviceName == "host", 1, 0)') == {"A"}
    assert P["spl"]('A=1 | eval flag=if(B=="x",1,0)') == {"A"}


def test_kql_project_rename_output_is_not_a_predicate():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["kql"]('T | where A == "x" | project-rename FriendlyName = FileName') == {"A"}


def test_kql_string_operators_are_predicates_for_both_extractors():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P, extract_kql_fields

    q = ('DeviceProcessEvents | where FileName has "mshta" and ProcessCommandLine contains "http" '
         'and InitiatingProcessFileName in~ ("winword.exe") and FolderPath startswith "C:"')
    want = {"FileName", "ProcessCommandLine", "InitiatingProcessFileName", "FolderPath"}
    assert P["kql"](q) == want
    assert want <= extract_kql_fields(q)


def test_sql_prewhere_is_a_predicate_and_subquery_projections_are_not():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["sql"]("SELECT * FROM events PREWHERE EventCode = 4688") == {"EventCode"}
    assert P["sql"](
        "SELECT 1 FROM events WHERE EXISTS "
        "(SELECT display_name FROM related WHERE related.id = events.id)"
    ) == {"id"}
    assert P["sql"]("`a` = 1 AND `b` IN (SELECT c FROM t WHERE d = 2)") == {"a", "b", "d"}


def test_routing_fields_are_per_language(tmp_path):
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P, routing_fields

    assert {"field", "host", "span", "datamodel"} <= routing_fields("spl")
    assert not ({"field", "host", "window"} & routing_fields("sql"))
    # an SPL command parameter is not in a filter stage at all
    assert P["spl"](r'a=1 | rex field=_raw "(?<user>\w+)" | search user=bob') == {"a"}
    # ...and a SQL column that happens to be called `field` is an ordinary field
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", "SELECT * FROM t WHERE `field` = 'x'", "sql", "sql", "t"),
        _rec("D-0002", "b", "SELECT * FROM t WHERE `field` = 'y'", "sql", "sql", "t"),
        _rec("D-0003", "c", SIGMA, "", "sigma", "wineventlog"),
    ])
    idx = build_field_index(build_corpus(ws), ws)
    assert idx.matching_for("D-0001") != "unparseable"
    assert [h.detection_id for h in idx.candidates("D-0001", 5)] == ["D-0002"]


def test_a_filter_on_a_renamed_column_reads_the_original_field():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["kql"]('T | project-rename FriendlyName = FileName | where FriendlyName == "x"') == {"FileName"}
    assert P["spl"]('index=a | rename Image AS proc | search proc="x.exe"') == {"index", "Image"}



def test_cql_function_parameters_are_not_fields():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P, extract_cql_fields

    q = ('#event_simpleName=ProcessRollup2 ImageFileName=/mshta/i '
         '| groupBy([aid], function=count(as=cnt), limit=max) | bucket(span=1h)')
    assert P["cql"](q) == {"ImageFileName"}
    assert extract_cql_fields(q) == {"#event_simpleName", "ImageFileName"}  # schema check: no span/limit
    # the field a function tests is its `field=` argument
    assert P["cql"]('in(field="FileName", values=["a.exe", "b.exe"])') == {"FileName"}


def test_kql_summarize_default_output_names_are_outputs():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["kql"]('SigninLogs | where ResultType == "50126" | summarize count() by IPAddress '
                    '| where count_ > 10') == {"ResultType"}
    assert P["kql"]('T | where A == 1 | summarize dcount(DeviceId) by U | where dcount_DeviceId > 3') == {"A"}


def test_quotes_and_comments_do_not_break_pipeline_reading():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P, extract_kql_fields

    q = ('DeviceProcessEvents\n// don\'t alert on signed binaries\n'
         '| where FileName =~ "mshta.exe" | extend lc = tolower(X) | summarize n = count() by D')
    assert P["kql"](q) == {"FileName"}
    verbatim = ('DeviceProcessEvents | where FolderPath startswith @"C:\\Users\\" '
                '| extend lc = tolower(ProcessCommandLine) | summarize n = count() by DeviceName')
    assert P["kql"](verbatim) == {"FolderPath"}
    phantom = ('SigninLogs | where ResultDescription has "Sign in was blocked" '
               '// find processes in temp\n| where A == 1')
    assert P["kql"](phantom) == {"ResultDescription", "A"}
    assert not ({"Sign", "processes"} & extract_kql_fields(phantom))
    tstats = ('| tstats count from datamodel=Endpoint.Processes '
              'where Processes.process="* by *" Processes.user=admin by Processes.dest')
    assert P["spl"](tstats) == {"Processes.process", "Processes.user"}


def test_sql_select_aliases_are_outputs():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["sql"]("SELECT user, count(*) AS cnt FROM t WHERE `process.name` = 'mshta.exe' "
                    "GROUP BY user HAVING cnt > 5") == {"process.name"}
    assert P["sql"]("SELECT lower(x) AS p FROM t WHERE p = 'x'") == set()
    assert P["sql"]("SELECT user AS user FROM t WHERE user = 'x'") == {"user"}  # alias of itself


def test_renaming_an_output_keeps_it_an_output():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["spl"]("index=a EventCode=1 | stats count by user | rename count AS total "
                    "| where total > 5") == {"index", "EventCode"}
    assert P["spl"]('index=a | eval p=lower(Image) | rename p AS proc | search proc="x"') == {"index"}
    assert P["kql"]('T | where B == 1 | extend lc = tolower(X) | project-rename L = lc '
                    '| where L == "a"') == {"B"}


def test_self_normalisation_keeps_the_event_field():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["spl"]('index=a | eval Image=lower(Image) | where Image="*\\\\mshta.exe"') == {"index", "Image"}
    assert P["kql"]('T | extend FileName = tolower(FileName) | where FileName == "mshta.exe"') == {"FileName"}


def test_spl_in_function_and_keywords_are_not_fields():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P, extract_spl_fields

    assert extract_spl_fields('index=a | where in(process_name, "a.exe")') == {"index", "process_name"}
    assert P["spl"]('index=a | where NOT in(process_name, "a.exe")') == {"index", "process_name"}
    assert P["spl"]('index=a NOT user IN (x, y)') == {"index", "user"}


def test_spl_regex_filters_and_kql_parse_outputs():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    assert P["spl"]('index=a | regex CommandLine="(?i)foo"') == {"index", "CommandLine"}
    assert P["kql"]('T | where A == 1 | parse CommandLine with * "-enc " Encoded " " * '
                    '| where Encoded has "x"') == {"A"}


def test_predicate_and_full_extractor_maps_share_keys():
    from adef.core.rule_parser import FIELD_EXTRACTORS, PREDICATE_FIELD_EXTRACTORS

    assert set(PREDICATE_FIELD_EXTRACTORS) == set(FIELD_EXTRACTORS)


def test_rex_outputs_count_only_from_their_own_stage_onward():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    # the first rex creates only `acct`; `user` is an event field until the SECOND rex
    q = (r'index=a | rex field=_raw "(?<acct>\w+)" | search user=bob '
         r'| rex field=_raw "(?<user>\w+)" | search user=eve')
    assert P["spl"](q) == {"index", "user"}
    q2 = r'index=a | rex field=_raw "(?<acct>\w+)" | search acct=bob'
    assert P["spl"](q2) == {"index"}


def test_a_kql_verbatim_string_ending_in_backslash_does_not_swallow_the_query():
    from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS as P

    q = 'T | where FolderPath startswith @"C:\\Users\\" and FileName == "x.exe" | extend lc = tolower(X)'
    assert P["kql"](q) == {"FolderPath", "FileName"}


def test_cql_field_arguments_in_comments_or_strings_are_not_fields():
    from adef.core.rule_parser import extract_cql_fields

    q = ('ImageFileName=/mshta/i // see in(field="Bogus", values=[1])\n'
         '| CommandLine="regex(field=Phantom)"')
    assert extract_cql_fields(q) == {"ImageFileName", "CommandLine"}


def test_cql_field_text_inside_an_argument_value_is_not_a_parameter():
    from adef.core.rule_parser import extract_cql_fields

    assert extract_cql_fields('in(field="FileName", values=["field=Evil", "b"])') == {"FileName"}
