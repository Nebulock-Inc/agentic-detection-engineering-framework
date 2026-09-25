# Corpus Unification — Design

**Story:** Shortcut 10188, part 1 of 2. Part 2 (logic-aware retrieval — the
cross-language matching signal) is a separate spec that builds on this one.

**Goal:** Give ADEF one answer to "which detections exist in this workspace,"
shared by every consumer, and remove the feedback loop where Refine's own
output inflated the scores of the pairs it had already compared.

**Status:** approved design, ready for an implementation plan.

---

## Why this exists

ADEF's Refine stage answers "does a rule like this already exist?" Today it
answers unreliably for three distinct reasons. This spec addresses two of
them; the third is part 2.

### 1. The two agents disagree about what is in the catalog

A detection in an ADEF workspace has up to **two** artifacts, stored
separately and joined only by its `D-XXXX` id:

```
<workspace>/
├── journals/D-0001.md                    # history: append-only stage blocks
└── catalog/<platform>/D-0001-<slug>.yml  # current state: query, platform, MITRE
```

Either can be absent:

| How it was created | Journal | Record |
|---|---|---|
| `adef catalog <repo>` / `adef sync` | skeleton ✓ | ✓ |
| `adef detection new "title"` (no `--source`) | ✓ | **✗** |
| `adef detection new --source <s>` | ✓ | ✓ (draft) |
| journal deleted or never created | **✗** | ✓ |

`RuleSimilarityAgent` walks `journals/`. `RuleOverlapAgent` walks `catalog/`.
In the common case both artifacts exist and nobody notices. In the two bold
rows they silently diverge: a catalogued rule whose journal is missing can be
reported by Overlap as a 98%-similar duplicate in the same Refine run where
Similarity says nothing like it exists.

`adef sync` re-creates missing journals, which is why this has stayed hidden.

### 2. Refine fed its own output back into the retrieval index

`MemoryIndex` indexes journal bodies. `run_refine_chain` appends its results
*to* journal bodies. So each Refine run wrote a neighbour's details into the
target's journal, and the next run scored that pair higher for no new
evidence.

Two attempts to fix this by filtering *content* both failed, and the reason
they failed is the design constraint for this spec:

- Capping rendered values at 300 chars bounded the amplification without
  removing it.
- Omitting the `query` key did nothing, because `MemoryIndex._snippet` builds
  `snippet` from the journal body **plus** `record_search_text(record)`, which
  ends in the record's query. The same text arrived under a different key. The
  ISA, the forge-stage skill, and a PR description all carried the false claim
  that the loop was closed, and the regression test passed because it fed the
  renderer a synthetic payload with no `snippet` key.

**A key-name denylist on a shared renderer cannot make a claim about content.**
This spec cuts the cycle at **provenance** instead — a structural property of
how a block got into the journal, which nothing about its contents can defeat.

### 3. Cross-language blindness — not in this spec

BM25 compares words, so the same detection written in Sigma and in SQL scores
near zero against itself. That is a *recall* problem no reranker can fix, and
it is part 2. Nothing here changes which signals are used for scoring — only
which detections are in the corpus and which text is indexed.

---

## Non-goals

- The cross-language / field-set overlap signal (part 2).
- AST or predicate-level query comparison.
- Any change to what `RuleOverlapAgent.classify_pair` computes.
- Letting a journal-only draft be the *target* of `adef detection refine`. It
  has no logic to compare; the existing `NoCatalogRecordError` behaviour is
  correct and stays.

---

## Design

### Corpus model

New module `adef/core/corpus.py`. One type, one resolver.

```python
@dataclass(frozen=True)
class CorpusEntry:
    detection_id: str
    record: dict | None = None            # None → journal-only draft
    record_path: Path | None = None
    journal: JournalEntry | None = None   # None → catalogued, journal missing

    @property
    def title(self) -> str
    @property
    def current_stage(self) -> str
    @property
    def path(self) -> Path
    @property
    def index_text(self) -> str


def build_corpus(workspace: Path) -> list[CorpusEntry]:
    """Every detection in the workspace — it exists if it has a record OR a
    journal. Exactly one entry per detection id."""
```

This is the abstraction whose absence caused problem 1. ADEF's unit of work is
a *detection*, which has up to two artifacts; until now nothing in the codebase
said so, and two call sites each picked a different half.

**Field precedence is asymmetric and deliberate:**

| Property | Wins | Why |
|---|---|---|
| `title` | record, else journal frontmatter | `sync` refreshes the record from source; the journal's title is set once at creation |
| `current_stage` | journal, else `record["stage"]` | the journal owns the stage machine — `advance_stage` writes its frontmatter |
| `path` | journal, else `record_path` | whichever artifact actually exists; never fabricated |

Anything symmetric here would let the two artifacts contradict each other
silently, which is the failure being removed.

A record-only entry needs no special-casing downstream: records already carry
`id`, `title`, `status`, and `stage`, so it reports a real stage and a real
path.

### Indexed text

```
index_text = record_search_text(record)          # title, mitre, platform,
                                                 # data_source, format, query
           OR title                              # journal-only: no record
                                                 # projection to carry it
           + journal narrative                   # human-authored blocks only
```

Precisely, **journal narrative** is the journal body minus two things: the
static template preamble (everything before the first `## [ts] Stage:` block —
unfilled scaffolding, not reasoning, already stripped for snippets today) and
every block or note marked machine-generated — by provenance (the
`<!-- adef:generated -->` marker, set at write time), never by content.
Housekeeping notes such as `catalog`/`sync`'s "Catalogued from …" line are
excluded the same way: they are marked generated at write time like any other
machine writer, not matched by their text. Either half may be empty: a
journal-only draft contributes narrative
only, a record-only detection contributes the record projection only, and
`index_text` must handle `record is None` and `journal is None` without a
guard at every call site.

**The standalone title is conditional, not additive.** A journal-only entry
(a fresh `detection new` draft with no catalog record yet) has no
`record_search_text` to carry a title, and a sparse, unadvanced journal has no
narrative either — without its frontmatter title such an entry scores 0.0
against every query and can never be shortlisted. `index_text` therefore adds
the journal's frontmatter title only when there is no record. A record-backed
entry does **not** get the standalone title added on top: `record_search_text`
already puts the record's title first, and adding it again would double-weight
it in BM25 relative to every other field.

Both artifacts, working together. A human's Observe note ("mshta-from-Office
baseline ~3/day, FP source: admin GPO scripts") is legitimate evidence for
"does a rule like this already exist?" and can never feed back, because
nothing automated writes it.

### Provenance marking

Machine-generated blocks are marked **at write time**, not inferred at read
time:

```python
Journal.append_block(detection_id, heading, body, generated: bool = False)
```

`generated=True` emits a marker line immediately beneath the heading — an HTML
comment, so it is invisible in rendered markdown, trivially greppable, and
ignored by any markdown consumer:

```markdown
### Refine / Similarity (2026-09-24T15:30:03-04:00)
<!-- adef:generated -->

- **detection_id:** D-0001
```

The exact marker string is `<!-- adef:generated -->`, defined once in
`journal.py` and referenced by both the writer and the indexer.
`run_refine_chain` is the only caller that passes `generated=True`.

The indexer drops any block carrying the marker. For journals that already
exist it falls back to matching the `### Refine / ` heading prefix — a
permanent fallback, not a transition.

**Splitting the stage area into blocks.** The indexer splits on every `### `
sub-block heading — where Refine results land — but *also* on every
`## [ts] Stage: ...` transition: a `### ` boundary alone would let a generated
block "extend" past the next stage transition and swallow it, dropping
whatever a human wrote under the next stage along with the machine output it
was appended to. Both kinds of boundary are ignored when they fall inside a
fenced code block (`` ``` `` or `~~~`): a traceback or a pasted log wrapped in
a fence can itself contain a line starting with `### ` or `## [ts]`, and
splitting on that would carve the generated block into pieces that carry
neither the marker nor the legacy heading prefix, leaking the tail into the
index.

**Exclusion is index-only.** Refine blocks stay in the journal file, stay in
`adef detection show`, and stay visible to any agent reading the journal. They
simply earn no BM25 score. Agents remain aware of both artifacts in full.

### `MemoryIndex` becomes corpus-agnostic

```python
index = MemoryIndex()                        # was MemoryIndex(journals_dir=...)
index.build(entries: Iterable[CorpusEntry])
```

The `extra_text_for` callback is removed. It existed only to keep `memory.py`
from importing `Catalog`; `corpus.py` now owns that join and the index reads
`entry.index_text`. Three call sites update: `adef/agents/rule_similarity.py`,
`adef/mcp/tools/memory_tools.py`, and the `detection search` command in
`adef/commands/detection.py`.

**Targeted cleanup in code we are already touching:** `_STAGE_BLOCK_RE` and
journal block parsing currently live in `memory.py`, which is why block
structure leaked into the search layer and made the provenance question hard
to answer in the first place. That moves to `journal.py`, which owns the
format. `memory.py` stops knowing what a stage block is.

### Consumers

**`RuleSimilarityAgent`** builds from `build_corpus(ws)` and gains catalog-only
rules as candidates. The target still requires a record (see Non-goals). A
candidate with no record still yields empty `_logic_fields` — already handled
and already documented.

**`RuleOverlapAgent`** switches to `build_corpus` for membership and
*explicitly* skips entries with no `query`, rather than arriving at the right
answer by accident via `iter_records()`. Its observable behaviour does not
change — a journal-only draft has no MITRE and was never in a technique
cluster. The value is that "both agents resolve the same list" becomes a
property a test asserts, instead of a coincidence of two iteration paths.

**`adef detection search`** gains catalog-only detections, which is what
`CLAUDE.md` already promises ("findable by what it detects even when its
journal is sparse") — so the blind spot is a bug, not a semantic change. It
loses the ability to match on Refine verdicts; accepted, since those blocks
remain readable in the journal and in `detection show`.

### Journal fidelity

The censoring added while chasing problem 2 is partly reverted:

- **`query` returns** for the target *and* each candidate. Stripping it left a
  journal that recorded *that* D-0002 was shortlisted but not what either rule
  looked for — and it removed the target's own query from the target's own
  journal, so months later you cannot tell what the rule was when the
  comparison was made. That was collateral damage from matching a key name,
  not a decision.
- **`snippet` stays out.** `_JOURNAL_OMIT_KEYS` shrinks to `{"snippet"}` and
  `_prune_for_journal` is kept. Its justification changes and the spec is
  explicit about that: it is no longer protecting the index, it is avoiding
  ~240 characters of text already present on the same line under its own
  labels (`snippet` is title + MITRE + platform + format + query,
  concatenated).
- `_inline`'s 300-char cap stays, for readability of free text such as an LLM
  judge's `reasoning`. Its docstring must stop citing the corpus argument.

---

## Migration

None required.

- Existing journals are read via the heading-prefix fallback; nothing on disk
  is rewritten.
- No workspace version bump: the provenance marker is an HTML comment, so an
  older ADEF reading a newer journal sees an inert comment.
- Search results change for existing workspaces — catalog-only detections start
  appearing and Refine-block text stops matching. This is the intended fix and
  should be noted in the changelog.

---

## Testing

Load-bearing tests, each tied to a failure this spec removes:

| Test | Asserts |
|---|---|
| Union membership | record-only, journal-only, and both → all three present, exactly once each |
| **Agreement invariant** | Similarity and Overlap resolve identical membership — the direct regression test for problem 1 |
| **Original bug, end-to-end** | catalogued rule with journal deleted: Similarity shortlists it (today it cannot) while Overlap reports it |
| Provenance | a term appearing *only* inside a marked Refine block scores zero |
| Legacy provenance | same, for an unmarked `### Refine /` block in a pre-existing journal |
| No fabricated paths | a record-only hit reports the record's path and the record's stage |
| Journal fidelity | `query` present for both sides; `snippet` absent |
| Search reach | `detection search` finds a catalog-only detection |

**One existing test is inverted.** `test_rule_logic_never_reaches_the_journal`
asserted the query is absent from the journal. It should now assert the query
is *present*, with a new test covering what it was actually protecting — that
the Refine block earns no score. Every provenance test must be verified to
fail with the marker check disabled; the predecessor of this test passed
against broken code because it exercised a synthetic payload rather than the
real pipeline. End-to-end, not unit, for anything asserting a corpus property.

---

## Constraint

ADEF is standalone and open-source first. No private codebase is a design
input, reference corpus, or justification for anything in this spec — see
"Direction of Integration" in `CLAUDE.md`. Every decision above is justified
from ADEF's own data model and observed behaviour in its own test workspaces.
