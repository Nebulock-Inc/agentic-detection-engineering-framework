# Verify tests fail

**Before you trust a test, break the behaviour it names and confirm it goes red.**
Then restore and confirm it goes green. A test you have only ever seen pass tells
you nothing about whether it can fail.

This is not a style preference. Over two branches of ADEFv2 work, **twenty tests
passed for the wrong reason** — their fixtures could not reach the code they
claimed to cover. One of them let a false claim ("the Refine→index feedback loop
is closed") ship into a design doc, a skill file, and a PR description
while the loop was still open. Every one was caught by breaking the behaviour.
None was caught by reading the test.

## The check

```
1. Write the test.
2. Break the specific behaviour the test names — delete the guard, revert the
   fix, stub the filter, disable the weighting.
3. Run only that test. It MUST fail, and the failure message must name the thing
   you broke.
4. Restore. Run it again. It must pass.
5. If it stayed green at step 3, your fixture is wrong. Not the code.
```

Step 3's second clause matters: a test that fails for an unrelated reason is
still not testing what it claims. Read the assertion message, not just the exit
code.

**Confirm the break landed before you trust a green result.** An edit that
silently fails to apply is indistinguishable from a verification that passed —
the suite is green either way. `diff` against a copy of the file, or check the
line you meant to change. This is not hypothetical: the first attempt to verify
one of the fixes on this very work was a no-op, because the mutation used a
line-anchored pattern against a *nested, indented* function, so nothing changed
and both runs passed identically. The absence of any failure for a bug already
known to exist was the only clue.

**Landing on disk is not landing in the interpreter.** Python reuses a cached
`.pyc` when the source's mtime (whole seconds) and size match what the cache
recorded. Scripted mutations run back to back can hit exactly that: two edits
inside one second that happen to leave the file the same size, and the
interpreter keeps running the *previous* mutation. Here, a "first path only"
mutation reported the failure belonging to the mutation before it — red, for
the wrong reason. `diff` was clean, because the file really had changed. When
you mutate in a loop, run with bytecode caching off —
`PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -p no:cacheprovider`, after
deleting existing `__pycache__/` — and check that each red names the test the
mutation targets. A red from the wrong test is as untrustworthy as a green.

**Confirm the restore, too.** A harness whose restore silently fails leaves
each mutation in place, so later mutations stack and every red after the first
is meaningless. This happened on the same work: in zsh an unquoted `$FILES`
is one word, so `cp $FILES` backed up nothing and each "restore" was a no-op —
visible only because the failure count grew run over run. Commit first and
restore with `git checkout -- <file>`, then check `git diff --quiet` before the
next mutation.

For a behaviour you cannot break in one edit, the equivalent is to check out the
pre-fix version of the one file under test, run the test against it, and restore.
Do that with a file copy rather than `git stash` — the stash stack is shared with
other worktrees and other sessions.

## The shapes this keeps taking

Each of these shipped here. When a test passes first time, check it against this
list before believing it.

**Synthetic input missing the field that carries the bug.** A test fed
`_format_payload` a hand-built dict asserting rule logic never reaches the
journal. It had no `snippet` key — and `snippet` was where the logic travelled.
Green while the bug was live.

**A fixture so small the property holds by degeneracy.** Two detections, each
reading one field, makes that field present in *every* detection. Three separate
tests were exercising that degeneracy rather than the feature, and the reviewer
only found out by raising the corpus size. If your fixture has two records, ask
what is trivially true of two records.

**The guard under test is unreachable from the fixture.** A test named
"skips entries with no query" used a journal-only draft — which has no MITRE, so
the technique-cluster lookup excluded it several steps before the query filter
ran. The filter could be deleted entirely and the test stayed green. Separately,
a fixture file named `D9999.yml` was never discovered at all, because the glob is
`D-*.yml`.

**Asserting the weaker property.** `..._resolve_deterministically` asserted the
result was *stable*, never that it was *right* — so it passed while alias
resolution returned the wrong canonical name. Others checked `len(x) == 1`
without checking *which* one survived, or compared two in-process runs over
identical input (which cannot differ). Stability, length and presence are all
cheaper to assert than correctness, identity and absence. Assert the expensive
one.

**The wrong variant of the input class.** A test named
"unparseable artifacts are skipped, not fatal" wrote a journal with *no*
frontmatter — which parses cleanly. Malformed frontmatter, the actual failure,
still killed the whole corpus build. "Unparseable" is a class; name which member
you used.

**Silent input transformation.** SQL fixtures used `process.name` unquoted; the
parser collapsed it to a bare `name` token, so every alias-canonicalization
assertion was testing nothing. If a fixture value passes through a parser,
confirm what comes out the other side before asserting on the result.

**A declared constraint with no test at all.** `k=60`, "do not normalize BM25
into 0–1", and a 200-char egress bound were all written into a spec as hard
requirements. Each survived being replaced with the exact thing the spec
forbade, because nothing asserted them. **A declared constraint with no test is
indistinguishable from an undeclared one** — and worse, a document will claim it
holds.

## When this applies

Every test that guards a behaviour someone could plausibly break later. That
includes tests you did not write, when you are about to rely on one: if a test's
green result is load-bearing for a decision, verify it can fail before you lean
on it.

It does not apply to trivial assertions with no logic behind them — a constructor
storing a field, a constant having a value.

## Say what you did

When reporting work, state which tests you broke and what you saw. "Tests pass"
is not evidence; "I disabled the provenance filter and exactly these two tests
failed with `assert 'MACHINETOKEN' not in body`" is. If you could not verify a
test fails, say that too — an unverified test is a known gap, not a silent one.

## Related

`CONTRIBUTING.md`'s "The gate" — `pytest`, `ruff check`, `mypy`. Those three
are the net for what this rule misses; this rule is what makes their green
results mean something. Maintainers run additional review passes on top,
configured locally.
