# Contributing to ADEF

Thanks for being here. ADEF is a detection-engineering tool built by detection
engineers, and the most useful contributions usually come from someone who hit a
real wall with their own rule repo.

## Before you write code

Open an issue first for anything beyond a typo or an obvious bug fix. There are
three templates — bug report, feature request, detection contribution — at
[new issue](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/issues/new/choose).
A five-line issue saves you from building something that collides with the
[roadmap](docs/roadmap.md) or one of the anti-goals below.

For a security issue, **don't** open an issue — see [`SECURITY.md`](SECURITY.md).

## Dev setup

```bash
git clone https://github.com/Nebulock-Inc/agentic-detection-engineering-framework.git
cd agentic-detection-engineering-framework
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip          # >= 21.3, for PEP 660 editable installs
pip install -e ".[dev,mcp]"
```

Python 3.10 or newer.

## The gate

Three commands. All three must pass before you open a pull request, and CI runs
the same ones:

```bash
pytest                   # the whole suite
ruff check adef/ tests/  # lint
mypy adef/               # types
```

`ruff format adef/ tests/` for formatting.

## Tests: verify yours can fail

**A test you have only ever seen pass tells you nothing.** Before you trust a
new test, break the behaviour it names — delete the guard, revert the fix, stub
the filter — run only that test, and confirm it goes red *with a message naming
the thing you broke*. Then restore and confirm green.

This is not a style preference. It has caught tests here whose fixtures could
not reach the code they claimed to cover: a filter that could be deleted
entirely while its test stayed green, an assertion of *stability* that passed
while the value was wrong, a two-record fixture where the property held by
degeneracy. When you report your work, say which behaviour you broke and what
you saw.

## The four anti-goals (CI-enforced)

These are tested. A pull request that violates one fails CI, and the test is
the specification:

| Anti-goal | Test |
|---|---|
| ADEF never writes inside a `detections/` tree. Your rule repo is read-only, always. | `tests/test_schema_parity.py` |
| Exactly four engines: `sigma`, `sql`, `sch_sql`, `composite`. No new engine types. | `tests/test_no_new_engine_types.py` |
| No vendor API connectors (CrowdStrike, Splunk, SentinelOne, …). You hand ADEF a file; it never fetches. Connectors belong in separate adapter packages. | `tests/test_no_vendor_connectors.py` |
| No web UI dependencies. ADEF is a CLI and an MCP server. | `tests/test_no_web_ui_deps.py` |

If your feature needs one of these, it needs a design discussion first, not a
pull request.

## One rule no test can enforce

**ADEF is built standalone and open-source first.** Any private or in-house
codebase — including the maintainers' own — is a *future adopter* of ADEF, not
an input to it:

- A private codebase is **not a reference corpus.** Don't measure against it,
  sample from it, or query its production data to settle an ADEF design question.
- A private codebase is **not a justification.** "Our pipeline does X" is not a
  reason for ADEF to support X. Justify from language semantics, published
  practitioner standards, or a demonstrated ADEF user need.
- A private dialect is **not an interface shape.** Never fit a public format to
  one in-house implementation's quirks.

If a capability is only explicable by pointing at in-house tooling, it doesn't
belong in ADEF yet. This is broader than the no-vendor-connectors guard, which
only catches SDK imports — this one governs *design inputs*, so it's on you.

## Extending ADEF

The clean way to add something is usually a plugin, not a core edit. ADEF
discovers Click commands, agents, and MCP tools through entry points
(`adef.commands`, `adef.agents`, `adef.mcp_tools`), and discovery is defensive —
a broken plugin logs to stderr and never kills CLI startup. See
[`AGENTS.md`](AGENTS.md) for the layout and the development patterns.

Vendor-specific work — a connector for your SIEM, a testing-platform
integration — belongs in your own package that depends on ADEF.

## Pull requests

- One logical change per pull request.
- Say what you tested and what you broke to prove the test works.
- Update the docs in the same pull request. A flag with no entry in
  [`docs/cli-reference.md`](docs/cli-reference.md) isn't finished.
- Match the surrounding code: its comment density, naming, and idiom. ADEF's
  comments tend to explain *why a decision was made*, not what the line does.
- Commits use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(cli):`, `fix(health):`, `docs(readme):`).

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Contributions are accepted under the [MIT License](LICENSE).
