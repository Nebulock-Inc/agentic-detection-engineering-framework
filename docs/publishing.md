# Publishing ADEF to PyPI

ADEF publishes the same way as its sibling ATHF: a GitHub Release triggers
`.github/workflows/publish.yml`, which builds the sdist + wheel and uploads them.
The package name is **`agentic-detection-engineering-framework`**.

## One-time account setup (blocks the first publish)

Nobody has done these yet — they need a human with a browser.

1. **Create a PyPI account** → https://pypi.org/account/register/ and verify the
   email. (Optional but recommended: also register on https://test.pypi.org/ so
   pre-releases have somewhere to land.) Turn on 2FA when prompted.

2. **Reserve the name.** The name is claimed by the *first upload*, not
   reserved in advance. Until then, guard against a name-squat by doing a real
   first upload (even an alpha) as soon as the account exists.

3. **Create an API token** → PyPI → *Account settings* → *API tokens* →
   *Add API token*. For the very first upload the token must be
   **account-scoped** (the project doesn't exist yet); after the first release,
   replace it with a **project-scoped** token for least privilege.

4. **Store the token as a GitHub Actions secret**: repo → *Settings* →
   *Secrets and variables* → *Actions* → *New repository secret*:
   - `PYPI_API_TOKEN` — the pypi.org token (required)
   - `TEST_PYPI_API_TOKEN` — the test.pypi.org token (only if using pre-releases)

> Prefer no stored secrets? Switch to PyPI **Trusted Publishing** (OIDC): add a
> pending publisher on PyPI (owner `Nebulock-Inc`, repo
> `agentic-detection-engineering-framework`, workflow `publish.yml`) and drop the
> `password:` lines from the workflow. The `id-token: write` permission is
> already declared. This is the more modern path; token auth above matches ATHF.

## Cutting a release

1. Bump the version in **both** `adef/__init__.py` and `pyproject.toml` (they
   must match; the workflow's tag check enforces tag == pyproject version).
2. Commit, then draft a GitHub Release with tag `vX.Y.Z` (e.g. `v0.1.0`).
   - Tick **"Set as a pre-release"** to publish to Test PyPI first.
   - A normal (non-pre-release) publish goes to real PyPI.
3. Publish the release → the workflow builds, runs `twine check`, and uploads.

## Verify a build locally before releasing

```bash
python -m venv /tmp/adef-build && source /tmp/adef-build/bin/activate
pip install build twine
python -m build            # writes dist/*.whl and dist/*.tar.gz
twine check dist/*         # must PASS
pip install dist/*.whl && adef --version   # smoke test
```

## Known gap: bundled skills don't ship on PyPI

`adef install-skills` copies from the repo's `claude-plugin/` tree, which is
**not** included in the wheel. PyPI installs should get the skills via the
plugin marketplace (`/plugin install adef@adef-marketplace`) or a source
checkout. This is intentional for v0.1.0 — see `adef/commands/install_skills.py`.
