# Security Policy

## Reporting a vulnerability

Report security issues **privately**, not as a public GitHub issue.

- **Preferred:** [open a draft security advisory](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/security/advisories/new) on this repository.
- **Or email:** [sydney@nebulock.io](mailto:sydney@nebulock.io).

Please include the ADEF version (`adef --version`), the command or MCP tool
involved, and what an attacker gets out of it. A proof-of-concept repository or
capture document helps a lot.

We will acknowledge a report within five business days and keep you updated
until it's resolved. If you'd like credit in the advisory, say so and tell us
how you want to be named.

## Supported versions

Only the latest release is supported. Security fixes land on `main` and go out
in the next tagged release; there are no maintained release branches and no
backports to older tags.

## What's in scope

ADEF is a local CLI and an MCP server. There is no hosted service, so the
interesting boundaries are all about untrusted *input* and unintended *egress*:

| Area | Why it's a boundary |
|---|---|
| Rule repos read by `adef catalog` / `adef sync` | Untrusted YAML, `.conf`, Python and SQL from third-party rule repos. Path traversal out of the workspace, or arbitrary code execution during parsing, is in scope. |
| Extraction profiles (`adef profile lint`) | User-authored YAML that drives field extraction. |
| Data-source declarations and schema documents | Source names become filenames under `schema/`. |
| Health capture documents (`adef ingest`) | Detection IDs and telemetry source names become filenames under `health/`. |
| `--similarity-mode llm` / `auto` in `adef detection refine` | **The only code path that makes an outbound network call.** It sends rule content to the Anthropic API. Egress beyond what the README's Refine section documents is a vulnerability — report it. |
| The `adef-mcp` server | Tools are reachable by whatever assistant is wired to it. A tool that writes outside the workspace, or discloses more than its documented return, is in scope. |

## What's out of scope

- **Rule *content* being wrong.** A detection that misses an attack is a
  detection-engineering problem, not an ADEF vulnerability. File a normal issue.
- **A workspace being readable by other users on the same machine.** ADEF writes
  plain files with your umask. Protect the workspace the way you protect any
  other local directory — and note that
  `field_observations.fields[].sample_values` is event-derived data if you choose
  to include it, so it is stored at rest in `health/sources/`.
- **An `ADEF_WRAPPER_*` override you configured yourself** loading arbitrary
  code. That is what the setting is for.
- **Vendor API connectors.** ADEF has none and will never have any — it's a
  CI-enforced anti-goal. A missing connector is not a finding.
