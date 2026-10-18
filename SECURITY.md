# Security policy

## Supported versions

The latest release line (`0.1.x`) receives fixes. Pre-1.0 the API may change
between minor versions.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(*Security → Report a vulnerability*). Do not open a public issue for anything
that could leak a secret or expose a user.

Include: affected version, a description of the issue, a minimal reproduction
(use fake secrets only), and the impact you expect. We aim to acknowledge within
a few days.

## Security model

`maskgap` is a tool that *reads live secrets by design* — you point it at the
values you want protected. Its safety properties are about what it does with
them:

* **Output discipline.** Findings and reports carry a label and a
  non-reversible `sha256:` fingerprint, never the value. Preview lines have
  every known match masked before they are printed. The CLI test suite asserts
  this end to end.
* **No side channels.** No network access, no telemetry, no update checks, no
  subprocesses, no `eval`, no deserialisation of untrusted data, no temporary
  files holding secrets except the atomic-rewrite temp file of `--in-place`
  (same directory, renamed over the original).
* **Zero runtime dependencies.** The supply-chain surface is the Python standard
  library plus this repository's code. Dev tooling is pinned exactly and audited
  with `pip-audit` on every push (see [docs/security-audit.md](docs/security-audit.md)).
* **Read-only unless asked.** `scan`, `audit` and `encoders` never modify input;
  `redact` writes to stdout or `--output`, and only `--in-place` rewrites files.

## Out of scope

* Secrets that were never loaded into the scanner cannot be found by value
  matching (provider-shaped tokens are covered heuristically; see the README).
* A compromised host, shell history, or process list is outside the threat
  model — `maskgap` protects what you feed it, not the environment.
* The coverage model reflects the public `actions/runner` source and can lag the
  platform; gaps in *that model* are documentation bugs, not vulnerabilities.
  Please open a regular issue for those.
