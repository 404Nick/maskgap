# maskgap

**Find the gaps in your CI secret masking.** `maskgap` knows the actual secret
values in your environment and searches logs, artefacts and streams for them in
every encoding they might appear in — including the encodings your CI platform
does *not* mask.

[![CI](https://github.com/404Nick/maskgap/actions/workflows/ci.yml/badge.svg)](https://github.com/404Nick/maskgap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](pyproject.toml)

## The problem

GitHub Actions masks a secret by registering a fixed list of *literal* strings
(the value, its base64, its JSON-escaped form, ...) and replacing exactly those
substrings in every log line. It never hex-encodes, never strips base64
padding, never lower-cases `%2b`. So a build log like
[`examples/leaky-build.log`](examples/leaky-build.log) — where a deploy key
reaches stdout through an argument, a hex checksum, a wrapped base64 payload and
a URL — ends up with several forms of the live secret printed in the clear,
while the platform's own masking reports nothing unusual:

```console
$ maskgap scan --env DEPLOY_KEY examples/leaky-build.log
maskgap 0.1.0: scanned 1 input(s), 1 secret(s), 13 patterns
  examples/leaky-build.log:7:38           ok   raw                 env:DEPLOY_KEY              sha256:5d157618ca91
      [debug] argv: deploy-service --token ***
  examples/leaky-build.log:8:48           ok   raw                 env:DEPLOY_KEY              sha256:5d157618ca91
      [debug] upload response: {"status":200,"echo":"***"}
  examples/leaky-build.log:9:34           GAP  base64-no-pad       env:DEPLOY_KEY              sha256:5d157618ca91
      [debug] Authorization: Basic Y2k6***=
  examples/leaky-build.log:10:34          GAP  hex                 env:DEPLOY_KEY              sha256:5d157618ca91
      [debug] artifact checksum (hex): ***
  examples/leaky-build.log:12:1           GAP  base64-linewrap     env:DEPLOY_KEY              sha256:5d157618ca91
      ***
  examples/leaky-build.log:14:63          GAP  uri-lower           env:DEPLOY_KEY              sha256:5d157618ca91
      [debug] callback url: https://registry.example.com/auth?token=***
  examples/leaky-build.log:15:31          GAP  github-pat          generic:github-pat          sha256:ad240812ea3f
      [warn] legacy helper ran with ***
7 findings in 1 input(s): 5 gap(s) the platform masking does not cover, 2 covered form(s).
```

`GAP` means: the GitHub Actions runner would print this form in the clear (the
coverage model is derived from `actions/runner` source — see
[docs/github-masking.md](docs/github-masking.md)). `ok` means the platform
masks it.

## How it works

* **Value-aware.** You give it the real secrets (`--env NAME`, `--env auto`,
  `--env-prefix`, dotenv or secrets files). It searches for *those values* in
  every form — 30 transformations from hex and base64 variants to JSON/XML/URI
  escaping, case folding, line wrapping and truncation.
* **Transformation-aware.** Each transformation is tagged with whether the CI
  platform registers it as a mask hint. `--only-gaps` narrows everything to the
  forms that actually survive, and `maskgap audit` shows the full matrix for
  your secrets.
* **Safe by construction.** Findings carry a label and a `sha256:` fingerprint,
  never the value; previews have every known match masked. No network, no
  telemetry, no subprocesses, zero runtime dependencies, ~2900 lines of
  auditable Python.

## Install

No runtime dependencies; Python ≥ 3.10.

```console
# from GitHub (until there is a PyPI release)
pipx install "git+https://github.com/404Nick/maskgap"
# or from a checkout
python -m venv .venv && . .venv/bin/activate
pip install .
```

## Quickstart

```console
# 1. What would the platform not mask? Look at the coverage matrix.
$ maskgap audit --env GITHUB_TOKEN --extended

# 2. Scan a build log for the real value in any plausible encoding. Exit code
#    1 when something is found, so it gates a pipeline.
$ maskgap scan --env auto build.log
$ maskgap scan --env auto --only-gaps --json build.log   # only actionable forms

# 3. Scrub a stream (filter) or files (atomic rewrite).
$ build-command 2>&1 | maskgap redact --env auto > build.clean.log
$ maskgap redact --env auto --in-place ci/logs/*.log
```

Useful flags:

| flag | meaning |
| --- | --- |
| `--env auto` | load every environment variable whose name looks like a credential (`*_TOKEN`, `*_SECRET`, `*_KEY`, ...) |
| `--env NAME` | load one variable explicitly (repeatable, comma-separated allowed) |
| `--only-gaps` | report/redact only forms the platform does not mask |
| `--extended` | add exotic encodings (base32, ROT13, reversed, prefix/suffix) |
| `--all-forms` | show every raw match instead of the most informative one per region |
| `--mask '{detector}'` | redact to a named placeholder, e.g. `<hex>` |
| `--fail-on-leak` | make `redact` exit 1 when anything was replaced |
| `--ignore-fingerprint sha256:...` | accept a known-benign match without weakening the rest |

Exit codes: `0` clean, `1` leaks found (`scan`; or `redact --fail-on-leak`),
`2` usage or configuration error.

## In CI

Redact artefacts before they are uploaded, and fail only on what the platform
does not mask:

```yaml
- run: make build 2>&1 | tee build.log
- run: maskgap redact --env auto --in-place build.log
- uses: actions/upload-artifact@v4
  with: { name: build-log, path: build.log }
```

A full template, including `scan` as a gate, is in
[`examples/workflow-redact.yml`](examples/workflow-redact.yml).

## What it is not

Pattern scanners and entropy checkers (gitleaks, detect-secrets, TruffleHog)
answer *"does something secret-shaped appear?"* and do not know your values.
`maskgap` answers *"did my actual secret leak in a form my platform will not
mask, and can I scrub it?"* The two are complementary: run a pattern scanner to
find unknown credentials, run `maskgap` to find the encodings of the ones you
already have.

## Documentation

* [docs/github-masking.md](docs/github-masking.md) — what the runner masks,
  derived from source, with caveats
* [docs/design.md](docs/design.md) — architecture, streaming model, guarantees
* [docs/security-audit.md](docs/security-audit.md) — dependency audit and
  static hygiene evidence

## Development

```console
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest==9.0.3 ruff==0.14.0 pip-audit==2.9.0
PYTHONPATH=src pytest tests/ -q     # 207 tests
ruff check . && ruff format --check .
pip-audit --skip-editable
```

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
