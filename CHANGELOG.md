# Changelog

All notable changes to this project are documented in this file, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-18

### Added

* `maskgap scan` — find secret values in any registered encoding in files or
  stdin; findings carry labels and `sha256:` fingerprints, never values.
* `maskgap redact` — streaming redaction (stdin/stdout filter, `--output`, or
  atomic `--in-place`), with `--mask '{detector}'` templates, `--report` stats
  and `--fail-on-leak` for gating.
* `maskgap audit` — per-secret masking-coverage matrix for the GitHub Actions
  runner, derived from `actions/runner` source (`docs/github-masking.md`).
* 30 transformations covering the 13 encodings the runner registers plus the 17
  it does not (base64 variants, hex, URI case, JSON-ASCII, case folding,
  line-wrapping, truncation, base32, ROT13, ...).
* 23 provider-shaped generic rules (GitHub, GitLab, AWS, Slack, Stripe, Google,
  OpenAI, Anthropic, npm, JWTs, private key blocks, credential assignments, ...),
  each with positive and negative tests.
* Streaming Aho–Corasick engine with chunk-size invariance as a tested
  guarantee; bounded memory for arbitrarily large logs.
* Secret sources: `--env`, `--env auto` heuristic, `--env-prefix`, `--env-file`
  (dotenv), `--secrets-file`; duplicate values are merged by fingerprint.
* 207 tests, zero runtime dependencies, CI on Python 3.10–3.14 with lint,
  tests and `pip-audit`.
