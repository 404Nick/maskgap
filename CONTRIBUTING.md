# Contributing

Thanks for taking the time to help. This is a small, opinionated tool; the rules
below exist to keep it auditable.

## Setup

```console
git clone https://github.com/404Nick/maskgap
cd maskgap
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest==9.0.3 ruff==0.14.0 pip-audit==2.9.0
```

## Checks that must pass

```console
PYTHONPATH=src pytest tests/ -q     # all tests
ruff check .                        # lint (also: ruff format --check .)
pip-audit --skip-editable           # dependency audit must stay clean
```

## Ground rules

* **Never print a secret value.** Reports, previews, notes, exceptions: labels
  and `sha256:` fingerprints only. The test suite asserts this end to end.
* **Keep the streaming guarantees.** Scan results and redacted bytes must not
  depend on the chunk size. Every streaming change needs a test that re-runs it
  with chunk sizes from 1 byte upwards (`tests/test_scanner.py` has the
  pattern).
* **No new dependencies.** The tool is stdlib-only by design; PRs that add a
  runtime dependency will be declined (a good idea implemented with more code is
  welcome).
* **No subprocesses, no network, no `eval`.** maskgap parses arguments with
  `argparse`, reads files and streams, and does nothing else.
* **Keep it deterministic.** No clock, no randomness, no locale-dependent
  behaviour in the scanning path.

## Adding a transformation (encoder)

1. Prove coverage from source before changing `covered_by_runner`: read
   `actions/runner` (`src/Sdk/DTLogging/Logging/ValueEncoders.cs`,
   `src/Runner.Common/HostContext.cs`, `src/Runner.Worker/Worker.cs`) and cite
   the symbol you map to. If the runner adds, removes or renames one, update
   [docs/github-masking.md](docs/github-masking.md) in the same PR.
2. Add the function and `EncoderInfo` entry in `src/maskgap/encoders.py`
   (`runner_symbol` is required whenever `covered_by_runner=True`; a test
   enforces this).
3. Add tests in `tests/test_encoders.py`: exact expected output, edge cases
   (empty output, short values), and update the coverage-set test if the set of
   covered encoders changes.

## Adding a provider rule

Rules live in `src/maskgap/generic.py`. Every rule needs a positive test (a
realistic sample token is found) and a negative test (text that resembles the
token but must not match), plus a note in the rule's `summary`. Avoid nested
quantifiers — a ReDoS-guard test runs the compiled rules against adversarial
input.

## Pull requests

* One topic per PR; describe *what* it changes and *why*.
* Include the commands you ran and their results in the description.
* New behaviour needs tests; bug fixes need a regression test first.
* By contributing you agree your contribution is licensed under the MIT license
  of this repository.
