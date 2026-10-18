# Dependency and security audit

Date: 2026-10-18. Environment: Python 3.14.8, Linux.

## Runtime dependencies

**None.** `maskgap` uses only the Python standard library; `pyproject.toml`
declares `dependencies = []` and the CI job installs nothing else for the tool
itself. The attack surface of the scanner is therefore the stdlib plus this
repository's ~2900 lines of code, all of which is yours to read.

## Dependency audit

Dev tools are pinned to exact versions (`pytest==9.0.3`, `ruff==0.14.0`,
`pip-audit==2.9.0`) and audited with `pip-audit`:

```console
$ pip-audit --skip-editable
No known vulnerabilities found
```

An earlier run of this project pinned `pytest==8.4.2` and `pip-audit` reported:

```console
$ pip-audit --skip-editable
Found 1 known vulnerability in 1 package
Name   Version ID              Fix Versions
------ ------- --------------- ------------
pytest 8.4.2   PYSEC-2026-1845 9.0.3
```

The pin was upgraded to `pytest==9.0.3`, the full suite was re-run (all tests
pass), and the re-audit is clean. `pip-audit --skip-editable` runs on every push
in CI (`.github/workflows/ci.yml`, job `audit`), so the pin cannot silently rot.
(The `--skip-editable` flag is needed only because this checkout is installed as
an editable package and has no PyPI release yet; `maskgap` itself has no
dependencies to audit.)

Reproduce with:

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e . pytest==9.0.3 ruff==0.14.0 pip-audit==2.9.0
$ pip-audit --skip-editable
```

## Static hygiene review

Checked on 2026-10-18 against the committed source:

```console
$ grep -rnE "subprocess|os\.system|os\.popen|eval\(|exec\(|pickle|marshal|mktemp" \
      --include='*.py' src/maskgap/
src/maskgap/cli.py:17:  maskgap never spawns a subprocess;
```

The single hit is the sentence in the module docstring. The tool does not spawn
processes, does not evaluate code, does not deserialize untrusted data, and
never passes user input to a shell — command-line arguments go through `argparse`
and are used as filenames or matched strings only.

Network access:

```console
$ grep -rnE "^import |^from " src/maskgap/ | grep -E "socket|http|urllib|requests"
src/maskgap/encoders.py:30:import urllib.parse
```

`urllib.parse.quote` is a pure string function (percent-encoding for the `uri`
and `uri-lower` encoder models); nothing in the package opens a socket, and
there is no telemetry, analytics or update check of any kind.

## Secret-handling rules

The tool *reads* live secrets by design; the safety model is about output:

* secret values are never written into any report, JSON payload, log line or
  error message — findings carry a label and a non-reversible
  `sha256:` fingerprint, and previews are masked before printing;
* the CLI test suite asserts end to end that scanned and redacted output
  contains none of the secret's known forms;
* `--in-place` uses an atomic temp-file-and-rename so an interrupted run cannot
  corrupt a log or leave a partially scrubbed file;
* no secret material is ever committed to this repository; the example log uses
  a deliberately fake value.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
