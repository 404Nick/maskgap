"""Shared fixtures and helpers.

Two kinds of helpers live here:

* :func:`make_secret` / :func:`make_scanner` build the objects under test with
  predictable defaults;
* :func:`run_cli` runs the real command line entry point in a subprocess, which
  is the only way to exercise stdin/stdout handling exactly as a user would.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
from collections.abc import Iterable, Sequence

import pytest

from maskgap.encoders import ENCODERS, EncoderInfo, select_encoders
from maskgap.scanner import Scanner
from maskgap.secrets import Secret

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC_ROOT = PROJECT_ROOT / "src"

#: A token shaped like a real credential, used across the test suite. The
#: prefix is split off so no contiguous token-shaped literal exists here.
TOKEN = "ghp_" + "Example0Token0WithSlashAnd1234"


def make_secret(value: str = TOKEN, label: str = "env:TEST_TOKEN") -> Secret:
    return Secret(label=label, value=value, source="environment")


def make_scanner(
    secrets: Iterable[Secret] = (),
    *,
    encoders: Sequence[EncoderInfo] | None = None,
    extended: bool = True,
    **kwargs: object,
) -> Scanner:
    """Build a scanner with every encoder enabled unless told otherwise."""
    selected = encoders if encoders is not None else select_encoders(extended=extended)
    return Scanner(secrets=list(secrets), encoders=selected, **kwargs)  # type: ignore[arg-type]


def finding_keys(findings: Iterable[object]) -> list[tuple[int, str, str, str]]:
    """Position/identity of findings, ignoring presentation-only fields."""
    return [finding.dedupe_key() for finding in findings]  # type: ignore[attr-defined]


def all_encoder_names() -> list[str]:
    return [encoder.name for encoder in ENCODERS]


def run_cli(
    *args: str,
    stdin: bytes | None = None,
    env: dict[str, str] | None = None,
    cwd: pathlib.Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run ``python -m maskgap`` with a clean environment plus ``env`` overrides.

    The environment is scrubbed of anything that auto-detection would pick up, so
    tests never depend on the machine they run on.
    """
    process_env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(SRC_ROOT),
        "PYTHONIOENCODING": "utf-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    process_env.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "maskgap", *args],
        input=stdin if stdin is not None else b"",
        capture_output=True,
        env=process_env,
        cwd=str(cwd or PROJECT_ROOT),
        check=False,
    )


@pytest.fixture()
def token() -> str:
    return TOKEN


@pytest.fixture()
def secret() -> Secret:
    return make_secret()
