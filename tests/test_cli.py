"""End-to-end tests that drive the real command line entry point.

Everything here runs ``python -m maskgap`` in a subprocess with a scrubbed
environment, which is the only way to check exit codes, stdin/stdout handling,
and the promise that no secret value ever reaches a report.
"""

from __future__ import annotations

import base64
import json
import pathlib

from maskgap.encoders import ENCODERS

from .conftest import TOKEN, run_cli

SECRET_ENV = {"MASKGAP_TEST_TOKEN": TOKEN}


def _secret_forms() -> list[bytes]:
    """Every literal that must never survive a scan or a redaction."""
    encoded = TOKEN.encode()
    return [encoded, base64.b64encode(encoded), encoded.hex().encode()]


def _leaky(tmp_path: pathlib.Path) -> pathlib.Path:
    encoded = base64.b64encode(TOKEN.encode()).decode()
    path = tmp_path / "build.log"
    path.write_bytes(
        f"== build log ==\nplain: {TOKEN}\nhex: {TOKEN.encode().hex()}\nb64: {encoded}\n".encode()
    )
    return path


# --------------------------------------------------------------------------- #
# encoders and audit                                                          #
# --------------------------------------------------------------------------- #


def test_version_exits_0() -> None:
    result = run_cli("--version")
    assert result.returncode == 0
    assert result.stdout.startswith(b"maskgap ")


def test_encoders_command_lists_the_registry() -> None:
    result = run_cli("encoders")
    assert result.returncode == 0
    text = result.stdout.decode()
    assert "raw" in text
    assert "hex" in text
    assert "masked" in text
    assert "gap" in text


def test_encoders_json_matches_the_registry() -> None:
    result = run_cli("encoders", "--extended", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    listed = {entry["name"]: entry["masked_by_runner"] for entry in payload["encoders"]}
    expected = {info.name: info.covered_by_runner for info in ENCODERS}
    assert listed == expected


def test_audit_reports_coverage_without_values() -> None:
    result = run_cli("audit", "--env", "MASKGAP_TEST_TOKEN", "--extended", env=SECRET_ENV)
    assert result.returncode == 0
    text = result.stdout.decode()
    assert "MASKED" in text
    assert "GAPS" in text
    assert "hex" in text
    assert "sha256:" in text
    assert TOKEN not in text


def test_audit_json_counts_gaps() -> None:
    result = run_cli("audit", "--env", "MASKGAP_TEST_TOKEN", "--json", env=SECRET_ENV)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    entry = payload["secrets"][0]
    assert entry["gaps"] > 0
    assert entry["masked_by_runner"] > 0
    assert payload["summary"]["encoders_not_covered"] > 0


# --------------------------------------------------------------------------- #
# scan                                                                        #
# --------------------------------------------------------------------------- #


def test_scan_reports_a_leak_and_exits_1(tmp_path: pathlib.Path) -> None:
    path = _leaky(tmp_path)
    result = run_cli("scan", str(path), "--env", "MASKGAP_TEST_TOKEN", env=SECRET_ENV)
    assert result.returncode == 1
    text = result.stdout.decode()
    assert "build.log" in text
    assert "GAP" in text
    for form in _secret_forms():
        assert form not in result.stdout


def test_scan_clean_input_exits_0(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "clean.log"
    path.write_bytes(b"nothing interesting here\n")
    result = run_cli("scan", str(path), "--env", "MASKGAP_TEST_TOKEN", env=SECRET_ENV)
    assert result.returncode == 0
    assert b"No leaks found." in result.stdout


def test_scan_json_payload_is_parseable_and_safe(tmp_path: pathlib.Path) -> None:
    path = _leaky(tmp_path)
    result = run_cli("scan", str(path), "--env", "MASKGAP_TEST_TOKEN", "--json", env=SECRET_ENV)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings"] >= 3
    assert payload["summary"]["gaps"] >= 2
    # The unpadded base64 form is a gap and outranks the padded covered form.
    assert {"raw", "hex", "base64-no-pad"} <= set(payload["summary"]["by_detector"])
    for finding in payload["findings"]:
        assert finding["fingerprint"].startswith("sha256:")
        assert TOKEN not in finding["context"]
    for form in _secret_forms():
        assert form not in result.stdout


def test_scan_only_gaps_skips_covered_forms(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "log"
    path.write_bytes(f"plain: {TOKEN}\nhex: {TOKEN.encode().hex()}\n".encode())
    result = run_cli(
        "scan",
        str(path),
        "--env",
        "MASKGAP_TEST_TOKEN",
        "--only-gaps",
        "--json",
        env=SECRET_ENV,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings"] >= 1
    assert all(finding["gap"] for finding in payload["findings"])
    assert "raw" not in payload["summary"]["by_detector"]


def test_scan_missing_file_is_a_usage_error(tmp_path: pathlib.Path) -> None:
    result = run_cli(
        "scan", str(tmp_path / "nope.log"), "--env", "MASKGAP_TEST_TOKEN", env=SECRET_ENV
    )
    assert result.returncode == 2
    assert b"no such file" in result.stderr


# --------------------------------------------------------------------------- #
# redact                                                                      #
# --------------------------------------------------------------------------- #


def test_redact_filters_stdin_to_stdout() -> None:
    data = f"plain: {TOKEN}\n".encode()
    result = run_cli("redact", "--env", "MASKGAP_TEST_TOKEN", stdin=data, env=SECRET_ENV)
    assert result.returncode == 0
    assert result.stdout == b"plain: ***\n"


def test_redact_report_and_fail_on_leak() -> None:
    data = f"plain: {TOKEN}\n".encode()
    result = run_cli(
        "redact",
        "--env",
        "MASKGAP_TEST_TOKEN",
        "--report",
        "--fail-on-leak",
        stdin=data,
        env=SECRET_ENV,
    )
    assert result.returncode == 1
    assert b"redacted" in result.stderr


def test_redact_supports_a_detector_template() -> None:
    data = f"plain: {TOKEN}\n".encode()
    result = run_cli(
        "redact",
        "--env",
        "MASKGAP_TEST_TOKEN",
        "--mask",
        "<{detector}>",
        stdin=data,
        env=SECRET_ENV,
    )
    assert result.stdout == b"plain: <raw>\n"


def test_redact_only_gaps_leaves_covered_forms_alone() -> None:
    data = f"plain: {TOKEN}\n".encode()
    result = run_cli(
        "redact", "--env", "MASKGAP_TEST_TOKEN", "--only-gaps", stdin=data, env=SECRET_ENV
    )
    assert result.returncode == 0
    assert result.stdout == data


def test_redact_writes_to_an_output_file(tmp_path: pathlib.Path) -> None:
    source = _leaky(tmp_path)
    destination = tmp_path / "clean.log"
    result = run_cli(
        "redact",
        str(source),
        "--env",
        "MASKGAP_TEST_TOKEN",
        "-o",
        str(destination),
        env=SECRET_ENV,
    )
    assert result.returncode == 0
    output = destination.read_bytes()
    for form in _secret_forms():
        assert form not in output


def test_redact_in_place_rewrites_atomically(tmp_path: pathlib.Path) -> None:
    path = _leaky(tmp_path)
    result = run_cli(
        "redact", str(path), "--env", "MASKGAP_TEST_TOKEN", "--in-place", env=SECRET_ENV
    )
    assert result.returncode == 0
    data = path.read_bytes()
    for form in _secret_forms():
        assert form not in data
    assert b"== build log ==" in data, "untouched bytes must survive"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == [path.name], (
        "no temporary file may be left behind"
    )


def test_in_place_without_paths_is_a_usage_error() -> None:
    result = run_cli(
        "redact", "--in-place", "--env", "MASKGAP_TEST_TOKEN", stdin=b"x", env=SECRET_ENV
    )
    assert result.returncode == 2
    assert b"--in-place requires explicit file paths" in result.stderr


def test_unknown_encoder_is_a_usage_error() -> None:
    result = run_cli("encoders", "--encoders", "nope")
    assert result.returncode == 2
    assert b"unknown encoder" in result.stderr


# --------------------------------------------------------------------------- #
# secret sources and generic tokens                                           #
# --------------------------------------------------------------------------- #


def test_auto_detection_finds_a_credential_shaped_variable() -> None:
    result = run_cli(
        "scan", "--json", stdin=TOKEN.encode() + b"\n", env={"GH_EXAMPLE_API_TOKEN": TOKEN}
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["by_detector"].get("raw") == 1
    assert payload["secrets_loaded"] == ["env:GH_EXAMPLE_API_TOKEN"]


def test_require_secrets_without_a_source_is_a_usage_error(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "clean.log"
    path.write_bytes(b"hello\n")
    result = run_cli("scan", str(path), "--require-secrets", "--no-generic")
    assert result.returncode == 2
    assert b"no secrets loaded" in result.stderr


def test_generic_token_is_found_without_loaded_secrets() -> None:
    body = b"docker login with REMOVED_EXAMPLE_FIXTURE\n"
    result = run_cli("scan", "--json", stdin=body)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["by_detector"] == {"docker-pat": 1}
    assert body.strip() not in result.stdout


def test_no_generic_disables_provider_patterns() -> None:
    body = b"docker login with REMOVED_EXAMPLE_FIXTURE\n"
    result = run_cli("scan", "--no-generic", "--json", stdin=body)
    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"]["findings"] == 0


def test_verbose_config_never_prints_values() -> None:
    result = run_cli(
        "scan", "--env", "MASKGAP_TEST_TOKEN", "--verbose", stdin=b"clean\n", env=SECRET_ENV
    )
    assert result.returncode == 0
    assert TOKEN.encode() not in result.stdout
    assert TOKEN.encode() not in result.stderr
    assert b"env:MASKGAP_TEST_TOKEN" in result.stderr
