"""Unit tests for the streaming detection and redaction engine.

The two properties that matter most are tested exhaustively:

* **nothing is missed** — every occurrence is found, even when the chunk size is
  smaller than the pattern, so matches straddle boundaries over and over;
* **nothing is invented** — the redacted output is byte-identical to the input
  apart from the replaced matches, and the transformation does not depend on how
  the stream was cut into chunks.
"""

from __future__ import annotations

import base64
import io
import random

import pytest

from maskgap.encoders import ENCODERS, select_encoders, variants
from maskgap.scanner import Scanner, collapse_findings
from maskgap.secrets import Secret

from .conftest import TOKEN, make_scanner, make_secret

CHUNK_SIZES = (1, 2, 3, 5, 8, 17, 64, 1024, 65536)


def log_with_every_form(secret: str = TOKEN) -> bytes:
    data = secret.encode()
    lines = [
        "== build log ==",
        f"plain: {secret}",
        f"base64: {base64.b64encode(data).decode()}",
        f"hex: {data.hex()}",
        f"uri: {secret}",
        "unrelated line",
    ]
    return ("\n".join(lines) + "\n").encode()


# --------------------------------------------------------------------------- #
# detection                                                                   #
# --------------------------------------------------------------------------- #


def test_detects_raw_base64_and_hex_forms() -> None:
    scanner = make_scanner([make_secret()])
    findings = scanner.scan_bytes(log_with_every_form(), "log")
    detectors = {finding.detector for finding in findings}
    assert {"raw", "base64", "hex"} <= detectors


def test_findings_carry_label_fingerprint_and_coverage(secret) -> None:
    scanner = make_scanner([secret])
    findings = scanner.scan_bytes(log_with_every_form(), "log")
    raw = next(finding for finding in findings if finding.detector == "raw")
    assert raw.label == "env:TEST_TOKEN"
    assert raw.fingerprint == secret.fingerprint
    assert raw.covered_by_runner is True
    assert raw.is_gap is False
    assert raw.line == 2
    assert raw.column == len("plain: ") + 1
    assert raw.source == "log"


def test_hex_is_reported_as_a_gap() -> None:
    scanner = make_scanner([make_secret()])
    findings = scanner.scan_bytes(log_with_every_form(), "log")
    hex_finding = next(finding for finding in findings if finding.detector == "hex")
    assert hex_finding.is_gap is True
    assert hex_finding.covered_by_runner is False


def test_no_findings_for_clean_input() -> None:
    scanner = make_scanner([make_secret()])
    assert scanner.scan_bytes(b"nothing to see here\n", "log") == []


@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_findings_do_not_depend_on_chunk_size(chunk_size: int) -> None:
    baseline = make_scanner([make_secret()], chunk_size=65536)
    reference = {
        (f.offset, f.detector, f.line, f.column) for f in baseline.scan_bytes(log_with_every_form())
    }

    scanner = make_scanner([make_secret()], chunk_size=chunk_size)
    actual = {
        (f.offset, f.detector, f.line, f.column) for f in scanner.scan_bytes(log_with_every_form())
    }
    assert actual == reference


def test_match_across_a_chunk_boundary_is_found_once() -> None:
    secret = TOKEN
    padding = b"x" * 40
    data = padding + secret.encode() + b" tail"
    for chunk_size in (8, 16, 32):
        scanner = make_scanner([make_secret(secret)], chunk_size=chunk_size, extended=False)
        findings = [f for f in scanner.scan_bytes(data) if f.detector == "raw"]
        assert len(findings) == 1
        assert findings[0].offset == len(padding)
        assert findings[0].length == len(secret)


def test_long_stream_with_many_matches_is_streamed() -> None:
    scanner = make_scanner([make_secret()], chunk_size=512, extended=False)
    line = b"filler filler filler filler filler\n"
    body = (line * 200) + b"leak: " + TOKEN.encode() + b"\n" + (line * 200)
    findings = scanner.scan_bytes(body)
    assert [f.detector for f in findings if f.detector == "raw"] == ["raw"]
    assert findings[-1].line == 201


def test_multi_line_secret_is_found_line_by_line() -> None:
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
        "-----END PRIVATE KEY-----\n"
    )
    secret = Secret(label="env:KEY", value=pem, source="environment")
    scanner = make_scanner([secret])
    findings = scanner.scan_bytes(("key material follows\n" + pem).encode(), "log")
    detectors = {finding.detector for finding in findings}
    assert "lines" in detectors
    # The PEM banner itself must not be reported: it carries no secret material.
    assert all("BEGIN PRIVATE KEY" not in finding.preview for finding in findings)


def test_multi_line_secret_lines_are_covered_per_line() -> None:
    # Worker.InitializeSecretMasker registers every trimmed line of a secret
    # variable, so a key printed with indentation is still platform-covered.
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ  \n"
        "-----END PRIVATE KEY-----\n"
    )
    secret = Secret(label="env:KEY", value=pem, source="environment")
    scanner = make_scanner([secret], extended=False)
    findings = scanner.scan_bytes(pem.encode(), "log")
    lines = [finding for finding in findings if finding.detector == "lines"]
    assert lines
    assert lines[0].covered_by_runner is True


def test_surrounding_whitespace_is_trimmed_like_the_runner_registers_it() -> None:
    # The runner registers ``value.Trim()``, not the padded original.
    scanner = make_scanner(
        [make_secret("  padded-secret-value  ", label="env:PAD")], extended=False
    )
    findings = scanner.scan_bytes(b"value: padded-secret-value\n", "log")
    assert [finding.detector for finding in findings] == ["raw"]


def test_generic_rules_report_tokens_that_were_never_loaded() -> None:
    scanner = make_scanner([])
    body = b"docker login with dckr_pat_" + b"abcdefghijklmnopqrstuvwxy\n"
    findings = scanner.scan_bytes(body, "log")
    assert [finding.detector for finding in findings] == ["docker-pat"]
    assert findings[0].label == "generic:docker-pat"
    assert findings[0].is_gap is True


def test_known_value_wins_over_generic_pattern() -> None:
    token = "ghp_" + "a" * 36
    scanner = make_scanner([make_secret(token, label="env:GH")], extended=False)
    findings = scanner.scan_bytes(f"token: {token}\n".encode(), "log")
    assert len(findings) == 1
    assert findings[0].kind == "value"
    assert findings[0].label == "env:GH"


def test_only_gaps_filters_covered_forms() -> None:
    scanner = make_scanner([make_secret()], only_gaps=True)
    findings = scanner.scan_bytes(log_with_every_form(), "log")
    assert findings, "hex/uri-lower forms are gaps and must survive the filter"
    assert all(finding.is_gap for finding in findings)
    assert "raw" not in {finding.detector for finding in findings}


def test_ignore_fingerprint_suppresses_a_known_value() -> None:
    secret = make_secret()
    scanner = make_scanner([secret], ignore_fingerprints=[secret.fingerprint])
    assert scanner.scan_bytes(log_with_every_form(), "log") == []


def test_short_secrets_are_skipped_with_a_note() -> None:
    scanner = make_scanner([make_secret("tiny", label="env:TINY")], min_secret_length=8)
    assert scanner.notes and "env:TINY" in scanner.notes[0]
    assert scanner.pattern_count == 0


def test_long_secrets_are_truncated_with_a_note() -> None:
    secret = make_secret("x" * 20000, label="env:HUGE")
    scanner = make_scanner([secret], max_secret_length=64)
    assert any("env:HUGE" in note for note in scanner.notes)


def test_empty_input_reports_nothing() -> None:
    scanner = make_scanner([make_secret()])
    assert scanner.scan_bytes(b"") == []


def test_binary_input_does_not_break_detection() -> None:
    scanner = make_scanner([make_secret()], extended=False)
    body = b"\x00\x01\x02" + TOKEN.encode() + b"\xff\xfe\n"
    findings = scanner.scan_bytes(body, "bin")
    assert [finding.detector for finding in findings] == ["raw"]


# --------------------------------------------------------------------------- #
# previews                                                                    #
# --------------------------------------------------------------------------- #


def test_preview_masks_every_match_on_the_line_and_leaks_nothing() -> None:
    second = "secondSecretValue123"
    scanner = make_scanner([make_secret(), make_secret(second, label="env:SECOND")], extended=False)
    line = f"a={TOKEN} b={second}\n".encode()
    findings = scanner.scan_bytes(line, "log")
    assert len(findings) == 2
    for finding in findings:
        assert TOKEN not in finding.preview
        assert second not in finding.preview
        assert finding.preview.count("***") == 2


def test_preview_is_trimmed_for_very_long_lines() -> None:
    scanner = make_scanner([make_secret()], extended=False)
    line = ("filler " * 100) + TOKEN + (" more filler" * 100) + "\n"
    finding = scanner.scan_bytes(line.encode(), "log")[0]
    assert len(finding.preview) < 300
    assert "…" in finding.preview
    assert TOKEN not in finding.preview


def test_preview_of_first_line_without_leading_newline() -> None:
    scanner = make_scanner([make_secret()], extended=False)
    finding = scanner.scan_bytes(f"{TOKEN}\nsecond".encode(), "log")[0]
    assert finding.line == 1
    assert finding.preview == "***"


# --------------------------------------------------------------------------- #
# redaction                                                                   #
# --------------------------------------------------------------------------- #


def redact(data: bytes, **kwargs: object) -> tuple[bytes, object]:
    scanner = make_scanner([make_secret()], **kwargs)  # type: ignore[arg-type]
    out = io.BytesIO()
    stats = scanner.redact_stream(io.BytesIO(data), out)
    return out.getvalue(), stats


def test_redact_replaces_every_form() -> None:
    data = log_with_every_form()
    out, stats = redact(data)
    assert TOKEN.encode() not in out
    assert base64.b64encode(TOKEN.encode()) not in out
    assert TOKEN.encode().hex().encode() not in out
    assert stats.bytes_in == len(data)
    assert stats.replacements >= 3
    # The token appears verbatim twice: once on the "plain:" line and once on
    # the "uri:" line (the URI form of this token is the token itself).
    assert stats.detectors["raw"] == 2
    assert stats.gaps >= 1


@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_redacted_output_is_independent_of_chunk_size(chunk_size: int) -> None:
    data = log_with_every_form() * 3
    reference, _ = redact(data, chunk_size=65536)
    actual, _ = redact(data, chunk_size=chunk_size)
    assert actual == reference


def test_redaction_keeps_everything_else_intact() -> None:
    data = b"before\n" + TOKEN.encode() + b"\nafter\n"
    out, _ = redact(data)
    assert out == b"before\n***\nafter\n"


def test_redaction_is_idempotent() -> None:
    data = log_with_every_form()
    once, _ = redact(data)
    twice, _ = redact(once)
    assert once == twice


def test_redaction_with_detector_template() -> None:
    data = b"token=" + TOKEN.encode() + b"\n"
    out, _ = redact(data, mask="<{detector}>")
    assert out == b"token=<raw>\n"


def test_redaction_leaves_clean_input_byte_identical() -> None:
    data = b"nothing secret here\njust text\n"
    out, stats = redact(data)
    assert out == data
    assert stats.replacements == 0
    assert stats.bytes_out == len(data)


def test_redaction_of_empty_input() -> None:
    out, stats = redact(b"")
    assert out == b""
    assert stats.bytes_in == 0
    assert stats.replacements == 0


def test_redaction_reports_line_numbers() -> None:
    data = b"line one\nline two\n" + TOKEN.encode() + b"\n"
    _, stats = redact(data)
    assert stats.findings[0].line == 3


def test_redaction_records_gap_count() -> None:
    data = b"plain: " + TOKEN.encode() + b"\nhex: " + TOKEN.encode().hex().encode() + b"\n"
    _, stats = redact(data)
    assert stats.gaps == 1
    assert stats.replacements == 2


def test_redaction_with_only_gaps_keeps_covered_forms() -> None:
    data = b"plain: " + TOKEN.encode() + b"\nhex: " + TOKEN.encode().hex().encode() + b"\n"
    out, _ = redact(data, only_gaps=True)
    assert TOKEN.encode() in out
    assert TOKEN.encode().hex().encode() not in out


def test_redaction_of_a_stream_that_needs_positional_tracking() -> None:
    # Multi-line secret: the line variants must be redacted wherever they appear.
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
    secret = Secret(label="env:KEY", value=pem, source="environment")
    scanner = make_scanner([secret])
    out = io.BytesIO()
    scanner.redact_stream(io.BytesIO(pem.encode()), out)
    assert b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ" not in out.getvalue()


# --------------------------------------------------------------------------- #
# collapse                                                                    #
# --------------------------------------------------------------------------- #


def test_collapse_prefers_a_gap_over_a_longer_covered_nested_form() -> None:
    # 31 characters, so the base64 form has "=" padding and the unpadded form is
    # a distinct (shorter, uncovered) literal.
    secret = make_secret("ExactToken1234567890abcdefghijk")
    scanner = make_scanner([secret], extended=False)
    encoded = base64.b64encode(secret.value.encode()).decode()
    findings = scanner.scan_bytes(f"b64: {encoded}\n".encode(), "log")
    assert {finding.detector for finding in findings} == {"base64", "base64-no-pad"}

    collapsed, suppressed = collapse_findings(findings)
    assert len(collapsed) == 1
    # The unpadded form is a masking gap and is therefore the one worth reporting,
    # even though the padded form is longer.
    assert collapsed[0].detector == "base64-no-pad"
    assert collapsed[0].is_gap is True
    assert suppressed == 1


def test_collapse_is_deterministic() -> None:
    scanner = make_scanner([make_secret()], extended=False)
    findings = scanner.scan_bytes(log_with_every_form() * 2, "log")
    first = collapse_findings(findings)[0]
    second = collapse_findings(list(reversed(findings)))[0]
    assert [(f.offset, f.detector, f.length) for f in first] == [
        (f.offset, f.detector, f.length) for f in second
    ]


def test_collapse_of_empty_input() -> None:
    collapsed, suppressed = collapse_findings([])
    assert collapsed == []
    assert suppressed == 0


# --------------------------------------------------------------------------- #
# randomised end-to-end check                                                 #
# --------------------------------------------------------------------------- #


def test_random_logs_are_fully_redacted_and_chunk_invariant() -> None:
    """Deterministic fuzz: random secrets, random placements, random chunking."""
    rng = random.Random(2026)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for _ in range(15):
        secret_value = "".join(rng.choice(alphabet) for _ in range(rng.randint(12, 40)))
        secret = make_secret(secret_value, label="env:FUZZ")
        scanner = make_scanner([secret], extended=True)
        blocks: list[bytes] = []
        selected = select_encoders(extended=True)
        secret_variants = [variant.text.encode() for variant in variants(secret_value, selected)]
        for _ in range(rng.randint(1, 6)):
            blocks.append(("noise-" * rng.randint(1, 5)).encode())
            blocks.append(rng.choice(secret_variants))
            blocks.append(b"\n")
        data = b"".join(blocks)

        out = io.BytesIO()
        scanner.redact_stream(io.BytesIO(data), out)
        redacted = out.getvalue()
        for variant in secret_variants:
            assert variant not in redacted

        for chunk_size in (1, 7, 4096):
            other = make_scanner([secret], extended=True, chunk_size=chunk_size)
            buffer = io.BytesIO()
            other.redact_stream(io.BytesIO(data), buffer)
            assert buffer.getvalue() == redacted


def test_encoder_registry_core_group_is_usable_without_extended() -> None:
    scanner = Scanner(secrets=[], encoders=select_encoders())
    assert scanner.pattern_count == 0  # no secrets, no patterns
    assert {encoder.group for encoder in ENCODERS} == {"core", "extended"}
