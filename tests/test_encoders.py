"""Unit tests for the transformation catalogue.

The encoders marked as covered by the GitHub Actions runner are checked against
the behaviour of the corresponding ``ValueEncoders`` methods in
``actions/runner`` (see ``docs/github-masking.md``), so a regression here is a
regression in what maskgap claims about platform coverage.
"""

from __future__ import annotations

import base64

import pytest

from maskgap.encoders import (
    ENCODERS,
    MIN_VARIANT_LENGTH,
    encoders_by_name,
    run_variants,
    select_encoders,
    variants,
)

SECRET = "ghp_" + "Example0Token0WithSlashAnd1234"


def only(name: str):
    return (encoders_by_name()[name],)


def encoded(name: str, secret: str = SECRET) -> list[str]:
    return [text for _, text in run_variants(secret, only(name))]


# --------------------------------------------------------------------------- #
# registry                                                                    #
# --------------------------------------------------------------------------- #


def test_every_encoder_has_a_unique_name() -> None:
    names = [encoder.name for encoder in ENCODERS]
    assert len(names) == len(set(names))


def test_registry_is_not_empty_and_has_both_groups() -> None:
    groups = {encoder.group for encoder in ENCODERS}
    assert groups == {"core", "extended"}


def test_runner_coverage_is_limited_to_the_documented_set() -> None:
    covered = {encoder.name for encoder in ENCODERS if encoder.covered_by_runner}
    assert covered == {
        "raw",
        "base64",
        "base64-shift1",
        "base64-shift2",
        "json",
        "uri",
        "xml",
        "cmd",
        "expression",
        "powershell-pre",
        "powershell-post",
        "trim-quotes",
        "lines",
    }


def test_every_covered_encoder_names_its_runner_symbol() -> None:
    for encoder in ENCODERS:
        if encoder.covered_by_runner:
            assert encoder.runner_symbol, f"{encoder.name} claims runner coverage"


# --------------------------------------------------------------------------- #
# runner-covered encoders                                                     #
# --------------------------------------------------------------------------- #


def test_raw_is_the_value_itself() -> None:
    assert encoded("raw") == [SECRET]


def test_base64_matches_stdlib() -> None:
    assert encoded("base64") == [base64.b64encode(SECRET.encode()).decode()]


def test_base64_shift_encoders_drop_leading_bytes() -> None:
    data = SECRET.encode()
    assert encoded("base64-shift1") == [base64.b64encode(data[1:]).decode()]
    assert encoded("base64-shift2") == [base64.b64encode(data[2:]).decode()]


def test_base64_shift_is_a_no_op_for_values_shorter_than_the_shift() -> None:
    assert encoded("base64-shift1", "a") == []
    assert encoded("base64-shift2", "ab") == []


def test_cmd_escape_targets_double_quotes() -> None:
    assert encoded("cmd", 'pa"ss') == ['pa\\"ss']


def test_expression_escape_doubles_single_quotes() -> None:
    assert encoded("expression", "pa'ss") == ["pa''ss"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "plain"),
        ('say "hi"', 'say \\"hi\\"'),
        ("back\\slash", "back\\\\slash"),
        ("line\nbreak", "line\\nbreak"),
        ("tab\there", "tab\\there"),
        ("bell\x07", "bell\\u0007"),
        ("sep\u2028", "sep\\u2028"),
    ],
)
def test_json_escape(value: str, expected: str) -> None:
    assert encoded("json", value) == [expected]


def test_json_escape_keeps_printable_non_ascii() -> None:
    # Newtonsoft's default handling leaves non-ASCII characters untouched.
    assert encoded("json", "ключ") == ["ключ"]


def test_uri_escape_keeps_rfc3986_unreserved_characters() -> None:
    # .NET's Uri.EscapeDataString keeps ALPHA / DIGIT / - . _ ~
    assert encoded("uri", "a-b.c_d~e9") == ["a-b.c_d~e9"]


def test_uri_escape_uses_upper_case_hex() -> None:
    assert encoded("uri", "a b/c?d=e&f") == ["a%20b%2Fc%3Fd%3De%26f"]


def test_uri_lower_differs_only_in_hex_case() -> None:
    assert encoded("uri-lower", "a b") == ["a%20b"]
    assert encoded("uri-lower", "a/b") == ["a%2fb"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a&b", "a&amp;b"),
        ("a<b>c", "a&lt;b&gt;c"),
        ('q"q', "q&quot;q"),
        ("it's", "it&apos;s"),
    ],
)
def test_xml_escape(value: str, expected: str) -> None:
    assert encoded("xml", value) == [expected]


def test_trim_quotes_only_applies_to_long_quoted_values() -> None:
    assert encoded("trim-quotes", '"a-long-quoted-token"') == ["a-long-quoted-token"]
    assert encoded("trim-quotes", '"short"') == []
    assert encoded("trim-quotes", "no-quotes-at-all") == []


def test_powershell_pre_masks_the_leading_section() -> None:
    assert encoded("powershell-pre", "part1&part2&part3") == ["part1&part2&"]
    assert encoded("powershell-pre", "before&+after-long-enough") == ["before&+"]


def test_powershell_pre_ignores_values_without_ampersand_or_too_short() -> None:
    assert encoded("powershell-pre", "no-ampersand-here") == []
    assert encoded("powershell-pre", "a&b") == []


def test_powershell_post_masks_the_trailing_section() -> None:
    assert encoded("powershell-post", "part1&part2&trailing") == ["trailing"]
    assert encoded("powershell-post", "longen&+rest-of-the-value") == ["est-of-the-value"]


def test_powershell_post_edge_cases() -> None:
    assert encoded("powershell-post", "no-ampersand-here") == []
    assert encoded("powershell-post", "t&") == []
    assert encoded("powershell-post", "x&+y") == []
    # Sections shorter than six characters are not registered by the runner.
    assert encoded("powershell-post", "part1&part2&p3") == []


# --------------------------------------------------------------------------- #
# gap encoders                                                                #
# --------------------------------------------------------------------------- #


def test_base64_no_pad_strips_padding() -> None:
    out = encoded("base64-no-pad", "abc")
    assert out == [base64.b64encode(b"abc").decode().rstrip("=")]


def test_base64url_uses_the_url_safe_alphabet() -> None:
    value = "\xfb\xff\xfe"
    assert encoded("base64url", value) == [base64.urlsafe_b64encode(value.encode()).decode()]


def test_base64_linewrap_only_applies_to_long_values() -> None:
    assert encoded("base64-linewrap", "short") == []
    long_value = "x" * 100
    wrapped = encoded("base64-linewrap", long_value)[0]
    assert "\n" in wrapped
    assert wrapped.replace("\n", "") == base64.b64encode(long_value.encode()).decode()


def test_hex_encoders() -> None:
    assert encoded("hex", "AB") == ["4142"]
    # A value whose hex representation contains letters shows the case difference
    # (the value is UTF-8 encoded first, hence the leading c2).
    assert encoded("hex", "\xab") == ["c2ab"]
    assert encoded("hex-upper", "\xab") == ["C2AB"]


def test_base32_encoder() -> None:
    assert encoded("base32", "abc") == [base64.b32encode(b"abc").decode()]


def test_case_and_obfuscation_encoders() -> None:
    assert encoded("upper", "aB") == ["AB"]
    assert encoded("lower", "aB") == ["ab"]
    assert encoded("reverse", "abc") == ["cba"]
    assert encoded("rot13", "abc") == ["nop"]


def test_fold_and_char_space_encoders() -> None:
    assert encoded("fold-64", "x" * 10) == []
    folded = encoded("fold-64", "x" * 65)[0]
    assert folded.splitlines()[0] == "x" * 64
    assert encoded("char-space", "abc") == ["a b c"]


def test_prefix_and_suffix_encoders() -> None:
    value = "abcdefghij" * 5  # 50 characters
    assert encoded("prefix-32", value) == [value[:32]]
    assert encoded("suffix-32", value) == [value[-32:]]
    assert encoded("prefix-32", "short") == []


def test_lines_encoder_splits_multi_line_secrets() -> None:
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
        "-----END PRIVATE KEY-----"
    )
    out = encoded("lines", pem)
    assert out == ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"]


def test_lines_encoder_is_a_no_op_for_single_line_values() -> None:
    assert encoded("lines", "single-line-token") == []


def test_lines_encoder_skips_blank_lines() -> None:
    assert encoded("lines", "first-line-here\n\nsecond-line-here") == [
        "first-line-here",
        "second-line-here",
    ]


def test_lines_encoder_trims_lines_the_way_the_runner_registers_them() -> None:
    # Worker.InitializeSecretMasker splits with TrimEntries; indentation is not
    # part of the registered per-line hint.
    assert encoded("lines", "  first-line-here  \n\tsecond-line-here\t\r\n") == [
        "first-line-here",
        "second-line-here",
    ]


# --------------------------------------------------------------------------- #
# variant assembly                                                            #
# --------------------------------------------------------------------------- #


def test_variants_drops_short_forms() -> None:
    produced = variants("abc", select_encoders(extended=True))
    assert all(len(variant.text) >= MIN_VARIANT_LENGTH for variant in produced)


def test_variants_merges_identical_texts_and_marks_coverage() -> None:
    # An already upper-case secret makes the "upper" encoder redundant; the
    # merged variant must stay marked as covered because "raw" is covered.
    produced = variants("UPPERCASE-TOKEN-123", select_encoders(extended=True))
    texts = [variant.text for variant in produced]
    assert len(texts) == len(set(texts))
    merged = next(variant for variant in produced if variant.text == "UPPERCASE-TOKEN-123")
    assert merged.covered_by_runner is True
    assert "raw" in (merged.encoder, *merged.aliases)


def test_variants_are_deterministic() -> None:
    encoders = select_encoders(extended=True)
    assert variants(SECRET, encoders) == variants(SECRET, encoders)


def test_variants_cover_the_same_secret_differently_for_hex() -> None:
    produced = variants("ABCDEF123456", select_encoders(extended=True))
    hex_variant = next(variant for variant in produced if variant.encoder == "hex")
    assert hex_variant.text == "414243444546313233343536"
    assert hex_variant.covered_by_runner is False


# --------------------------------------------------------------------------- #
# selection                                                                   #
# --------------------------------------------------------------------------- #


def test_select_encoders_default_is_core_only() -> None:
    names = {encoder.name for encoder in select_encoders()}
    assert "hex" in names
    assert "rot13" not in names


def test_select_encoders_extended_adds_more() -> None:
    core = {encoder.name for encoder in select_encoders()}
    extended = {encoder.name for encoder in select_encoders(extended=True)}
    assert core < extended


def test_select_encoders_explicit_list() -> None:
    names = [encoder.name for encoder in select_encoders("raw,hex")]
    assert names == ["raw", "hex"]


def test_select_encoders_skip_removes_entries() -> None:
    names = {encoder.name for encoder in select_encoders(extended=True, skip=["hex", "raw"])}
    assert "hex" not in names
    assert "raw" not in names


def test_select_encoders_rejects_unknown_names() -> None:
    with pytest.raises(ValueError, match="unknown encoder"):
        select_encoders("nope")


def test_select_encoders_rejects_unknown_skips() -> None:
    with pytest.raises(ValueError, match="unknown encoder"):
        select_encoders(skip=["nope"])


def test_encoders_by_name_returns_a_copy() -> None:
    registry = encoders_by_name()
    registry.pop("hex")
    assert "hex" in encoders_by_name()
