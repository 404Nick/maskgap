"""Unit tests for the Aho–Corasick matcher.

The classic reference case ("he", "she", "hers", "his") is included because it is
the smallest input that exercises failure links *and* output propagation: a match
of "she" has to report both "she" and "he".
"""

from __future__ import annotations

from maskgap.matcher import Matcher


def test_empty_matcher_reports_nothing() -> None:
    matcher: Matcher[str] = Matcher([])
    assert len(matcher) == 0
    assert matcher.max_pattern_length == 0
    assert list(matcher.iter_matches(b"anything")) == []


def test_single_pattern() -> None:
    matcher = Matcher({b"needle": "n"})
    found = [(match.start, match.end, match.value) for match in matcher.iter_matches(b"a needle b")]
    assert found == [(2, 8, "n")]


def test_multiple_patterns_are_all_reported() -> None:
    matcher = Matcher({b"ab": "ab", b"bc": "bc", b"abc": "abc"})
    found = sorted((m.start, m.end, m.value) for m in matcher.iter_matches(b"abc"))
    assert found == [(0, 2, "ab"), (0, 3, "abc"), (1, 3, "bc")]


def test_failure_links_report_suffix_matches() -> None:
    matcher = Matcher({b"he": "he", b"she": "she", b"hers": "hers", b"his": "his"})
    found = sorted((m.start, m.value) for m in matcher.iter_matches(b"ushers"))
    assert found == [(1, "she"), (2, "he"), (2, "hers")]


def test_overlapping_matches_are_all_reported() -> None:
    matcher = Matcher({b"aaa": "a", b"aa": "b"})
    found = {(m.start, m.end, m.value) for m in matcher.iter_matches(b"aaaa")}
    assert found == {
        (0, 2, "b"),
        (0, 3, "a"),
        (1, 3, "b"),
        (1, 4, "a"),
        (2, 4, "b"),
    }


def test_offset_shifts_reported_positions() -> None:
    matcher = Matcher({b"x": "x"})
    match = next(iter(matcher.iter_matches(b"abx", offset=1000)))
    assert (match.start, match.end) == (1002, 1003)


def test_identical_patterns_carry_all_values() -> None:
    matcher = Matcher([(b"dup", "first"), (b"dup", "second")])
    values = sorted(match.value for match in matcher.iter_matches(b"dup dup"))
    assert values == ["first", "first", "second", "second"]


def test_empty_patterns_are_ignored() -> None:
    matcher = Matcher([(b"", "empty"), (b"a", "a")])
    assert len(matcher) == 1
    assert [match.value for match in matcher.iter_matches(b"a")] == ["a"]


def test_binary_safe_including_nul_bytes() -> None:
    matcher = Matcher({b"\x00\x01\xff": "bin"})
    data = b"prefix\x00\x01\xffsuffix"
    match = next(iter(matcher.iter_matches(data)))
    assert (match.start, match.end) == (6, 9)


def test_utf8_patterns_and_data() -> None:
    pattern = "ключ-🔑".encode()
    matcher = Matcher({pattern: "ru"})
    data = "перед ".encode() + pattern + " после".encode()
    match = next(iter(matcher.iter_matches(data)))
    assert data[match.start : match.end] == pattern


def test_max_pattern_length_and_state_count() -> None:
    matcher = Matcher({b"a": "a", b"abcd": "d", b"ab": "b"})
    assert matcher.max_pattern_length == 4
    assert matcher.state_count >= 5  # root + a + ab + abc + abcd
    assert len(matcher) == 3


def test_no_match_returns_nothing() -> None:
    matcher = Matcher({b"absent": "x"})
    assert list(matcher.iter_matches(b"nothing to see here")) == []


def test_prefix_patterns_do_not_require_a_suffix() -> None:
    matcher = Matcher({b"secret": "s"})
    matches = list(matcher.iter_matches(b"topsecret"))
    assert [(m.start, m.end) for m in matches] == [(3, 9)]
