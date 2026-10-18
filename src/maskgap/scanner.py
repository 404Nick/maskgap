"""Streaming leak detection and redaction.

Two operations are built on the same machinery:

``scan``
    Walk a byte stream once and report every occurrence of a transformed secret
    (and of a provider-shaped token) with enough context to decide what to do
    about it. The secret value itself is never printed.

``redact``
    The same walk, but matched bytes are replaced in the output. This is the form
    you use as a filter (``build | maskgap redact --env auto``) or to scrub
    artefacts before uploading them.

Both are streaming: memory use is bounded by the chunk size plus the longest
pattern, so a 4 GB log is as fine as a 4 KB one.

The one subtlety worth spelling out is the overlap between windows. Each window
keeps the last ``longest pattern - 1`` bytes of the previous one, which means a
match that straddles a chunk boundary is still found. Bytes that are still inside
that overlap are not *acted upon* yet — they may belong to a longer match whose
tail has not been read — so they are carried over instead of being reported twice
or masked twice. As a result both operations produce exactly the same output no
matter how the input happens to be split into chunks, which the test suite checks
by re-running everything with chunk sizes from 1 byte upwards.
"""

from __future__ import annotations

import bisect
import dataclasses
import hashlib
import io
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from typing import BinaryIO

from maskgap.encoders import MIN_VARIANT_LENGTH, EncoderInfo, variants
from maskgap.generic import GENERIC_RULES, GenericRule, compile_rules
from maskgap.matcher import Match, Matcher
from maskgap.secrets import MAX_SECRET_LENGTH, Secret

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_MASK",
    "Finding",
    "PatternTag",
    "RedactStats",
    "Scanner",
    "build_patterns",
    "collapse_findings",
]

DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_MASK = "***"

#: Longest variant that is turned into a search pattern. Whole-value encodings of
#: a huge secret are pointless (they would never fit in a log line) and would
#: dominate the automaton, so they give way to the per-line variants.
MAX_VARIANT_LENGTH = 4096

#: Context window for a finding, in characters.
PREVIEW_WIDTH = 200


@dataclasses.dataclass(frozen=True, slots=True)
class PatternTag:
    """Payload carried by every search pattern."""

    kind: str
    detector: str
    covered_by_runner: bool
    label: str
    fingerprint: str


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    """One place where a secret (in some form) would end up in the output."""

    offset: int
    length: int
    kind: str
    detector: str
    covered_by_runner: bool
    label: str
    fingerprint: str
    source: str
    line: int
    column: int
    preview: str

    @property
    def is_gap(self) -> bool:
        """True when the CI platform's own masking would *not* cover this form."""
        return not self.covered_by_runner

    def dedupe_key(self) -> tuple[int, str, str, str]:
        return (self.offset, self.detector, self.label, self.fingerprint)

    def location(self) -> str:
        return f"{self.source}:{self.line}:{self.column}"


@dataclasses.dataclass(slots=True)
class RedactStats:
    """What a redaction run did."""

    bytes_in: int = 0
    bytes_out: int = 0
    replacements: int = 0
    detectors: Counter[str] = dataclasses.field(default_factory=Counter)
    findings: list[Finding] = dataclasses.field(default_factory=list)

    @property
    def gaps(self) -> int:
        return sum(1 for finding in self.findings if finding.is_gap)


@dataclasses.dataclass(slots=True)
class _Window:
    """A slice of the input plus the bookkeeping needed for stable positions."""

    data: bytes
    #: Absolute offset of ``data[0]`` in the stream.
    offset: int
    #: How many leading bytes of ``data`` are final and may be acted upon.
    limit: int
    #: Newlines in the stream before ``data[0]``.
    newlines: int
    #: Absolute offset at which the line containing ``data[0]`` started.
    line_start: int
    #: Bytes newly read for this window (not counting the overlap).
    fresh: int


class _WindowReader:
    """Read a stream in overlapping windows, at the caller's pace.

    The caller decides how much of each window to consume (:meth:`consume`),
    because a redaction may need to extend past the durable limit to cover a
    match that started in the overlap. Positions reported by :meth:`next` always
    describe the buffer as a whole, so the caller never has to shift offsets.
    """

    __slots__ = (
        "_chunk_size",
        "_stream",
        "buffer",
        "done",
        "eof",
        "keep",
        "line_start",
        "newlines",
        "offset",
    )

    def __init__(self, stream: BinaryIO, chunk_size: int, keep: int) -> None:
        self._stream = stream
        self._chunk_size = chunk_size
        self.buffer = b""
        self.offset = 0
        self.newlines = 0
        self.line_start = 0
        self.keep = keep
        self.eof = False
        self.done = False

    def next(self) -> _Window | None:  # noqa: A003 - reads like ``next(reader)``
        """Return the next window, or ``None`` once the stream is drained."""
        if self.done:
            return None
        fresh = 0
        if not self.eof:
            chunk = self._stream.read(self._chunk_size)
            if chunk:
                self.buffer += chunk
                fresh = len(chunk)
            else:
                self.eof = True
        if self.eof and not self.buffer:
            self.done = True
            return None
        limit = len(self.buffer) if self.eof else max(0, len(self.buffer) - self.keep)
        return _Window(
            data=self.buffer,
            offset=self.offset,
            limit=limit,
            newlines=self.newlines,
            line_start=self.line_start,
            fresh=fresh,
        )

    def consume(self, count: int) -> None:
        """Drop the first ``count`` bytes of the buffer and advance positions."""
        count = min(count, len(self.buffer))
        dropped = self.buffer[:count]
        self.newlines += dropped.count(b"\n")
        last_newline = dropped.rfind(b"\n")
        if last_newline != -1:
            self.line_start = self.offset + last_newline + 1
        self.offset += count
        self.buffer = self.buffer[count:]


def _to_bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def _fingerprint_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()[:12]}"


def _column(window: _Window, match: Match[PatternTag]) -> int:
    """1-based column of the match start within its line.

    A newline inside the window settles the column directly; otherwise the line
    began before the window, and ``line_start`` (an absolute offset) is the
    reference point.
    """
    start = match.start - window.offset
    last_newline = window.data.rfind(b"\n", 0, start)
    if last_newline != -1:
        return start - last_newline
    return match.start - window.line_start + 1


def build_patterns(
    secrets: Sequence[Secret],
    encoders: Sequence[EncoderInfo],
    *,
    min_secret_length: int,
    max_secret_length: int = MAX_SECRET_LENGTH,
    max_variant_length: int = MAX_VARIANT_LENGTH,
) -> tuple[list[tuple[bytes, PatternTag]], list[str]]:
    """Turn secrets into literal search patterns.

    Returns the patterns plus human-readable notes about secrets that were
    skipped or truncated, so callers can warn instead of silently pretending
    everything was covered.
    """
    patterns: list[tuple[bytes, PatternTag]] = []
    notes: list[str] = []

    for secret in secrets:
        # The runner registers ``value.Trim()`` (Worker.InitializeSecretMasker),
        # so surrounding whitespace is not part of the masked secret.
        value = secret.value.strip()
        if len(value) < min_secret_length:
            notes.append(
                f"skipped {secret.label}: shorter than the minimum of "
                f"{min_secret_length} characters"
            )
            continue
        if len(value) > max_secret_length:
            notes.append(
                f"{secret.label}: longer than {max_secret_length} characters; only its "
                f"first {max_secret_length} characters and its individual lines are checked"
            )
            value = value[:max_secret_length]
        fingerprint = secret.fingerprint
        for variant in variants(value, encoders):
            if not MIN_VARIANT_LENGTH <= len(variant.text) <= max_variant_length:
                continue
            patterns.append(
                (
                    _to_bytes(variant.text),
                    PatternTag(
                        kind="value",
                        detector=variant.encoder,
                        covered_by_runner=variant.covered_by_runner,
                        label=secret.label,
                        fingerprint=fingerprint,
                    ),
                )
            )
    return patterns, notes


class Scanner:
    """Detect and redact secrets in byte streams.

    Parameters
    ----------
    secrets:
        Secret values to hunt for. Values shorter than ``min_secret_length`` are
        ignored: short literals appear in unrelated text by chance.
    encoders:
        Which transformations to search for (see :mod:`maskgap.encoders`).
    generic_rules:
        Provider-shaped patterns to search for in addition to known values.
        Defaults to :data:`maskgap.generic.GENERIC_RULES`; pass an empty tuple to
        disable pattern matching entirely.
    only_gaps:
        Act only on forms the CI platform does not mask.
    ignore_fingerprints:
        Fingerprints (``sha256:...``) to suppress — used to accept a known benign
        match without weakening everything else.
    mask:
        Replacement text. ``{detector}`` is substituted with the encoder or rule
        name; nothing else is interpreted.
    """

    def __init__(
        self,
        *,
        secrets: Sequence[Secret] = (),
        encoders: Sequence[EncoderInfo],
        min_secret_length: int = 8,
        max_secret_length: int = MAX_SECRET_LENGTH,
        generic_rules: Sequence[GenericRule] | None = None,
        skip_generic_rules: Iterable[str] = (),
        only_gaps: bool = False,
        ignore_fingerprints: Iterable[str] = (),
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        mask: str = DEFAULT_MASK,
    ) -> None:
        patterns, self.notes = build_patterns(
            secrets,
            encoders,
            min_secret_length=min_secret_length,
            max_secret_length=max_secret_length,
        )
        self._matcher: Matcher[PatternTag] = Matcher(patterns)
        rules = GENERIC_RULES if generic_rules is None else tuple(generic_rules)
        self._rules = compile_rules(rules, skip=frozenset(skip_generic_rules))
        self._only_gaps = only_gaps
        self._ignored = frozenset(ignore_fingerprints)
        self._chunk_size = max(1, chunk_size)
        self._mask = mask
        self._secrets = tuple(secrets)

    # -- introspection ----------------------------------------------------- #

    @property
    def pattern_count(self) -> int:
        return len(self._matcher)

    @property
    def state_count(self) -> int:
        return self._matcher.state_count

    @property
    def secret_count(self) -> int:
        return len(self._secrets)

    @property
    def mask(self) -> str:
        return self._mask

    @property
    def generic_rule_count(self) -> int:
        return len(self._rules)

    # -- windows ----------------------------------------------------------- #

    def _reader(self, stream: BinaryIO) -> _WindowReader:
        return _WindowReader(
            stream,
            chunk_size=self._chunk_size,
            keep=max(0, self._matcher.max_pattern_length - 1),
        )

    # -- matching ---------------------------------------------------------- #

    def _visible(self, matches: Sequence[Match[PatternTag]]) -> list[Match[PatternTag]]:
        """Apply the wanted-filter plus the ``only_gaps`` shadowing rule.

        In ``only_gaps`` mode a gap match that lies completely inside a covered
        match is dropped: the platform masks the whole covered span, so the
        nested form is not an independent leak. Without this, encoders that
        produce substrings of the value (``prefix-32``, ``suffix-32``,
        ``base64-no-pad``) would carve holes out of a value the platform would
        otherwise mask, and the tattletale bytes would remain in clear text.
        """
        visible = [match for match in matches if self._wanted(match.value)]
        if not self._only_gaps or not visible:
            return visible
        intervals = sorted(
            (match.start, match.end) for match in matches if match.value.covered_by_runner
        )
        if not intervals:
            return visible
        merged: list[tuple[int, int]] = []
        for start, end in intervals:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        starts = [start for start, _ in merged]
        kept: list[Match[PatternTag]] = []
        for match in visible:
            index = bisect.bisect_right(starts, match.start) - 1
            if index >= 0 and merged[index][1] >= match.end:
                continue
            kept.append(match)
        return kept

    def _iter_matches(self, window: bytes, offset: int) -> Iterator[Match[PatternTag]]:
        yield from self._matcher.iter_matches(window, offset=offset)
        if self._rules:
            # Latin-1 decoding keeps a one-to-one mapping between character and
            # byte offsets, so regex positions stay valid for binary input too.
            text = window.decode("latin-1")
            for rule, regex in self._rules:
                for found in regex.finditer(text):
                    start, end = found.span(rule.group)
                    yield Match(
                        start=offset + start,
                        end=offset + end,
                        value=PatternTag(
                            kind="generic",
                            detector=rule.name,
                            covered_by_runner=False,
                            label=f"generic:{rule.name}",
                            fingerprint=_fingerprint_bytes(window[start:end]),
                        ),
                    )

    # -- scanning ---------------------------------------------------------- #

    def scan_stream(self, stream: BinaryIO, source: str) -> Iterator[Finding]:
        """Yield findings for one input stream, in order of appearance."""
        seen: set[tuple[int, str, str, str]] = set()
        reader = self._reader(stream)
        while (window := reader.next()) is not None:
            matches = list(self._iter_matches(window.data, window.offset))
            for match in self._visible(matches):
                if match.start - window.offset >= window.limit:
                    # Starts inside the overlap: the bytes are kept for the next
                    # window, so this match is judged then, with a settled line.
                    continue
                finding = self._make_finding(window, match, matches, source)
                if finding is None:
                    continue
                key = finding.dedupe_key()
                if key in seen:
                    continue
                seen.add(key)
                yield finding
            reader.consume(window.limit)

    def scan_bytes(self, data: bytes, source: str = "<bytes>") -> list[Finding]:
        """Convenience wrapper around :meth:`scan_stream` for whole buffers."""
        return list(self.scan_stream(io.BytesIO(data), source))

    def _wanted(self, tag: PatternTag) -> bool:
        if self._only_gaps and tag.covered_by_runner:
            return False
        return tag.fingerprint not in self._ignored

    def _make_finding(
        self,
        window: _Window,
        match: Match[PatternTag],
        matches: Sequence[Match[PatternTag]],
        source: str,
    ) -> Finding | None:
        tag = match.value
        if not self._wanted(tag):
            return None
        start = match.start - window.offset
        if tag.kind == "generic" and any(
            other.value.kind == "value" and other.start < match.end and match.start < other.end
            for other in matches
        ):
            # A hit on a known value is strictly better information than a guess.
            return None
        return Finding(
            offset=match.start,
            length=match.end - match.start,
            kind=tag.kind,
            detector=tag.detector,
            covered_by_runner=tag.covered_by_runner,
            label=tag.label,
            fingerprint=tag.fingerprint,
            source=source,
            line=window.newlines + window.data.count(b"\n", 0, start) + 1,
            column=_column(window, match),
            preview=_render_preview(window.data, window.offset, match, matches, self._mask),
        )

    # -- redaction --------------------------------------------------------- #

    def redact_stream(
        self, stream: BinaryIO, out: BinaryIO, source: str = "<stream>"
    ) -> RedactStats:
        """Copy ``stream`` to ``out``, replacing every match with the mask text."""
        stats = RedactStats()
        reader = self._reader(stream)
        while (window := reader.next()) is not None:
            stats.bytes_in += window.fresh
            regions, commit_end = self._select_regions(window)
            limit = commit_end - window.offset

            position = 0
            for start, end, tag in regions:
                local_start = start - window.offset
                local_end = end - window.offset
                out.write(window.data[position:local_start])
                out.write(_to_bytes(self._mask_for(tag)))
                position = local_end
                stats.replacements += 1
                stats.detectors[tag.detector] += 1
                stats.findings.append(
                    Finding(
                        offset=start,
                        length=end - start,
                        kind=tag.kind,
                        detector=tag.detector,
                        covered_by_runner=tag.covered_by_runner,
                        label=tag.label,
                        fingerprint=tag.fingerprint,
                        source=source,
                        line=window.newlines + window.data.count(b"\n", 0, local_start) + 1,
                        column=_column(window, Match(start=start, end=end, value=tag)),
                        preview="",
                    )
                )
            out.write(window.data[position:limit])
            stats.bytes_out += limit
            reader.consume(limit)

        return stats

    def _select_regions(self, window: _Window) -> tuple[list[tuple[int, int, PatternTag]], int]:
        """Pick the byte regions to mask, and how much of the window is final.

        Two rules keep the output safe and chunk-size independent:

        * a region is only acted upon once its bytes are *durable* — matches that
          start inside the trailing overlap are judged by the next window;
        * overlapping matches are merged into one region, so the tail of a longer
          overlapping match can never survive next to a shorter one.

        Returns ``(regions, commit_end)`` with absolute offsets.
        """
        limit = window.offset + window.limit
        wanted = self._visible(list(self._iter_matches(window.data, window.offset)))
        candidates = sorted(wanted, key=lambda item: (item.start, -(item.end - item.start)))

        selected: list[Match[PatternTag]] = []
        while True:
            selected = [match for match in candidates if match.start < limit]
            if not selected:
                break
            new_limit = max(limit, max(match.end for match in selected))
            if new_limit == limit:
                break
            # Growing the frontier can pull in a match that started in the
            # overlap but reaches past everything seen so far.
            limit = new_limit

        regions: list[list] = []
        for match in selected:
            if regions and match.start <= regions[-1][1]:
                regions[-1][1] = max(regions[-1][1], match.end)
            else:
                regions.append([match.start, match.end, match.value])
        return [(start, end, tag) for start, end, tag in regions], limit

    def _mask_for(self, tag: PatternTag) -> str:
        if "{detector}" in self._mask:
            return self._mask.replace("{detector}", tag.detector)
        return self._mask


def collapse_findings(findings: Sequence[Finding]) -> tuple[list[Finding], int]:
    """Reduce overlapping findings to the most informative one per region.

    Encodings nest: the unpadded base64 of a value is a prefix of the padded
    form, and both are found, so the same leak is reported twice. When findings
    overlap, keep the one that is a *gap* (the actionable kind) and, among
    equals, the longest. Returns the kept findings (sorted by position) and the
    number that were suppressed.
    """
    ordered = sorted(findings, key=lambda f: (not f.is_gap, -f.length, f.offset))
    accepted: list[tuple[int, int, Finding]] = []
    starts: list[int] = []
    for finding in ordered:
        start = finding.offset
        end = start + finding.length
        index = bisect.bisect_right(starts, start)
        overlaps = False
        for neighbour in (index - 1, index):
            if 0 <= neighbour < len(accepted):
                other_start, other_end, _ = accepted[neighbour]
                if start < other_end and other_start < end:
                    overlaps = True
                    break
        if overlaps:
            continue
        accepted.insert(index, (start, end, finding))
        starts.insert(index, start)

    kept = sorted((entry[2] for entry in accepted), key=lambda f: (f.offset, f.detector))
    return kept, len(findings) - len(kept)


def _render_preview(
    window: bytes,
    offset: int,
    match: Match[PatternTag],
    matches: Iterable[Match[PatternTag]],
    mask: str,
) -> str:
    """Show the surrounding line with *every* known match in it masked.

    Masking all matches — not just the one being reported — matters: two secrets
    can share a line, and a preview is meant to be pasteable into a bug report.
    """
    start = match.start - offset
    end = match.end - offset
    line_start = window.rfind(b"\n", 0, start) + 1
    line_end = window.find(b"\n", end)
    if line_end == -1:
        line_end = len(window)

    spans = sorted(
        (item.start - offset, item.end - offset)
        for item in matches
        if item.start - offset < line_end and line_start < item.end - offset
    )
    pieces: list[str] = []
    position = line_start
    for span_start, span_end in spans:
        if span_start < position:
            continue
        pieces.append(_decode(window[position:span_start]))
        pieces.append(mask)
        position = span_end
    pieces.append(_decode(window[position:line_end]))
    text = "".join(pieces)

    if len(text) <= PREVIEW_WIDTH:
        return text
    index = text.find(mask)
    if index == -1:  # pragma: no cover - defensive
        return text[: PREVIEW_WIDTH - 1] + "…"
    left = max(0, index - PREVIEW_WIDTH // 3)
    right = min(len(text), left + PREVIEW_WIDTH)
    snippet = text[left:right]
    if left > 0:
        snippet = "…" + snippet
    if right < len(text):
        snippet = snippet + "…"
    return snippet


def _decode(data: bytes) -> str:
    """Best-effort decoding for previews: never raises, never leaks more than intended."""
    return data.decode("utf-8", "replace")
