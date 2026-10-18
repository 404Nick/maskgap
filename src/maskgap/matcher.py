"""A byte-level Aho–Corasick automaton for literal multi-pattern search.

Why not ``re``? maskgap searches for thousands of literal byte strings — the
transformed variants of every loaded secret — inside logs that may contain
arbitrary binary data and embedded newlines. Python's regex engine degrades
badly with huge alternations, and each variant would have to be escaped first.
A trie with failure links scans in predictable linear time and the behaviour is
straightforward to test.

The automaton works on ``bytes`` so that offsets always refer to raw positions in
the input, no matter what the input encoding is.
"""

from __future__ import annotations

import dataclasses
from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from typing import Generic, TypeVar

__all__ = ["Match", "Matcher"]

T = TypeVar("T")


@dataclasses.dataclass(frozen=True, slots=True)
class Match(Generic[T]):
    """One occurrence of a pattern at ``[start, end)`` in the scanned buffer."""

    start: int
    end: int
    value: T

    @property
    def length(self) -> int:  # pragma: no cover - trivial
        return self.end - self.start


class Matcher(Generic[T]):
    """Find every occurrence of a set of literal byte patterns in one pass.

    Each unique pattern carries an arbitrary payload (here: a
    :class:`~maskgap.scanner.PatternTag`). Patterns that share the same bytes are
    allowed and all of their payloads are reported.
    """

    __slots__ = ("_goto", "_fail", "_out", "_max_length", "_pattern_count")

    def __init__(self, patterns: Mapping[bytes, T] | Iterable[tuple[bytes, T]]) -> None:
        items: Iterable[tuple[bytes, T]]
        items = patterns.items() if isinstance(patterns, Mapping) else patterns

        self._goto: list[dict[int, int]] = [{}]
        self._fail: list[int] = [0]
        self._out: list[list[tuple[T, int]]] = [[]]
        self._max_length = 0
        self._pattern_count = 0

        for pattern, value in items:
            if not pattern:
                continue
            self._insert(pattern, value)

        self._build_failure_links()

    # -- construction ------------------------------------------------------ #

    def _insert(self, pattern: bytes, value: T) -> None:
        state = 0
        for byte in pattern:
            nxt = self._goto[state].get(byte)
            if nxt is None:
                nxt = len(self._goto)
                self._goto[state][byte] = nxt
                self._goto.append({})
                self._fail.append(0)
                self._out.append([])
            state = nxt
        self._out[state].append((value, len(pattern)))
        self._pattern_count += 1
        if len(pattern) > self._max_length:
            self._max_length = len(pattern)

    def _build_failure_links(self) -> None:
        """Breadth-first construction of failure links, with output propagation."""
        queue: deque[int] = deque()
        for child in self._goto[0].values():
            self._fail[child] = 0
            queue.append(child)

        while queue:
            state = queue.popleft()
            for byte, child in self._goto[state].items():
                queue.append(child)
                fallback = self._fail[state]
                while fallback and byte not in self._goto[fallback]:
                    fallback = self._fail[fallback]
                candidate = self._goto[fallback].get(byte, 0)
                self._fail[child] = candidate if candidate != child else 0
                # Patterns that match a suffix of this state must fire too.
                if self._out[candidate]:
                    self._out[child].extend(self._out[candidate])

    # -- querying ---------------------------------------------------------- #

    def __len__(self) -> int:
        return self._pattern_count

    @property
    def max_pattern_length(self) -> int:
        """Longest pattern; callers use it to size their overlap window."""
        return self._max_length

    @property
    def state_count(self) -> int:
        """Number of automaton states — handy for performance diagnostics."""
        return len(self._goto)

    def iter_matches(self, data: bytes, *, offset: int = 0) -> Iterator[Match[T]]:
        """Yield every match in ``data``; ``offset`` shifts reported positions."""
        goto = self._goto
        fail = self._fail
        out = self._out
        state = 0
        for index, byte in enumerate(data):
            while state and byte not in goto[state]:
                state = fail[state]
            state = goto[state].get(byte, 0)
            outputs = out[state]
            if outputs:
                end = index + 1
                for value, length in outputs:
                    yield Match(start=offset + end - length, end=offset + end, value=value)
