# Design

maskgap answers one question well: *given the actual secret values, which
literals in this stream would survive the CI platform's masking?* Everything in
the implementation follows from taking that question literally.

## Data flow

```
secret sources            transforms              stream                        reports
──────────────            ──────────              ──────                        ───────
--env NAME        ┐                                                      ┌─ scan: findings,
--env auto        │      30 encoders          ┌── streaming window ──┐    │  exit 1
--env-prefix P    ├──▶  (data-driven,    ──▶  │  Aho–Corasick over   │ ──▶├─ redact: bytes out
--env-file .env   │      coverage flags)       │  variants + regex    │    │  (+ stats)
--secrets-file    ┘                           │  provider rules      │    └─ audit / encoders
                                              └──────────────────────┘
```

Modules, in dependency order:

| module | responsibility |
| --- | --- |
| `encoders.py` | the transformation registry; `covered_by_runner` is the platform-coverage claim, `runner_symbol` names the runner source |
| `secrets.py` | secret sources, the `auto` name heuristic, fingerprints |
| `matcher.py` | Aho–Corasick automaton over literal patterns |
| `generic.py` | 23 provider-shaped regular expressions (GitHub, AWS, Slack, JWT, ...) |
| `scanner.py` | streaming windows, matching, findings, redaction, collapse |
| `report.py` | text/JSON rendering — presentation only, never sees a need to print a value |
| `cli.py` | argparse plumbing, exit codes, atomic in-place rewrite |

## Matching

Patterns are *literals*: every encoder variant of every secret value (bounded by
`MIN_VARIANT_LENGTH` = 6 and `MAX_VARIANT_LENGTH` = 4096), plus the provider
regexes. Aho–Corasick gives one pass per byte regardless of how many patterns
are loaded — a job with 50 secrets and all encoders produces thousands of
patterns, and the automaton's failure links keep scanning linear.

Positions are byte offsets. Regex rules run over the window decoded as Latin-1,
which is a one-to-one mapping from byte to character, so `re` offsets stay valid
for binary input and no re-encoding guesswork is needed.

## Streaming and chunk-size invariance

Input is read in `chunk_size` (default 64 KiB) windows. Each window keeps the
last `max_pattern_length - 1` bytes of the previous one, so a match straddling a
boundary is still seen. Bytes that lie in that overlap are *not acted upon yet*:
their match may still grow, or may start inside the overlap and be better judged
by the next window. The window reader lets the consumer decide how much to
consume (`_WindowReader.consume`), which is what makes redaction of a match that
ends past the durable limit possible without reprocessing.

The invariant this buys: **scan findings and redacted bytes do not depend on how
the stream was cut into chunks.** The test suite re-runs scanning and redaction
with chunk sizes 1, 2, 3, 5, 8, 17, 64, 1024 and 65536 bytes and compares.

## Redaction

`redact_stream` selects regions with two rules:

1. only *durable* matches are acted on (those whose start is before the limit of
   final bytes), because a match starting in the overlap is judged next round;
2. overlapping matches are **merged into one region**, so the tail of a longer
   nested match can never survive next to a shorter one.

Between regions the input bytes are copied verbatim; `bytes_in` counts what was
read, `bytes_out` what was written, and nothing else is altered. `--in-place`
writes a sibling temporary file and renames it, so an interrupted run cannot
leave a half-scrubbed log; a file with no matches is left untouched (mtime
included).

`--only-gaps` adds a third rule: a gap match that lies completely inside a
covered match is dropped. Without it, encoders that produce substrings of the
value (`prefix-32`, `suffix-32`, `base64-no-pad`) would carve holes out of a
value the platform masks anyway — and the point of the mode is to touch only
what the platform misses. The containment check is sound in the window design:
if a gap match is durable and a covered match contains it, the covered match is
at most `max_pattern_length` bytes long and therefore fully in the buffer, so it
cannot be missed.

## Findings, fingerprints, and the no-leak invariant

A `Finding` carries the source, line, column, byte offset, length, the encoder or
rule that found it, the secret's *label*, its `sha256:` fingerprint, and a
context line. The context has **every known match on that line masked**, not just
the finding's own — previews are meant to be pasteable into a bug report.

Rules the code and tests enforce:

* no secret value appears in any text report, JSON payload, preview or note (the
  CLI test suite asserts this end to end, byte for byte);
* fingerprints are stable identifiers (`sha256:` + 12 hex digits), not
  reversible;
* `collapse_findings` reduces nested duplicates per region — a gap form wins
  over a longer covered form, because "this survives masking" is the actionable
  statement — while `--all-forms` skips this for debugging.

## Provider rules

A value-aware scanner knows your secrets; it cannot know a token that was never
loaded. `generic.py` closes part of that gap with conservative regexes for
provider-shaped tokens. They are always reported as gaps: pattern matching is
heuristic, and maskgap will not vouch for the platform masking a guess. When a
known value and a generic rule hit the same region, the known value wins — real
information beats a guess. Every rule ships with a positive and a negative test,
and the regexes are written without nested quantifiers (a test guards against
ReDoS-shaped rewrites of the `private-key-block` rule).

## Performance and memory

* one automaton pass per byte, regardless of pattern count;
* memory is bounded by `chunk_size + max_pattern_length` plus the pattern set —
  a 4 GB log scans in constant memory;
* the automaton is built once per run; `--verbose` prints pattern and state
  counts so you can see what you asked for.

## Failure behaviour

Exit codes are part of the interface: `0` clean, `1` leaks found (`scan`), or
`--fail-on-leak` with replacements (`redact`), `2` usage or configuration error.
Errors never include secret material: a bad `--env-file` names the file, an
unknown encoder names the encoder.

## Testing strategy

207 tests, no network, no fixture secrets: encoder transforms are checked
against stdlib equivalents; the matcher is fuzzed against a naive substring
implementation; the scanner is checked for chunk-size invariance, byte-exact
redaction, idempotence, preview masking, binary input, and deterministic fuzzing
(random secrets, placements and chunk sizes); the CLI is exercised through
`python -m maskgap` in a subprocess with a scrubbed environment. The one ReDoS
test is deliberately adversarial.
