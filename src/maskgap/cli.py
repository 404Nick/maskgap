"""The ``maskgap`` command line interface.

Four verbs:

``scan``
    Report leaks. Exit code 1 when anything is found, so it can gate a pipeline.
``redact``
    Filter a stream (or rewrite files in place) with the leaks masked.
``audit``
    Show which encodings the CI platform masks and which ones it does not.
``encoders``
    List the transformation registry.

Design rules that the tests enforce:

* argparse only — arguments are never evaluated, never passed to a shell, and
  maskgap never spawns a subprocess;
* I/O is limited to stdin/stdout/stderr and the files named on the command line;
* reports never contain secret values.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import pathlib
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator, Sequence
from typing import BinaryIO, TextIO

from maskgap import __version__
from maskgap import report as report_mod
from maskgap.encoders import EncoderInfo, select_encoders
from maskgap.generic import GENERIC_RULES
from maskgap.scanner import Finding, RedactStats, Scanner, build_patterns, collapse_findings
from maskgap.secrets import (
    MAX_SECRET_LENGTH,
    Secret,
    dedupe_secrets,
    from_env,
    from_env_auto,
    from_env_file,
    from_env_prefix,
    from_secrets_file,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

DEFAULT_MIN_SECRET_LENGTH = 8
DEFAULT_LIMIT = 50

COVERAGE_REFERENCE = "https://github.com/404Nick/maskgap/blob/main/docs/github-masking.md"

EPILOG = """\
exit codes:
  0  nothing found / operation successful
  1  leaks found (scan), or --fail-on-leak with a non-empty redaction
  2  usage or configuration problem

examples:
  maskgap scan ci-output.log
  maskgap scan --env auto --only-gaps < build.log
  maskgap redact --env auto < build.log > build.clean.log
  maskgap audit --extended
"""


# --------------------------------------------------------------------------- #
# argument parsing                                                            #
# --------------------------------------------------------------------------- #


def _split_list(value: str | None) -> list[str]:
    """Split a comma separated CLI value, dropping empty entries."""
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _flatten(values: Sequence[str] | None) -> list[str]:
    """Flatten repeatable, comma separated options into a single list."""
    result: list[str] = []
    for value in values or ():
        result.extend(_split_list(value))
    return result


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that keeps usage errors on exit code 2."""

    def error(self, message: str) -> None:  # pragma: no cover - argparse plumbing
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _add_secret_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("secret sources")
    group.add_argument(
        "--env",
        action="append",
        metavar="NAME[,NAME...]",
        help="environment variable(s) holding secrets; 'auto' uses a name heuristic",
    )
    group.add_argument(
        "--env-prefix",
        action="append",
        metavar="PREFIX[,PREFIX...]",
        help="load every environment variable starting with PREFIX",
    )
    group.add_argument(
        "--env-file",
        action="append",
        metavar="PATH",
        help="dotenv-style file to read secrets from (repeatable)",
    )
    group.add_argument(
        "--secrets-file",
        action="append",
        metavar="PATH",
        help="file with one secret per line, or NAME=value pairs (repeatable)",
    )
    group.add_argument(
        "--min-secret-length",
        type=int,
        default=DEFAULT_MIN_SECRET_LENGTH,
        metavar="N",
        help=f"ignore secrets shorter than N characters (default: {DEFAULT_MIN_SECRET_LENGTH})",
    )
    group.add_argument(
        "--max-secret-length",
        type=int,
        default=MAX_SECRET_LENGTH,
        metavar="N",
        help=(
            "only transform the first N characters of longer secrets "
            f"(default: {MAX_SECRET_LENGTH})"
        ),
    )
    group.add_argument(
        "--require-secrets",
        action="store_true",
        help="fail when no secret could be loaded instead of warning",
    )
    group.add_argument(
        "--no-generic",
        action="store_true",
        help="do not look for provider-shaped tokens (GitHub, AWS, Slack, JWTs, ...)",
    )
    group.add_argument(
        "--skip-generic-rules",
        action="append",
        metavar="NAME[,NAME...]",
        help="disable individual provider patterns, e.g. credential-assignment",
    )
    group.add_argument(
        "--ignore-fingerprint",
        action="append",
        metavar="sha256:XXXX",
        help="suppress matches of a known benign value (repeatable)",
    )
    group.add_argument(
        "--only-gaps",
        action="store_true",
        help="act only on encodings the CI platform does not mask",
    )


def _add_encoder_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("transformations")
    group.add_argument(
        "--encoders",
        metavar="NAME[,NAME...]",
        help="search only these transformations (see 'maskgap encoders')",
    )
    group.add_argument(
        "--extended",
        action="store_true",
        help="also search the exotic encodings (base32, ROT13, reversed, ...)",
    )
    group.add_argument(
        "--skip-encoders",
        action="append",
        metavar="NAME[,NAME...]",
        help="disable individual transformations",
    )


def _add_runtime_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("runtime")
    group.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        metavar="BYTES",
        help="streaming chunk size (default: 65536)",
    )
    group.add_argument("-q", "--quiet", action="store_true", help="suppress notes on stderr")
    group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print what was loaded and searched (never prints secret values)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="maskgap",
        description=(
            "Find the gaps in your CI secret masking. maskgap knows the actual secret "
            "values in your environment and searches logs, artefacts and streams for "
            "them in every encoding they might appear in — including the ones your CI "
            "platform does not mask."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"maskgap {__version__}")

    secrets_parent = _Parser(add_help=False)
    _add_secret_options(secrets_parent)
    encoders_parent = _Parser(add_help=False)
    _add_encoder_options(encoders_parent)
    runtime_parent = _Parser(add_help=False)
    _add_runtime_options(runtime_parent)
    common = [secrets_parent, encoders_parent, runtime_parent]

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = subparsers.add_parser(
        "scan",
        parents=common,
        help="report secrets found in files, logs or stdin",
        description="Scan inputs for secret values in any encoding. Exits 1 on findings.",
    )
    scan.add_argument("paths", nargs="*", metavar="PATH", help="files to scan ('-' for stdin)")
    scan.add_argument("--json", action="store_true", help="machine readable report on stdout")
    scan.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        metavar="N",
        help=f"print at most N findings in the text report, 0 for all (default: {DEFAULT_LIMIT})",
    )
    scan.add_argument(
        "--all-forms",
        action="store_true",
        help="report every raw match instead of the most informative one per region",
    )
    scan.add_argument("--no-preview", action="store_true", help="omit the context line")

    redact = subparsers.add_parser(
        "redact",
        parents=common,
        help="replace secrets with a mask while copying a stream",
        description=(
            "Copy input to output with every detected secret replaced by the mask. "
            "Works as a filter, so it can wrap any pipeline: build | maskgap redact."
        ),
    )
    redact.add_argument("paths", nargs="*", metavar="PATH", help="files to redact ('-' for stdin)")
    redact.add_argument("-o", "--output", metavar="PATH", help="write to PATH instead of stdout")
    redact.add_argument(
        "--in-place",
        action="store_true",
        help="rewrite each input file atomically (requires explicit paths)",
    )
    redact.add_argument(
        "--mask",
        default="***",
        metavar="TEXT",
        help="replacement text; '{detector}' expands to the encoding name (default: ***)",
    )
    redact.add_argument("--report", action="store_true", help="print a summary to stderr")
    redact.add_argument(
        "--fail-on-leak",
        action="store_true",
        help="exit 1 when anything had to be redacted",
    )

    audit = subparsers.add_parser(
        "audit",
        parents=common,
        help="show which transformations the CI platform masks and which it does not",
        description=(
            "Explain the masking coverage of the loaded secrets: for each encoding, "
            "whether the CI platform registers it as a mask hint."
        ),
    )
    audit.add_argument("--json", action="store_true", help="machine readable report on stdout")

    encoders = subparsers.add_parser(
        "encoders",
        parents=[encoders_parent],
        help="list the transformations maskgap can search for",
        description="List every encoding maskgap understands, with platform coverage.",
    )
    encoders.add_argument("--json", action="store_true", help="machine readable report on stdout")

    return parser


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True)
class SecretSet:
    """Secrets to search for, plus what the user should know about them."""

    secrets: list[Secret]
    notes: list[str] = dataclasses.field(default_factory=list)
    auto_detected: bool = False


def collect_secrets(args: argparse.Namespace, err: TextIO) -> SecretSet:
    """Resolve every secret source named on the command line.

    Raises :class:`ValueError` with a user-facing message for a bad source; the
    caller turns that into exit code 2.
    """
    names = _flatten(args.env)
    prefixes = _flatten(args.env_prefix)

    secrets: list[Secret] = []
    notes: list[str] = []
    auto = False

    if not (names or prefixes or args.env_file or args.secrets_file):
        auto = True
        names = ["auto"]

    for name in names:
        if name.lower() == "auto":
            auto = True
            found = from_env_auto(args.min_secret_length)
            if not found:
                notes.append(
                    "no environment variable looked like a credential; "
                    "name secrets explicitly with --env NAME"
                )
            secrets.extend(found)
        else:
            found = from_env([name])
            if not found:
                notes.append(f"environment variable {name} is empty or not set")
            secrets.extend(found)

    if prefixes:
        found = from_env_prefix(prefixes)
        if not found:
            notes.append(f"no environment variable starts with {', '.join(prefixes)}")
        secrets.extend(found)

    for path in args.env_file or ():
        if not pathlib.Path(path).is_file():
            raise ValueError(f"--env-file {path}: no such file")
        secrets.extend(from_env_file(path))

    for path in args.secrets_file or ():
        if not pathlib.Path(path).is_file():
            raise ValueError(f"--secrets-file {path}: no such file")
        secrets.extend(from_secrets_file(path))

    deduped = dedupe_secrets(secrets)
    if len(deduped) != len(secrets):
        notes.append(f"{len(secrets) - len(deduped)} duplicate value(s) merged")
    if not deduped:
        message = (
            "no secrets loaded: pass --env NAME, --env-prefix P, --env-file PATH "
            "or --secrets-file PATH"
        )
        if args.require_secrets and args.no_generic:
            raise ValueError(message)
        err.write(f"warning: {message}\n")
        err.write(
            "warning: only provider-shaped tokens will be reported; "
            "secret values cannot be found without a source\n"
        )
    return SecretSet(secrets=deduped, notes=notes, auto_detected=auto)


def resolve_encoders(args: argparse.Namespace) -> tuple[EncoderInfo, ...]:
    """Turn ``--encoders/--extended/--skip-encoders`` into registry entries."""
    return select_encoders(args.encoders, extended=args.extended, skip=_flatten(args.skip_encoders))


def _iter_inputs(paths: Sequence[str]) -> Iterator[tuple[str, BinaryIO]]:
    """Yield ``(display_name, binary stream)``; ``-`` and no paths mean stdin."""
    if not paths:
        if sys.stdin.isatty():
            raise ValueError(
                "no input given and stdin is a terminal; pass PATH arguments or pipe data in"
            )
        yield "<stdin>", sys.stdin.buffer
        return
    for path in paths:
        if path == "-":
            yield "<stdin>", sys.stdin.buffer
            continue
        target = pathlib.Path(path)
        if target.is_dir():
            raise ValueError(f"{path}: is a directory")
        if not target.is_file():
            raise ValueError(f"{path}: no such file")
        with target.open("rb") as handle:
            yield path, handle


def _make_scanner(
    args: argparse.Namespace,
    secrets: Sequence[Secret],
    encoders: Sequence[EncoderInfo],
    err: TextIO,
) -> Scanner:
    rules = () if args.no_generic else GENERIC_RULES
    skip_rules = frozenset(_flatten(args.skip_generic_rules))
    unknown = skip_rules - {rule.name for rule in GENERIC_RULES}
    if unknown:
        raise ValueError(f"unknown generic rule(s): {', '.join(sorted(unknown))}")

    kwargs: dict[str, object] = {
        "secrets": secrets,
        "encoders": encoders,
        "min_secret_length": args.min_secret_length,
        "max_secret_length": args.max_secret_length,
        "generic_rules": rules,
        "skip_generic_rules": skip_rules,
        "only_gaps": args.only_gaps,
        "ignore_fingerprints": [
            _normalise_fingerprint(value) for value in args.ignore_fingerprint or ()
        ],
        "mask": getattr(args, "mask", "***"),
    }
    if args.chunk_size is not None:
        if args.chunk_size < 1:
            raise ValueError("--chunk-size must be at least 1")
        kwargs["chunk_size"] = args.chunk_size

    scanner = Scanner(**kwargs)  # type: ignore[arg-type]
    if not args.quiet:
        for note in scanner.notes:
            err.write(f"note: {note}\n")
    return scanner


def _normalise_fingerprint(value: str) -> str:
    value = value.strip()
    if value.startswith("sha256:"):
        return value
    if not value or any(char not in "0123456789abcdefABCDEF" for char in value):
        raise ValueError(f"--ignore-fingerprint {value!r}: expected sha256:HEX or HEX")
    return f"sha256:{value.lower()}"


def _verbose_config(
    scanner: Scanner,
    encoders: Sequence[EncoderInfo],
    secret_set: SecretSet,
    err: TextIO,
) -> None:
    err.write(f"maskgap {__version__}\n")
    err.write(f"encoders: {', '.join(encoder.name for encoder in encoders)}\n")
    err.write(
        f"secrets: {len(secret_set.secrets)} "
        f"(auto-detected: {'yes' if secret_set.auto_detected else 'no'})\n"
    )
    for secret in secret_set.secrets:
        err.write(f"  - {secret.describe()}\n")
    err.write(f"patterns: {scanner.pattern_count} (automaton states: {scanner.state_count})\n")


def _json_dump(payload: object, out: TextIO) -> None:
    json.dump(payload, out, indent=2, sort_keys=False)
    out.write("\n")


# --------------------------------------------------------------------------- #
# commands                                                                    #
# --------------------------------------------------------------------------- #


def cmd_scan(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    secret_set = collect_secrets(args, err)
    encoders = resolve_encoders(args)
    scanner = _make_scanner(args, secret_set.secrets, encoders, err)
    for note in secret_set.notes:
        if not args.quiet:
            err.write(f"note: {note}\n")
    if args.verbose:
        _verbose_config(scanner, encoders, secret_set, err)

    findings: list[Finding] = []
    sources: list[str] = []
    for name, stream in _iter_inputs(args.paths):
        sources.append(name)
        findings.extend(scanner.scan_stream(stream, name))

    suppressed = 0
    if not args.all_forms:
        findings, suppressed = collapse_findings(findings)

    if args.json:
        _json_dump(
            report_mod.scan_payload(
                findings,
                secrets=secret_set.secrets,
                encoders=encoders,
                sources=sources,
                suppressed=suppressed,
                notes=scanner.notes,
            ),
            out,
        )
    else:
        out.write(
            f"maskgap {__version__}: scanned {len(sources)} input(s), "
            f"{len(secret_set.secrets)} secret(s), {scanner.pattern_count} patterns\n"
        )
        report_mod.render_findings(
            findings,
            out,
            limit=None if args.limit == 0 else args.limit,
            show_preview=not args.no_preview,
        )
        report_mod.render_summary(findings, out, suppressed=suppressed, sources=sources)
    return EXIT_FINDINGS if findings else EXIT_OK


def cmd_redact(
    args: argparse.Namespace,
    out: TextIO,  # noqa: ARG001 - redacted bytes go to stdout.buffer, not the text layer
    err: TextIO,
) -> int:
    if args.in_place and args.output:
        raise ValueError("--in-place and --output are mutually exclusive")
    if args.in_place and not args.paths:
        raise ValueError("--in-place requires explicit file paths")
    if args.in_place and "-" in args.paths:
        raise ValueError("--in-place cannot be used with stdin")

    secret_set = collect_secrets(args, err)
    encoders = resolve_encoders(args)
    scanner = _make_scanner(args, secret_set.secrets, encoders, err)
    for note in secret_set.notes:
        if not args.quiet:
            err.write(f"note: {note}\n")
    if args.verbose:
        _verbose_config(scanner, encoders, secret_set, err)

    total = RedactStats()
    if args.in_place:
        for path in args.paths:
            _accumulate(total, _redact_file_in_place(scanner, path))
    else:
        handle: BinaryIO
        close_output = False
        if args.output:
            handle = pathlib.Path(args.output).open("wb")  # noqa: SIM115 - closed below
            close_output = True
        else:
            handle = sys.stdout.buffer
        try:
            for name, stream in _iter_inputs(args.paths):
                _accumulate(total, scanner.redact_stream(stream, handle, source=name))
            handle.flush()
        finally:
            if close_output:
                handle.close()

    if args.report:
        report_mod.render_redact_report(
            report_mod.RedactReport(
                bytes_in=total.bytes_in,
                bytes_out=total.bytes_out,
                replacements=total.replacements,
                gaps=total.gaps,
                detectors=total.detectors,
            ),
            err,
        )
    if args.fail_on_leak and total.replacements:
        return EXIT_FINDINGS
    return EXIT_OK


def _redact_file_in_place(scanner: Scanner, path: str) -> RedactStats:
    """Rewrite ``path`` atomically, replacing every match with the mask.

    The replacement file is created next to the original and moved into place, so
    an interrupted run never leaves a half-rewritten log behind. A file with no
    matches is left untouched (including its mtime).
    """
    target = pathlib.Path(path)
    mode = target.stat().st_mode & 0o7777
    tmp_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".maskgap",
            delete=False,
        ) as handle:
            tmp_path = pathlib.Path(handle.name)
            with target.open("rb") as source:
                stats = scanner.redact_stream(source, handle, source=path)
        if not stats.replacements:
            tmp_path.unlink()
            return stats
        tmp_path.chmod(mode)
        tmp_path.replace(target)
        return stats
    except BaseException:
        if tmp_path is not None:
            with contextlib.suppress(OSError):  # pragma: no cover - best effort cleanup
                tmp_path.unlink()
        raise


def _accumulate(total: RedactStats, stats: RedactStats) -> None:
    total.bytes_in += stats.bytes_in
    total.bytes_out += stats.bytes_out
    total.replacements += stats.replacements
    total.detectors.update(stats.detectors)
    total.findings.extend(stats.findings)


def cmd_audit(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    secret_set = collect_secrets(args, err)
    encoders = resolve_encoders(args)
    for note in secret_set.notes:
        if not args.quiet:
            err.write(f"note: {note}\n")

    patterns, notes = build_patterns(
        secret_set.secrets,
        encoders,
        min_secret_length=args.min_secret_length,
        max_secret_length=args.max_secret_length,
    )
    if not args.quiet:
        for note in notes:
            err.write(f"note: {note}\n")

    totals: Counter[str] = Counter()
    gaps: Counter[str] = Counter()
    for _, tag in patterns:
        totals[tag.label] += 1
        if not tag.covered_by_runner:
            gaps[tag.label] += 1

    variant_counts = [
        (secret, totals[secret.label], gaps[secret.label]) for secret in secret_set.secrets
    ]

    if args.json:
        _json_dump(
            report_mod.audit_payload(
                encoders,
                variant_counts=variant_counts,
                reference=COVERAGE_REFERENCE,
            ),
            out,
        )
        return EXIT_OK

    uncovered_encoders = sum(1 for encoder in encoders if not encoder.covered_by_runner)
    out.write(
        f"maskgap {__version__}: masking coverage of {len(secret_set.secrets)} secret(s) "
        f"across {len(encoders)} transformation(s)\n\n"
    )
    report_mod.render_audit(
        encoders,
        out=out,
        variant_counts=variant_counts,
        reference=COVERAGE_REFERENCE,
    )
    out.write(
        f"\n{uncovered_encoders} of {len(encoders)} transformations are not registered as "
        "mask hints by the GitHub Actions runner.\n"
        f"For the secrets above that is {sum(gaps.values())} searchable form(s) that would "
        "survive platform masking.\n"
        "Run 'maskgap scan' on a real log to see which of them actually occur.\n"
    )
    return EXIT_OK


def cmd_encoders(args: argparse.Namespace, out: TextIO) -> int:
    encoders = resolve_encoders(args)
    if args.json:
        _json_dump(
            {
                "tool": "maskgap",
                "version": __version__,
                "coverage_reference": COVERAGE_REFERENCE,
                "encoders": [
                    {
                        "name": encoder.name,
                        "group": encoder.group,
                        "masked_by_runner": encoder.covered_by_runner,
                        "runner_symbol": encoder.runner_symbol,
                        "summary": encoder.summary,
                    }
                    for encoder in encoders
                ],
            },
            out,
        )
        return EXIT_OK
    report_mod.render_encoder_table(encoders, out)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# entry point                                                                 #
# --------------------------------------------------------------------------- #


def dispatch(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Run the selected subcommand."""
    if args.command == "scan":
        return cmd_scan(args, out, err)
    if args.command == "redact":
        return cmd_redact(args, out, err)
    if args.command == "audit":
        return cmd_audit(args, out, err)
    if args.command == "encoders":
        return cmd_encoders(args, out)
    raise AssertionError(f"unhandled command {args.command!r}")  # pragma: no cover


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return dispatch(args, sys.stdout, sys.stderr)
    except ValueError as error:
        sys.stderr.write(f"maskgap: error: {error}\n")
        return EXIT_USAGE
    except BrokenPipeError:
        # Something closed the pipe (| head). Leave quietly, without a traceback.
        with contextlib.suppress(OSError):  # pragma: no cover - best effort
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        sys.stderr.write("maskgap: interrupted\n")
        return 130
    except OSError as error:
        sys.stderr.write(f"maskgap: error: {error}\n")
        return EXIT_USAGE
