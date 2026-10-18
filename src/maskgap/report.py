"""Rendering of findings and audits.

Everything here is presentation only. Two rules are absolute:

* a report never contains a secret value — findings carry a label and a
  ``sha256:`` fingerprint instead, and previews have every known match masked;
* reports are stable: the same findings always render byte for byte the same
  way, which is what makes them diffable and testable.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Sequence
from typing import Any, TextIO

from maskgap import __version__
from maskgap.encoders import EncoderInfo
from maskgap.scanner import Finding
from maskgap.secrets import Secret

__all__ = [
    "audit_payload",
    "finding_to_dict",
    "render_audit",
    "render_encoder_table",
    "render_findings",
    "render_redact_report",
    "render_summary",
    "scan_payload",
]

GAP_LABEL = "GAP"
MASKED_LABEL = "ok"

#: Column widths for source locations; longer names are truncated in the middle.
_SOURCE_WIDTH = 38
_DETECTOR_WIDTH = 18
_LABEL_WIDTH = 26


def _elide(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    keep = width - 1
    head = keep // 2
    return f"{text[:head]}…{text[len(text) - (keep - head) :]}"


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialise a finding. Contains no secret material by construction."""
    return {
        "source": finding.source,
        "line": finding.line,
        "column": finding.column,
        "offset": finding.offset,
        "length": finding.length,
        "kind": finding.kind,
        "detector": finding.detector,
        "label": finding.label,
        "fingerprint": finding.fingerprint,
        "masked_by_runner": finding.covered_by_runner,
        "gap": finding.is_gap,
        "context": finding.preview,
    }


def _status(finding: Finding) -> str:
    return GAP_LABEL if finding.is_gap else MASKED_LABEL


def render_findings(
    findings: Sequence[Finding],
    out: TextIO,
    *,
    limit: int | None = None,
    show_preview: bool = True,
) -> int:
    """Write findings as aligned text. Returns how many were written."""
    written = 0
    for finding in findings:
        if limit is not None and written >= limit:
            break
        location = _elide(finding.location(), _SOURCE_WIDTH)
        out.write(
            f"  {location:<{_SOURCE_WIDTH}}  {_status(finding):<3}  "
            f"{finding.detector:<{_DETECTOR_WIDTH}}  "
            f"{_elide(finding.label, _LABEL_WIDTH):<{_LABEL_WIDTH}}  {finding.fingerprint}\n"
        )
        if show_preview and finding.preview:
            out.write(f"      {finding.preview}\n")
        written += 1
    if limit is not None and len(findings) > written:
        out.write(f"  … {len(findings) - written} more finding(s) not shown (use --limit 0)\n")
    return written


def render_summary(
    findings: Sequence[Finding],
    out: TextIO,
    *,
    suppressed: int = 0,
    sources: Sequence[str] = (),
) -> None:
    """Write the one-paragraph verdict that follows a scan."""
    gaps = sum(1 for finding in findings if finding.is_gap)
    covered = len(findings) - gaps
    files = len(set(sources)) or len({finding.source for finding in findings})

    if not findings:
        out.write("No leaks found.\n")
    else:
        word = "finding" if len(findings) == 1 else "findings"
        out.write(
            f"{len(findings)} {word} in {files} input(s): "
            f"{gaps} gap(s) the platform masking does not cover, {covered} covered form(s).\n"
        )
        by_detector = Counter(finding.detector for finding in findings)
        out.write(
            "By form: "
            + ", ".join(f"{name}={count}" for name, count in by_detector.most_common())
            + "\n"
        )
    if suppressed:
        out.write(
            f"{suppressed} nested/overlapping match(es) suppressed; "
            "use --all-forms to see every match.\n"
        )
    if gaps:
        out.write(
            "Next step: keep these values out of the log, or scrub the stream:\n"
            "    maskgap redact --env auto < input.log > clean.log\n"
        )


def scan_payload(
    findings: Sequence[Finding],
    *,
    secrets: Sequence[Secret],
    encoders: Sequence[EncoderInfo],
    sources: Sequence[str],
    suppressed: int = 0,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """JSON document for ``maskgap scan --json``."""
    return {
        "tool": "maskgap",
        "version": __version__,
        "sources": list(sources),
        "secrets_loaded": [secret.label for secret in secrets],
        "encoders_used": [encoder.name for encoder in encoders],
        "notes": list(notes),
        "summary": {
            "findings": len(findings),
            "gaps": sum(1 for finding in findings if finding.is_gap),
            "suppressed": suppressed,
            "by_detector": dict(Counter(finding.detector for finding in findings)),
            "by_label": dict(Counter(finding.label for finding in findings)),
        },
        "findings": [finding_to_dict(finding) for finding in findings],
    }


def render_encoder_table(encoders: Sequence[EncoderInfo], out: TextIO) -> None:
    """Write the encoder registry: what maskgap can search for, and coverage."""
    out.write(f"  {'ENCODER':<18} {'GROUP':<9} {'RUNNER':<7} SUMMARY\n")
    for encoder in encoders:
        runner = "masked" if encoder.covered_by_runner else "gap"
        out.write(f"  {encoder.name:<18} {encoder.group:<9} {runner:<7} {encoder.summary}\n")
    out.write(
        "\nRUNNER=masked means the GitHub Actions runner registers that form as a mask hint\n"
        "(see docs/github-masking.md); gap means it does not.\n"
    )


def render_audit(
    encoders: Sequence[EncoderInfo],
    *,
    out: TextIO,
    variant_counts: Sequence[tuple[Secret, int, int]],
    reference: str,
) -> None:
    """Write the masking coverage audit."""
    render_encoder_table(encoders, out)
    out.write(f"\nSECRET{' ' * 34}VARIANTS  MASKED  GAPS\n")
    for secret, total, gaps in variant_counts:
        covered = total - gaps
        label = _elide(secret.label, _LABEL_WIDTH)
        detail = f"{label} ({secret.fingerprint}, {secret.length} chars)"
        out.write(f"  {detail:<40}  {total:>8}  {covered:>6}  {gaps:>4}\n")
    out.write(f"\nCoverage reference: {reference}\n")


def audit_payload(
    encoders: Sequence[EncoderInfo],
    *,
    variant_counts: Sequence[tuple[Secret, int, int]],
    reference: str,
) -> dict[str, Any]:
    """JSON document for ``maskgap audit --json``."""
    return {
        "tool": "maskgap",
        "version": __version__,
        "coverage_reference": reference,
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
        "secrets": [
            {
                "label": secret.label,
                "fingerprint": secret.fingerprint,
                "length": secret.length,
                "variants": total,
                "masked_by_runner": total - gaps,
                "gaps": gaps,
            }
            for secret, total, gaps in variant_counts
        ],
        "summary": {
            "encoders": len(encoders),
            "encoders_masked_by_runner": sum(1 for e in encoders if e.covered_by_runner),
            "encoders_not_covered": sum(1 for e in encoders if not e.covered_by_runner),
        },
    }


@dataclasses.dataclass(frozen=True, slots=True)
class RedactReport:
    """Small value object so the CLI can print a redaction summary."""

    bytes_in: int
    bytes_out: int
    replacements: int
    gaps: int
    detectors: Counter[str]


def render_redact_report(report: RedactReport, out: TextIO) -> None:
    """Write the ``maskgap redact --report`` summary (never touches secret bytes)."""
    out.write(
        f"redacted {report.replacements} occurrence(s) "
        f"({report.gaps} of them in forms the platform does not mask); "
        f"{report.bytes_in} bytes in, {report.bytes_out} bytes out\n"
    )
    if report.detectors:
        out.write(
            "By form: "
            + ", ".join(f"{name}={count}" for name, count in report.detectors.most_common())
            + "\n"
        )
