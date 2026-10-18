"""The transformation catalogue: every shape a secret value can take in text.

A secret that is printed verbatim is usually masked by the CI platform. The same
secret that reaches a log *after* a transformation (``base64``, ``hex``, URL or
JSON escaping, a hard line wrap, ...) frequently is not, because platform masking
is literal string matching over a fixed list of encodings.

This module defines that fixed list as data: one :class:`EncoderInfo` per
transformation, tagged with ``covered_by_runner`` — whether the GitHub Actions
runner registers that variant as a mask hint. The list of masked encodings was
derived from the runner source (see ``docs/github-masking.md``); everything else
is by definition a masking gap.

Usage::

    >>> from maskgap.encoders import ENCODERS, variants
    >>> [v.text for v in variants("s3cret!", ENCODERS) if v.encoder == "hex"]
    ['73336372657421']

``variants()`` is deterministic: for the same secret and encoder selection it
always returns the same tuple, in registry order, with exact duplicates removed.
"""

from __future__ import annotations

import base64
import codecs
import dataclasses
import json
import urllib.parse
from collections.abc import Callable, Iterable, Sequence

__all__ = [
    "ENCODERS",
    "MIN_VARIANT_LENGTH",
    "EncoderInfo",
    "Variant",
    "encoders_by_name",
    "run_variants",
    "select_encoders",
    "variants",
]

#: Variants shorter than this are not searched for: short literals show up in
#: unrelated text by chance, which would produce noise instead of signal.
MIN_VARIANT_LENGTH = 6

#: Encoders that run by default. "extended" encoders are opt-in because they
#: are either exotic in practice or produce a lot of long variants.
GROUP_CORE = "core"
GROUP_EXTENDED = "extended"

Runner = Callable[[str], tuple[str, ...]]


@dataclasses.dataclass(frozen=True, slots=True)
class EncoderInfo:
    """One way of rewriting a secret value into the bytes that may land in a log."""

    name: str
    group: str
    covered_by_runner: bool
    summary: str
    fn: Runner = dataclasses.field(repr=False)
    #: Name of the encoder in the GitHub Actions runner source, when covered.
    runner_symbol: str | None = None

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclasses.dataclass(frozen=True, slots=True)
class Variant:
    """A literal string that must not appear in a log, and why."""

    text: str
    encoder: str
    covered_by_runner: bool
    #: Other encoders that produce the exact same text. Useful when auditing:
    #: a variant is "covered" as soon as *one* covered encoder produces it.
    aliases: tuple[str, ...] = ()

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.text)


# --------------------------------------------------------------------------- #
# encoders covered by the GitHub Actions runner                               #
# --------------------------------------------------------------------------- #


def _raw(secret: str) -> tuple[str, ...]:
    """The untouched value — registered by ``ISecretMasker.AddValue``."""
    return (secret,)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _base64(secret: str) -> tuple[str, ...]:
    return (_b64(secret.encode("utf-8")),)


def _base64_shift(secret: str, shift: int) -> tuple[str, ...]:
    """Base64 of the value with the first ``shift`` bytes dropped.

    The runner does this because ``base64(user + ":" + password)`` contains a
    different base64 text for the password than ``base64(password)`` does,
    depending on the alignment of the leading content.
    """
    data = secret.encode("utf-8")
    if len(data) <= shift:
        return ()
    return (_b64(data[shift:]),)


def _base64_shift1(secret: str) -> tuple[str, ...]:
    return _base64_shift(secret, 1)


def _base64_shift2(secret: str) -> tuple[str, ...]:
    return _base64_shift(secret, 2)


def _cmd(secret: str) -> tuple[str, ...]:
    r"""Escape ``"`` as ``\"`` — how the runner passes values to docker args."""
    return (secret.replace('"', '\\"'),)


def _expression(secret: str) -> tuple[str, ...]:
    r"""GitHub expression string escaping: ``'`` becomes ``''``."""
    return (secret.replace("'", "''"),)


#: Newtonsoft ``JsonConvert.ToString`` writes these two-character escapes.
_JSON_SHORT_ESCAPES = {
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    '"': '\\"',
    "\\": "\\\\",
    # Newtonsoft escapes these even though they are printable.
    "\u0085": "\\u0085",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def _json_escape(secret: str) -> tuple[str, ...]:
    """JSON string escaping without the surrounding quotes (Newtonsoft style)."""
    chunks: list[str] = []
    for char in secret:
        replacement = _JSON_SHORT_ESCAPES.get(char)
        if replacement is None and char < "\u0020":
            replacement = f"\\u{ord(char):04x}"
        chunks.append(replacement if replacement is not None else char)
    return ("".join(chunks),)


def _json_ascii(secret: str) -> tuple[str, ...]:
    """ASCII-only JSON escaping, e.g. Python's ``json.dumps`` default."""
    return (json.dumps(secret, ensure_ascii=True)[1:-1],)


def _uri(secret: str) -> tuple[str, ...]:
    """``Uri.EscapeDataString``: RFC 3986 unreserved characters stay, rest is %XX."""
    return (urllib.parse.quote(secret, safe="-._~"),)


def _uri_lower(secret: str) -> tuple[str, ...]:
    """Percent-encoding with lower-case hex digits (``tr A-Z a-z`` on the URI form)."""
    escaped = urllib.parse.quote(secret, safe="-._~")
    out: list[str] = []
    index = 0
    while index < len(escaped):
        char = escaped[index]
        if char == "%" and index + 2 < len(escaped):
            out.append(escaped[index : index + 3].lower())
            index += 3
        else:
            out.append(char)
            index += 1
    return ("".join(out),)


#: ``SecurityElement.Escape`` — the set used by the runner's XmlDataEscape.
_XML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;"}


def _xml(secret: str) -> tuple[str, ...]:
    return ("".join(_XML_ESCAPES.get(char, char) for char in secret),)


def _trim_quotes(secret: str) -> tuple[str, ...]:
    """Value already wrapped in double quotes: the runner also masks the inner part."""
    if len(secret) > 8 and secret.startswith('"') and secret.endswith('"'):
        return (secret[1:-1],)
    return ()


def _powershell_pre(secret: str) -> tuple[str, ...]:
    """PowerShell colour codes split a value at ``&``; mask the leading section."""
    if "&" not in secret:
        return ()
    if "&+" in secret:
        section = secret[: secret.index("&+") + 2]
    else:
        section = secret[: secret.rindex("&") + 1]
    return (section,) if len(section) >= 6 else ()


def _powershell_post(secret: str) -> tuple[str, ...]:
    """Same as :func:`_powershell_pre`, for the trailing section."""
    if "&" not in secret:
        return ()
    if "&+" in secret:
        offset = secret.index("&+") + 3
        if len(secret) <= offset:
            return ()
        section = secret[offset:]
    else:
        section = secret[secret.rindex("&") + 1 :]
    return (section,) if len(section) >= 6 else ()


# --------------------------------------------------------------------------- #
# encoders the runner does *not* cover — the gaps                             #
# --------------------------------------------------------------------------- #


def _base64_no_pad(secret: str) -> tuple[str, ...]:
    return (_b64(secret.encode("utf-8")).rstrip("="),)


def _base64_url(secret: str) -> tuple[str, ...]:
    return (base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii"),)


def _base64_double(secret: str) -> tuple[str, ...]:
    """Double-encoded, e.g. a token that is itself stored base64-encoded."""
    return (_b64(_b64(secret.encode("utf-8")).encode("ascii")),)


def _base64_linewrap(secret: str) -> tuple[str, ...]:
    """``base64 -w 76`` / MIME output: the same bytes, split by newlines.

    The runner registers only the unwrapped form, so a line-wrapped base64 blob
    in a log stays in clear text. Newlines are re-inserted when reading back.
    """
    data = _b64(secret.encode("utf-8"))
    if len(data) <= 76:
        return ()
    return ("\n".join(data[i : i + 76] for i in range(0, len(data), 76)),)


def _hex(secret: str) -> tuple[str, ...]:
    return (secret.encode("utf-8").hex(),)


def _hex_upper(secret: str) -> tuple[str, ...]:
    return (secret.encode("utf-8").hex().upper(),)


def _base32(secret: str) -> tuple[str, ...]:
    return (base64.b32encode(secret.encode("utf-8")).decode("ascii"),)


def _upper(secret: str) -> tuple[str, ...]:
    return (secret.upper(),)


def _lower(secret: str) -> tuple[str, ...]:
    return (secret.lower(),)


def _reverse(secret: str) -> tuple[str, ...]:
    return (secret[::-1],)


def _rot13(secret: str) -> tuple[str, ...]:
    return (codecs.encode(secret, "rot13"),)


def _fold_64(secret: str) -> tuple[str, ...]:
    """The raw value hard-wrapped at 64 characters (``fold -w 64``)."""
    if len(secret) <= 64:
        return ()
    return ("\n".join(secret[i : i + 64] for i in range(0, len(secret), 64)),)


def _char_space(secret: str) -> tuple[str, ...]:
    """Characters separated by spaces, e.g. ``' '.join(secret)`` or shell debugging."""
    if len(secret) < 2:
        return ()
    return (" ".join(secret),)


def _prefix(secret: str, size: int = 32) -> tuple[str, ...]:
    """A truncated prefix — logs and error messages love to cut values short."""
    if len(secret) <= size:
        return ()
    return (secret[:size],)


def _suffix(secret: str, size: int = 32) -> tuple[str, ...]:
    if len(secret) <= size:
        return ()
    return (secret[-size:],)


def _lines(secret: str) -> tuple[str, ...]:
    """Each line of a multi-line secret, trimmed the way the runner registers it.

    ``Worker.InitializeSecretMasker`` registers the whole (trimmed) secret value
    plus every non-empty trimmed line, and ``ActionCommandManager`` does the same
    for ``::add-mask::`` values — a private key printed line by line is covered.
    PEM banners (``-----BEGIN ... -----``) are skipped: they are public
    formatting, not secret material, and would otherwise produce noise.
    """
    if "\n" not in secret and "\r" not in secret:
        return ()
    normalised = secret.replace("\r\n", "\n").replace("\r", "\n")
    result: list[str] = []
    for line in normalised.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("-----") and line.endswith("-----"):
            continue
        result.append(line)
    return tuple(result)


# --------------------------------------------------------------------------- #
# registry                                                                    #
# --------------------------------------------------------------------------- #

ENCODERS: tuple[EncoderInfo, ...] = (
    EncoderInfo(
        name="raw",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="the value itself",
        fn=_raw,
        runner_symbol="SecretMasker.AddValue",
    ),
    EncoderInfo(
        name="base64",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="base64 (RFC 4648, with padding)",
        fn=_base64,
        runner_symbol="ValueEncoders.Base64StringEscape",
    ),
    EncoderInfo(
        name="base64-shift1",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="base64 of the value with the first byte dropped",
        fn=_base64_shift1,
        runner_symbol="ValueEncoders.Base64StringEscapeShift1",
    ),
    EncoderInfo(
        name="base64-shift2",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="base64 of the value with the first two bytes dropped",
        fn=_base64_shift2,
        runner_symbol="ValueEncoders.Base64StringEscapeShift2",
    ),
    EncoderInfo(
        name="base64-no-pad",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="base64 with padding stripped",
        fn=_base64_no_pad,
    ),
    EncoderInfo(
        name="base64url",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="base64url alphabet (JWT bodies, query strings)",
        fn=_base64_url,
    ),
    EncoderInfo(
        name="base64-double",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="base64 of base64",
        fn=_base64_double,
    ),
    EncoderInfo(
        name="base64-linewrap",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="base64 wrapped at 76 columns (base64 -w 76, MIME)",
        fn=_base64_linewrap,
    ),
    EncoderInfo(
        name="hex",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="lower-case hex",
        fn=_hex,
    ),
    EncoderInfo(
        name="hex-upper",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="upper-case hex",
        fn=_hex_upper,
    ),
    EncoderInfo(
        name="json",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary='JSON string escaping (" and control characters)',
        fn=_json_escape,
        runner_symbol="ValueEncoders.JsonStringEscape",
    ),
    EncoderInfo(
        name="json-ascii",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="JSON escaping with \\uXXXX for every non-ASCII character",
        fn=_json_ascii,
    ),
    EncoderInfo(
        name="uri",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="percent-encoding with upper-case hex (Uri.EscapeDataString)",
        fn=_uri,
        runner_symbol="ValueEncoders.UriDataEscape",
    ),
    EncoderInfo(
        name="uri-lower",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="percent-encoding with lower-case hex digits",
        fn=_uri_lower,
    ),
    EncoderInfo(
        name="xml",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="XML entity escaping of & < > \" '",
        fn=_xml,
        runner_symbol="ValueEncoders.XmlDataEscape",
    ),
    EncoderInfo(
        name="cmd",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary='command-line escaping of " as \\"',
        fn=_cmd,
        runner_symbol="ValueEncoders.CommandLineArgumentEscape",
    ),
    EncoderInfo(
        name="expression",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="GitHub expression escaping: ' becomes ''",
        fn=_expression,
        runner_symbol="ValueEncoders.ExpressionStringEscape",
    ),
    EncoderInfo(
        name="powershell-pre",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="leading section of a value split by PowerShell colouring",
        fn=_powershell_pre,
        runner_symbol="ValueEncoders.PowerShellPreAmpersandEscape",
    ),
    EncoderInfo(
        name="powershell-post",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="trailing section of a value split by PowerShell colouring",
        fn=_powershell_post,
        runner_symbol="ValueEncoders.PowerShellPostAmpersandEscape",
    ),
    EncoderInfo(
        name="trim-quotes",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="value without its surrounding double quotes",
        fn=_trim_quotes,
        runner_symbol="ValueEncoders.TrimDoubleQuotes",
    ),
    EncoderInfo(
        name="upper",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="upper-cased value",
        fn=_upper,
    ),
    EncoderInfo(
        name="lower",
        group=GROUP_CORE,
        covered_by_runner=False,
        summary="lower-cased value",
        fn=_lower,
    ),
    EncoderInfo(
        name="lines",
        group=GROUP_CORE,
        covered_by_runner=True,
        summary="each trimmed line of a multi-line secret",
        fn=_lines,
        runner_symbol="Worker.InitializeSecretMasker (per-line values)",
    ),
    EncoderInfo(
        name="base32",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="base32 (TOTP secrets, some devices)",
        fn=_base32,
    ),
    EncoderInfo(
        name="fold-64",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="raw value wrapped at 64 columns",
        fn=_fold_64,
    ),
    EncoderInfo(
        name="char-space",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="characters joined by spaces",
        fn=_char_space,
    ),
    EncoderInfo(
        name="prefix-32",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="first 32 characters of the value",
        fn=_prefix,
    ),
    EncoderInfo(
        name="suffix-32",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="last 32 characters of the value",
        fn=_suffix,
    ),
    EncoderInfo(
        name="reverse",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="reversed value",
        fn=_reverse,
    ),
    EncoderInfo(
        name="rot13",
        group=GROUP_EXTENDED,
        covered_by_runner=False,
        summary="ROT13 of the value",
        fn=_rot13,
    ),
)

_ENCODERS_BY_NAME: dict[str, EncoderInfo] = {info.name: info for info in ENCODERS}


def encoders_by_name() -> dict[str, EncoderInfo]:
    """Registry indexed by encoder name (a copy, safe to mutate)."""
    return dict(_ENCODERS_BY_NAME)


def select_encoders(
    names: str | Iterable[str] | None = None,
    *,
    extended: bool = False,
    skip: Iterable[str] | None = None,
) -> tuple[EncoderInfo, ...]:
    """Resolve a user-provided encoder selection into registry entries.

    ``names`` may be a comma separated string or an iterable of encoder names.
    ``extended`` adds the opt-in group, ``skip`` removes names afterwards.
    Raises :class:`ValueError` for unknown names so the CLI can report them.
    """
    if names is None:
        selected = [info for info in ENCODERS if info.group == GROUP_CORE or extended]
    else:
        if isinstance(names, str):
            names = [part.strip() for part in names.split(",") if part.strip()]
        selected = []
        for name in names:
            info = _ENCODERS_BY_NAME.get(name)
            if info is None:
                raise ValueError(f"unknown encoder {name!r}; run 'maskgap encoders' to list them")
            selected.append(info)
    if skip:
        if isinstance(skip, str):  # defensive: callers should pass an iterable
            skip = [part.strip() for part in skip.split(",") if part.strip()]
        skipped = set(skip)
        unknown = skipped - set(_ENCODERS_BY_NAME)
        if unknown:
            raise ValueError(
                f"unknown encoder(s) {', '.join(sorted(unknown))}; "
                "run 'maskgap encoders' to list them"
            )
        selected = [info for info in selected if info.name not in skipped]
    return tuple(selected)


def run_variants(secret: str, encoders: Sequence[EncoderInfo]) -> list[tuple[str, str]]:
    """Return ``(encoder_name, text)`` pairs for one secret, before de-duplication."""
    produced: list[tuple[str, str]] = []
    for info in encoders:
        for text in info.fn(secret):
            if text:
                produced.append((info.name, text))
    return produced


def variants(
    secret: str,
    encoders: Sequence[EncoderInfo],
    *,
    min_length: int = MIN_VARIANT_LENGTH,
) -> tuple[Variant, ...]:
    """Every distinct literal form of ``secret``, in registry order.

    Duplicates (for example ``base64`` and ``base64url`` of a value that contains
    no ``+``/``/``) are merged into a single :class:`Variant`; the merged entry is
    marked as covered when *any* of the encoders producing it is covered.
    """
    order: dict[str, int] = {}
    merged: dict[str, Variant] = {}
    for encoder_name, text in run_variants(secret, encoders):
        if len(text) < min_length:
            continue
        info = _ENCODERS_BY_NAME[encoder_name]
        existing = merged.get(text)
        if existing is None:
            order[text] = len(order)
            merged[text] = Variant(
                text=text,
                encoder=encoder_name,
                covered_by_runner=info.covered_by_runner,
            )
        else:
            merged[text] = dataclasses.replace(
                existing,
                covered_by_runner=existing.covered_by_runner or info.covered_by_runner,
                aliases=(*existing.aliases, encoder_name),
            )
    return tuple(merged[text] for text in sorted(order, key=order.__getitem__))
