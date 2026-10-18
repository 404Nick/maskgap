"""Where secrets come from, and how to talk about them without printing them.

A scanner that prints the thing it found is not a useful scanner, so findings
never carry the secret value: they carry a stable *fingerprint*
(``sha256:`` plus the first 12 hex characters of the SHA-256 of the value).

Secrets can be loaded from:

* the process environment, either by explicit name (``--env``), by name prefix
  (``--env-prefix CI_``) or by a conservative name heuristic (``--env auto``,
  the default) that picks variables whose names look like credentials;
* a dotenv-style file (``--env-file .env``);
* a plain text file with one secret per line or ``NAME=value`` pairs
  (``--secrets-file secrets.txt``).

All loading is local: no network access is involved anywhere in maskgap.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
from collections.abc import Iterable, Mapping, Sequence

__all__ = [
    "Secret",
    "dedupe_secrets",
    "fingerprint",
    "from_env",
    "from_env_auto",
    "from_env_file",
    "from_env_prefix",
    "from_secrets_file",
    "looks_like_secret_name",
    "parse_env_file",
]

#: Number of hex characters kept from the SHA-256 digest of a secret value.
FINGERPRINT_LENGTH = 12

#: Substrings that make a variable name "look like a credential". The list is
#: deliberately narrow: desktop-session variables (``DESKTOP_SESSION``,
#: ``XAUTHORITY``) are *not* credentials, and dragging them in would only bloat
#: the automaton and clutter reports.
_NAME_HINTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "API_KEY",
    "APIKEY",
    "BEARER",
    "AUTH_TOKEN",
)

#: Suffixes that mark a variable as a *pointer* to a path rather than a value.
_NOT_A_VALUE_SUFFIXES = ("_PATH", "_DIR", "_FILE", "_HOME", "_ROOT")

MAX_SECRET_LENGTH = 8192


@dataclasses.dataclass(frozen=True, slots=True)
class Secret:
    """A secret value plus a printable handle."""

    label: str
    value: str
    source: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.value)

    @property
    def length(self) -> int:
        return len(self.value)

    def describe(self) -> str:
        """Human readable handle, e.g. ``env:API_TOKEN (sha256:1f3a…, 40 chars)``."""
        digest = self.fingerprint.split(":", 1)[1][:4]
        return f"{self.label} (sha256:{digest}…, {self.length} chars)"


def fingerprint(value: str) -> str:
    """``sha256:`` + the first :data:`FINGERPRINT_LENGTH` hex digits of ``value``."""
    digest = hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()
    return f"sha256:{digest[:FINGERPRINT_LENGTH]}"


def looks_like_secret_name(name: str) -> bool:
    """Best-effort heuristic used by ``--env auto``.

    Deliberately conservative: false positives only cost a little scanning time,
    but a missed credential means a missed leak, so the rule errs on the
    inclusive side. Variables that hold a *path* (``*_PATH``, ``*_FILE``) and
    desktop-session noise are filtered out.
    """
    upper = name.upper()
    if upper.endswith(_NOT_A_VALUE_SUFFIXES):
        return False
    if upper.endswith(("KEY", "KEYS")) or "_KEY" in upper or "KEY_" in upper:
        return True
    return any(hint in upper for hint in _NAME_HINTS)


def _clean(value: str) -> str:
    """Normalise a raw value read from a file: drop line endings, keep everything else."""
    return value.rstrip("\r\n")


def from_env(names: Iterable[str], env: Mapping[str, str] | None = None) -> list[Secret]:
    """Load the named environment variables. Missing or empty names are skipped."""
    environ = os.environ if env is None else env
    secrets: list[Secret] = []
    for name in names:
        value = environ.get(name)
        if value:
            secrets.append(Secret(label=f"env:{name}", value=_clean(value), source="environment"))
    return secrets


def from_env_auto(
    min_length: int,
    env: Mapping[str, str] | None = None,
) -> list[Secret]:
    """Load every environment variable whose name looks like a credential."""
    environ = os.environ if env is None else env
    names = [
        name
        for name in sorted(environ)
        if looks_like_secret_name(name) and len(environ[name]) >= min_length
    ]
    return from_env(names, environ)


def from_env_prefix(
    prefixes: Iterable[str],
    env: Mapping[str, str] | None = None,
) -> list[Secret]:
    """Load every environment variable starting with one of ``prefixes``."""
    environ = os.environ if env is None else env
    wanted = tuple(prefix.upper() for prefix in prefixes)
    names = [name for name in sorted(environ) if name.upper().startswith(wanted)]
    return from_env(names, environ)


def parse_env_file(text: str) -> list[tuple[str, str]]:
    """Parse dotenv-style content into ``(name, value)`` pairs.

    Supports ``KEY=value``, ``KEY="value"``, ``KEY='value'``, ``export KEY=value``,
    ``#`` comments and blank lines. Values are not interpolated or expanded —
    maskgap never executes anything it reads.
    """
    pairs: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not name or " " in name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if value:
            pairs.append((name, value))
    return pairs


def from_env_file(path: str | os.PathLike[str]) -> list[Secret]:
    """Load secrets from a dotenv-style file."""
    file_path = pathlib.Path(path)
    text = file_path.read_text(encoding="utf-8", errors="surrogateescape")
    return [
        Secret(label=f"env-file:{file_path.name}:{name}", value=value, source=str(file_path))
        for name, value in parse_env_file(text)
    ]


def from_secrets_file(path: str | os.PathLike[str]) -> list[Secret]:
    """Load one secret per line; ``NAME=value`` lines keep ``NAME`` as the label."""
    file_path = pathlib.Path(path)
    text = file_path.read_text(encoding="utf-8", errors="surrogateescape")
    secrets: list[Secret] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        value = raw_line.rstrip("\r")
        if not value.strip() or value.lstrip().startswith("#"):
            continue
        name, separator, rest = value.partition("=")
        if separator and name.strip() and " " not in name.strip():
            label = f"file:{file_path.name}:{name.strip()}"
            value = rest
        else:
            label = f"file:{file_path.name}:line {number}"
        if value:
            secrets.append(Secret(label=label, value=value, source=str(file_path)))
    return secrets


def dedupe_secrets(secrets: Sequence[Secret]) -> list[Secret]:
    """Merge secrets that share a value, keeping the first label and noting the rest.

    The same token commonly shows up in several variables (``GH_TOKEN`` and
    ``GITHUB_TOKEN``); scanning it once is enough.
    """
    seen: dict[str, Secret] = {}
    order: list[str] = []
    for secret in secrets:
        existing = seen.get(secret.value)
        if existing is None:
            seen[secret.value] = secret
            order.append(secret.value)
        else:
            merged_label = f"{existing.label}|{secret.label}"
            seen[secret.value] = dataclasses.replace(existing, label=merged_label)
    return [seen[value] for value in order]
