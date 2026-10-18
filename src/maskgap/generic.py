"""High-confidence provider token shapes found by pattern, not by value.

Knowing the secret values in your environment is what makes maskgap able to catch
*transformed* leaks. That covers your own secrets, but not the ones that show up
in a log for other reasons: a token pasted into a config dump, a CI variable of a
third-party action, a private key echoed by a broken build script.

This module therefore adds a small set of *pattern* rules. Only shapes with a
distinctive, fixed prefix are included — generic "high entropy string" detection
is deliberately out of scope (it belongs to tools such as gitleaks and
trufflehog, and it produces far more noise than signal). Every rule in this file
carries a positive and a negative example in ``tests/test_generic.py``.

All patterns are linear-time: no nested quantifiers, no user-supplied regexes.
"""

from __future__ import annotations

import dataclasses
import re

__all__ = ["GENERIC_RULES", "GenericRule", "compile_rules"]


@dataclasses.dataclass(frozen=True, slots=True)
class GenericRule:
    """One provider-shaped credential pattern."""

    name: str
    pattern: str
    summary: str
    #: Capturing group that holds the credential itself (0 = whole match).
    group: int = 0
    flags: int = 0

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)


GENERIC_RULES: tuple[GenericRule, ...] = (
    GenericRule(
        name="github-pat",
        pattern=r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])",
        summary="GitHub personal access / OAuth / server token",
    ),
    GenericRule(
        name="github-fine-grained-pat",
        pattern=r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}",
        summary="GitHub fine-grained personal access token",
    ),
    GenericRule(
        name="gitlab-pat",
        pattern=r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,64}",
        summary="GitLab personal access token",
    ),
    GenericRule(
        name="aws-access-key-id",
        pattern=r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])",
        summary="AWS access key ID",
    ),
    GenericRule(
        name="slack-token",
        pattern=r"(?<![A-Za-z0-9-])xox[aboprsd]-[A-Za-z0-9-]{10,128}",
        summary="Slack API / bot / user token",
    ),
    GenericRule(
        name="stripe-key",
        pattern=r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,128}",
        summary="Stripe secret or restricted key",
    ),
    GenericRule(
        name="google-api-key",
        pattern=r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}",
        summary="Google API key",
    ),
    GenericRule(
        name="openai-key",
        pattern=r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,128}",
        summary="OpenAI API key",
    ),
    GenericRule(
        name="anthropic-key",
        pattern=r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,128}",
        summary="Anthropic API key",
    ),
    GenericRule(
        name="npm-token",
        pattern=r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])",
        summary="npm automation / publish token",
    ),
    GenericRule(
        name="pypi-token",
        pattern=r"(?<![A-Za-z0-9_-])pypi-[A-Za-z0-9_-]{40,128}",
        summary="PyPI API token",
    ),
    GenericRule(
        name="docker-pat",
        pattern=r"(?<![A-Za-z0-9_-])dckr_pat_[A-Za-z0-9_-]{20,128}",
        summary="Docker Hub personal access token",
    ),
    GenericRule(
        name="huggingface-token",
        pattern=r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,64}(?![A-Za-z0-9])",
        summary="Hugging Face access token",
    ),
    GenericRule(
        name="digitalocean-token",
        pattern=r"(?<![A-Za-z0-9_])dop_v1_[0-9a-f]{64}",
        summary="DigitalOcean personal access token",
    ),
    GenericRule(
        name="shopify-token",
        pattern=r"(?<![A-Za-z0-9_])shpat_[0-9a-f]{32}",
        summary="Shopify admin API access token",
    ),
    GenericRule(
        name="hashicorp-vault-token",
        pattern=r"(?<![A-Za-z0-9_])hvs\.[A-Za-z0-9_-]{24,128}",
        summary="HashiCorp Vault service token",
    ),
    GenericRule(
        name="telegram-bot-token",
        pattern=r"(?<![0-9])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])",
        summary="Telegram bot token",
    ),
    GenericRule(
        name="sendgrid-api-key",
        pattern=r"(?<![A-Za-z0-9_])SG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,64}",
        summary="SendGrid API key",
    ),
    GenericRule(
        name="private-key-block",
        # The leading algorithm words are spelled out instead of using
        # ``(?:[A-Z0-9]+ )*`` so the pattern contains no nested quantifier.
        pattern=(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )*PRIVATE KEY-----"),
        summary="PEM private key header",
    ),
    GenericRule(
        name="jwt",
        pattern=(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        ),
        summary="JSON Web Token (any issuer)",
    ),
    GenericRule(
        name="bearer-token",
        pattern=r"(?i)\bauthorization\b\s*:\s*(?:bearer|token)\s+([A-Za-z0-9._~+/=-]{20,512})",
        summary="Bearer token in an Authorization header",
        group=1,
    ),
    GenericRule(
        name="credential-assignment",
        pattern=(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{16,512})[\"']?"
        ),
        summary="credential-looking key=value assignment",
        group=1,
    ),
)


def compile_rules(
    rules: tuple[GenericRule, ...] = GENERIC_RULES,
    *,
    skip: frozenset[str] = frozenset(),
) -> tuple[tuple[GenericRule, re.Pattern[str]], ...]:
    """Compile the rules, dropping any named in ``skip``."""
    compiled = []
    for rule in rules:
        if rule.name in skip:
            continue
        compiled.append((rule, rule.compile()))
    return tuple(compiled)
