"""Unit tests for provider-shaped pattern rules.

Each rule needs a positive example that reflects a real token shape and a
negative example that is close enough to be tempting. That pairing is what keeps
the rule set honest: no rule ships without evidence that it does not fire on
ordinary text.
"""

from __future__ import annotations

import re

import pytest

from maskgap.generic import GENERIC_RULES, compile_rules


def find(rule_name: str, text: str) -> str | None:
    for rule, regex in compile_rules():
        if rule.name != rule_name:
            continue
        match = regex.search(text)
        return match.group(rule.group) if match else None
    raise AssertionError(f"unknown rule {rule_name}")


# Every provider sample below is assembled from fragments at runtime on purpose.
# The values are fake, but a contiguous token-shaped literal in the repository
# is matched by GitHub push protection, secret scanning and third-party regex
# scanners alike -- the shape alone is enough, so there must be nothing to
# match. The tests receive the assembled string, exactly as before.
SLACK_TOKEN = "xox" + "b-123456789012-abcdefghijklmnop"
STRIPE_KEY = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"


POSITIVE: dict[str, str] = {
    "github-pat": "token " + "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789" + " end",
    "github-fine-grained-pat": (
        "github_pat_" + "11ABCDEFG0abcdefghijklmnop_" + "abcdefghijklmnopqrstuvwxyz01"
    ),
    "gitlab-pat": "glpat-" + "abcdefghijklmnopqrst",
    "aws-access-key-id": "AKIA" + "IOSFODNN7EXAMPLE",
    "slack-token": SLACK_TOKEN,
    "stripe-key": STRIPE_KEY,
    "google-api-key": "AIza" + "SyD-ExampleKey0123456789abcdefghijk",
    "openai-key": "sk-proj-" + "abcdefghijklmnopqrstuvwxyz012345",
    "anthropic-key": "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyz",
    "npm-token": "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "pypi-token": "pypi-" + "AgEIcHlwaS5vcmcCJGFiY2RlZmdoaWprbG1ub3BxcnN0dXY",
    "docker-pat": "dckr_pat_" + "abcdefghijklmnopqrstuvwxy",
    "huggingface-token": "hf_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "digitalocean-token": "dop_v1_" + "0" * 64,
    "shopify-token": "shpat_" + "a" * 32,
    "hashicorp-vault-token": "hvs." + "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
    "telegram-bot-token": "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
    "sendgrid-api-key": "SG." + "abcdefghijklmnopqrstuv" + "." + "abcdefghijklmnopqrstuv",
    "private-key-block": "-----BEGIN RSA PRIVATE" + " KEY-----",
    "jwt": (
        "eyJhbGciOiJIUzI1NiJ9"
        + "."
        + "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        + "."
        + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    ),
    "bearer-token": "Authorization: Bearer " + "abcdefghijklmnopqrstuvwxyz01",
    "credential-assignment": 'api_key = "' + "abcdefghijklmnopqrstuvwx" + '"',
}

NEGATIVE: dict[str, str] = {
    "github-pat": "ghp_short",
    "github-fine-grained-pat": "github_pat_short",
    "gitlab-pat": "glpat-short",
    "aws-access-key-id": "AKIA1234",
    "slack-token": "xoxb-1",
    "stripe-key": "sk_live_short",
    "google-api-key": "AIza-short",
    "openai-key": "sk-short",
    "anthropic-key": "sk-ant-short",
    "npm-token": "npm_short",
    "pypi-token": "pypi-short",
    "docker-pat": "dckr_pat_short",
    "huggingface-token": "hf_short",
    "digitalocean-token": "dop_v1_" + "0" * 32,
    "shopify-token": "shpat_" + "a" * 16,
    "hashicorp-vault-token": "hvs.short",
    "telegram-bot-token": "123456789:short",
    "sendgrid-api-key": "SG.short.short",
    "private-key-block": "-----BEGIN PUBLIC KEY-----",
    "jwt": "eyJhbGci.short.short",
    "bearer-token": "Authorization: Bearer short",
    "credential-assignment": "api_key = short",
}


def test_every_rule_has_a_positive_and_a_negative_example() -> None:
    names = {rule.name for rule in GENERIC_RULES}
    assert names == set(POSITIVE)
    assert names == set(NEGATIVE)


@pytest.mark.parametrize("rule_name", sorted(POSITIVE))
def test_rule_detects_its_positive_example(rule_name: str) -> None:
    assert find(rule_name, POSITIVE[rule_name]) is not None


@pytest.mark.parametrize("rule_name", sorted(NEGATIVE))
def test_rule_ignores_its_negative_example(rule_name: str) -> None:
    assert find(rule_name, NEGATIVE[rule_name]) is None


def test_rule_names_are_unique() -> None:
    names = [rule.name for rule in GENERIC_RULES]
    assert len(names) == len(set(names))


def test_group_extraction_returns_the_credential_not_the_header() -> None:
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz01"
    assert find("bearer-token", text) == "abcdefghijklmnopqrstuvwxyz01"


def test_plain_prose_is_not_reported() -> None:
    prose = (
        "The build finished in 12 seconds.\n"
        "Downloading https://example.com/pkg-1.2.3.tar.gz\n"
        "User alice@example.com logged in from 10.0.0.1\n"
        "SHA256 checksum: 0" * 3
    )
    for _, regex in compile_rules():
        assert not regex.search(prose), "a rule fired on ordinary log text"


def test_rules_can_be_skipped() -> None:
    compiled = compile_rules(skip=frozenset({"jwt"}))
    assert all(rule.name != "jwt" for rule, _ in compiled)


def test_patterns_are_linear_time_safe() -> None:
    # Guard against accidentally introducing nested quantifiers (ReDoS risk):
    # a quantified group that itself ends in a quantifier is the classic footgun.
    nested = re.compile(r"\([^()]*[+*][^()]*\)[+*{]")
    for rule in GENERIC_RULES:
        assert not nested.search(rule.pattern), f"{rule.name} has a nested quantifier"
