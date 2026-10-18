"""Unit tests for secret loading and fingerprinting.

The name heuristic behind ``--env auto`` gets a lot of attention here: it decides
what maskgap looks for by default, and a heuristic that quietly returns nothing
is worse than one that is a little too eager.
"""

from __future__ import annotations

from maskgap.secrets import (
    MAX_SECRET_LENGTH,
    Secret,
    dedupe_secrets,
    fingerprint,
    from_env,
    from_env_auto,
    from_env_file,
    from_env_prefix,
    from_secrets_file,
    looks_like_secret_name,
    parse_env_file,
)

TOKEN = "ghp_" + "Example0Token0WithSlashAnd1234"


# --------------------------------------------------------------------------- #
# fingerprinting                                                              #
# --------------------------------------------------------------------------- #


def test_fingerprint_is_stable_and_scoped() -> None:
    first = fingerprint(TOKEN)
    assert first == fingerprint(TOKEN)
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 12
    assert fingerprint("other-value") != first


def test_secret_describe_never_contains_the_value() -> None:
    secret = Secret(label="env:TOKEN", value=TOKEN, source="environment")
    description = secret.describe()
    assert TOKEN not in description
    assert "env:TOKEN" in description
    assert secret.length == len(TOKEN)
    assert secret.fingerprint == fingerprint(TOKEN)


def test_max_secret_length_is_defined() -> None:
    assert MAX_SECRET_LENGTH > 0


# --------------------------------------------------------------------------- #
# name heuristic                                                              #
# --------------------------------------------------------------------------- #


def test_looks_like_secret_name_accepts_credentials() -> None:
    for name in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "API_KEY",
        "MYKEY",
        "SSH_KEY",
        "DB_PASSWORD",
        "DB_PASSWD",
        "NPM_CREDENTIAL",
        "TLS_PRIVATE_KEY",
        "AUTH_TOKEN",
        "SLACK_BEARER",
        "KEYCLOAK_KEY",
    ):
        assert looks_like_secret_name(name), name


def test_looks_like_secret_name_rejects_noise() -> None:
    for name in (
        "PATH",
        "HOME",
        "PWD",
        "DESKTOP_SESSION",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "OPENCODE_SESSION_ID",
        "LANG",
        # Pointers to files, not values.
        "PRIVATE_KEY_PATH",
        "SECRET_FILE",
        "TOKEN_DIR",
    ):
        assert not looks_like_secret_name(name), name


# --------------------------------------------------------------------------- #
# sources                                                                     #
# --------------------------------------------------------------------------- #


def test_from_env_reads_present_variables_only() -> None:
    env = {"TOKEN_A": TOKEN, "TOKEN_B": ""}
    secrets = from_env(["TOKEN_A", "TOKEN_B", "TOKEN_C"], env)
    assert [secret.label for secret in secrets] == ["env:TOKEN_A"]
    assert secrets[0].source == "environment"


def test_from_env_strips_trailing_line_endings() -> None:
    secrets = from_env(["TOKEN"], {"TOKEN": TOKEN + "\r\n"})
    assert secrets[0].value == TOKEN


def test_from_env_auto_respects_min_length() -> None:
    env = {"MY_TOKEN": "short", "MY_SECRET": TOKEN}
    secrets = from_env_auto(min_length=8, env=env)
    assert [secret.label for secret in secrets] == ["env:MY_SECRET"]


def test_from_env_auto_is_sorted_and_deduplicated_by_name() -> None:
    env = {"B_TOKEN": TOKEN, "A_TOKEN": TOKEN + "x"}
    assert [secret.label for secret in from_env_auto(1, env)] == ["env:A_TOKEN", "env:B_TOKEN"]


def test_from_env_prefix_selects_by_case_insensitive_prefix() -> None:
    env = {"CI_TOKEN": TOKEN, "ci_secret": TOKEN + "x", "OTHER": TOKEN + "y"}
    labels = [secret.label for secret in from_env_prefix(["ci_"], env)]
    assert labels == ["env:CI_TOKEN", "env:ci_secret"]


def test_parse_env_file_handles_common_syntax() -> None:
    text = (
        "# comment\n"
        "\n"
        "PLAIN=value1\n"
        'QUOTED="value2"\n'
        "SINGLE='value3'\n"
        "export EXPORTED=value4\n"
        "TRAILING=value5 # inline comment\n"
        "EMPTY=\n"
        "not a pair\n"
    )
    assert parse_env_file(text) == [
        ("PLAIN", "value1"),
        ("QUOTED", "value2"),
        ("SINGLE", "value3"),
        ("EXPORTED", "value4"),
        ("TRAILING", "value5"),
    ]


def test_from_env_file_labels_include_the_file_name(tmp_path) -> None:
    path = tmp_path / ".env"
    path.write_text(f"API_TOKEN={TOKEN}\n", encoding="utf-8")
    secrets = from_env_file(path)
    assert len(secrets) == 1
    assert secrets[0].label == "env-file:.env:API_TOKEN"
    assert secrets[0].value == TOKEN


def test_from_secrets_file_supports_bare_lines_and_pairs(tmp_path) -> None:
    path = tmp_path / "secrets.txt"
    path.write_text(f"# comment\n{TOKEN}\nNAMED={TOKEN}2\n\n", encoding="utf-8")
    secrets = from_secrets_file(path)
    assert [secret.label for secret in secrets] == [
        "file:secrets.txt:line 2",
        "file:secrets.txt:NAMED",
    ]
    assert secrets[0].value == TOKEN
    assert secrets[1].value == f"{TOKEN}2"


def test_dedupe_secrets_merges_labels_for_equal_values() -> None:
    secrets = [
        Secret(label="env:A", value=TOKEN, source="environment"),
        Secret(label="env:B", value=TOKEN, source="environment"),
        Secret(label="env:C", value=TOKEN + "x", source="environment"),
    ]
    deduped = dedupe_secrets(secrets)
    assert len(deduped) == 2
    assert deduped[0].label == "env:A|env:B"
    assert deduped[1].label == "env:C"


def test_dedupe_secrets_preserves_order() -> None:
    secrets = [
        Secret(label="first", value="1-value-here", source="test"),
        Secret(label="second", value="2-value-here", source="test"),
    ]
    assert [secret.label for secret in dedupe_secrets(secrets)] == ["first", "second"]
