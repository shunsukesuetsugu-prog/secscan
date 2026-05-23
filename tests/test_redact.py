"""Redaction must be defense-in-depth: known-secret replacement plus
pattern-based scrubbing for stderr / message paths that "should not" contain
secrets but historically have. We test both."""

from __future__ import annotations

from secscan.redact import (
    REDACTED,
    redact_secret,
    redact_text,
    truncate,
)

# --- redact_secret ---------------------------------------------------------


def test_redact_secret_replaces_value_entirely() -> None:
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == REDACTED


def test_redact_secret_passes_empty_unchanged() -> None:
    # We do not synthesize a token for empty input — there's nothing to hide.
    assert redact_secret("") == ""


def test_redact_secret_returns_no_portion_of_original() -> None:
    secret = "supersecretvalue12345"
    out = redact_secret(secret)
    # Even a 4-char suffix would be an oracle.
    assert secret not in out
    assert out[-4:] != secret[-4:]


# --- hash_secret is intentionally removed ----------------------------------


def test_hash_secret_helper_is_not_exposed() -> None:
    # Hashing secrets creates a brute-force oracle; we deliberately removed
    # the helper. This test pins that absence so a future refactor can't
    # quietly reintroduce it.
    import secscan.redact as redact_module

    assert not hasattr(redact_module, "hash_secret")


# --- redact_text -----------------------------------------------------------


def test_redact_text_scrubs_known_secret() -> None:
    text = "logged secret=hunter2 something else"
    out = redact_text(text, known_secrets=["hunter2"])
    assert "hunter2" not in out
    assert REDACTED in out


def test_redact_text_scrubs_aws_access_key_pattern() -> None:
    text = "leaked key AKIAIOSFODNN7EXAMPLE in env"
    out = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert REDACTED in out


def test_redact_text_scrubs_github_token_pattern() -> None:
    text = "token ghp_" + "a" * 40 + " visible"
    out = redact_text(text)
    assert "ghp_" not in out


def test_redact_text_scrubs_bearer_header_value() -> None:
    text = "Authorization: Bearer abc.def.ghi-jkl_mno"
    out = redact_text(text)
    assert "abc.def.ghi-jkl_mno" not in out
    # Header name is fine to preserve.
    assert "Authorization" in out


def test_redact_text_scrubs_npm_authtoken_in_config_line() -> None:
    # Codex 8th review: .npmrc-style "key=value" pairs must redact the
    # value but keep the key name for context.
    text = "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    out = redact_text(text)
    assert "npm_abcdefghijklmnopqrstuvwxyz" not in out
    assert "_authToken" in out


def test_redact_text_scrubs_npm_token_prefixed() -> None:
    text = "leaked npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ABCD trailing"
    out = redact_text(text)
    assert "npm_aBcDeFgHiJk" not in out


def test_redact_text_scrubs_pypi_token() -> None:
    text = "found pypi-AgEIcHlwaS5vcmcCJDk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5 in env"
    out = redact_text(text)
    assert "pypi-AgEI" not in out


def test_redact_text_scrubs_url_basic_auth() -> None:
    """URL-embedded credentials are a common leak path in pip/npm stderr
    output. The redactor preserves scheme + host so the operator can see
    WHICH registry was failing, but drops the user:pass."""
    text = "Fetching https://alice:p4ssw0rd@registry.example.com/pkg failed"
    out = redact_text(text)
    assert "alice:p4ssw0rd" not in out
    # Host and scheme are still useful for debugging.
    assert "registry.example.com" in out
    assert "https://" in out


def test_redact_text_scrubs_pip_index_url_config_line() -> None:
    text = "index-url=https://user:secret@private.pypi.org/simple/"
    out = redact_text(text)
    assert "user:secret" not in out


def test_redact_text_scrubs_jwt() -> None:
    # Realistically-sized JWT: header.payload.signature, each segment well
    # above the {8,} minimum the redactor requires.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKFabcdef"
    text = f"got jwt: {jwt}"
    out = redact_text(text)
    assert jwt not in out


def test_redact_text_handles_empty_known_secrets() -> None:
    text = "no secrets here"
    assert redact_text(text) == text


def test_redact_text_skips_empty_known_secret() -> None:
    # An empty string in known_secrets must not collapse the whole text.
    text = "some content"
    out = redact_text(text, known_secrets=["", ""])
    assert out == text


# --- truncate --------------------------------------------------------------


def test_truncate_returns_short_text_unchanged() -> None:
    assert truncate("hello", limit=100) == "hello"


def test_truncate_long_text_adds_ellipsis() -> None:
    long = "x" * 1000
    out = truncate(long, limit=100)
    assert len(out) == 100
    assert out.endswith("...")


def test_truncate_handles_exact_limit() -> None:
    text = "y" * 100
    assert truncate(text, limit=100) == text
