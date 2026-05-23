"""Redaction must be defense-in-depth: known-secret replacement plus
pattern-based scrubbing for stderr / message paths that "should not" contain
secrets but historically have. We test both."""

from __future__ import annotations

from secscan.redact import (
    REDACTED,
    hash_secret,
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


# --- hash_secret -----------------------------------------------------------


def test_hash_secret_is_stable_sha256() -> None:
    # SHA-256("foo") = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    expected = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    assert hash_secret("foo") == expected


def test_hash_secret_handles_unicode() -> None:
    # Should not raise on non-ASCII.
    h1 = hash_secret("日本語パスワード")
    h2 = hash_secret("日本語パスワード")
    assert h1 == h2
    assert len(h1) == 64


def test_hash_secret_handles_surrogateescape() -> None:
    # Bytes that don't decode cleanly are still hashable via surrogateescape.
    bad = b"\xff\xfe\xfd".decode("utf-8", errors="surrogateescape")
    out = hash_secret(bad)
    assert len(out) == 64


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
