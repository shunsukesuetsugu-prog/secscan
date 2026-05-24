"""Input-validator tests for the DAST adapter.

These cover the security boundary: anything that flows from
``--zap-image`` / ``--target`` into the docker argv list goes
through ``validate_image_ref`` / ``validate_target_url`` first.
A regression here is a command-injection / supply-chain bypass,
so the table-driven matrices below are deliberately exhaustive.
"""

from __future__ import annotations

import pytest

from secscan.scanners.dast.zap import (
    DastInputError,
    validate_image_ref,
    validate_target_url,
)

# --- validate_image_ref ----------------------------------------------------

_VALID_DIGEST = "a" * 64
_VALID_IMAGE = f"zaproxy/zap-stable@sha256:{_VALID_DIGEST}"
_VALID_IMAGE_WITH_TAG = f"zaproxy/zap-stable:2.15.0@sha256:{_VALID_DIGEST}"


class TestValidateImageRef:
    def test_accepts_repo_with_digest(self) -> None:
        assert validate_image_ref(_VALID_IMAGE) == _VALID_IMAGE

    def test_accepts_repo_with_tag_and_digest(self) -> None:
        assert validate_image_ref(_VALID_IMAGE_WITH_TAG) == _VALID_IMAGE_WITH_TAG

    def test_strips_surrounding_whitespace(self) -> None:
        assert validate_image_ref(f"  {_VALID_IMAGE}  ") == _VALID_IMAGE

    def test_rejects_empty(self) -> None:
        with pytest.raises(DastInputError, match="must not be empty"):
            validate_image_ref("")

    def test_rejects_none(self) -> None:
        with pytest.raises(DastInputError):
            validate_image_ref(None)  # type: ignore[arg-type]

    def test_rejects_leading_dash(self) -> None:
        """Critical: a leading ``-`` would let the value be interpreted
        as a docker flag if argv ordering ever regressed.

        Codex 2nd review for Phase 2-D explicitly pinned this guard.
        """
        with pytest.raises(DastInputError, match="docker flag"):
            validate_image_ref(f"-{_VALID_IMAGE}")

    def test_rejects_internal_whitespace(self) -> None:
        with pytest.raises(DastInputError, match="whitespace or control"):
            validate_image_ref(f"zaproxy/zap stable@sha256:{_VALID_DIGEST}")

    def test_rejects_control_characters(self) -> None:
        with pytest.raises(DastInputError, match="whitespace or control"):
            validate_image_ref(f"zaproxy/zap-stable\x07@sha256:{_VALID_DIGEST}")

    def test_rejects_missing_digest(self) -> None:
        with pytest.raises(DastInputError, match="digest pinning is required"):
            validate_image_ref("zaproxy/zap-stable:2.15.0")

    def test_rejects_short_digest(self) -> None:
        with pytest.raises(DastInputError, match="digest pinning is required"):
            validate_image_ref("zaproxy/zap-stable@sha256:" + "a" * 63)

    def test_rejects_nonhex_digest(self) -> None:
        with pytest.raises(DastInputError, match="digest pinning is required"):
            validate_image_ref("zaproxy/zap-stable@sha256:" + "z" * 64)

    def test_rejects_uppercase_repo(self) -> None:
        """OCI repo names must be lowercase — relaxing this rule would
        accept ``Zaproxy/zap-stable`` which Docker Hub treats as
        invalid; we keep the regex consistent with the registry spec."""
        with pytest.raises(DastInputError):
            validate_image_ref(f"Zaproxy/zap-stable@sha256:{_VALID_DIGEST}")


# --- validate_target_url ---------------------------------------------------


class TestValidateTargetUrl:
    def test_accepts_https(self) -> None:
        canonical, host, warnings = validate_target_url("https://example.com/")
        assert canonical == "https://example.com/"
        assert host == "example.com"
        assert warnings == ()

    def test_lowercases_host(self) -> None:
        canonical, host, warnings = validate_target_url("https://Example.COM/api")
        assert canonical == "https://example.com/api"
        assert host == "example.com"
        assert warnings == ()

    def test_preserves_port(self) -> None:
        canonical, host, _ = validate_target_url("http://example.com:8080/path")
        assert canonical == "http://example.com:8080/path"
        assert host == "example.com:8080"

    def test_accepts_idna(self) -> None:
        canonical, host, _ = validate_target_url("https://例え.テスト/")
        # IDNA-encoded form for "例え.テスト" is xn--r8jz45g.xn--zckzah.
        assert host == "xn--r8jz45g.xn--zckzah"
        assert canonical.startswith("https://xn--")

    def test_rejects_empty(self) -> None:
        with pytest.raises(DastInputError, match="must not be empty"):
            validate_target_url("")

    def test_rejects_file_scheme(self) -> None:
        with pytest.raises(DastInputError, match="http or https"):
            validate_target_url("file:///etc/passwd")

    def test_rejects_javascript_scheme(self) -> None:
        with pytest.raises(DastInputError, match="http or https"):
            validate_target_url("javascript:alert(1)")

    def test_rejects_missing_host(self) -> None:
        with pytest.raises(DastInputError, match="hostname"):
            validate_target_url("https:///path")

    def test_rejects_leading_dash_host(self) -> None:
        with pytest.raises(DastInputError, match="must not start with '-'"):
            validate_target_url("https://-flag.example.com/")

    def test_rejects_whitespace(self) -> None:
        with pytest.raises(DastInputError, match="whitespace or control"):
            validate_target_url("https://example.com/ space")

    def test_rejects_control_characters(self) -> None:
        with pytest.raises(DastInputError, match="whitespace or control"):
            validate_target_url("https://example.com/\x01")

    @pytest.mark.parametrize(
        "host",
        [
            "https://localhost/",
            "https://127.0.0.1/",
            "http://10.0.0.5:8080/",
            "http://192.168.1.10/",
            "http://169.254.169.254/",
            "http://172.16.0.1/",
            "http://app.local/",
        ],
    )
    def test_private_or_loopback_warning(self, host: str) -> None:
        _, _, warnings = validate_target_url(host)
        assert any("private or loopback" in w for w in warnings)

    def test_public_host_no_warning(self) -> None:
        _, _, warnings = validate_target_url("https://www.example.com/")
        assert warnings == ()
