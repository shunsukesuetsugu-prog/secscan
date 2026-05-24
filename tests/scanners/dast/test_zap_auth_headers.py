"""Phase 2-K: HTTP auth-header validator + argv tests.

The ``--auth-header`` value lands inside ZAP's ``-z`` config
expression — a place where an attacker-controlled string could
break out of the expected key/value position. The validator's
charset rules and the argv shape are the security contract.
"""

from __future__ import annotations

import pytest

from secscan.scanners.dast.zap import (
    DastInputError,
    ZapInvocation,
    build_argv,
    validate_auth_header,
)

_VALID_DIGEST = "a" * 64
_VALID_IMAGE = f"zaproxy/zap-stable@sha256:{_VALID_DIGEST}"


class TestValidateAuthHeader:
    def test_accepts_basic_auth_header(self) -> None:
        h = validate_auth_header("Authorization: Bearer abc.def.ghi")
        assert h.name == "Authorization"
        assert h.value == "Bearer abc.def.ghi"

    def test_accepts_dashed_name(self) -> None:
        h = validate_auth_header("X-API-Key: secret123")
        assert h.name == "X-API-Key"
        assert h.value == "secret123"

    def test_strips_surrounding_whitespace(self) -> None:
        # ``"  Header: value  "`` → both ends trimmed. Internal
        # spaces in the value (e.g. ``Bearer <token>``) are
        # preserved.
        h = validate_auth_header("  X-Token:   inner   value  ")
        assert h.name == "X-Token"
        assert h.value == "inner   value"

    def test_rejects_no_colon(self) -> None:
        with pytest.raises(DastInputError, match="missing ':'"):
            validate_auth_header("Authorization Bearer x")

    def test_rejects_empty_value(self) -> None:
        with pytest.raises(DastInputError, match="empty value"):
            validate_auth_header("X-Custom:")

    def test_rejects_name_with_spaces(self) -> None:
        with pytest.raises(DastInputError, match="safe HTTP token"):
            validate_auth_header("Two Word: value")

    def test_rejects_name_with_zap_syntax_sigil(self) -> None:
        """ZAP's ``-z`` config uses ``=``/``,``/``(`` as separators.
        A name containing those characters could break out of the
        replacer key/value position."""
        for bad in ("name=evil: v", "name,evil: v", "name(evil): v"):
            with pytest.raises(DastInputError, match="safe HTTP token"):
                validate_auth_header(bad)

    def test_rejects_crlf_in_value(self) -> None:
        """Classic header smuggling: a CR/LF in the value would let
        the attacker inject additional headers when ZAP renders the
        request."""
        with pytest.raises(DastInputError, match="CR/LF"):
            validate_auth_header("X-Header: line1\r\nInjected: hostile")

    def test_rejects_non_printable_in_value(self) -> None:
        with pytest.raises(DastInputError, match="non-printable"):
            validate_auth_header("X-Header: bad\x01value")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(DastInputError, match="must be a string"):
            validate_auth_header(12345)  # type: ignore[arg-type]

    def test_rejects_single_quote_in_value(self) -> None:
        """Phase 2-K: the value is wrapped in single quotes when
        forwarded to ZAP's ``-z`` config (the only way to preserve
        spaces in Bearer tokens). An embedded single quote would
        close the wrap early — reject."""
        with pytest.raises(DastInputError, match="single quote"):
            validate_auth_header("X-Header: don't")


class TestArgvWithAuthHeaders:
    def _invocation(self, headers: tuple[str, ...]) -> ZapInvocation:
        return ZapInvocation(
            target_url="https://example.com/",
            image_ref=_VALID_IMAGE,
            report_volume="secscan-zap-abc123",
            auth_headers=headers,
        )

    def test_no_headers_no_z_flag(self) -> None:
        argv = build_argv(self._invocation(()))
        assert "-z" not in argv

    def test_single_header_emits_z(self) -> None:
        argv = build_argv(self._invocation(("Authorization: Bearer xyz",)))
        assert "-z" in argv
        z_value = argv[argv.index("-z") + 1]
        # Each ``key=value`` pair is wrapped in single quotes so
        # spaces in the value (e.g. ``Bearer xyz``) survive ZAP's
        # internal whitespace tokenisation.
        assert "'replacer.full_list(0).description=secscan-auth-0'" in z_value
        assert "'replacer.full_list(0).enabled=true'" in z_value
        assert "'replacer.full_list(0).matchtype=REQ_HEADER'" in z_value
        assert "'replacer.full_list(0).matchstr=Authorization'" in z_value
        assert "'replacer.full_list(0).regex=false'" in z_value
        assert "'replacer.full_list(0).replacement=Bearer xyz'" in z_value

    def test_multiple_headers_are_indexed(self) -> None:
        argv = build_argv(
            self._invocation(
                ("Authorization: Bearer xyz", "X-Custom: abc")
            )
        )
        z_value = argv[argv.index("-z") + 1]
        assert "'replacer.full_list(0).matchstr=Authorization'" in z_value
        assert "'replacer.full_list(1).matchstr=X-Custom'" in z_value

    def test_invalid_header_raises_at_argv_build(self) -> None:
        """Even when the header makes it into the ZapInvocation
        (e.g. via a direct programmatic call), the argv builder
        re-validates so the bad value never reaches docker."""
        with pytest.raises(DastInputError):
            build_argv(self._invocation(("BadHeader without colon",)))

    def test_z_appears_after_target(self) -> None:
        argv = build_argv(self._invocation(("Authorization: Bearer xyz",)))
        # ``-z`` is a ZAP option (not docker) — must come AFTER the
        # image position so docker doesn't see it.
        z_idx = argv.index("-z")
        image_idx = argv.index(_VALID_IMAGE)
        assert z_idx > image_idx
