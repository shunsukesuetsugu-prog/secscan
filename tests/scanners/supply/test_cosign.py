"""Phase 2-Q: cosign argv builder + failure classifier.

Pure tests — no docker. Verify the security-critical argv shape
(``--cap-drop=ALL`` / ``--network=bridge`` / digest-pinned
images / ``--`` separator / exact-match identity by default) and
the 4-way failure classification.
"""

from __future__ import annotations

import pytest

from secscan.models import Severity
from secscan.scanners.supply.cosign import (
    CosignVerification,
    build_argv,
    classify_cosign_failure,
    severity_for_rule,
)
from secscan.scanners.supply.validators import SupplyInputError

_VALID_DIGEST = "a" * 64
_TARGET = f"alpine@sha256:{_VALID_DIGEST}"
_COSIGN = f"gcr.io/projectsigstore/cosign@sha256:{'b' * 64}"


class TestBuildArgv:
    def _inv(self, **kw: object) -> CosignVerification:
        base: dict[str, object] = {
            "target_image": _TARGET,
            "signer_identity": "user@example.com",
            "signer_issuer": "https://issuer.example.com",
            "cosign_image": _COSIGN,
        }
        base.update(kw)
        return CosignVerification(**base)  # type: ignore[arg-type]

    def test_safety_flags(self) -> None:
        argv = build_argv(self._inv())
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=bridge" in argv

    def test_separator_before_cosign_image(self) -> None:
        argv = build_argv(self._inv())
        sep = argv.index("--")
        assert argv[sep + 1] == _COSIGN
        assert argv[sep + 2] == "verify"

    def test_target_image_is_last(self) -> None:
        argv = build_argv(self._inv())
        assert argv[-1] == _TARGET

    def test_literal_identity_default(self) -> None:
        """Codex Phase 2-Q design review MUST-FIX #2: literal
        ``--certificate-identity`` is the default. The regex
        variant is only used when explicitly opted in."""
        argv = build_argv(self._inv())
        assert "--certificate-identity" in argv
        idx = argv.index("--certificate-identity")
        assert argv[idx + 1] == "user@example.com"
        assert "--certificate-identity-regexp" not in argv

    def test_regex_identity_opt_in(self) -> None:
        argv = build_argv(
            self._inv(
                signer_identity=None,
                signer_identity_regexp=r"^https://github\.com/.*$",
            )
        )
        assert "--certificate-identity-regexp" in argv
        assert "--certificate-identity" not in argv

    def test_oidc_issuer_forwarded(self) -> None:
        argv = build_argv(self._inv())
        assert "--certificate-oidc-issuer" in argv
        idx = argv.index("--certificate-oidc-issuer")
        assert argv[idx + 1] == "https://issuer.example.com"

    def test_output_json(self) -> None:
        argv = build_argv(self._inv())
        assert "--output" in argv
        assert argv[argv.index("--output") + 1] == "json"

    def test_both_identity_forms_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="EXACTLY one"):
            build_argv(
                self._inv(
                    signer_identity="foo@bar.com",
                    signer_identity_regexp=r"^.*$",
                )
            )

    def test_neither_identity_form_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="EXACTLY one"):
            build_argv(
                self._inv(
                    signer_identity=None,
                    signer_identity_regexp=None,
                )
            )

    def test_missing_issuer_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="signer-issuer"):
            build_argv(self._inv(signer_issuer=""))

    def test_tag_only_cosign_image_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="digest pinning"):
            build_argv(self._inv(cosign_image="gcr.io/projectsigstore/cosign:v2.4.1"))


class TestClassifyCosignFailure:
    def test_signature_missing(self) -> None:
        rule = classify_cosign_failure(
            returncode=1,
            stderr=b"Error: no matching signatures found\n",
            timed_out=False,
        )
        assert rule == "cosign-signature-missing"

    def test_identity_mismatch(self) -> None:
        rule = classify_cosign_failure(
            returncode=1,
            stderr=(
                b"Error: none of the expected identities matched what "
                b"was in the certificate"
            ),
            timed_out=False,
        )
        assert rule == "cosign-identity-mismatch"

    def test_network_failure(self) -> None:
        rule = classify_cosign_failure(
            returncode=1,
            stderr=b"failed to get the TUF targets: i/o timeout",
            timed_out=False,
        )
        assert rule == "cosign-verification-network-failure"

    def test_timeout_is_network_failure(self) -> None:
        rule = classify_cosign_failure(
            returncode=0,
            stderr=b"",
            timed_out=True,
        )
        assert rule == "cosign-verification-network-failure"

    def test_unrecognized_falls_back_to_invalid(self) -> None:
        """Codex Phase 2-Q design review MUST-FIX #3: novel
        non-zero exit defaults to ``signature_invalid`` (HIGH),
        the safer of the alternatives."""
        rule = classify_cosign_failure(
            returncode=2,
            stderr=b"some new error message we don't recognize",
            timed_out=False,
        )
        assert rule == "cosign-signature-invalid"


class TestSeverityMap:
    def test_signature_invalid_is_high(self) -> None:
        assert (
            severity_for_rule("cosign-signature-invalid")
            == Severity.HIGH
        )

    def test_identity_mismatch_is_high(self) -> None:
        assert (
            severity_for_rule("cosign-identity-mismatch") == Severity.HIGH
        )

    def test_signature_missing_is_medium(self) -> None:
        assert (
            severity_for_rule("cosign-signature-missing")
            == Severity.MEDIUM
        )

    def test_network_failure_is_low(self) -> None:
        assert (
            severity_for_rule("cosign-verification-network-failure")
            == Severity.LOW
        )

    def test_unknown_falls_back_to_low(self) -> None:
        assert severity_for_rule("cosign-future-rule") == Severity.LOW
