"""Phase 2-Q: validators for cosign image refs, signer identities,
lockfile paths.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secscan.scanners.supply.validators import (
    SupplyInputError,
    classify_lockfile,
    validate_image_ref,
    validate_signer_identity,
    validate_signer_identity_regexp,
    validate_signer_issuer,
)

_VALID_DIGEST = "0" * 63 + "1"
_VALID_REF = f"alpine@sha256:{_VALID_DIGEST}"


class TestValidateImageRef:
    def test_accepts_digest_pinned(self) -> None:
        assert validate_image_ref(_VALID_REF) == _VALID_REF

    def test_rejects_tag_only(self) -> None:
        with pytest.raises(SupplyInputError, match="digest pinning"):
            validate_image_ref("alpine:3.21")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(SupplyInputError, match="must not start with '-'"):
            validate_image_ref(f"-evil@sha256:{_VALID_DIGEST}")


class TestValidateSignerIdentity:
    def test_email_accepted(self) -> None:
        assert (
            validate_signer_identity("foo@bar.com")
            == "foo@bar.com"
        )

    def test_url_accepted(self) -> None:
        url = (
            "https://github.com/myorg/repo/.github/workflows/"
            "release.yml@refs/tags/v1.0"
        )
        assert validate_signer_identity(url) == url

    def test_rejects_whitespace(self) -> None:
        with pytest.raises(SupplyInputError, match="whitespace"):
            validate_signer_identity("user name")

    def test_rejects_empty(self) -> None:
        with pytest.raises(SupplyInputError, match="must not be empty"):
            validate_signer_identity("")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(SupplyInputError, match="must not start with '-'"):
            validate_signer_identity("-evil")


class TestValidateSignerIdentityRegexp:
    def test_simple_regex_accepted(self) -> None:
        assert (
            validate_signer_identity_regexp(r"^https://github\.com/.*$")
            == r"^https://github\.com/.*$"
        )

    def test_rejects_whitespace_in_regex(self) -> None:
        with pytest.raises(SupplyInputError, match="whitespace"):
            validate_signer_identity_regexp("foo bar")


class TestValidateSignerIssuer:
    def test_https_url_accepted(self) -> None:
        assert (
            validate_signer_issuer(
                "https://token.actions.githubusercontent.com"
            )
            == "https://token.actions.githubusercontent.com"
        )

    def test_http_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="scheme must be https"):
            validate_signer_issuer("http://issuer.example.com")

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="userinfo"):
            validate_signer_issuer("https://u:p@issuer.example.com")

    def test_query_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="query"):
            validate_signer_issuer("https://issuer.example.com?x=1")

    def test_fragment_rejected(self) -> None:
        with pytest.raises(SupplyInputError, match="fragment"):
            validate_signer_issuer("https://issuer.example.com#x")


class TestClassifyLockfile:
    def test_package_lock_classified_as_npm(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "package-lock.json"
        f.write_text("{}")
        t = classify_lockfile(str(f))
        assert t.ecosystem == "npm"

    def test_pipfile_lock_classified_as_pip(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "Pipfile.lock"
        f.write_text("{}")
        t = classify_lockfile(str(f))
        assert t.ecosystem == "pip"

    def test_uv_lock_classified_as_uv(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "uv.lock"
        f.write_text("")
        t = classify_lockfile(str(f))
        assert t.ecosystem == "uv"

    def test_unsupported_lockfile_rejected(
        self, tmp_path: Path
    ) -> None:
        # Cargo.lock — out-of-scope for Phase 2-Q.
        f = tmp_path / "Cargo.lock"
        f.write_text("")
        with pytest.raises(SupplyInputError, match="unsupported lockfile"):
            classify_lockfile(str(f))

    def test_non_existing_path_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SupplyInputError, match="does not exist"):
            classify_lockfile(str(tmp_path / "missing.lock"))

    def test_symlink_rejected(self, tmp_path: Path) -> None:
        real = tmp_path / "real.json"
        real.write_text("{}")
        link = tmp_path / "package-lock.json"
        link.symlink_to(real)
        with pytest.raises(SupplyInputError, match="symlink"):
            classify_lockfile(str(link))

    def test_scan_root_confinement_enforced(
        self, tmp_path: Path
    ) -> None:
        """Codex Phase 2-Q design review carry-over: config-origin
        lockfile paths must live under the scan root."""
        outside_dir = tmp_path.parent / f"outside-{tmp_path.name}"
        outside_dir.mkdir(exist_ok=True)
        try:
            outside_lockfile = outside_dir / "package-lock.json"
            outside_lockfile.write_text("{}")
            with pytest.raises(SupplyInputError, match="escapes the scan root"):
                classify_lockfile(
                    str(outside_lockfile), scan_root=tmp_path
                )
        finally:
            if outside_dir.exists():
                outside_lockfile.unlink(missing_ok=True)
                outside_dir.rmdir()

    def test_no_scan_root_allows_anywhere(
        self, tmp_path: Path
    ) -> None:
        """CLI-origin lockfile (scan_root=None) bypasses
        confinement."""
        outside_dir = tmp_path.parent / f"cli-{tmp_path.name}"
        outside_dir.mkdir(exist_ok=True)
        try:
            outside = outside_dir / "package-lock.json"
            outside.write_text("{}")
            t = classify_lockfile(str(outside), scan_root=None)
            assert t.ecosystem == "npm"
        finally:
            if outside_dir.exists():
                outside.unlink(missing_ok=True)
                outside_dir.rmdir()
