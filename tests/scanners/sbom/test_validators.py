"""Phase 2-N: unit tests for the SBOM scanner input validators.

The validators classify ``--target`` arguments and enforce the
scan-root confinement rule. They're the security boundary between
operator input and the docker bind-mount layer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.scanners.sbom.validators import (
    MAX_SBOM_BYTES,
    DirectoryTarget,
    ImageTarget,
    SbomFileTarget,
    SbomInputError,
    assert_target_under_scan_root,
    classify_target,
    validate_cache_volume_name,
    validate_intermediate_volume_name,
    validate_platform,
)

_VALID_DIGEST = "0" * 63 + "1"
_VALID_REF = f"alpine@sha256:{_VALID_DIGEST}"


def _write_sbom(p: Path) -> Path:
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    return p


class TestClassifyTargetExistingFile:
    def test_cdx_extension_is_sbom_file(self, tmp_path: Path) -> None:
        f = _write_sbom(tmp_path / "x.cdx.json")
        t = classify_target(str(f))
        assert isinstance(t, SbomFileTarget)
        assert t.path == f.resolve()

    def test_spdx_extension_is_sbom_file(self, tmp_path: Path) -> None:
        f = _write_sbom(tmp_path / "x.spdx.json")
        assert isinstance(classify_target(str(f)), SbomFileTarget)

    def test_bare_json_extension_accepted(self, tmp_path: Path) -> None:
        f = _write_sbom(tmp_path / "report.json")
        assert isinstance(classify_target(str(f)), SbomFileTarget)

    def test_file_without_sbom_extension_rejected(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "stuff.txt"
        f.write_text("hello")
        with pytest.raises(SbomInputError, match="recognized SBOM extension"):
            classify_target(str(f))

    def test_empty_sbom_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.json"
        f.write_text("")
        with pytest.raises(SbomInputError, match="empty"):
            classify_target(str(f))

    def test_oversized_sbom_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex MUST-FIX #4: SBOM > 32 MiB must be rejected at
        validation time, not allowed to flow into Grype."""
        f = tmp_path / "huge.cdx.json"
        f.write_text("{}")
        # Patch the cap to a smaller number so we don't actually
        # write a 32 MiB file in CI.
        from secscan.scanners.sbom import validators as vmod

        monkeypatch.setattr(vmod, "MAX_SBOM_BYTES", 1, raising=True)
        with pytest.raises(SbomInputError, match="exceeds"):
            classify_target(str(f))


class TestClassifyTargetExistingDirectory:
    def test_directory_is_dir_target(self, tmp_path: Path) -> None:
        d = tmp_path / "venv"
        d.mkdir()
        t = classify_target(str(d))
        assert isinstance(t, DirectoryTarget)
        assert t.path == d.resolve()


class TestClassifyTargetNonExistingImageRef:
    def test_valid_digest_pin_is_image(self) -> None:
        t = classify_target(_VALID_REF)
        assert isinstance(t, ImageTarget)
        assert t.ref == _VALID_REF

    def test_tag_only_rejected(self) -> None:
        """Non-existing + no @sha256: → image-ref validator
        rejects it; we re-wrap the error as SbomInputError so the
        caller doesn't see ImageInputError leaking through."""
        with pytest.raises(SbomInputError, match="neither an existing"):
            classify_target("alpine:3.10")

    def test_path_with_at_sha256_in_filename_is_NOT_misclassified(
        self, tmp_path: Path
    ) -> None:
        """Codex MUST-FIX #1: a *real local file* whose name happens
        to contain ``@sha256:`` must be classified by path-first,
        NOT by substring contains. The earlier draft used a naive
        ``@sha256:`` contains check that would have misrouted this.

        Note: ':' is not allowed in our path charset, so the test
        uses a different shape — a file named like ``image-at-sha256-
        x.cdx.json`` that, under the bad classifier, could have
        been heuristically routed to image-ref. We assert it goes
        through file classification."""
        f = _write_sbom(tmp_path / "image-at-sha256-x.cdx.json")
        t = classify_target(str(f))
        assert isinstance(t, SbomFileTarget)


class TestClassifyTargetRejections:
    def test_non_string(self) -> None:
        with pytest.raises(SbomInputError, match="must be a string"):
            classify_target(123)  # type: ignore[arg-type]

    def test_empty(self) -> None:
        with pytest.raises(SbomInputError, match="must not be empty"):
            classify_target("")

    def test_leading_dash(self) -> None:
        with pytest.raises(SbomInputError, match="must not start with '-'"):
            classify_target("-foo")

    def test_symlink_top_level_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(SbomInputError, match="symlink"):
            classify_target(str(link))


class TestAssertTargetUnderScanRoot:
    def test_image_target_always_ok(self, tmp_path: Path) -> None:
        # Image targets never bind-mount, so confinement doesn't apply.
        assert_target_under_scan_root(
            ImageTarget(ref=_VALID_REF), scan_root=tmp_path
        )

    def test_path_inside_scan_root_ok(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        assert_target_under_scan_root(
            DirectoryTarget(path=sub), scan_root=tmp_path
        )

    def test_path_outside_scan_root_rejected(
        self, tmp_path: Path
    ) -> None:
        """Codex MUST-FIX #2: a config-supplied target that escapes
        the scan root must be refused. Otherwise an attacker-
        controlled .secscan.toml could trick secscan into bind-
        mounting /etc into the Syft container."""
        outside = tmp_path.parent
        with pytest.raises(SbomInputError, match="escapes the scan root"):
            assert_target_under_scan_root(
                DirectoryTarget(path=outside), scan_root=tmp_path
            )

    def test_sbom_file_inside_scan_root_ok(self, tmp_path: Path) -> None:
        f = _write_sbom(tmp_path / "sbom.cdx.json")
        assert_target_under_scan_root(
            SbomFileTarget(path=f), scan_root=tmp_path
        )

    def test_sbom_file_outside_scan_root_rejected(
        self, tmp_path: Path
    ) -> None:
        outside = tmp_path.parent / "sbom.cdx.json"
        outside.write_text("{}")
        try:
            with pytest.raises(SbomInputError, match="escapes"):
                assert_target_under_scan_root(
                    SbomFileTarget(path=outside), scan_root=tmp_path
                )
        finally:
            outside.unlink(missing_ok=True)


class TestValidatePlatform:
    def test_linux_amd64(self) -> None:
        assert validate_platform("linux/amd64") == "linux/amd64"

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(SbomInputError, match="must not start with '-'"):
            validate_platform("-privileged")

    def test_rejects_bad_shape(self) -> None:
        with pytest.raises(SbomInputError, match="not a valid docker platform"):
            validate_platform("linux")


class TestValidateIntermediateVolumeName:
    def test_accepts_expected_shape(self) -> None:
        # secrets.token_hex(16) → 32 hex chars
        name = "secscan-sbom-" + "a" * 32
        assert validate_intermediate_volume_name(name) == name

    def test_rejects_unprefixed(self) -> None:
        with pytest.raises(SbomInputError, match="secscan-sbom-"):
            validate_intermediate_volume_name("random-name-12345")

    def test_rejects_short_random(self) -> None:
        with pytest.raises(SbomInputError, match="secscan-sbom-"):
            validate_intermediate_volume_name("secscan-sbom-aaa")

    def test_rejects_non_hex(self) -> None:
        with pytest.raises(SbomInputError, match="secscan-sbom-"):
            validate_intermediate_volume_name(
                "secscan-sbom-" + "z" * 32
            )


class TestValidateCacheVolumeName:
    def test_accepts_bench_name(self) -> None:
        assert (
            validate_cache_volume_name("secscan-grype-cache")
            == "secscan-grype-cache"
        )

    def test_rejects_path_like(self) -> None:
        with pytest.raises(SbomInputError, match="must be a docker volume"):
            validate_cache_volume_name("/tmp/grype-cache")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(SbomInputError, match="must be a docker volume"):
            validate_cache_volume_name("-cache")


def test_max_sbom_bytes_is_32_mib() -> None:
    """Pin the cap so a future bump is intentional, not accidental."""
    assert MAX_SBOM_BYTES == 32 * 1024 * 1024


class TestUnicodePathSupport:
    """Codex Phase 2-N diff review contract test: international
    file paths (Japanese, accented, Cyrillic, etc.) must pass the
    classifier without false rejections. Pre-fix the charset regex
    was ASCII-only, which broke the bench on the actual dev
    machine. Pin the supported character classes here."""

    def test_japanese_path_classified_as_sbom_file(
        self, tmp_path: Path
    ) -> None:
        jp_dir = tmp_path / "セキュリティツール"
        jp_dir.mkdir()
        f = _write_sbom(jp_dir / "sbom.cdx.json")
        t = classify_target(str(f))
        assert isinstance(t, SbomFileTarget)

    def test_japanese_directory_path_accepted(self, tmp_path: Path) -> None:
        jp = tmp_path / "プロジェクト"
        jp.mkdir()
        t = classify_target(str(jp))
        from secscan.scanners.sbom.validators import DirectoryTarget

        assert isinstance(t, DirectoryTarget)

    def test_path_with_colon_still_rejected(self, tmp_path: Path) -> None:
        """``:`` would break docker -v <src>:<dst> parsing — must
        stay rejected even with the Unicode-aware charset."""
        # We can't actually create a file with ':' in its name on
        # all platforms, so we test the helper directly.
        from secscan.scanners.sbom.validators import _path_charset_ok

        assert _path_charset_ok("/Users/foo/bar/プロジェクト/sbom.cdx.json")
        assert not _path_charset_ok("/Users/bad:path/sbom.cdx.json")
        assert not _path_charset_ok("/Users/bad path/sbom.cdx.json")
        assert not _path_charset_ok("/Users/bad\\path/sbom.cdx.json")
        assert not _path_charset_ok("/Users/bad\nname/sbom.cdx.json")
