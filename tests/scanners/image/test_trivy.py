"""Phase 2-M: unit tests for the Trivy image-mode helpers.

Mirrors the structure of ``tests/scanners/config_scanner/test_trivy.py``.
All tests run without docker — the validators, argv builder, and
report parser are pure functions.
"""

from __future__ import annotations

import json

import pytest

from secscan.models import Severity
from secscan.scanners.image._pinned import TRIVY_CACHE_VOLUME
from secscan.scanners.image.trivy import (
    DEFAULT_TARGET_PLATFORM,
    DEFAULT_TRIVY_IMAGE,
    ImageInputError,
    TrivyImageInvocation,
    build_argv,
    build_db_seed_argv,
    classify_trivy_image_exit,
    parse_trivy_image_report,
    validate_cache_volume,
    validate_image_ref,
    validate_platform,
)

_VALID_DIGEST = "0" * 63 + "1"
_VALID_REF = f"alpine@sha256:{_VALID_DIGEST}"
_VALID_TAGGED_REF = f"alpine:3.10@sha256:{_VALID_DIGEST}"


# ---------------------------------------------------------------------------
# validate_image_ref
# ---------------------------------------------------------------------------


class TestValidateImageRef:
    def test_accepts_tagged_digest_ref(self) -> None:
        assert validate_image_ref(_VALID_TAGGED_REF) == _VALID_TAGGED_REF

    def test_accepts_untagged_digest_ref(self) -> None:
        assert validate_image_ref(_VALID_REF) == _VALID_REF

    def test_strips_surrounding_whitespace(self) -> None:
        assert validate_image_ref(f"  {_VALID_REF}  ") == _VALID_REF

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ImageInputError, match="must be a string"):
            validate_image_ref(123)  # type: ignore[arg-type]

    def test_rejects_empty(self) -> None:
        with pytest.raises(ImageInputError, match="must not be empty"):
            validate_image_ref("")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(ImageInputError, match="must not start with '-'"):
            validate_image_ref(f"-evil@sha256:{_VALID_DIGEST}")

    def test_rejects_whitespace(self) -> None:
        with pytest.raises(ImageInputError, match="whitespace"):
            validate_image_ref(f"alpine @sha256:{_VALID_DIGEST}")

    def test_rejects_tag_only_no_digest(self) -> None:
        # Phase 2-M design pin: digest is mandatory. Tag-only refs
        # would re-introduce the reproducibility hole the whole
        # validator was built to close.
        with pytest.raises(ImageInputError, match="digest pinning"):
            validate_image_ref("alpine:3.10")

    def test_rejects_short_digest(self) -> None:
        with pytest.raises(ImageInputError, match="digest pinning"):
            validate_image_ref("alpine@sha256:0123")

    def test_rejects_uppercase_digest(self) -> None:
        with pytest.raises(ImageInputError, match="digest pinning"):
            validate_image_ref(f"alpine@sha256:{('A' * 64)}")

    def test_label_appears_in_error(self) -> None:
        """The same validator is reused for the scanner image and
        each target; the ``label`` parameter must surface in the
        error so the operator knows which input was bad."""
        with pytest.raises(ImageInputError, match="scanner_image"):
            validate_image_ref("", label="scanner_image")


# ---------------------------------------------------------------------------
# validate_platform
# ---------------------------------------------------------------------------


class TestValidatePlatform:
    def test_accepts_linux_amd64(self) -> None:
        assert validate_platform("linux/amd64") == "linux/amd64"

    def test_accepts_linux_arm64(self) -> None:
        assert validate_platform("linux/arm64") == "linux/arm64"

    def test_accepts_linux_arm_v7(self) -> None:
        assert validate_platform("linux/arm/v7") == "linux/arm/v7"

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ImageInputError, match="must be a string"):
            validate_platform(42)  # type: ignore[arg-type]

    def test_rejects_empty(self) -> None:
        with pytest.raises(ImageInputError, match="must not be empty"):
            validate_platform("")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(ImageInputError, match="must not start with '-'"):
            validate_platform("-privileged")

    def test_rejects_no_slash(self) -> None:
        with pytest.raises(ImageInputError, match="not a valid docker platform"):
            validate_platform("linux")

    def test_rejects_whitespace(self) -> None:
        with pytest.raises(ImageInputError, match="not a valid docker platform"):
            validate_platform("linux /amd64")

    def test_rejects_too_many_segments(self) -> None:
        with pytest.raises(ImageInputError, match="not a valid docker platform"):
            validate_platform("linux/amd64/v3/foo")


# ---------------------------------------------------------------------------
# validate_cache_volume
# ---------------------------------------------------------------------------


class TestValidateCacheVolume:
    def test_accepts_named_volume(self) -> None:
        assert validate_cache_volume(TRIVY_CACHE_VOLUME) == TRIVY_CACHE_VOLUME

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ImageInputError, match="must be a string"):
            validate_cache_volume(None)  # type: ignore[arg-type]

    def test_rejects_empty(self) -> None:
        with pytest.raises(ImageInputError, match="must not be empty"):
            validate_cache_volume("")

    def test_rejects_path_like(self) -> None:
        """A path-like value would be interpreted by docker as a bind
        mount source — completely different security posture than a
        named volume. Reject."""
        with pytest.raises(ImageInputError, match="must be a docker volume name"):
            validate_cache_volume("/tmp/trivy-cache")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(ImageInputError, match="must be a docker volume name"):
            validate_cache_volume("-cache")

    def test_rejects_bad_charset(self) -> None:
        with pytest.raises(ImageInputError, match="charset"):
            validate_cache_volume("cache$with$dollar")


# ---------------------------------------------------------------------------
# build_argv
# ---------------------------------------------------------------------------


class TestBuildArgv:
    def _invocation(self, **overrides: object) -> TrivyImageInvocation:
        base = {
            "target_image": _VALID_REF,
            "scanner_image": DEFAULT_TRIVY_IMAGE,
            "platform": DEFAULT_TARGET_PLATFORM,
            "cache_volume": "",
        }
        base.update(overrides)
        return TrivyImageInvocation(**base)  # type: ignore[arg-type]

    def test_basic_argv_shape(self) -> None:
        argv = build_argv(self._invocation())
        assert argv[0] == "docker"
        assert argv[1] == "run"
        assert "--rm" in argv
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=bridge" in argv

    def test_platform_appears_on_both_layers(self) -> None:
        """``--platform`` must appear once on the docker layer (before
        ``--``) and once on the Trivy CLI layer (after the scanner
        image) so multi-arch index digests resolve identically."""
        argv = build_argv(self._invocation())
        sep_idx = argv.index("--")
        platform_positions = [i for i, t in enumerate(argv) if t == "--platform"]
        assert len(platform_positions) == 2
        assert platform_positions[0] < sep_idx
        assert platform_positions[1] > sep_idx

    def test_separator_before_scanner_image(self) -> None:
        """``--`` must immediately precede the scanner image so it
        can never be flag-interpreted by docker."""
        argv = build_argv(self._invocation())
        sep_idx = argv.index("--")
        assert argv[sep_idx + 1] == DEFAULT_TRIVY_IMAGE

    def test_target_image_is_last(self) -> None:
        argv = build_argv(self._invocation())
        assert argv[-1] == _VALID_REF

    def test_no_volume_means_no_v_flag(self) -> None:
        argv = build_argv(self._invocation(cache_volume=""))
        assert "-v" not in argv
        assert "--skip-db-update" not in argv

    def test_volume_emits_read_only_mount(self) -> None:
        argv = build_argv(self._invocation(cache_volume=TRIVY_CACHE_VOLUME))
        assert "-v" in argv
        v_idx = argv.index("-v")
        # Mount spec must end with ``:ro`` so a buggy scan can't
        # corrupt the seeded DB.
        mount = argv[v_idx + 1]
        assert mount.endswith(":/root/.cache/trivy:ro")
        assert mount.startswith(f"{TRIVY_CACHE_VOLUME}:")

    def test_volume_adds_skip_db_update(self) -> None:
        argv = build_argv(self._invocation(cache_volume=TRIVY_CACHE_VOLUME))
        assert "--skip-db-update" in argv

    def test_invalid_target_raises_at_argv_build(self) -> None:
        with pytest.raises(ImageInputError):
            build_argv(self._invocation(target_image="alpine:3.10"))

    def test_invalid_platform_raises_at_argv_build(self) -> None:
        with pytest.raises(ImageInputError):
            build_argv(self._invocation(platform="-evil"))

    def test_invalid_volume_raises_at_argv_build(self) -> None:
        with pytest.raises(ImageInputError):
            build_argv(self._invocation(cache_volume="/etc/passwd"))

    def test_extra_argv_appended_before_target(self) -> None:
        argv = build_argv(
            self._invocation(extra_argv=("--ignore-unfixed",))
        )
        assert argv[-2] == "--ignore-unfixed"
        assert argv[-1] == _VALID_REF

    def test_extra_argv_with_control_chars_rejected(self) -> None:
        with pytest.raises(ImageInputError, match="control characters"):
            build_argv(
                self._invocation(extra_argv=("--bad\nflag",))
            )


# ---------------------------------------------------------------------------
# build_db_seed_argv
# ---------------------------------------------------------------------------


class TestBuildDbSeedArgv:
    def test_basic_shape(self) -> None:
        argv = build_db_seed_argv(cache_volume=TRIVY_CACHE_VOLUME)
        assert "--download-db-only" in argv
        # No --skip-db-update on the seed call — that would defeat
        # the purpose.
        assert "--skip-db-update" not in argv
        # No target image on the seed call.
        assert argv[-1] == "--download-db-only"
        assert argv[-2] == "image"
        # The seed mount is RW (no ``:ro``) — this is the only path
        # that writes to the cache volume.
        v_idx = argv.index("-v")
        assert argv[v_idx + 1] == (
            f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy"
        )

    def test_rejects_missing_volume(self) -> None:
        with pytest.raises(ImageInputError, match="must not be empty"):
            build_db_seed_argv(cache_volume="")

    def test_rejects_bad_platform(self) -> None:
        with pytest.raises(ImageInputError):
            build_db_seed_argv(
                cache_volume=TRIVY_CACHE_VOLUME, platform="-priv"
            )


# ---------------------------------------------------------------------------
# parse_trivy_image_report
# ---------------------------------------------------------------------------


def _report_with(results: list[dict]) -> bytes:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.0"},
            "ArtifactName": "alpine:3.10",
            "Results": results,
        }
    ).encode("utf-8")


class TestParseTrivyImageReport:
    def test_extracts_vulnerability_into_finding(self) -> None:
        stdout = _report_with(
            [
                {
                    "Target": "alpine:3.10 (alpine 3.10.9)",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-3711",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1k-r0",
                            "FixedVersion": "1.1.1l-r0",
                            "Severity": "CRITICAL",
                            "Title": "openssl: SM2 decryption buffer overflow",
                            "Description": "A malicious sender ...",
                            "PrimaryURL": "https://avd.aquasec.com/x",
                            "References": [
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-3711",
                            ],
                            "CweIDs": ["CWE-787"],
                        }
                    ],
                }
            ]
        )
        parsed = parse_trivy_image_report(stdout, target_image=_VALID_REF)
        assert len(parsed.findings) == 1
        f = parsed.findings[0]
        assert f.rule_id == "CVE-2021-3711"
        assert f.severity == Severity.CRITICAL
        assert f.cwe == "CWE-787"
        assert "openssl 1.1.1k-r0" in f.message
        assert "fixed in 1.1.1l-r0" in f.message
        assert f.location is not None
        assert f.location.package == "openssl"
        assert f.location.file is not None
        assert f.location.file.startswith("image/os-pkgs/")

    def test_empty_stdout_warns(self) -> None:
        parsed = parse_trivy_image_report(b"", target_image=_VALID_REF)
        assert parsed.findings == ()
        assert any("empty" in w for w in parsed.warnings)

    def test_invalid_json_warns(self) -> None:
        parsed = parse_trivy_image_report(
            b"<not json>", target_image=_VALID_REF
        )
        assert parsed.findings == ()
        assert any("not valid JSON" in w for w in parsed.warnings)

    def test_oom_cap_refuses_huge_report(self) -> None:
        # Build a stdout > 32 MiB. Memory cost OK because Python
        # strings of NUL bytes are cheap.
        huge = b"x" * (33 * 1024 * 1024)
        parsed = parse_trivy_image_report(huge, target_image=_VALID_REF)
        assert parsed.findings == ()
        assert any("exceeded" in w for w in parsed.warnings)

    def test_unknown_severity_falls_back(self) -> None:
        stdout = _report_with(
            [
                {
                    "Target": "alpine",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-X",
                            "PkgName": "foo",
                            "InstalledVersion": "1.0",
                            "Severity": "WAT",
                        }
                    ],
                }
            ]
        )
        parsed = parse_trivy_image_report(stdout, target_image=_VALID_REF)
        assert parsed.findings[0].severity == Severity.UNKNOWN

    def test_deduplicates_same_vuln_in_same_pkg(self) -> None:
        """Trivy can report the same CVE in multiple Results entries
        (e.g. once under os-pkgs and once under language-pkgs if the
        same package appears in both layers). The parser dedups so
        the operator doesn't see double-counted findings."""
        vuln = {
            "VulnerabilityID": "CVE-2021-3711",
            "PkgName": "openssl",
            "InstalledVersion": "1.1.1k-r0",
            "Severity": "HIGH",
        }
        stdout = _report_with(
            [
                {
                    "Target": "alpine",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [vuln],
                },
                {
                    "Target": "alpine",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [vuln],
                },
            ]
        )
        parsed = parse_trivy_image_report(stdout, target_image=_VALID_REF)
        assert len(parsed.findings) == 1

    def test_strips_non_printable_in_target(self) -> None:
        """A tampered Trivy report with NUL/newline in the Target
        field must not propagate that into Finding.location.file."""
        stdout = _report_with(
            [
                {
                    "Target": "alpine\x00evil\nthing",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-X",
                            "PkgName": "foo",
                            "InstalledVersion": "1.0",
                            "Severity": "LOW",
                        }
                    ],
                }
            ]
        )
        parsed = parse_trivy_image_report(stdout, target_image=_VALID_REF)
        assert parsed.findings[0].location is not None
        assert "\n" not in (parsed.findings[0].location.file or "")
        assert "\x00" not in (parsed.findings[0].location.file or "")

    def test_extracts_tool_version(self) -> None:
        stdout = _report_with([])
        parsed = parse_trivy_image_report(stdout, target_image=_VALID_REF)
        assert parsed.tool_version == "0.70.0"


# ---------------------------------------------------------------------------
# classify_trivy_image_exit
# ---------------------------------------------------------------------------


class TestClassifyTrivyImageExit:
    def test_zero_is_success(self) -> None:
        ok, reason = classify_trivy_image_exit(0, timed_out=False)
        assert ok and reason is None

    def test_nonzero_is_failure(self) -> None:
        ok, reason = classify_trivy_image_exit(2, timed_out=False)
        assert not ok and reason is not None and "exited with 2" in reason

    def test_timeout_wins_over_returncode(self) -> None:
        ok, reason = classify_trivy_image_exit(0, timed_out=True)
        assert not ok and reason is not None and "timed out" in reason
