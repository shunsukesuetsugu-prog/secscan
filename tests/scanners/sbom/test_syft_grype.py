"""Phase 2-N: argv builder + Grype JSON parser unit tests.

Pure tests — no docker invocation. Verifies the security-critical
argv shapes (cap-drop, mount layout, ``--`` separator, RO/RW
volume distinctions) and the Grype output schema parsing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.models import Severity
from secscan.scanners.sbom._pinned import (
    DEFAULT_GRYPE_IMAGE,
    DEFAULT_SYFT_IMAGE,
    GRYPE_CACHE_VOLUME,
)
from secscan.scanners.sbom.grype import (
    SBOM_FILE_MOUNT,
    GrypeInvocation,
    build_db_seed_argv,
    classify_grype_exit,
    parse_grype_report,
)
from secscan.scanners.sbom.grype import (
    build_argv as grype_argv,
)
from secscan.scanners.sbom.syft import (
    SBOM_OUT_PATH,
    SyftInvocation,
    classify_syft_exit,
)
from secscan.scanners.sbom.syft import (
    build_argv as syft_argv,
)
from secscan.scanners.sbom.validators import (
    DirectoryTarget,
    ImageTarget,
    SbomInputError,
)

_VALID_DIGEST = "a" * 64
_VALID_REF = f"alpine@sha256:{_VALID_DIGEST}"
_INTER_VOL = "secscan-sbom-" + "b" * 32


# ---------------------------------------------------------------------------
# Syft argv
# ---------------------------------------------------------------------------


class TestSyftArgvDirectoryTarget:
    def test_basic_shape(self, tmp_path: Path) -> None:
        d = tmp_path / "venv"
        d.mkdir()
        argv = syft_argv(
            SyftInvocation(
                target=DirectoryTarget(path=d), intermediate_volume=_INTER_VOL
            )
        )
        # Safety flags
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=bridge" in argv
        # Intermediate volume mount (RW — Syft writes the SBOM here).
        v_idx = argv.index("-v")
        assert argv[v_idx + 1] == f"{_INTER_VOL}:/work"
        # Source dir bind mounted RO — find the bind for /scan:ro.
        scan_mount = next(
            (
                t
                for t in argv
                if isinstance(t, str) and t.endswith(":/scan:ro")
            ),
            None,
        )
        assert scan_mount is not None
        # ``--`` separator before scanner image.
        sep = argv.index("--")
        assert argv[sep + 1] == DEFAULT_SYFT_IMAGE
        # Syft target uses the dir: scheme so Syft itself can't
        # confuse a directory for an image ref.
        assert argv[sep + 2] == "dir:/scan"
        # Output spec is explicit (Codex MUST-FIX #3).
        assert "-o" in argv
        assert argv[argv.index("-o") + 1] == f"cyclonedx-json={SBOM_OUT_PATH}"

    def test_directory_target_does_not_add_platform_flag(
        self, tmp_path: Path
    ) -> None:
        """``--platform`` is only meaningful for image targets
        (multi-arch index resolution). A dir scan has no platform
        notion, so emitting --platform would be misleading."""
        d = tmp_path / "venv"
        d.mkdir()
        argv = syft_argv(
            SyftInvocation(
                target=DirectoryTarget(path=d), intermediate_volume=_INTER_VOL
            )
        )
        assert "--platform" not in argv


class TestSyftArgvImageTarget:
    def test_uses_registry_scheme(self) -> None:
        argv = syft_argv(
            SyftInvocation(
                target=ImageTarget(ref=_VALID_REF),
                intermediate_volume=_INTER_VOL,
            )
        )
        sep = argv.index("--")
        # registry: scheme forces Syft to fetch from the registry,
        # not check the docker daemon.
        assert argv[sep + 2] == f"registry:{_VALID_REF}"

    def test_platform_forwarded_to_syft_cli(self) -> None:
        """``--platform`` is forwarded AFTER the syft target and
        BEFORE the -o flag (Syft CLI accepts that ordering)."""
        argv = syft_argv(
            SyftInvocation(
                target=ImageTarget(ref=_VALID_REF),
                intermediate_volume=_INTER_VOL,
            )
        )
        assert "--platform" in argv
        plat_idx = argv.index("--platform")
        # MUST appear AFTER the ``--`` docker separator, on the
        # Syft side of the argv — not on the docker side.
        assert plat_idx > argv.index("--")

    def test_invalid_volume_raises(self) -> None:
        with pytest.raises(SbomInputError):
            syft_argv(
                SyftInvocation(
                    target=ImageTarget(ref=_VALID_REF),
                    intermediate_volume="bad-name",
                )
            )


# ---------------------------------------------------------------------------
# Grype argv
# ---------------------------------------------------------------------------


class TestGrypeArgvFromIntermediateVolume:
    def test_basic_shape(self) -> None:
        argv = grype_argv(
            GrypeInvocation(intermediate_volume=_INTER_VOL)
        )
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=bridge" in argv
        # Volume mounted READ-ONLY here — Syft wrote it; Grype
        # only reads.
        v_idx = argv.index("-v")
        assert argv[v_idx + 1] == f"{_INTER_VOL}:/work:ro"
        # ``--`` separator before scanner image.
        sep = argv.index("--")
        assert argv[sep + 1] == DEFAULT_GRYPE_IMAGE
        assert argv[sep + 2] == f"sbom:{SBOM_OUT_PATH}"
        assert "-o" in argv
        assert argv[argv.index("-o") + 1] == "json"

    def test_grype_never_redirects_home_or_tmpdir_to_work(self) -> None:
        """Codex Phase 2-N diff review contract test: Grype must
        NOT have HOME=/work or TMPDIR=/work set when the /work
        mount is RO. Doing so would force Grype to attempt a write
        to the RO mount for its DB listing temp file and crash.

        This regression test pins the e2e-discovered bug so a
        future refactor that adds back the env override is caught
        by the unit tests."""
        argv = grype_argv(
            GrypeInvocation(intermediate_volume=_INTER_VOL)
        )
        joined = " ".join(argv)
        assert "HOME=/work" not in joined
        assert "TMPDIR=/work" not in joined

    def test_cache_volume_adds_db_mount_and_auto_update_false(self) -> None:
        argv = grype_argv(
            GrypeInvocation(
                intermediate_volume=_INTER_VOL,
                cache_volume=GRYPE_CACHE_VOLUME,
            )
        )
        cache_mount = next(
            (t for t in argv if t.startswith(f"{GRYPE_CACHE_VOLUME}:")),
            None,
        )
        assert cache_mount is not None
        assert cache_mount.endswith(":ro")  # cache always RO at scan time
        # Auto-update OFF so the seeded DB is used as-is.
        assert "GRYPE_DB_AUTO_UPDATE=false" in argv


class TestGrypeArgvFromSbomFile:
    def test_file_mount_is_readonly(self, tmp_path: Path) -> None:
        f = tmp_path / "sbom.cdx.json"
        f.write_text("{}")
        argv = grype_argv(
            GrypeInvocation(sbom_file_path=str(f))
        )
        mount = next(
            (t for t in argv if isinstance(t, str) and t.endswith(":ro")),
            None,
        )
        assert mount is not None
        assert mount.startswith(f"{f}:") or mount.startswith(f"{f.resolve()}:")
        assert "intermediate" not in " ".join(argv)
        # Grype argument uses the in-container path.
        sep = argv.index("--")
        assert argv[sep + 2] == f"sbom:{SBOM_FILE_MOUNT}"

    def test_rejects_both_inputs(self) -> None:
        with pytest.raises(SbomInputError, match="exactly one"):
            grype_argv(
                GrypeInvocation(
                    intermediate_volume=_INTER_VOL,
                    sbom_file_path="/tmp/sbom.cdx.json",
                )
            )

    def test_rejects_neither_input(self) -> None:
        with pytest.raises(SbomInputError, match="exactly one"):
            grype_argv(GrypeInvocation())

    def test_rejects_path_with_colon(self) -> None:
        # Phase 2-W: a colon outside the Windows drive-letter
        # position is rejected by ``path_charset_check`` because
        # it would collide with the docker -v separator.
        with pytest.raises(SbomInputError, match="forbidden character"):
            grype_argv(
                GrypeInvocation(sbom_file_path="/tmp/sb:om.json")
            )


# ---------------------------------------------------------------------------
# DB seed argv
# ---------------------------------------------------------------------------


class TestBuildDbSeedArgv:
    def test_seed_mounts_rw(self) -> None:
        argv = build_db_seed_argv(cache_volume=GRYPE_CACHE_VOLUME)
        v_idx = argv.index("-v")
        # RW mount — only the seed step writes to the cache volume.
        assert argv[v_idx + 1] == f"{GRYPE_CACHE_VOLUME}:/.cache/grype/db"
        assert ":ro" not in argv[v_idx + 1]
        # The argv ends with ``db update`` so it doesn't try to
        # scan anything.
        assert argv[-2:] == ["db", "update"]

    def test_rejects_missing_volume(self) -> None:
        with pytest.raises(SbomInputError, match="must not be empty"):
            build_db_seed_argv(cache_volume="")


# ---------------------------------------------------------------------------
# Grype JSON parser
# ---------------------------------------------------------------------------


def _grype_report(matches: list[dict]) -> bytes:
    return json.dumps(
        {
            "matches": matches,
            "descriptor": {"name": "grype", "version": "0.99.0"},
        }
    ).encode()


_SAMPLE_MATCH: dict[str, object] = {
    "vulnerability": {
        "id": "CVE-2022-37434",
        "severity": "Critical",
        "description": "zlib heap-based buffer over-read",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37434"],
        "cwes": ["CWE-787"],
        "fix": {"versions": ["1.2.12-r1"], "state": "fixed"},
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2022-37434",
    },
    "artifact": {
        "name": "zlib",
        "version": "1.2.11-r3",
        "type": "apk",
        "purl": "pkg:apk/alpine/zlib@1.2.11-r3",
    },
}


class TestParseGrypeReport:
    def test_extracts_match_into_finding(self) -> None:
        stdout = _grype_report([_SAMPLE_MATCH])
        parsed = parse_grype_report(stdout, target_label="alpine:3.10")
        assert len(parsed.findings) == 1
        f = parsed.findings[0]
        assert f.scanner == "sbom"
        assert f.rule_id == "CVE-2022-37434"
        assert f.severity == Severity.CRITICAL
        assert f.cwe == "CWE-787"
        assert "zlib 1.2.11-r3" in f.message
        assert "fixed in 1.2.12-r1" in f.message
        assert f.location is not None
        assert f.location.package == "zlib"
        assert f.location.ecosystem == "apk"
        assert f.location.file is not None
        assert f.location.file.startswith("sbom/apk/")

    def test_negligible_maps_to_info(self) -> None:
        match = json.loads(json.dumps(_SAMPLE_MATCH))
        match["vulnerability"]["severity"] = "Negligible"
        parsed = parse_grype_report(
            _grype_report([match]), target_label="x"
        )
        assert parsed.findings[0].severity == Severity.INFO

    def test_unknown_severity_falls_back(self) -> None:
        match = json.loads(json.dumps(_SAMPLE_MATCH))
        match["vulnerability"]["severity"] = "WhoKnows"
        parsed = parse_grype_report(
            _grype_report([match]), target_label="x"
        )
        assert parsed.findings[0].severity == Severity.UNKNOWN

    def test_empty_stdout_warns(self) -> None:
        parsed = parse_grype_report(b"", target_label="x")
        assert parsed.findings == ()
        assert any("empty" in w for w in parsed.warnings)

    def test_invalid_json_warns(self) -> None:
        parsed = parse_grype_report(b"not json", target_label="x")
        assert parsed.findings == ()
        assert any("not valid JSON" in w for w in parsed.warnings)

    def test_oom_cap_refuses_huge_report(self) -> None:
        huge = b"x" * (33 * 1024 * 1024)
        parsed = parse_grype_report(huge, target_label="x")
        assert parsed.findings == ()
        assert any("exceeded" in w for w in parsed.warnings)

    def test_dedup_within_one_report(self) -> None:
        """Two matches with the same CVE+pkg+version+location-label
        produce ONE Finding (the dedup key in fingerprint)."""
        stdout = _grype_report([_SAMPLE_MATCH, _SAMPLE_MATCH])
        parsed = parse_grype_report(stdout, target_label="x")
        assert len(parsed.findings) == 1

    def test_extracts_tool_version(self) -> None:
        parsed = parse_grype_report(
            _grype_report([]), target_label="x"
        )
        assert parsed.tool_version == "0.99.0"

    def test_cwe_extracted_from_description_fallback(self) -> None:
        """Grype usually emits ``cwes: []`` but the description
        sometimes contains CWE-N inline. We extract it as a
        fallback."""
        match = json.loads(json.dumps(_SAMPLE_MATCH))
        match["vulnerability"]["cwes"] = []
        match["vulnerability"]["description"] = (
            "this issue is tracked as CWE-119 in the database"
        )
        parsed = parse_grype_report(
            _grype_report([match]), target_label="x"
        )
        assert parsed.findings[0].cwe == "CWE-119"


# ---------------------------------------------------------------------------
# Exit classification
# ---------------------------------------------------------------------------


class TestClassifyExits:
    def test_syft_zero_success(self) -> None:
        ok, reason = classify_syft_exit(0, timed_out=False)
        assert ok and reason is None

    def test_syft_nonzero_failure(self) -> None:
        ok, reason = classify_syft_exit(2, timed_out=False)
        assert not ok and "syft exited with 2" in (reason or "")

    def test_syft_timeout(self) -> None:
        ok, reason = classify_syft_exit(0, timed_out=True)
        assert not ok and "timed out" in (reason or "")

    def test_grype_zero_success(self) -> None:
        ok, reason = classify_grype_exit(0, timed_out=False)
        assert ok and reason is None

    def test_grype_nonzero_failure(self) -> None:
        ok, reason = classify_grype_exit(1, timed_out=False)
        assert not ok and "exited with 1" in (reason or "")
