"""End-to-end tests for SbomScanner (Syft + Grype adapter).

FakeRunner scripts the docker subprocess calls so the tests cover
the full pipeline lifecycle (volume create → Syft → Grype → volume
rm) without ever invoking docker.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

from secscan.models import ScanConfig, Severity, WorkUnit
from secscan.runner import CommandResult
from secscan.scanners.sbom import SbomScanner

_VALID_DIGEST_A = "a" * 64
_VALID_DIGEST_B = "b" * 64
_IMAGE_A = f"alpine@sha256:{_VALID_DIGEST_A}"
_IMAGE_B = f"debian@sha256:{_VALID_DIGEST_B}"


@dataclass
class FakeRunner:
    responses: list[CommandResult] = field(default_factory=list)
    calls: list[tuple[tuple[str, ...], Path, int]] = field(default_factory=list)

    def push(
        self,
        *,
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        timed_out: bool = False,
    ) -> None:
        self.responses.append(
            CommandResult(
                argv=(),
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=0.01,
                timed_out=timed_out,
            )
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int = 900,
    ) -> CommandResult:
        self.calls.append((tuple(argv), cwd, timeout_seconds))
        if not self.responses:
            raise AssertionError(
                f"FakeRunner ran out of scripted responses for argv={list(argv)}"
            )
        result = self.responses.pop(0)
        return CommandResult(
            argv=tuple(argv),
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=result.duration_seconds,
            timed_out=result.timed_out,
        )


@pytest.fixture()
def fake_runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture()
def work_unit(tmp_path: Path) -> WorkUnit:
    return WorkUnit(root=tmp_path)


@pytest.fixture(autouse=True)
def pretend_docker_installed() -> Iterator[None]:
    with patch.object(shutil, "which", return_value="/usr/bin/docker"):
        yield


def _config(
    *targets: str,
    confine: bool = True,
    cache_volume: str = "",
) -> ScanConfig:
    """Test helper. ``confine=True`` (default) routes targets
    through ``config_targets`` (always confined). ``confine=False``
    routes them through ``cli_targets`` with the unconfine flag
    set — mirroring how the real CLI populates these fields."""
    if confine:
        extra: dict[str, object] = {
            "targets": tuple(targets),
            "cli_targets": (),
            "unconfine_cli_targets": False,
            "cache_volume": cache_volume,
        }
    else:
        extra = {
            "targets": (),
            "cli_targets": tuple(targets),
            "unconfine_cli_targets": True,
            "cache_volume": cache_volume,
        }
    return ScanConfig(
        timeout_seconds=900,
        extra=MappingProxyType(extra),
    )


def _grype_report(matches: list[dict]) -> bytes:
    return json.dumps(
        {
            "matches": matches,
            "descriptor": {"name": "grype", "version": "0.99.0"},
        }
    ).encode()


_SAMPLE_MATCH = {
    "vulnerability": {
        "id": "CVE-2022-37434",
        "severity": "Critical",
        "description": "zlib over-read",
    },
    "artifact": {"name": "zlib", "version": "1.2.11-r3", "type": "apk"},
}


class TestSbomScannerOptIn:
    def test_no_targets_returns_noop(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = SbomScanner().scan(work_unit, fake_runner, _config())
        assert outcome.findings == ()
        assert outcome.warnings == ()
        assert outcome.error is None
        assert fake_runner.calls == []


class TestSbomScannerImageTargetPipeline:
    def test_full_pipeline_invokes_create_syft_grype_rm(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        # 1. docker volume create
        fake_runner.push(returncode=0)
        # 2. syft
        fake_runner.push(returncode=0)
        # 3. grype
        fake_runner.push(
            returncode=0, stdout=_grype_report([_SAMPLE_MATCH])
        )
        # 4. docker volume rm (in finally)
        fake_runner.push(returncode=0)
        outcome = SbomScanner().scan(
            work_unit, fake_runner, _config(_IMAGE_A)
        )
        # One finding came through.
        (finding,) = outcome.findings
        assert finding.scanner == "sbom"
        assert finding.rule_id == "CVE-2022-37434"
        assert finding.severity == Severity.CRITICAL

        # Pipeline shape:
        assert len(fake_runner.calls) == 4
        create_argv = fake_runner.calls[0][0]
        syft_argv = fake_runner.calls[1][0]
        grype_argv = fake_runner.calls[2][0]
        rm_argv = fake_runner.calls[3][0]
        assert create_argv[:3] == ("docker", "volume", "create")
        # Syft argv contains registry:image and write-RW volume
        assert any(t.startswith("secscan-sbom-") for t in syft_argv)
        assert any(t == f"registry:{_IMAGE_A}" for t in syft_argv)
        # Grype mounts volume RO
        assert any(
            isinstance(t, str) and t.endswith(":/work:ro") for t in grype_argv
        )
        # Cleanup
        assert rm_argv[:4] == ("docker", "volume", "rm", "-f")

    def test_volume_rm_runs_even_after_syft_failure(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """A Syft crash must not leak the named volume."""
        fake_runner.push(returncode=0)  # create
        fake_runner.push(
            returncode=2, stderr=b"syft: oh no"
        )  # syft fails
        fake_runner.push(returncode=0)  # volume rm (finally)
        outcome = SbomScanner().scan(
            work_unit, fake_runner, _config(_IMAGE_A)
        )
        assert outcome.error is not None
        assert "syft exited with 2" in outcome.error.reason
        # The volume rm MUST have run.
        rm_argv = fake_runner.calls[-1][0]
        assert rm_argv[:4] == ("docker", "volume", "rm", "-f")

    def test_volume_create_failure_skips_syft(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(
            returncode=125, stderr=b"docker volume create failed"
        )
        # The scanner still runs the finally block (volume rm). We
        # need a response for the rm even though it's effectively
        # a no-op against a non-existent volume.
        fake_runner.push(returncode=0)
        outcome = SbomScanner().scan(
            work_unit, fake_runner, _config(_IMAGE_A)
        )
        assert outcome.error is not None
        assert "intermediate volume" in outcome.error.reason
        # Syft and Grype never ran.
        assert len(fake_runner.calls) == 2


class TestSbomScannerSbomFileTarget:
    def test_skips_syft_runs_grype_only(
        self,
        tmp_path: Path,
        fake_runner: FakeRunner,
    ) -> None:
        # SBOM file lives INSIDE the scan root so confine-to-scan-root
        # is satisfied.
        sbom = tmp_path / "my.cdx.json"
        sbom.write_text(json.dumps({"bomFormat": "CycloneDX"}))
        wu = WorkUnit(root=tmp_path)
        # Only one docker call expected: Grype (no volume create/rm,
        # no Syft).
        fake_runner.push(
            returncode=0, stdout=_grype_report([_SAMPLE_MATCH])
        )
        outcome = SbomScanner().scan(
            wu, fake_runner, _config(str(sbom))
        )
        assert len(fake_runner.calls) == 1
        argv = fake_runner.calls[0][0]
        # SBOM file mounted RO.
        assert any(
            isinstance(t, str) and t.endswith(":ro") for t in argv
        )
        # Sbom: scheme uses the in-container mount path.
        assert any(t.startswith("sbom:/sbom/") for t in argv)
        # Finding came through.
        assert len(outcome.findings) == 1


class TestSbomScannerConfigOriginAlwaysConfined:
    """Codex Phase 2-N diff review MUST-FIX (security): a
    config-supplied target is ALWAYS confined to the scan root,
    even when ``unconfine_cli_targets`` is set. This prevents an
    attacker-controlled .secscan.toml from coupling with a CLI
    flag to escape the scan root.
    """

    def test_config_target_outside_root_rejected_even_with_unconfine_flag(
        self, tmp_path: Path, fake_runner: FakeRunner
    ) -> None:
        outside = tmp_path.parent
        wu = WorkUnit(root=tmp_path)
        # Direct ScanConfig assembly to express the attack: config
        # targets escape AND unconfine flag is set.
        cfg = ScanConfig(
            timeout_seconds=900,
            extra=MappingProxyType(
                {
                    "targets": (str(outside),),  # config-origin
                    "cli_targets": (),
                    "unconfine_cli_targets": True,  # unconfine flag
                }
            ),
        )
        outcome = SbomScanner().scan(wu, fake_runner, cfg)
        assert outcome.error is not None
        assert "escapes" in outcome.error.reason
        # No docker call — fail fast.
        assert fake_runner.calls == []


class TestSbomScannerScanRootConfinement:
    def test_target_outside_scan_root_rejected_when_confined(
        self, tmp_path: Path, fake_runner: FakeRunner
    ) -> None:
        """A config-supplied directory target that escapes the scan
        root must error out BEFORE any docker call (Codex MUST-FIX
        #2)."""
        outside = tmp_path.parent
        wu = WorkUnit(root=tmp_path)
        outcome = SbomScanner().scan(
            wu, fake_runner, _config(str(outside))
        )
        assert outcome.error is not None
        assert "escapes" in outcome.error.reason
        assert fake_runner.calls == []  # no docker invocation

    def test_target_outside_scan_root_ok_when_unconfined(
        self, tmp_path: Path, fake_runner: FakeRunner
    ) -> None:
        """With ``confine_to_scan_root=False`` (CLI flag /
        operator override), targets outside the scan root are
        allowed — operator owns the choice."""
        outside_root = tmp_path.parent / f"sbom-test-{tmp_path.name}"
        outside_root.mkdir(exist_ok=True)
        try:
            wu = WorkUnit(root=tmp_path)
            # Full pipeline: create + syft + grype + rm
            fake_runner.push(returncode=0)
            fake_runner.push(returncode=0)
            fake_runner.push(returncode=0, stdout=_grype_report([]))
            fake_runner.push(returncode=0)
            outcome = SbomScanner().scan(
                wu,
                fake_runner,
                _config(str(outside_root), confine=False),
            )
            assert outcome.error is None
        finally:
            outside_root.rmdir()


class TestSbomScannerMultipleTargets:
    def test_failure_on_first_keeps_findings_from_second(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """First image target fails (syft crash), second succeeds
        and emits a finding. The failure becomes a warning; the
        second target's finding is reported."""
        # Target A: create OK, syft fails, rm OK
        fake_runner.push(returncode=0)  # create A
        fake_runner.push(returncode=2, stderr=b"syft A failed")
        fake_runner.push(returncode=0)  # rm A
        # Target B: create OK, syft OK, grype OK, rm OK
        fake_runner.push(returncode=0)  # create B
        fake_runner.push(returncode=0)  # syft B
        fake_runner.push(
            returncode=0, stdout=_grype_report([_SAMPLE_MATCH])
        )
        fake_runner.push(returncode=0)  # rm B
        outcome = SbomScanner().scan(
            work_unit, fake_runner, _config(_IMAGE_A, _IMAGE_B)
        )
        assert outcome.error is None  # findings present → warning, not error
        assert len(outcome.findings) == 1
        assert any("syft exited with 2" in w for w in outcome.warnings)


class TestSbomScannerErrorPaths:
    def test_missing_docker_raises_tool_not_found(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        from secscan.scanners.base import ToolNotFoundError

        with (
            patch.object(shutil, "which", return_value=None),
            pytest.raises(ToolNotFoundError),
        ):
            SbomScanner().scan(work_unit, fake_runner, _config(_IMAGE_A))

    def test_bad_target_returns_input_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = SbomScanner().scan(
            work_unit, fake_runner, _config("alpine:3.10")  # no digest
        )
        assert outcome.error is not None
        assert (
            "digest" in outcome.error.reason.lower()
            or "neither an existing" in outcome.error.reason.lower()
        )
        assert fake_runner.calls == []

    def test_bad_targets_type_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType({"targets": "alpine"}),
        )
        outcome = SbomScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.error is not None
        assert "list of strings" in outcome.error.reason
