"""End-to-end tests for ImageScanner (Trivy image-mode adapter).

Uses a FakeRunner so the tests never hit docker. The scanner loops
over ``[image].refs`` (one ``docker run`` per target), so a single
test can verify multi-image behaviour by scripting multiple
responses.
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
from secscan.scanners.image import ImageScanner
from secscan.scanners.image._pinned import (
    DEFAULT_TARGET_PLATFORM,
    DEFAULT_TRIVY_IMAGE,
    TRIVY_CACHE_VOLUME,
)

_VALID_DIGEST_A = "a" * 64
_VALID_DIGEST_B = "b" * 64
_TARGET_A = f"alpine@sha256:{_VALID_DIGEST_A}"
_TARGET_B = f"debian@sha256:{_VALID_DIGEST_B}"


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
        timeout_seconds: int = 600,
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
    *refs: str,
    cache_volume: str = "",
) -> ScanConfig:
    return ScanConfig(
        timeout_seconds=600,
        extra=MappingProxyType(
            {
                "refs": tuple(refs),
                "scanner_image": DEFAULT_TRIVY_IMAGE,
                "platform": DEFAULT_TARGET_PLATFORM,
                "cache_volume": cache_volume,
            }
        ),
    )


def _trivy_image_report(
    vulns: list[dict[str, object]] | None = None,
    *,
    artifact: str = "alpine:3.10",
) -> bytes:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.0"},
            "ArtifactName": artifact,
            "Results": [
                {
                    "Target": f"{artifact} (alpine 3.10.9)",
                    "Class": "os-pkgs",
                    "Vulnerabilities": vulns or [],
                }
            ],
        }
    ).encode()


_SAMPLE_VULN: dict[str, object] = {
    "VulnerabilityID": "CVE-2021-3711",
    "PkgName": "openssl",
    "InstalledVersion": "1.1.1k-r0",
    "FixedVersion": "1.1.1l-r0",
    "Severity": "CRITICAL",
    "Title": "openssl buffer overflow",
}


class TestImageScannerOptIn:
    def test_no_refs_returns_noop_outcome(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Phase 2-M design pin: no refs → no findings, no warnings,
        no docker calls. Matches the DAST opt-in invariant."""
        outcome = ImageScanner().scan(work_unit, fake_runner, _config())
        assert outcome.findings == ()
        assert outcome.warnings == ()
        assert outcome.error is None
        # Docker must never have been invoked.
        assert fake_runner.calls == []


class TestImageScannerHappyPath:
    def test_single_target_findings(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(
            returncode=0, stdout=_trivy_image_report([_SAMPLE_VULN])
        )
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config(_TARGET_A)
        )
        (finding,) = outcome.findings
        assert finding.scanner == "image"
        assert finding.rule_id == "CVE-2021-3711"
        assert finding.severity == Severity.CRITICAL

    def test_multiple_targets_each_invoked(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(
            returncode=0,
            stdout=_trivy_image_report([_SAMPLE_VULN], artifact="alpine:3.10"),
        )
        fake_runner.push(
            returncode=0,
            stdout=_trivy_image_report([], artifact="debian:bookworm"),
        )
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config(_TARGET_A, _TARGET_B)
        )
        assert len(fake_runner.calls) == 2
        # Each call's argv must end with the target image.
        assert fake_runner.calls[0][0][-1] == _TARGET_A
        assert fake_runner.calls[1][0][-1] == _TARGET_B
        # Findings aggregate across targets.
        assert len(outcome.findings) == 1

    def test_dedup_across_targets(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Two targets that emit the same CVE+pkg+version produce one
        Finding, not two. Otherwise CI dashboards double-count."""
        fake_runner.push(
            returncode=0,
            stdout=_trivy_image_report([_SAMPLE_VULN], artifact="alpine:a"),
        )
        fake_runner.push(
            returncode=0,
            stdout=_trivy_image_report([_SAMPLE_VULN], artifact="alpine:a"),
        )
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config(_TARGET_A, _TARGET_B)
        )
        assert len(outcome.findings) == 1

    def test_argv_carries_safety_flags(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0, stdout=_trivy_image_report([]))
        ImageScanner().scan(work_unit, fake_runner, _config(_TARGET_A))
        argv, _cwd, _t = fake_runner.calls[0]
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        # Phase 2-M design pin: image scanner MUST allow registry
        # outbound. ``none`` would prevent Trivy from pulling.
        assert "--network=bridge" in argv
        # Platform forwarded on both layers.
        assert argv.count("--platform") == 2
        # ``--`` separator before the scanner image.
        assert argv.index("--") < argv.index(DEFAULT_TRIVY_IMAGE)


class TestImageScannerWithCacheVolume:
    def test_volume_mount_and_skip_db_update(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0, stdout=_trivy_image_report([]))
        ImageScanner().scan(
            work_unit,
            fake_runner,
            _config(_TARGET_A, cache_volume=TRIVY_CACHE_VOLUME),
        )
        argv, _cwd, _t = fake_runner.calls[0]
        v_idx = argv.index("-v")
        # Read-only mount — only ``build_db_seed_argv`` gets RW.
        assert argv[v_idx + 1].endswith(":/root/.cache/trivy:ro")
        assert "--skip-db-update" in argv


class TestImageScannerErrorPaths:
    def test_invalid_target_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config("alpine:3.10")  # no digest
        )
        assert outcome.error is not None
        assert "digest" in outcome.error.reason.lower()
        # No docker call once an upfront validation fails.
        assert fake_runner.calls == []

    def test_nonzero_exit_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(
            returncode=2, stdout=b"", stderr=b"trivy: pull failed"
        )
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config(_TARGET_A)
        )
        assert outcome.error is not None
        assert "exited with 2" in outcome.error.reason

    def test_timeout_is_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0, stdout=b"", timed_out=True)
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config(_TARGET_A)
        )
        assert outcome.error is not None
        assert "timed out" in outcome.error.reason.lower()

    def test_partial_failure_keeps_other_findings(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Two targets: first fails, second succeeds. The failure
        becomes a warning, the success's findings make it through."""
        fake_runner.push(returncode=2, stderr=b"first target failed")
        fake_runner.push(
            returncode=0, stdout=_trivy_image_report([_SAMPLE_VULN])
        )
        outcome = ImageScanner().scan(
            work_unit, fake_runner, _config(_TARGET_A, _TARGET_B)
        )
        # First-target error becomes the leading warning, not the
        # ScanOutcome.error (because we have findings to report).
        assert outcome.error is None
        assert outcome.findings != ()
        assert any("exited with 2" in w for w in outcome.warnings)

    def test_missing_docker_raises_tool_not_found(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        from secscan.scanners.base import ToolNotFoundError

        with (
            patch.object(shutil, "which", return_value=None),
            pytest.raises(ToolNotFoundError),
        ):
            ImageScanner().scan(
                work_unit, fake_runner, _config(_TARGET_A)
            )

    def test_bad_refs_type_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType({"refs": "alpine"}),  # str not list/tuple
        )
        outcome = ImageScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.error is not None
        assert "list of strings" in outcome.error.reason


class TestBlankRefRejection:
    """Codex Phase 2-M diff review FIX_NEEDED: a blank ref (``""``
    or ``" "``) must never reach the scanner as a "valid but
    no-op" target. The whole point of the dispatcher's zero-refs
    guard is to prevent CI silent-pass.
    """

    def test_config_parser_rejects_blank_ref(self) -> None:
        """``[image].refs = [" "]`` in .secscan.toml must error at
        load time, not silently become a no-op scan exit 0."""
        from secscan.config import ConfigError, _parse_image

        with pytest.raises(ConfigError, match="must not be blank"):
            _parse_image({"refs": [" "]})

    def test_cli_strips_blank_image_args(self) -> None:
        """``secscan image --image " "`` (whitespace-only) must end
        up triggering the dispatcher's zero-refs usage error,
        NOT being passed through as a phantom target."""
        from argparse import Namespace

        from secscan.cli import _apply_cli_overrides
        from secscan.config import ImageConfig, ProjectConfig

        base = ProjectConfig(image=ImageConfig(refs=()))
        result = _apply_cli_overrides(
            base, Namespace(image_refs=["  ", ""])
        )
        # Blank entries are stripped; the merge produces an empty
        # tuple identical to the input.
        assert result.image.refs == ()


class TestPinnedImagesAgree:
    """Codex Phase 2-M design pin (item 4): the Trivy default image
    digest is duplicated between ``config_scanner/_pinned.py`` and
    ``image/_pinned.py``. Drift between them would mean two
    different Trivy versions getting pulled for the two scanners,
    breaking cache-volume reuse and surprising the operator.
    """

    def test_config_and_image_pins_match(self) -> None:
        from secscan.scanners.config_scanner._pinned import (
            DEFAULT_TRIVY_IMAGE as CONFIG_PIN,
        )

        assert CONFIG_PIN == DEFAULT_TRIVY_IMAGE
