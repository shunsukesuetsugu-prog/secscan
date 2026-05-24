"""End-to-end tests for ConfigScanner (Trivy adapter).

Uses a FakeRunner so the tests never hit docker. Mirrors the
DAST test layout but is simpler because the config scanner only
runs one ``docker run`` per scan.
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
from secscan.scanners.config_scanner import ConfigScanner
from secscan.scanners.config_scanner._pinned import DEFAULT_TRIVY_IMAGE

_VALID_DIGEST = "1" * 64
_VALID_IMAGE = f"aquasec/trivy@sha256:{_VALID_DIGEST}"


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
        timeout_seconds: int = 300,
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


def _config(image: str = _VALID_IMAGE) -> ScanConfig:
    return ScanConfig(
        timeout_seconds=300,
        extra=MappingProxyType({"image": image}),
    )


def _trivy_report(misconfigs: list[dict[str, object]] | None = None) -> bytes:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.0"},
            "Results": [
                {
                    "Target": "deployment.yaml",
                    "Type": "kubernetes",
                    "Misconfigurations": misconfigs or [],
                }
            ],
        }
    ).encode()


class TestConfigScannerHappyPath:
    def test_findings_emitted(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        misc = [
            {
                "ID": "KSV-0017",
                "Severity": "HIGH",
                "Title": "Privileged container",
                "CauseMetadata": {"StartLine": 5},
            }
        ]
        fake_runner.push(returncode=0, stdout=_trivy_report(misc))
        outcome = ConfigScanner().scan(work_unit, fake_runner, _config())
        (finding,) = outcome.findings
        assert finding.scanner == "config"
        assert finding.rule_id == "KSV-0017"
        assert finding.severity == Severity.HIGH

    def test_argv_carries_safety_flags(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0, stdout=_trivy_report([]))
        ConfigScanner().scan(work_unit, fake_runner, _config())
        argv, _cwd, _t = fake_runner.calls[0]
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=none" in argv
        # Read-only bind mount.
        v_idx = argv.index("-v")
        assert argv[v_idx + 1].endswith(":/work:ro")
        # ``--`` separator before the image.
        assert argv.index("--") < argv.index(_VALID_IMAGE)

    def test_default_image_used_when_missing(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0, stdout=_trivy_report([]))
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType({}),  # no image key
        )
        ConfigScanner().scan(work_unit, fake_runner, cfg)
        argv, _cwd, _t = fake_runner.calls[0]
        assert DEFAULT_TRIVY_IMAGE in argv


class TestConfigScannerErrorPaths:
    def test_invalid_image_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = ConfigScanner().scan(
            work_unit, fake_runner, _config(image="aquasec/trivy:latest")
        )
        assert outcome.error is not None
        assert "digest" in outcome.error.reason.lower()
        # FakeRunner must not have been touched.
        assert fake_runner.calls == []

    def test_nonzero_exit_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(
            returncode=2, stdout=b"", stderr=b"trivy: parse error"
        )
        outcome = ConfigScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is not None
        assert "exited with 2" in outcome.error.reason

    def test_timeout_is_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0, stdout=b"", timed_out=True)
        outcome = ConfigScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is not None
        assert "timed out" in outcome.error.reason.lower()

    def test_missing_docker_raises_tool_not_found(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        from secscan.scanners.base import ToolNotFoundError

        with (
            patch.object(shutil, "which", return_value=None),
            pytest.raises(ToolNotFoundError),
        ):
            ConfigScanner().scan(work_unit, fake_runner, _config())

    def test_bad_image_type_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType({"image": 12345}),  # not a string
        )
        outcome = ConfigScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.error is not None
        assert "string" in outcome.error.reason.lower()
