"""End-to-end tests for ApifuzzScanner (Schemathesis adapter).

FakeRunner scripts the docker subprocess sequence so the tests
exercise the full pipeline lifecycle (volume create → chown →
schemathesis run → size check → extract → volume rm) without
hitting docker.
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
from secscan.scanners.apifuzz import ApifuzzScanner
from secscan.scanners.apifuzz._pinned import (
    DEFAULT_HELPER_IMAGE,
    DEFAULT_SCHEMATHESIS_IMAGE,
)

_API_URL = "https://api.example.com/v3"
_SCHEMA_URL = "https://api.example.com/v3/openapi.json"


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
        timeout_seconds: int = 1200,
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
    *,
    api_url: str = _API_URL,
    schema: str = _SCHEMA_URL,
    mode: str = "baseline",
    allow_active: bool = False,
    schema_from_cli: bool = False,
    unconfine_cli_schema: bool = False,
    headers: tuple[str, ...] = (),
    max_examples: int = 5,
    seed: int | None = 1,
    deterministic: bool = True,
    timeout_seconds: int = 1200,
) -> ScanConfig:
    return ScanConfig(
        timeout_seconds=timeout_seconds,
        extra=MappingProxyType(
            {
                "api_url": api_url,
                "schema": schema,
                "schema_from_cli": schema_from_cli,
                "unconfine_cli_schema": unconfine_cli_schema,
                "mode": mode,
                "allow_active": allow_active,
                "headers": headers,
                "scanner_image": DEFAULT_SCHEMATHESIS_IMAGE,
                "helper_image": DEFAULT_HELPER_IMAGE,
                "max_examples": max_examples,
                "seed": seed,
                "deterministic": deterministic,
                "request_timeout": 5.0,
            }
        ),
    )


_FAILURE_EVENT = {
    "ScenarioFinished": {
        "id": "scen-1",
        "suite_id": "suite-1",
        "status": "failure",
        "recorder": {
            "label": "POST /pet",
            "cases": {"c1": {"value": {}}},
            "checks": {
                "c1": [
                    {
                        "name": "not_a_server_error",
                        "status": "failure",
                        "failure_info": {
                            "failure": {
                                "type": "ServerError",
                                "message": "Server error",
                            }
                        },
                    }
                ]
            },
            "interactions": {
                "c1": {
                    "request": {
                        "method": "POST",
                        "uri": "https://api.example.com/v3/pet",
                    },
                    "response": {"status_code": 500},
                }
            },
        },
    }
}


def _ndjson_blob() -> bytes:
    return json.dumps(_FAILURE_EVENT).encode() + b"\n"


class TestApifuzzOptIn:
    def test_no_api_url_returns_noop(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = _config(api_url="", schema=_SCHEMA_URL)
        outcome = ApifuzzScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.findings == ()
        assert outcome.error is None
        assert fake_runner.calls == []

    def test_no_schema_returns_noop(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = _config(api_url=_API_URL, schema="")
        outcome = ApifuzzScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.findings == ()
        assert fake_runner.calls == []


class TestApifuzzFullPipeline:
    def test_create_chown_run_size_extract_rm_order(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        # 1. docker volume create
        fake_runner.push(returncode=0)
        # 2. helper chown
        fake_runner.push(returncode=0)
        # 3. schemathesis run (exit 1 = check failures present)
        fake_runner.push(returncode=1)
        # 4. helper wc -c (size check)
        report = _ndjson_blob()
        fake_runner.push(returncode=0, stdout=f"{len(report)} /work/report.ndjson\n".encode())
        # 5. helper cat (extract)
        fake_runner.push(returncode=0, stdout=report)
        # 6. volume rm (in finally)
        fake_runner.push(returncode=0)

        outcome = ApifuzzScanner().scan(
            work_unit, fake_runner, _config()
        )
        assert outcome.error is None
        assert len(outcome.findings) == 1
        assert outcome.findings[0].severity == Severity.HIGH

        # 6 docker calls in expected order.
        assert len(fake_runner.calls) == 6
        argvs = [c[0] for c in fake_runner.calls]
        assert argvs[0][:3] == ("docker", "volume", "create")
        # chown
        assert "chown" in argvs[1]
        # schemathesis
        assert DEFAULT_SCHEMATHESIS_IMAGE in argvs[2]
        assert "run" in argvs[2]
        # wc
        assert "wc" in argvs[3]
        # cat
        assert "cat" in argvs[4]
        # volume rm
        assert argvs[5][:4] == ("docker", "volume", "rm", "-f")

    def test_volume_rm_runs_after_schemathesis_failure(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Even if Schemathesis crashes (exit != 0/1), the volume
        rm must execute (try/finally guarantee)."""
        fake_runner.push(returncode=0)  # create
        fake_runner.push(returncode=0)  # chown
        fake_runner.push(returncode=2, stderr=b"schemathesis crashed")
        fake_runner.push(returncode=0)  # volume rm

        outcome = ApifuzzScanner().scan(
            work_unit, fake_runner, _config()
        )
        assert outcome.error is not None
        assert "schemathesis exited with 2" in outcome.error.reason
        assert fake_runner.calls[-1][0][:4] == (
            "docker",
            "volume",
            "rm",
            "-f",
        )

    def test_report_oversized_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Codex Phase 2-O design review MUST-FIX #4: the size
        check must refuse to ``cat`` a GB-sized report."""
        fake_runner.push(returncode=0)  # create
        fake_runner.push(returncode=0)  # chown
        fake_runner.push(returncode=1)  # schemathesis ran
        # wc reports a billion bytes
        fake_runner.push(
            returncode=0, stdout=b"1000000000 /work/report.ndjson\n"
        )
        # cat must NOT be called — but volume rm still must.
        fake_runner.push(returncode=0)  # volume rm

        outcome = ApifuzzScanner().scan(
            work_unit, fake_runner, _config()
        )
        assert outcome.error is not None
        assert "exceeds" in outcome.error.reason
        # Expected calls: create, chown, schemathesis, wc, volume rm
        # — NO cat call between wc and rm.
        assert len(fake_runner.calls) == 5
        assert "cat" not in fake_runner.calls[-1][0]


class TestApifuzzSecurityGates:
    def test_active_mode_without_allow_active_blocked(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Codex Phase 2-O design review MUST-FIX #2: active mode
        without the CLI-only ``--allow-active`` flag fails the
        validator BEFORE any docker call."""
        cfg = _config(mode="active", allow_active=False)
        outcome = ApifuzzScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.error is not None
        assert "second-opt-in" in outcome.error.reason
        assert fake_runner.calls == []

    def test_active_mode_with_allow_active_runs(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = _config(mode="active", allow_active=True)
        fake_runner.push(returncode=0)  # create
        fake_runner.push(returncode=0)  # chown
        fake_runner.push(returncode=0)  # schemathesis ran (no failures)
        fake_runner.push(returncode=0, stdout=b"0 /work/report.ndjson\n")  # wc
        fake_runner.push(returncode=0, stdout=b"")  # cat
        fake_runner.push(returncode=0)  # volume rm
        outcome = ApifuzzScanner().scan(work_unit, fake_runner, cfg)
        # No error — active mode allowed because allow_active=True.
        assert outcome.error is None or "second-opt-in" not in outcome.error.reason

    def test_invalid_api_url_fails_before_docker(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        cfg = _config(api_url="ftp://nope.example.com")
        outcome = ApifuzzScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.error is not None
        assert "scheme" in outcome.error.reason
        assert fake_runner.calls == []

    def test_config_schema_outside_scan_root_rejected(
        self, tmp_path: Path, fake_runner: FakeRunner
    ) -> None:
        """Codex Phase 2-N MUST-FIX carry-over: a config-supplied
        schema FILE that escapes the scan root must be refused,
        even with the CLI unconfine flag set (the CLI flag only
        applies to CLI-origin schemas)."""
        outside = tmp_path.parent / f"outside-{tmp_path.name}.yaml"
        outside.write_text("openapi")
        try:
            wu = WorkUnit(root=tmp_path)
            cfg = _config(
                schema=str(outside),
                schema_from_cli=False,  # config-origin
                unconfine_cli_schema=True,  # CLI unconfine flag IS set
            )
            outcome = ApifuzzScanner().scan(wu, fake_runner, cfg)
            assert outcome.error is not None
            assert "escapes" in outcome.error.reason
            assert fake_runner.calls == []
        finally:
            outside.unlink(missing_ok=True)

    def test_cli_schema_outside_scan_root_ok_when_unconfined(
        self, tmp_path: Path, fake_runner: FakeRunner
    ) -> None:
        outside = tmp_path.parent / f"sbom-test-{tmp_path.name}.yaml"
        outside.write_text("openapi")
        try:
            wu = WorkUnit(root=tmp_path)
            cfg = _config(
                schema=str(outside),
                schema_from_cli=True,
                unconfine_cli_schema=True,
            )
            fake_runner.push(returncode=0)  # create
            fake_runner.push(returncode=0)  # chown
            fake_runner.push(returncode=0)  # schemathesis
            fake_runner.push(returncode=0, stdout=b"0 /work/report.ndjson\n")
            fake_runner.push(returncode=0, stdout=b"")
            fake_runner.push(returncode=0)  # rm
            outcome = ApifuzzScanner().scan(wu, fake_runner, cfg)
            assert outcome.error is None
        finally:
            outside.unlink(missing_ok=True)


class TestApifuzzErrorPaths:
    def test_volume_create_failure_skips_pipeline(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(
            returncode=125, stderr=b"docker volume create denied"
        )
        fake_runner.push(returncode=0)  # rm still runs
        outcome = ApifuzzScanner().scan(
            work_unit, fake_runner, _config()
        )
        assert outcome.error is not None
        assert "intermediate volume" in outcome.error.reason
        assert len(fake_runner.calls) == 2

    def test_chown_failure_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        fake_runner.push(returncode=0)
        fake_runner.push(returncode=1, stderr=b"chown failed")
        fake_runner.push(returncode=0)  # rm
        outcome = ApifuzzScanner().scan(
            work_unit, fake_runner, _config()
        )
        assert outcome.error is not None
        assert "chown" in outcome.error.reason

    def test_missing_docker_raises(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        from secscan.scanners.base import ToolNotFoundError

        with (
            patch.object(shutil, "which", return_value=None),
            pytest.raises(ToolNotFoundError),
        ):
            ApifuzzScanner().scan(
                work_unit, fake_runner, _config()
            )
