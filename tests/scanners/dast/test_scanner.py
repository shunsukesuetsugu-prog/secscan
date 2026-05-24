"""End-to-end tests for the DastScanner adapter.

Uses a FakeRunner so the tests never hit docker; assertions focus on
the contract between scanner ↔ runner ↔ Findings:

- argv passed to docker matches the expected shape.
- exit codes 0/1/2 are "tool ran successfully" with possibly-empty
  Findings, never ScannerError; everything else is an error.
- timeout produces ScannerError with a sensible reason.
- Missing or invalid ``target`` results in a controlled ScannerError
  (not a crash), preserving the operator's ability to see *why*.
- The FAKE runner is invoked exactly once per scan (no retries).
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
from secscan.scanners.dast import DastScanner
from secscan.scanners.dast._pinned import DEFAULT_ZAP_IMAGE

_VALID_DIGEST = "1" * 64
_VALID_IMAGE = f"zaproxy/zap-stable@sha256:{_VALID_DIGEST}"


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
    """``DastScanner.scan`` checks ``shutil.which('docker')`` before
    invoking the runner. We mock it for every test so none of the
    test envs need docker on PATH."""
    with patch.object(shutil, "which", return_value="/usr/bin/docker"):
        yield


def _config(**overrides: object) -> ScanConfig:
    extra: dict[str, object] = {
        "target": "https://example.com/",
        "image": _VALID_IMAGE,
        "ajax_spider": False,
        "config_file": None,
        "network_mode": "bridge",
    }
    extra.update(overrides)
    return ScanConfig(timeout_seconds=120, extra=MappingProxyType(extra))


def _report(alerts: list[dict[str, object]]) -> bytes:
    return json.dumps({"site": [{"alerts": alerts}]}).encode()


def _push_scan_lifecycle(
    fake_runner: FakeRunner,
    *,
    scan_returncode: int,
    scan_stdout: bytes,
    scan_stderr: bytes = b"",
    scan_timed_out: bool = False,
) -> None:
    """Push the four CommandResults the Phase 2-H DastScanner needs:

    1. ``docker volume create`` — always succeeds in tests (rc=0).
    2. ``docker run alpine chown`` — always succeeds (rc=0).
    3. ``docker run zap zap-baseline.py`` — the test-supplied response.
    4. ``docker run alpine cat /wrk/report.json`` — supplies the
       report bytes via stdout (mirrors the production extraction).
    5. (in finally) ``docker volume rm`` — pushed but optional.

    The cleanup ``docker volume rm`` call is best-effort; we push a
    response so the FakeRunner doesn't assert out, but the
    scanner's finally swallows non-zero exits with a stderr
    warning.
    """
    fake_runner.push(returncode=0)  # volume create
    fake_runner.push(returncode=0)  # chown
    fake_runner.push(
        returncode=scan_returncode,
        stdout=b"",  # ZAP scan stdout is ignored — report comes via extract
        stderr=scan_stderr,
        timed_out=scan_timed_out,
    )
    fake_runner.push(returncode=0, stdout=scan_stdout)  # extract via cat
    fake_runner.push(returncode=0)  # volume rm (in finally)


class TestDastScannerHappyPath:
    def test_clean_run_returns_zero_findings(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        outcome = DastScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is None
        assert outcome.findings == ()

    def test_zap_argv_is_the_third_docker_call(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Phase 2-H lifecycle: docker volume create → chown helper →
        ZAP scan → cat helper → volume rm. The 3rd call (index 2)
        is the ZAP container and must carry the documented safety
        flags."""
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        DastScanner().scan(work_unit, fake_runner, _config())
        # 5 docker calls total: create, chown, scan, extract, rm.
        assert len(fake_runner.calls) == 5
        argv, _cwd, timeout = fake_runner.calls[2]
        assert timeout == 120
        assert argv[0] == "docker"
        assert argv[1] == "run"
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--" in argv
        assert _VALID_IMAGE in argv
        # ``-J report.json`` MUST appear (Phase 2-H bug fix — older
        # ``-J /dev/stdout`` was rejected by ZAP).
        assert "-J" in argv
        assert "report.json" in argv
        assert "/dev/stdout" not in argv

    def test_findings_present_on_exit_2(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        report = _report(
            [
                {
                    "pluginid": "10038",
                    "name": "CSP missing",
                    "riskcode": 2,
                    "instances": [{"uri": "https://example.com/login"}],
                }
            ]
        )
        _push_scan_lifecycle(
            fake_runner, scan_returncode=2, scan_stdout=report
        )
        outcome = DastScanner().scan(work_unit, fake_runner, _config())
        (finding,) = outcome.findings
        assert finding.severity == Severity.MEDIUM
        assert finding.scanner == "dast"
        assert finding.rule_id == "10038"

    def test_exit_1_with_warnings_not_an_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """ZAP returns 1 when only warn-level alerts are present.
        Treat it the same as 2 for parsing purposes — it's not an
        error condition."""
        report = _report(
            [
                {
                    "pluginid": "10",
                    "name": "info",
                    "riskcode": 0,
                    "instances": [{"uri": "https://example.com/a"}],
                }
            ]
        )
        _push_scan_lifecycle(
            fake_runner, scan_returncode=1, scan_stdout=report
        )
        outcome = DastScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is None
        assert len(outcome.findings) == 1

    def test_private_target_warning_surfaces(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        outcome = DastScanner().scan(
            work_unit, fake_runner, _config(target="http://127.0.0.1:8080/")
        )
        assert outcome.error is None
        assert any("private or loopback" in w for w in outcome.warnings)

    def test_volume_lifecycle_cleanup_called(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Phase 2-H invariant: ``docker volume rm`` MUST be called
        in the finally branch even when the scan succeeds, so
        orphaned ``secscan-zap-*`` volumes don't pile up."""
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        DastScanner().scan(work_unit, fake_runner, _config())
        # Last call is the cleanup.
        argv, _cwd, _t = fake_runner.calls[-1]
        assert argv[:4] == ("docker", "volume", "rm", "--force")


class TestDastScannerErrorPaths:
    def test_missing_target_returns_error_outcome(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = DastScanner().scan(work_unit, fake_runner, _config(target=""))
        assert outcome.error is not None
        assert "target" in outcome.error.reason.lower()
        # Runner must NOT have been called (validation happens first).
        assert fake_runner.calls == []

    def test_invalid_image_returns_error_outcome(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = DastScanner().scan(
            work_unit, fake_runner, _config(image="zaproxy/zap:latest")
        )
        assert outcome.error is not None
        assert "image" in outcome.error.reason.lower()
        assert fake_runner.calls == []

    def test_invalid_scheme_returns_error_outcome(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = DastScanner().scan(
            work_unit, fake_runner, _config(target="ftp://example.com/")
        )
        assert outcome.error is not None
        assert "scheme" in outcome.error.reason.lower()

    def test_timeout_is_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        _push_scan_lifecycle(
            fake_runner,
            scan_returncode=0,
            scan_stdout=b"",
            scan_timed_out=True,
        )
        outcome = DastScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is not None
        assert "timed out" in outcome.error.reason.lower()

    def test_unknown_exit_code_is_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        _push_scan_lifecycle(
            fake_runner,
            scan_returncode=125,
            scan_stdout=b"",
            scan_stderr=b"docker: bad image",
        )
        outcome = DastScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is not None
        assert "exited with 125" in outcome.error.reason

    def test_invalid_network_mode_returns_error(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        outcome = DastScanner().scan(
            work_unit, fake_runner, _config(network_mode="bogus")
        )
        assert outcome.error is not None
        assert fake_runner.calls == []

    def test_stderr_excerpt_redacted(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Defense in depth: a docker/ZAP stderr might echo back env
        values that look like credentials. The excerpt must be
        redacted before it lands in the ScannerError."""
        fake_runner.push(
            returncode=99,
            stdout=b"",
            stderr=b"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE failed to do x",
        )
        outcome = DastScanner().scan(work_unit, fake_runner, _config())
        assert outcome.error is not None
        excerpt = outcome.error.stderr_excerpt or ""
        assert "AKIAIOSFODNN7EXAMPLE" not in excerpt


class TestDastScannerToolDetection:
    def test_missing_docker_raises_tool_not_found(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        # Override the autouse mock so docker is "absent".
        from secscan.scanners.base import ToolNotFoundError

        with (
            patch.object(shutil, "which", return_value=None),
            pytest.raises(ToolNotFoundError),
        ):
            DastScanner().scan(work_unit, fake_runner, _config())


class TestDastScannerDefaults:
    def test_default_image_used_when_extra_missing_image(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """``image`` in extras may be missing or empty; the scanner
        falls back to ``DEFAULT_ZAP_IMAGE``."""
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType(
                {
                    "target": "https://example.com/",
                    # no "image" key at all
                    "ajax_spider": False,
                    "config_file": None,
                    "network_mode": "bridge",
                }
            ),
        )
        DastScanner().scan(work_unit, fake_runner, cfg)
        # Phase 2-H: call 2 (index 2) is the ZAP scan.
        argv, _cwd, _t = fake_runner.calls[2]
        assert DEFAULT_ZAP_IMAGE in argv

    def test_empty_string_image_falls_back_to_default(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Codex Phase 2-D diff review: ``image=""`` previously slid
        through and would hit the docker argv as a bare empty value.
        Strip + fallback to ``DEFAULT_ZAP_IMAGE`` instead."""
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType(
                {
                    "target": "https://example.com/",
                    "image": "   ",  # whitespace-only
                    "ajax_spider": False,
                    "config_file": None,
                    "network_mode": "bridge",
                }
            ),
        )
        DastScanner().scan(work_unit, fake_runner, cfg)
        argv, _cwd, _t = fake_runner.calls[2]
        assert DEFAULT_ZAP_IMAGE in argv

    def test_empty_config_file_is_treated_as_absent(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Codex Phase 2-D diff review: ``config_file=""`` previously
        ended up as ``-n ""`` in the argv. Treat empty / whitespace
        as "no config file" instead."""
        _push_scan_lifecycle(
            fake_runner, scan_returncode=0, scan_stdout=_report([])
        )
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType(
                {
                    "target": "https://example.com/",
                    "image": _VALID_IMAGE,
                    "ajax_spider": False,
                    "config_file": "  ",
                    "network_mode": "bridge",
                }
            ),
        )
        DastScanner().scan(work_unit, fake_runner, cfg)
        argv, _cwd, _t = fake_runner.calls[2]
        assert "-n" not in argv

    def test_ajax_spider_must_be_bool(
        self, fake_runner: FakeRunner, work_unit: WorkUnit
    ) -> None:
        """Codex Phase 2-D diff review: ``ajax_spider=1`` or
        ``"true"`` would silently coerce to True under the previous
        ``bool(extra.get(...))`` path. Require an exact ``bool``."""
        cfg = ScanConfig(
            timeout_seconds=60,
            extra=MappingProxyType(
                {
                    "target": "https://example.com/",
                    "image": _VALID_IMAGE,
                    "ajax_spider": 1,  # not a bool!
                    "config_file": None,
                    "network_mode": "bridge",
                }
            ),
        )
        outcome = DastScanner().scan(work_unit, fake_runner, cfg)
        assert outcome.error is not None
        assert "ajax_spider" in outcome.error.reason
        assert fake_runner.calls == []
