"""Tests for DepsScanner — the dispatch layer over npm/pnpm/pip-audit.

The adapter functions have their own dedicated tests; here we focus on
dispatch behavior:
- is_applicable filters by ecosystem.
- scan() picks the right tool based on package_manager.
- Lockfile policy (allow_missing_lockfile) is enforced.
- Missing tool raises ToolNotFoundError.
- Tool failure produces a redacted ScannerError, not a crash.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

from secscan.models import ScanConfig, Severity, WorkUnit
from secscan.runner import CommandResult
from secscan.scanners import ToolNotFoundError
from secscan.scanners.deps_scanner import DepsScanner

# --- Fake runner -----------------------------------------------------------


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
            raise AssertionError(f"FakeRunner exhausted: argv={list(argv)}")
        canned = self.responses.pop(0)
        return CommandResult(
            argv=tuple(argv),
            returncode=canned.returncode,
            stdout=canned.stdout,
            stderr=canned.stderr,
            duration_seconds=canned.duration_seconds,
            timed_out=canned.timed_out,
        )


@pytest.fixture()
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture()
def scanner() -> DepsScanner:
    return DepsScanner()


@pytest.fixture()
def stub_npm() -> object:
    with patch.object(shutil, "which", side_effect=lambda name: f"/usr/local/bin/{name}"):
        yield


# --- is_applicable --------------------------------------------------------


def test_is_applicable_for_npm_ecosystem(scanner: DepsScanner) -> None:
    assert scanner.is_applicable(
        WorkUnit(root=Path("/x"), ecosystem="npm", package_manager="npm")
    )


def test_is_applicable_for_pypi_ecosystem(scanner: DepsScanner) -> None:
    assert scanner.is_applicable(
        WorkUnit(root=Path("/x"), ecosystem="pypi", package_manager="pip")
    )


def test_is_not_applicable_for_unknown_ecosystem(scanner: DepsScanner) -> None:
    assert not scanner.is_applicable(WorkUnit(root=Path("/x")))
    assert not scanner.is_applicable(
        WorkUnit(root=Path("/x"), ecosystem="ruby", package_manager="bundler")
    )


# --- dispatch by package_manager ------------------------------------------


@pytest.mark.usefixtures("stub_npm")
def test_npm_workunit_invokes_npm_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig(timeout_seconds=60))
    assert outcome.succeeded
    call_argv, _cwd, call_timeout = runner.calls[0]
    assert call_argv[0] == "npm"
    assert "audit" in call_argv
    assert "--audit-level=none" in call_argv
    assert call_timeout == 60


@pytest.mark.usefixtures("stub_npm")
def test_pnpm_workunit_invokes_pnpm_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"advisories": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="pnpm",
        lockfile=tmp_path / "pnpm-lock.yaml",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    argv = runner.calls[0][0]
    assert argv[0] == "pnpm"
    assert "--audit-level=low" in argv


@pytest.mark.usefixtures("stub_npm")
def test_pypi_workunit_invokes_pip_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==1.0")
    payload = json.dumps({"dependencies": []}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip-requirements",
        manifest=req,
        lockfile=req,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    argv = runner.calls[0][0]
    assert argv[0] == "pip-audit"
    assert "--requirement" in argv
    assert str(req) in argv


# --- lockfile policy ------------------------------------------------------


@pytest.mark.usefixtures("stub_npm")
def test_npm_without_lockfile_requires_allow_flag(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=None,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "lockfile" in outcome.error.reason
    # Must never have executed the underlying tool.
    assert runner.calls == []


@pytest.mark.usefixtures("stub_npm")
def test_npm_without_lockfile_runs_when_allowed(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=None,
    )
    cfg = ScanConfig(extra=MappingProxyType({"allow_missing_lockfile": True}))
    outcome = scanner.scan(unit, runner, cfg)
    assert outcome.succeeded
    assert runner.calls != []


@pytest.mark.usefixtures("stub_npm")
def test_pip_audit_can_run_without_lockfile(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """pip-audit has a sensible no-lockfile path via the active env; the
    Scanner should let it run rather than blocking like npm/pnpm."""
    payload = json.dumps({"dependencies": []}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip",  # pyproject only, no lock
        manifest=tmp_path / "pyproject.toml",
        lockfile=None,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    argv = runner.calls[0][0]
    assert "--requirement" not in argv


# --- tool not found -------------------------------------------------------


def test_missing_npm_raises_tool_not_found(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    with (
        patch.object(shutil, "which", return_value=None),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(unit, runner, ScanConfig())
    assert exc_info.value.tool == "npm"


def test_missing_pip_audit_raises_tool_not_found(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip",
        manifest=tmp_path / "pyproject.toml",
    )
    with (
        patch.object(shutil, "which", return_value=None),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(unit, runner, ScanConfig())
    assert exc_info.value.tool == "pip-audit"


# --- error handling -------------------------------------------------------


@pytest.mark.usefixtures("stub_npm")
def test_tool_failure_becomes_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    runner.push(returncode=2, stdout=b"", stderr=b"network error")
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert outcome.error.stderr_excerpt is not None
    assert "network error" in outcome.error.stderr_excerpt


@pytest.mark.usefixtures("stub_npm")
def test_error_stderr_excerpt_is_redacted(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """Defense in depth: even if a dependency manager leaks a credential
    into its stderr (e.g. authenticated registry URL), the excerpt
    surfaced to the user must be redacted."""
    runner.push(
        returncode=2,
        stdout=b"",
        stderr=b"failed: registry token AKIAIOSFODNN7EXAMPLE invalid",
    )
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.error is not None
    assert outcome.error.stderr_excerpt is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in outcome.error.stderr_excerpt


@pytest.mark.usefixtures("stub_npm")
def test_findings_normalized_through_dispatch(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """Smoke test: dispatch through npm yields a properly-normalized
    Finding with severity, package, fix_version, etc."""
    npm_payload = json.dumps(
        {
            "vulnerabilities": {
                "left-pad": {
                    "name": "left-pad",
                    "severity": "critical",
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-PAD",
                            "title": "left-pad RCE",
                            "severity": "critical",
                            "cve": "CVE-2024-PAD",
                        }
                    ],
                    "fixAvailable": {"name": "left-pad", "version": "9.9.9"},
                }
            }
        }
    ).encode()
    runner.push(returncode=0, stdout=npm_payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    (f,) = outcome.findings
    assert f.severity == Severity.CRITICAL
    assert f.location is not None and f.location.package == "left-pad"
    assert f.fix_version == "9.9.9"
    assert f.cve == "CVE-2024-PAD"


def test_unknown_package_manager_is_a_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="yarn",  # Phase 1B doesn't ship a yarn adapter
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "package_manager" in outcome.error.reason


def test_workunit_without_package_manager_is_a_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(root=tmp_path, ecosystem="npm")  # package_manager omitted
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
