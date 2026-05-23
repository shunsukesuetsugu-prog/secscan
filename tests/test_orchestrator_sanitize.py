"""Orchestrator-level path sanitization tests.

These pin Codex 3rd review's "scanner output path containment" requirement.
A scanner that (bugs / lies / is fooled by a symlink) reports a path outside
the scan root must NOT leak that path to the user.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import pytest

from secscan.config import ProjectConfig
from secscan.models import (
    Finding,
    Location,
    ScanConfig,
    ScanOutcome,
    Severity,
    WorkUnit,
)
from secscan.orchestrator import run_scanners
from secscan.path_safety import resolve_scan_root
from secscan.runner import CommandRunner
from secscan.scanners.base import Scanner


@dataclass
class _FakeScanner(Scanner):
    name: ClassVar[str] = "secrets"
    tool_executable: ClassVar[str] = "fake"
    install_hint: ClassVar[str] = "n/a"

    outcome: ScanOutcome | None = None
    calls: list[WorkUnit] = field(default_factory=list)

    def is_applicable(self, unit: WorkUnit) -> bool:
        return True

    def scan(
        self, unit: WorkUnit, runner: CommandRunner, config: ScanConfig
    ) -> ScanOutcome:
        self.calls.append(unit)
        assert self.outcome is not None
        return self.outcome


class _NopRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: object = None,
        timeout_seconds: int = 300,
    ) -> object:
        raise AssertionError("should not be called")


@pytest.fixture()
def runner() -> CommandRunner:
    return _NopRunner()  # type: ignore[return-value]


def _finding_with_path(file: str | None) -> Finding:
    return Finding(
        scanner="secrets",
        rule_id="r",
        severity=Severity.HIGH,
        title="t",
        message="m",
        location=Location(file=file, line=1) if file else None,
        fingerprint="fp",
    )


def test_path_inside_root_is_preserved(
    tmp_path: Path, runner: CommandRunner
) -> None:
    (tmp_path / "src").mkdir()
    finding = _finding_with_path("src/a.py")
    scanner = _FakeScanner(outcome=ScanOutcome(scanner="secrets", findings=(finding,)))
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    (kept,) = out.result.findings
    assert kept.location is not None
    assert kept.location.file == "src/a.py"


def test_path_outside_root_is_stripped(tmp_path: Path, runner: CommandRunner) -> None:
    # A buggy / fooled scanner reports a path with .. — must not leak.
    finding = _finding_with_path("../../etc/passwd")
    scanner = _FakeScanner(outcome=ScanOutcome(scanner="secrets", findings=(finding,)))
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    (kept,) = out.result.findings
    assert kept.location is not None
    assert kept.location.file is None  # path stripped
    assert kept.location.line is None


def test_absolute_outside_path_is_stripped(
    tmp_path: Path, runner: CommandRunner
) -> None:
    # An absolute path to a real host file (/etc/passwd / /tmp/...) must
    # also be stripped — not just relative `..` escapes. The orchestrator
    # treats the scan-root boundary as authoritative regardless of how the
    # scanner expressed the path.
    finding = _finding_with_path("/etc/passwd")
    scanner = _FakeScanner(outcome=ScanOutcome(scanner="secrets", findings=(finding,)))
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    (kept,) = out.result.findings
    assert kept.location is not None
    assert kept.location.file is None
    # Equally important: nothing in the rendered report should reveal the
    # absolute path the scanner reported.
    assert kept.location.line is None


def test_path_in_ignored_dir_is_stripped(
    tmp_path: Path, runner: CommandRunner
) -> None:
    # A path inside node_modules should not be shown — those are vendor
    # files, not user code, and reporting them is almost always noise.
    finding = _finding_with_path("node_modules/lodash/index.js")
    scanner = _FakeScanner(outcome=ScanOutcome(scanner="secrets", findings=(finding,)))
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    (kept,) = out.result.findings
    assert kept.location is not None
    assert kept.location.file is None


def test_finding_without_location_unaffected(
    tmp_path: Path, runner: CommandRunner
) -> None:
    finding = _finding_with_path(None)
    scanner = _FakeScanner(outcome=ScanOutcome(scanner="secrets", findings=(finding,)))
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    (kept,) = out.result.findings
    assert kept.location is None


def test_exception_reason_is_redacted(
    tmp_path: Path, runner: CommandRunner
) -> None:
    """Exception messages can carry env values / file content; they MUST be
    redacted before landing in ScannerError.reason."""

    class _CrashingScanner(_FakeScanner):
        name: ClassVar[str] = "secrets"

        def scan(self, unit, runner, config):  # type: ignore[no-untyped-def, override]
            raise RuntimeError("crash with AKIAIOSFODNN7EXAMPLE in message")

    scanner = _CrashingScanner()
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    (err,) = out.result.errors
    assert "AKIAIOSFODNN7EXAMPLE" not in err.reason
