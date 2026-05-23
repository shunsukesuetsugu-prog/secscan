"""Orchestrator tests with fake scanners.

The orchestrator's job is glue: scanner selection, discovery, baseline
application, override application, decision computation. We test the glue,
not the scanners themselves (those have their own tests).

Each test uses a FakeScanner that records calls and returns canned outcomes
so we can assert orchestrator behavior without subprocess/IO.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest

from secscan import __version__ as SECSCAN_VERSION
from secscan.baseline import Baseline, BaselineEntry, save_baseline
from secscan.config import ProjectConfig, UnknownSeverityPolicy
from secscan.exit_codes import ExitCode
from secscan.models import (
    Finding,
    Location,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    Severity,
    WorkUnit,
)
from secscan.orchestrator import run_scanners
from secscan.path_safety import resolve_scan_root
from secscan.runner import CommandRunner
from secscan.scanners.base import Scanner, ToolNotFoundError

UTC = UTC


def _finding(
    scanner: str = "secrets",
    severity: Severity = Severity.HIGH,
    rule_id: str = "r1",
    fingerprint: str = "fp1",
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        title="t",
        message="m",
        location=Location(file="a.py", line=1),
        fingerprint=fingerprint,
    )


@dataclass
class FakeScanner(Scanner):
    name: ClassVar[str]
    tool_executable: ClassVar[str] = "fake"
    install_hint: ClassVar[str] = "fake install hint"

    outcome: ScanOutcome | None = None
    raise_tool_not_found: bool = False
    raise_exception: BaseException | None = None
    applicable: bool = True
    calls: list[WorkUnit] = field(default_factory=list)

    def is_applicable(self, unit: WorkUnit) -> bool:
        return self.applicable

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        self.calls.append(unit)
        if self.raise_tool_not_found:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)
        if self.raise_exception is not None:
            raise self.raise_exception
        assert self.outcome is not None, "FakeScanner needs an outcome or an exception"
        return self.outcome


class FakeSecretsScanner(FakeScanner):
    name: ClassVar[str] = "secrets"


class FakeSastScanner(FakeScanner):
    name: ClassVar[str] = "sast"


class FakeDepsScanner(FakeScanner):
    name: ClassVar[str] = "deps"


class _NopRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: object = None,
        timeout_seconds: int = 300,
    ) -> object:
        raise AssertionError("FakeScanner should not call the runner")


@pytest.fixture()
def runner() -> CommandRunner:
    return _NopRunner()  # type: ignore[return-value]


# --- Basic flow ------------------------------------------------------------


def test_runs_all_provided_scanners(tmp_path: Path, runner: CommandRunner) -> None:
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(
            scanner="secrets",
            findings=(_finding("secrets", Severity.HIGH, fingerprint="s1"),),
        )
    )
    sast = FakeSastScanner(
        outcome=ScanOutcome(
            scanner="sast",
            findings=(_finding("sast", Severity.MEDIUM, fingerprint="t1"),),
        )
    )
    root = resolve_scan_root(tmp_path)
    out = run_scanners(
        [secrets, sast],
        scan_root=root,
        config=ProjectConfig(),
        runner=runner,
    )
    assert {f.scanner for f in out.result.findings} == {"secrets", "sast"}
    assert len(secrets.calls) == 1
    assert len(sast.calls) == 1


def test_only_filter_restricts_scanners(tmp_path: Path, runner: CommandRunner) -> None:
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(scanner="secrets", findings=(_finding(),))
    )
    sast = FakeSastScanner(outcome=ScanOutcome(scanner="sast"))
    out = run_scanners(
        [secrets, sast],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
        only=("secrets",),
    )
    assert sast.calls == []
    assert secrets.calls != []
    assert "sast" in out.result.skipped


def test_skip_config_removes_scanner(tmp_path: Path, runner: CommandRunner) -> None:
    secrets = FakeSecretsScanner(outcome=ScanOutcome(scanner="secrets"))
    sast = FakeSastScanner(outcome=ScanOutcome(scanner="sast"))
    out = run_scanners(
        [secrets, sast],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(skip=("sast",)),
        runner=runner,
    )
    assert sast.calls == []
    assert "sast" in out.result.skipped


def test_only_wins_over_skip(tmp_path: Path, runner: CommandRunner) -> None:
    secrets = FakeSecretsScanner(outcome=ScanOutcome(scanner="secrets"))
    out = run_scanners(
        [secrets],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(skip=("secrets",)),  # configured to skip…
        runner=runner,
        only=("secrets",),  # …but user explicitly asked
    )
    assert secrets.calls != []
    assert "secrets" not in out.result.skipped


# --- Discovery filtering for deps -----------------------------------------


def test_deps_without_manifest_runs_no_scan(tmp_path: Path, runner: CommandRunner) -> None:
    deps = FakeDepsScanner(outcome=ScanOutcome(scanner="deps"))
    # Empty tmp_path -> no manifests detected -> no work units -> scanner
    # is_applicable never called, scan never called.
    out = run_scanners(
        [deps],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    assert deps.calls == []
    # Warning about missing manifest surfaces.
    assert any("no dependency manifest" in w for w in out.result.warnings)


def test_deps_with_manifest_runs_scan(tmp_path: Path, runner: CommandRunner) -> None:
    (tmp_path / "package.json").write_text("{}")
    deps = FakeDepsScanner(outcome=ScanOutcome(scanner="deps", findings=()))
    out = run_scanners(
        [deps],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    assert len(deps.calls) == 1
    assert out.result.errors == ()


# --- Error containment -----------------------------------------------------


def test_tool_not_found_becomes_scanner_error(
    tmp_path: Path, runner: CommandRunner
) -> None:
    scanner = FakeSecretsScanner(raise_tool_not_found=True)
    out = run_scanners(
        [scanner],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    assert len(out.result.errors) == 1
    err = out.result.errors[0]
    assert "tool not installed" in err.reason
    assert err.stderr_excerpt == scanner.install_hint
    assert out.decision.exit_code == ExitCode.SCAN_ERROR


def test_unexpected_exception_does_not_kill_other_scanners(
    tmp_path: Path, runner: CommandRunner
) -> None:
    broken = FakeSecretsScanner(raise_exception=RuntimeError("boom"))
    good = FakeSastScanner(
        outcome=ScanOutcome(scanner="sast", findings=(_finding("sast"),))
    )
    out = run_scanners(
        [broken, good],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    assert len(out.result.errors) == 1
    assert "RuntimeError" in out.result.errors[0].reason
    # Good scanner still ran.
    assert any(f.scanner == "sast" for f in out.result.findings)


def test_scanner_outcome_with_error_is_recorded(
    tmp_path: Path, runner: CommandRunner
) -> None:
    err = ScannerError(scanner="secrets", reason="exit 2", returncode=2)
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(scanner="secrets", error=err)
    )
    out = run_scanners(
        [secrets],
        scan_root=resolve_scan_root(tmp_path),
        config=ProjectConfig(),
        runner=runner,
    )
    assert out.result.errors == (err,)


# --- Baseline integration --------------------------------------------------


def test_baseline_suppresses_findings_and_records_them(
    tmp_path: Path, runner: CommandRunner
) -> None:
    fp = "match-me"
    finding = _finding(fingerprint=fp)
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(scanner="secrets", findings=(finding,))
    )
    baseline_path = tmp_path / "bl.json"
    save_baseline(
        Baseline(
            entries=(
                BaselineEntry(
                    fingerprint=fp,
                    scanner="secrets",
                    rule_id="r1",
                    reason="REQUIRED",
                    accepted_by="alice",
                    added_at=datetime(2026, 1, 1, tzinfo=UTC),
                    expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                    secscan_version=SECSCAN_VERSION,
                ),
            )
        ),
        baseline_path,
    )
    # Use a custom config pointing to the baseline file.
    cfg = ProjectConfig()
    # Replace baseline path post-hoc: ProjectConfig is frozen, so build new.
    from secscan.config import BaselineConfig

    cfg = ProjectConfig(
        baseline=BaselineConfig(path=baseline_path, default_expiry_days=90),
    )

    out = run_scanners(
        [secrets],
        scan_root=resolve_scan_root(tmp_path),
        config=cfg,
        runner=runner,
    )
    assert out.result.findings == ()
    assert out.result.suppressed_by_baseline == (finding,)


def test_baseline_expired_warning_surfaces(
    tmp_path: Path, runner: CommandRunner
) -> None:
    fp = "expired-fp"
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(scanner="secrets", findings=(_finding(fingerprint=fp),))
    )
    baseline_path = tmp_path / "bl.json"
    expires = datetime.now(UTC) - timedelta(days=1)
    save_baseline(
        Baseline(
            entries=(
                BaselineEntry(
                    fingerprint=fp,
                    scanner="secrets",
                    rule_id="r1",
                    reason="REQUIRED",
                    accepted_by="alice",
                    added_at=expires - timedelta(days=30),
                    expires_at=expires,
                    secscan_version=SECSCAN_VERSION,
                ),
            )
        ),
        baseline_path,
    )
    from secscan.config import BaselineConfig

    cfg = ProjectConfig(
        baseline=BaselineConfig(path=baseline_path, default_expiry_days=90),
    )

    out = run_scanners(
        [secrets],
        scan_root=resolve_scan_root(tmp_path),
        config=cfg,
        runner=runner,
    )
    # Expired entry must not suppress.
    assert len(out.result.findings) == 1
    assert any("expired" in w for w in out.result.warnings)


# --- Overrides and policy --------------------------------------------------


def test_severity_overrides_applied_before_policy(
    tmp_path: Path, runner: CommandRunner
) -> None:
    # A MEDIUM finding shouldn't cross HIGH threshold, but overrides upgrade
    # it to CRITICAL → should cross.
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(
            scanner="secrets",
            findings=(_finding(severity=Severity.MEDIUM, rule_id="noisy"),),
        )
    )
    cfg = ProjectConfig(
        fail_on=Severity.HIGH,
        severity_overrides={"secrets": {"noisy": Severity.CRITICAL}},
    )
    out = run_scanners(
        [secrets],
        scan_root=resolve_scan_root(tmp_path),
        config=cfg,
        runner=runner,
    )
    assert out.decision.exit_code == ExitCode.FINDINGS


def test_unknown_severity_policy_respected(
    tmp_path: Path, runner: CommandRunner
) -> None:
    secrets = FakeSecretsScanner(
        outcome=ScanOutcome(
            scanner="secrets",
            findings=(_finding(severity=Severity.UNKNOWN),),
        )
    )
    cfg = ProjectConfig(
        fail_on=Severity.HIGH,
        severity_unknown_policy=UnknownSeverityPolicy(secrets="warn"),
    )
    out = run_scanners(
        [secrets],
        scan_root=resolve_scan_root(tmp_path),
        config=cfg,
        runner=runner,
    )
    # warn → never crosses threshold
    assert out.decision.exit_code == ExitCode.OK
    assert out.decision.unknown_warning_count == 1
