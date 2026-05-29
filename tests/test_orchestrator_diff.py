"""Phase 2-Y: orchestrator diff-mode dispatch tests.

Pins the contract:
- AGNOSTIC scanners are SKIPPED in diff mode (recorded as skipped, not run).
- NATIVE scanners receive the baseline OID in their ScanConfig.
- ALWAYS scanners run with NO baseline OID (full scan).
- A diff banner heads the warnings list.
- With diff_baseline=None, every scanner runs normally (no skip).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import pytest

from secscan.config import ProjectConfig
from secscan.diffscan import DiffBaseline
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
from secscan.scanners.base import DiffMode, Scanner

_BASE_OID = "a" * 40


@dataclass
class _DiffFake(Scanner):
    name: ClassVar[str] = ""
    tool_executable: ClassVar[str] = "fake"
    install_hint: ClassVar[str] = "fake"
    received_oids: list[str | None] = field(default_factory=list)

    def is_applicable(self, unit: WorkUnit) -> bool:
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        self.received_oids.append(config.diff_baseline_oid)
        return ScanOutcome(
            scanner=self.name,
            findings=(
                Finding(
                    scanner=self.name,
                    rule_id="r1",
                    severity=Severity.LOW,
                    title="t",
                    message="m",
                    location=Location(file="a.py", line=1),
                    fingerprint=f"fp-{self.name}",
                ),
            ),
            warnings=(),
            tool_version="x",
            error=None,
        )


class _NativeFake(_DiffFake):
    name: ClassVar[str] = "secrets"
    diff_mode: ClassVar[DiffMode] = DiffMode.NATIVE


class _AlwaysFake(_DiffFake):
    name: ClassVar[str] = "deps"
    diff_mode: ClassVar[DiffMode] = DiffMode.ALWAYS


class _AgnosticFake(_DiffFake):
    name: ClassVar[str] = "dast"
    diff_mode: ClassVar[DiffMode] = DiffMode.AGNOSTIC


class _NullRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env=None,
        timeout_seconds: int = 300,
    ):  # pragma: no cover
        raise AssertionError("fake scanners must not call the runner")


@pytest.fixture
def scan_root(tmp_path: Path):
    return resolve_scan_root(str(tmp_path))


@pytest.fixture
def cfg():
    return ProjectConfig()


@pytest.fixture(autouse=True)
def patch_discovery(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from dataclasses import dataclass as _dc

    from secscan import orchestrator as _orch
    from secscan.models import WorkUnit as _WorkUnit

    @_dc(frozen=True)
    class _StubDiscovery:
        work_units: tuple[_WorkUnit, ...]
        warnings: tuple[str, ...] = ()

    def _fake_discover(scanner_name: str, _scan_root):
        return _StubDiscovery(
            work_units=(_WorkUnit(root=tmp_path, ecosystem=None, manifest=None),)
        )

    monkeypatch.setattr(_orch, "discover_for_scanner", _fake_discover)


def _baseline() -> DiffBaseline:
    return DiffBaseline(user_ref="HEAD~2", baseline_oid=_BASE_OID)


# --- dispatch ---------------------------------------------------------------


def test_agnostic_skipped_in_diff_mode(scan_root, cfg) -> None:
    native = _NativeFake()
    agnostic = _AgnosticFake()
    out = run_scanners(
        [native, agnostic],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=_baseline(),
    )
    # AGNOSTIC scanner never ran...
    assert agnostic.received_oids == []
    # ...and is recorded as skipped.
    assert "dast" in out.result.skipped
    # NATIVE scanner DID run.
    assert native.received_oids == [_BASE_OID]


def test_native_receives_baseline_oid(scan_root, cfg) -> None:
    native = _NativeFake()
    run_scanners(
        [native],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=_baseline(),
    )
    assert native.received_oids == [_BASE_OID]


def test_always_runs_full_without_oid(scan_root, cfg) -> None:
    always = _AlwaysFake()
    run_scanners(
        [always],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=_baseline(),
    )
    # ALWAYS scanner ran, but with NO baseline OID (full scan).
    assert always.received_oids == [None]


def test_banner_heads_warnings(scan_root, cfg) -> None:
    out = run_scanners(
        [_NativeFake(), _AlwaysFake()],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=_baseline(),
    )
    assert out.result.warnings, "expected a diff banner warning"
    banner = out.result.warnings[0]
    assert "DIFF SCAN since HEAD~2" in banner
    assert _BASE_OID[:12] in banner
    # Banner distinguishes per-scanner behaviour (Codex #6), built from
    # the actual scanners present.
    assert "secrets scanned only the commit delta" in banner
    assert "deps ran a FULL scan" in banner
    assert "NOT scanned" in banner


def test_banner_reflects_actual_scanners_not_fixed_text(scan_root, cfg) -> None:
    """Codex diff review #3: the banner must report what ACTUALLY ran, not
    a hardcoded "secrets/sast scanned" string. With only an ALWAYS scanner
    present (no NATIVE), the banner must NOT claim any delta scan happened —
    otherwise a partial diff reads as fully covered."""
    out = run_scanners(
        [_AlwaysFake()],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=_baseline(),
    )
    banner = out.result.warnings[0]
    assert "deps ran a FULL scan" in banner
    # No NATIVE scanner ran → no delta-scan claim, no "unchanged not scanned".
    assert "commit delta" not in banner
    assert "NOT scanned" not in banner


def test_no_diff_baseline_runs_everything(scan_root, cfg) -> None:
    """Without --since, even AGNOSTIC scanners run normally."""
    native = _NativeFake()
    always = _AlwaysFake()
    agnostic = _AgnosticFake()
    out = run_scanners(
        [native, always, agnostic],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=None,
    )
    # All three ran; none received a baseline OID (full mode).
    assert native.received_oids == [None]
    assert always.received_oids == [None]
    assert agnostic.received_oids == [None]
    # No diff skip recorded.
    assert "dast" not in out.result.skipped
    # No diff banner.
    assert not any("DIFF SCAN" in w for w in out.result.warnings)


def test_all_three_modes_together(scan_root, cfg) -> None:
    native = _NativeFake()
    always = _AlwaysFake()
    agnostic = _AgnosticFake()
    out = run_scanners(
        [native, always, agnostic],
        scan_root=scan_root,
        config=cfg,
        runner=_NullRunner(),
        parallel=False,
        diff_baseline=_baseline(),
    )
    assert native.received_oids == [_BASE_OID]   # delta
    assert always.received_oids == [None]        # full
    assert agnostic.received_oids == []          # skipped
    assert "dast" in out.result.skipped
    # secrets + deps findings present; dast absent.
    scanners_with_findings = {f.scanner for f in out.result.findings}
    assert scanners_with_findings == {"secrets", "deps"}
