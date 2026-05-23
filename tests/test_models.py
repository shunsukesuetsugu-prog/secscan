"""Tests for the core data model.

We focus on:
- Severity ordering and name-parsing (the only behavior; the dataclasses
  themselves are simple frozen carriers).
- Scanner/Orchestrator-level invariants on ScanOutcome and RunResult.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from secscan.models import (
    Finding,
    Location,
    RunResult,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    Severity,
    WorkUnit,
)

# --- Severity --------------------------------------------------------------


def test_severity_is_ordered() -> None:
    assert Severity.UNKNOWN < Severity.INFO < Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_from_name_is_case_insensitive() -> None:
    assert Severity.from_name("high") == Severity.HIGH
    assert Severity.from_name("HIGH") == Severity.HIGH
    assert Severity.from_name("  Medium  ") == Severity.MEDIUM


def test_severity_from_name_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Unknown severity"):
        Severity.from_name("critically-severe")


def test_severity_from_name_rejects_empty() -> None:
    with pytest.raises(ValueError):
        Severity.from_name("")


# --- Finding ---------------------------------------------------------------


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = dict(
        scanner="secrets",
        rule_id="aws-key",
        severity=Severity.HIGH,
        title="AWS Access Key",
        message="found",
        location=Location(file="src/a.py", line=10),
        fingerprint="abc123",
    )
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_finding_is_frozen_and_hashable() -> None:
    f = _make_finding()
    # Frozen → cannot mutate
    with pytest.raises(FrozenInstanceError):
        f.scanner = "deps"  # type: ignore[misc]
    # Hashable (tuple-friendly)
    assert hash(f) == hash(_make_finding())


def test_finding_equality_uses_all_fields() -> None:
    f1 = _make_finding()
    f2 = _make_finding(rule_id="other-rule")
    assert f1 != f2


# --- ScanOutcome -----------------------------------------------------------


def test_scan_outcome_success_has_no_error() -> None:
    outcome = ScanOutcome(scanner="secrets", findings=(_make_finding(),))
    assert outcome.succeeded
    assert outcome.error is None


def test_scan_outcome_error_has_empty_findings() -> None:
    err = ScannerError(scanner="secrets", reason="boom")
    outcome = ScanOutcome(scanner="secrets", error=err)
    assert not outcome.succeeded
    assert outcome.findings == ()


# --- RunResult -------------------------------------------------------------


def test_run_result_has_errors_flag() -> None:
    err = ScannerError(scanner="x", reason="r")
    rr = RunResult(errors=(err,))
    assert rr.has_errors


def test_run_result_default_is_empty_and_clean() -> None:
    rr = RunResult()
    assert rr.findings == ()
    assert rr.errors == ()
    assert rr.warnings == ()
    assert rr.skipped == ()
    assert rr.suppressed_by_baseline == ()
    assert not rr.has_errors


# --- WorkUnit / ScanConfig -------------------------------------------------


def test_work_unit_defaults() -> None:
    wu = WorkUnit(root=Path("/tmp"))
    assert wu.ecosystem is None
    assert wu.manifest is None
    assert wu.lockfile is None


def test_scan_config_extra_defaults_to_empty_mapping() -> None:
    cfg = ScanConfig()
    assert dict(cfg.extra) == {}


def test_scan_config_extra_default_is_immutable() -> None:
    # Codex 3rd review: ``extra`` claimed to be a read-only mapping must
    # actually reject mutation, otherwise the immutability promise leaks.
    cfg = ScanConfig()
    with pytest.raises(TypeError):
        cfg.extra["x"] = "y"  # type: ignore[index]
