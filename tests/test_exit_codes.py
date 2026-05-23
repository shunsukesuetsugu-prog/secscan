"""ExitCode is a tiny enum; we test the contract, not the values' bytes."""

from __future__ import annotations

from secscan.exit_codes import ExitCode


def test_exit_codes_are_integers() -> None:
    assert int(ExitCode.OK) == 0
    assert int(ExitCode.FINDINGS) == 1
    assert int(ExitCode.SCAN_ERROR) == 2
    assert int(ExitCode.INTERRUPTED) == 130


def test_exit_codes_are_distinct() -> None:
    values = {int(code) for code in ExitCode}
    assert len(values) == len(list(ExitCode)), "ExitCode values must be unique"


def test_findings_and_scan_error_do_not_overlap() -> None:
    assert ExitCode.FINDINGS != ExitCode.SCAN_ERROR
