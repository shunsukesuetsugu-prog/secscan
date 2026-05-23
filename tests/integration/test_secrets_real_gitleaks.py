"""Minimal end-to-end test against a real gitleaks binary.

Skipped when gitleaks is not on PATH (e.g. CI without it installed).
One representative case is enough — the FakeRunner tests cover branching;
this test verifies the wire-up (argv, exit-code 101 handling, redaction
enforcement) against the real tool's actual behavior.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secscan.models import ScanConfig, Severity, WorkUnit
from secscan.runner import SubprocessCommandRunner
from secscan.scanners.secrets import SecretsScanner

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _skip_if_no_gitleaks() -> None:
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks not installed (install via `brew install gitleaks`)")


def test_real_gitleaks_finds_aws_key_and_redacts(tmp_path: Path) -> None:
    # Plant an obvious AWS-shaped fake key in a file. gitleaks should detect
    # and emit a redacted finding.
    leaky = tmp_path / "config.py"
    leaky.write_text(
        "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
        encoding="utf-8",
    )

    scanner = SecretsScanner()
    runner = SubprocessCommandRunner()
    outcome = scanner.scan(
        WorkUnit(root=tmp_path),
        runner,
        ScanConfig(timeout_seconds=60),
    )

    assert outcome.succeeded, f"scanner errored: {outcome.error}"
    assert len(outcome.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in outcome.findings)
    # No raw secret leaked into normalized output.
    blob = " ".join(
        [f.message + " " + (f.location.file or "") for f in outcome.findings]
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "wJalrXUtnFEMI" not in blob
