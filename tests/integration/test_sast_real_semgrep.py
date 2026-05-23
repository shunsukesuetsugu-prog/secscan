"""Minimal end-to-end test against a real semgrep binary.

Skipped when semgrep is not on PATH. Semgrep is in our [dev] extras, so
this should usually run during development; CI environments without it
gracefully skip.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secscan.models import ScanConfig, Severity, WorkUnit
from secscan.runner import SubprocessCommandRunner
from secscan.scanners.sast import SastScanner

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _skip_if_no_semgrep() -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep not installed (install via `pip install semgrep`)")


def test_real_semgrep_finds_yaml_load(tmp_path: Path) -> None:
    """Plant a known-bad python file and verify semgrep + the adapter
    produces a normalized HIGH finding.

    We use a LOCAL rule file (not a registry ruleset like ``p/python``) so
    the test is hermetic: no network access, no dependency on the current
    registry contents, and a stable rule_id we can assert against.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "import yaml\n"
        "def load(x):\n"
        "    return yaml.load(x)\n",
        encoding="utf-8",
    )
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text(
        "rules:\n"
        "  - id: secscan-test.yaml-load\n"
        "    pattern: yaml.load($X)\n"
        "    message: dangerous yaml.load — use yaml.safe_load\n"
        "    languages: [python]\n"
        "    severity: ERROR\n",
        encoding="utf-8",
    )

    scanner = SastScanner()
    runner = SubprocessCommandRunner()
    outcome = scanner.scan(
        WorkUnit(root=tmp_path),
        runner,
        ScanConfig(
            timeout_seconds=180,
            extra={"semgrep_config": (str(rule_file),)},
        ),
    )

    assert outcome.succeeded, f"semgrep errored: {outcome.error}"
    assert outcome.findings, "expected at least one finding"
    yaml_findings = [
        f
        for f in outcome.findings
        if "yaml-load" in f.rule_id and f.location is not None
        and f.location.file and "vuln.py" in f.location.file
    ]
    assert yaml_findings, f"no yaml-load findings: {outcome.findings}"
    (f,) = yaml_findings
    assert f.severity == Severity.HIGH  # ERROR → HIGH normalization
    assert f.location is not None
    assert f.location.line == 3  # the yaml.load() call
