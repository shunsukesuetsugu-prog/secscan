"""Tests for the pip-audit adapter."""

from __future__ import annotations

import json

from secscan.models import Severity
from secscan.runner import CommandResult
from secscan.scanners.deps.pip_audit import (
    build_findings_from_pip_audit,
    classify_pip_audit_exit,
    pip_audit_argv,
)


def _result(
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        argv=("pip-audit",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.0,
        timed_out=timed_out,
    )


# --- argv ------------------------------------------------------------------


def test_argv_for_requirements_file() -> None:
    argv = pip_audit_argv(lockfile_or_requirements="reqs.txt")
    assert "pip-audit" in argv
    assert "--format" in argv and "json" in argv
    # --strict makes pip-audit fail on dependency-resolution problems
    # rather than silently producing a partial report.
    assert "--strict" in argv
    assert "--requirement" in argv
    assert "reqs.txt" in argv


def test_argv_without_lockfile_omits_requirement_flag() -> None:
    argv = pip_audit_argv(lockfile_or_requirements=None)
    assert "--requirement" not in argv


# --- classify_pip_audit_exit ---------------------------------------------


def test_classify_clean_run() -> None:
    payload = json.dumps({"dependencies": []}).encode()
    ok, err = classify_pip_audit_exit(_result(returncode=0, stdout=payload))
    assert ok
    assert err is None


def test_classify_findings_present() -> None:
    payload = json.dumps({"dependencies": [{"name": "x", "version": "1.0", "vulns": []}]}).encode()
    ok, err = classify_pip_audit_exit(_result(returncode=1, stdout=payload))
    assert ok
    assert err is None


def test_classify_internal_error_is_failure() -> None:
    # pip-audit returns non-(0,1) for dependency-resolution failure etc.
    ok, err = classify_pip_audit_exit(
        _result(returncode=2, stderr=b"could not resolve dependencies\n")
    )
    assert not ok
    assert err is not None
    assert "could not resolve" in err


def test_classify_malformed_json_is_failure() -> None:
    ok, _err = classify_pip_audit_exit(_result(returncode=0, stdout=b"not json"))
    assert not ok


def test_classify_timeout_is_failure() -> None:
    ok, err = classify_pip_audit_exit(_result(timed_out=True))
    assert not ok
    assert err is not None


# --- build_findings_from_pip_audit ---------------------------------------


def test_parses_modern_pip_audit_shape() -> None:
    payload = json.dumps(
        {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.0.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-1",
                            "fix_versions": ["2.32.0"],
                            "aliases": ["GHSA-AAAA", "CVE-2024-1111"],
                            "description": "TLS verification bypass.",
                        }
                    ],
                }
            ]
        }
    ).encode()
    findings = build_findings_from_pip_audit(payload)
    assert len(findings) == 1
    (f,) = findings
    assert f.scanner == "deps"
    # pip-audit never provides severity → UNKNOWN.
    assert f.severity == Severity.UNKNOWN
    assert f.rule_id == "PYSEC-2024-1"
    assert f.cve == "CVE-2024-1111"
    assert f.fix_version == "2.32.0"
    assert f.location is not None
    assert f.location.package == "requests@2.0.0"
    assert f.location.ecosystem == "pypi"
    assert "TLS verification" in f.title


def test_parses_legacy_top_level_list_shape() -> None:
    """pip-audit < 2.10 produced a top-level list instead of an object."""
    payload = json.dumps(
        [
            {
                "name": "django",
                "version": "3.0",
                "vulns": [{"id": "PYSEC-X", "fix_versions": ["3.2"]}],
            }
        ]
    ).encode()
    findings = build_findings_from_pip_audit(payload)
    assert len(findings) == 1
    assert findings[0].rule_id == "PYSEC-X"
    assert findings[0].fix_version == "3.2"


def test_cve_from_advisory_id_when_no_alias() -> None:
    payload = json.dumps(
        {
            "dependencies": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-2024-9999", "fix_versions": []}],
                }
            ]
        }
    ).encode()
    (f,) = build_findings_from_pip_audit(payload)
    assert f.cve == "CVE-2024-9999"


def test_clean_report_yields_no_findings() -> None:
    payload = json.dumps({"dependencies": []}).encode()
    assert build_findings_from_pip_audit(payload) == ()


def test_unparseable_outer_shape_yields_no_findings() -> None:
    payload = json.dumps({"unrelated": "what we expect"}).encode()
    assert build_findings_from_pip_audit(payload) == ()


def test_duplicate_advisory_id_is_deduped() -> None:
    payload = json.dumps(
        {
            "dependencies": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulns": [
                        {"id": "PYSEC-DUP", "fix_versions": ["2.0"]},
                        {"id": "PYSEC-DUP", "fix_versions": ["2.1"]},
                    ],
                }
            ]
        }
    ).encode()
    findings = build_findings_from_pip_audit(payload)
    assert len(findings) == 1
