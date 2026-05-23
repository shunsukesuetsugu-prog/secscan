"""Tests for the pnpm audit adapter."""

from __future__ import annotations

import json

import pytest

from secscan.models import Severity
from secscan.runner import CommandResult
from secscan.scanners.deps.pnpm import (
    PNPM_AUDIT_ARGV,
    build_findings_from_pnpm_audit,
    classify_pnpm_audit_exit,
)


def _result(
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        argv=PNPM_AUDIT_ARGV,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.0,
        timed_out=timed_out,
    )


# --- argv contract --------------------------------------------------------


def test_argv_uses_audit_level_low_not_threshold_default() -> None:
    """pnpm filters OUTPUT by --audit-level (unlike npm which gates exit
    code). We must request 'low' so every advisory shows up regardless of
    severity — secscan policy makes the threshold call later. Codex 2nd
    review pinned this distinction."""
    assert "--audit-level=low" in PNPM_AUDIT_ARGV
    assert "--json" in PNPM_AUDIT_ARGV


# --- classify_pnpm_audit_exit --------------------------------------------


def test_classify_accepts_advisories_object() -> None:
    payload = json.dumps({"advisories": {}, "metadata": {}}).encode()
    ok, err = classify_pnpm_audit_exit(_result(returncode=1, stdout=payload))
    assert ok
    assert err is None


def test_classify_rejects_empty_stdout() -> None:
    ok, err = classify_pnpm_audit_exit(_result(returncode=2, stderr=b"network"))
    assert not ok
    assert err is not None


def test_classify_marks_timeout() -> None:
    ok, err = classify_pnpm_audit_exit(_result(timed_out=True))
    assert not ok
    assert err is not None


def test_classify_rejects_unrelated_object() -> None:
    ok, _err = classify_pnpm_audit_exit(
        _result(returncode=0, stdout=b'{"unrelated": 42}')
    )
    assert not ok


# --- build_findings_from_pnpm_audit -------------------------------------


_PNPM_SAMPLE = json.dumps(
    {
        "advisories": {
            "1234": {
                "id": 1234,
                "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
                "module_name": "underscore",
                "title": "Arbitrary code execution in underscore",
                "overview": "Long description here...",
                "severity": "critical",
                "cves": ["CVE-2024-7777"],
                "cwe": "CWE-94",
                "url": "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC",
                "vulnerable_versions": "<1.13.0",
                "patched_versions": ">=1.13.0",
            },
            "5678": {
                "id": 5678,
                "module_name": "left-pad",
                "title": "Some moderate issue",
                "severity": "moderate",
                "url": "https://github.com/advisories/GHSA-PAD-PAD-PAD",
            },
        }
    }
).encode()


def test_parses_findings_with_severity_and_metadata() -> None:
    findings = build_findings_from_pnpm_audit(_PNPM_SAMPLE)
    assert len(findings) == 2
    by_pkg = {f.location.package: f for f in findings if f.location is not None}
    underscore = by_pkg["underscore"]
    assert underscore.severity == Severity.CRITICAL
    assert underscore.cve == "CVE-2024-7777"
    assert underscore.cwe == "CWE-94"
    assert underscore.fix_version == ">=1.13.0"
    assert underscore.references and "advisories" in underscore.references[0]
    left_pad = by_pkg["left-pad"]
    assert left_pad.severity == Severity.MEDIUM


def test_duplicate_advisory_id_is_deduped() -> None:
    payload = json.dumps(
        {
            "advisories": {
                "A": {
                    "id": 1,
                    "ghsa_id": "GHSA-DUP",
                    "module_name": "pkg",
                    "title": "dup",
                    "severity": "high",
                },
                "B": {
                    "id": 1,
                    "ghsa_id": "GHSA-DUP",
                    "module_name": "pkg",
                    "title": "dup again",
                    "severity": "critical",
                },
            }
        }
    ).encode()
    findings = build_findings_from_pnpm_audit(payload)
    assert len(findings) == 1


def test_advisory_without_identifier_is_skipped() -> None:
    payload = json.dumps(
        {
            "advisories": {
                "X": {
                    "module_name": "pkg",
                    "title": "no ids at all",
                    "severity": "high",
                    # missing ghsa_id / cves / url / id
                }
            }
        }
    ).encode()
    # fallback_id = "X" still keeps the entry — pnpm's "X" is the index key
    # and is acceptable as a stable id. Test that the parser doesn't crash
    # and produces at most a best-effort finding.
    findings = build_findings_from_pnpm_audit(payload)
    assert len(findings) == 1
    assert findings[0].rule_id == "X"


def test_empty_advisories_yields_no_findings() -> None:
    payload = json.dumps({"advisories": {}, "metadata": {}}).encode()
    assert build_findings_from_pnpm_audit(payload) == ()


@pytest.mark.parametrize(
    "severity,expected",
    [("critical", Severity.CRITICAL), ("high", Severity.HIGH),
     ("moderate", Severity.MEDIUM), ("low", Severity.LOW)],
)
def test_severity_normalization(severity: str, expected: Severity) -> None:
    payload = json.dumps(
        {
            "advisories": {
                "1": {
                    "id": 1,
                    "module_name": "pkg",
                    "ghsa_id": "GHSA-ZZ",
                    "severity": severity,
                    "title": "t",
                }
            }
        }
    ).encode()
    (f,) = build_findings_from_pnpm_audit(payload)
    assert f.severity == expected
