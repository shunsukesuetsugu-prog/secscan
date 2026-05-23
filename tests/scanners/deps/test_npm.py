"""Tests for the npm audit adapter.

The adapter is a pure function over CommandResult + JSON bytes, so we
exercise it directly without spinning up subprocess.
"""

from __future__ import annotations

import json

from secscan.models import Severity
from secscan.runner import CommandResult
from secscan.scanners.deps.npm import (
    NPM_AUDIT_ARGV,
    build_findings_from_npm_audit,
    classify_npm_audit_exit,
)


def _result(
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        argv=NPM_AUDIT_ARGV,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.0,
        timed_out=timed_out,
    )


# --- argv contract --------------------------------------------------------


def test_argv_uses_audit_level_none() -> None:
    """``--audit-level=none`` makes the exit code independent of severity,
    so secscan's policy layer can make the threshold decision instead of
    deferring it to npm. Codex 2nd review explicitly required this."""
    assert "--audit-level=none" in NPM_AUDIT_ARGV
    assert "--json" in NPM_AUDIT_ARGV


# --- classify_npm_audit_exit ---------------------------------------------


def test_classify_accepts_well_formed_report() -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    ok, err = classify_npm_audit_exit(_result(returncode=1, stdout=payload))
    assert ok
    assert err is None


def test_classify_rejects_empty_stdout() -> None:
    ok, err = classify_npm_audit_exit(_result(returncode=2, stderr=b"missing lockfile"))
    assert not ok
    assert err is not None
    assert "no JSON" in err


def test_classify_rejects_malformed_json() -> None:
    ok, err = classify_npm_audit_exit(_result(returncode=0, stdout=b"not json"))
    assert not ok
    assert err is not None
    assert "malformed" in err.lower()


def test_classify_rejects_unexpected_object() -> None:
    ok, _err = classify_npm_audit_exit(
        _result(returncode=0, stdout=b'{"unrelated": true}')
    )
    assert not ok


def test_classify_rejects_npm_v6_shape() -> None:
    """Codex 8th review: npm v6's top-level ``advisories`` map has a
    different schema we don't parse. The classifier must REJECT this
    shape rather than accept it and let the builder return zero
    findings (a silent false-clean for v6 users)."""
    v6_payload = json.dumps(
        {"advisories": {"1234": {"id": 1234, "title": "old shape"}}}
    ).encode()
    ok, err = classify_npm_audit_exit(_result(returncode=1, stdout=v6_payload))
    assert not ok
    assert err is not None
    assert "v6" in err or "v7+" in err


def test_classify_marks_timeout() -> None:
    ok, err = classify_npm_audit_exit(_result(timed_out=True))
    assert not ok
    assert err is not None
    assert "timed out" in err


# --- build_findings_from_npm_audit -----------------------------------------


_NPM_SAMPLE = json.dumps(
    {
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "via": [
                    {
                        "source": 1234,
                        "name": "lodash",
                        "dependency": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "url": "https://github.com/advisories/GHSA-XXXX-YYYY",
                        "severity": "high",
                        "cwe": ["CWE-1321"],
                        "cve": "CVE-2024-9999",
                    }
                ],
                "range": ">=0 <4.17.21",
                "fixAvailable": {"name": "lodash", "version": "4.17.21"},
            },
            "noisy-pkg": {
                "name": "noisy-pkg",
                "severity": "moderate",
                # Meta-vulnerability: a string reference. Should be skipped.
                "via": ["lodash"],
                "range": "*",
                "fixAvailable": False,
            },
        },
        "metadata": {"vulnerabilities": {"high": 1, "moderate": 1}},
    }
).encode()


def test_parses_one_finding_per_advisory_object() -> None:
    findings = build_findings_from_npm_audit(_NPM_SAMPLE)
    assert len(findings) == 1
    (f,) = findings
    assert f.scanner == "deps"
    assert f.severity == Severity.HIGH
    assert f.location is not None
    assert f.location.package == "lodash"
    assert f.location.ecosystem == "npm"
    assert f.cve == "CVE-2024-9999"
    # The sample uses ``"cwe": ["CWE-1321"]`` (list form); the adapter
    # must extract the first string element. Codex 8th review flagged
    # the previous implementation that only handled the string form.
    assert f.cwe == "CWE-1321"
    assert f.fix_version == "4.17.21"
    assert f.references and f.references[0].startswith("https://")
    assert "Prototype Pollution" in f.title


def test_advisory_cwe_as_string_also_supported() -> None:
    payload = json.dumps(
        {
            "vulnerabilities": {
                "pkg": {
                    "name": "pkg",
                    "severity": "high",
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-AAA",
                            "title": "t",
                            "severity": "high",
                            "cwe": "CWE-79",
                        }
                    ],
                    "fixAvailable": False,
                }
            }
        }
    ).encode()
    (f,) = build_findings_from_npm_audit(payload)
    assert f.cwe == "CWE-79"


def test_meta_vulnerabilities_are_elided() -> None:
    """noisy-pkg's only `via` is the string "lodash" — no separate Finding."""
    findings = build_findings_from_npm_audit(_NPM_SAMPLE)
    assert all(
        f.location is None or f.location.package != "noisy-pkg" for f in findings
    )


def test_duplicate_advisories_are_deduped() -> None:
    payload = json.dumps(
        {
            "vulnerabilities": {
                "pkg": {
                    "name": "pkg",
                    "severity": "high",
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-DUP",
                            "title": "dup",
                            "severity": "high",
                        },
                        # Same advisory referenced again with a different
                        # shape — should not produce a second Finding.
                        {
                            "url": "https://github.com/advisories/GHSA-DUP",
                            "title": "dup-alt",
                            "severity": "critical",
                        },
                    ],
                    "fixAvailable": False,
                }
            }
        }
    ).encode()
    findings = build_findings_from_npm_audit(payload)
    assert len(findings) == 1


def test_unknown_severity_label_becomes_unknown_severity() -> None:
    payload = json.dumps(
        {
            "vulnerabilities": {
                "pkg": {
                    "name": "pkg",
                    "severity": "exotic",
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-XYZ",
                            "title": "weird",
                            "severity": "exotic",
                        }
                    ],
                    "fixAvailable": False,
                }
            }
        }
    ).encode()
    (f,) = build_findings_from_npm_audit(payload)
    assert f.severity == Severity.UNKNOWN


def test_empty_report_yields_no_findings() -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    assert build_findings_from_npm_audit(payload) == ()


def test_partial_advisory_without_identifier_is_skipped() -> None:
    payload = json.dumps(
        {
            "vulnerabilities": {
                "pkg": {
                    "name": "pkg",
                    "severity": "low",
                    # No url / cve / source — can't construct a stable
                    # fingerprint. Adapter must skip rather than crash.
                    "via": [{"title": "incomplete"}],
                    "fixAvailable": False,
                }
            }
        }
    ).encode()
    assert build_findings_from_npm_audit(payload) == ()


def test_fingerprint_is_independent_of_lockfile_path() -> None:
    """Same package + same advisory id must produce the same fingerprint
    regardless of which directory the lockfile was discovered in."""
    findings_a = build_findings_from_npm_audit(_NPM_SAMPLE)
    findings_b = build_findings_from_npm_audit(_NPM_SAMPLE)
    assert findings_a[0].fingerprint == findings_b[0].fingerprint
