"""Tests for secscan-json v1 formatter.

The schema/format_version pair is part of the public contract — downstream
tools key on those — so we pin them. The rest of the tests guard the
security invariants Codex 17th review demanded (no raw / no raw_fingerprint)
and the round-trip shape (every documented field shows up).
"""

from __future__ import annotations

import json

from secscan import __version__ as SECSCAN_VERSION
from secscan.config import ProjectConfig
from secscan.exit_codes import ExitCode
from secscan.formatters import format_json
from secscan.formatters.json_format import FORMAT_VERSION, SCHEMA_NAME
from secscan.models import (
    Finding,
    Location,
    RunResult,
    ScannerError,
    Severity,
)
from secscan.policy import evaluate


def _finding(
    *,
    scanner: str = "secrets",
    severity: Severity = Severity.HIGH,
    rule_id: str = "aws-key",
    fingerprint: str = "fp1",
    file: str | None = "src/a.py",
    line: int | None = 10,
    raw: dict | None = None,
    raw_fingerprint: str | None = None,
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        title="t",
        message="m",
        location=Location(file=file, line=line) if file else None,
        fingerprint=fingerprint,
        raw=raw,
        raw_fingerprint=raw_fingerprint,
    )


def _parsed(result: RunResult) -> dict:
    decision = evaluate(result, ProjectConfig())
    return json.loads(format_json(result, decision))


# --- schema identifier --------------------------------------------------


def test_schema_identifier_and_version_are_pinned() -> None:
    out = _parsed(RunResult())
    assert out["schema"] == SCHEMA_NAME
    assert out["format_version"] == FORMAT_VERSION
    assert out["secscan_version"] == SECSCAN_VERSION


def test_threshold_and_exit_code_are_present() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.HIGH),))
    out = _parsed(rr)
    assert out["threshold"] == "high"
    assert out["exit_code"] == int(ExitCode.FINDINGS)


# --- summary ------------------------------------------------------------


def test_summary_counts_by_severity_match_findings() -> None:
    rr = RunResult(
        findings=(
            _finding(severity=Severity.CRITICAL, fingerprint="c"),
            _finding(severity=Severity.HIGH, fingerprint="h1"),
            _finding(severity=Severity.HIGH, fingerprint="h2"),
            _finding(severity=Severity.LOW, fingerprint="l"),
        )
    )
    out = _parsed(rr)
    counts = out["summary"]["counts_by_severity"]
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 0
    assert counts["low"] == 1
    assert out["summary"]["findings_total"] == 4


# --- finding shape ------------------------------------------------------


def test_finding_payload_contains_documented_fields() -> None:
    f = Finding(
        scanner="deps",
        rule_id="CVE-2024-1",
        severity=Severity.HIGH,
        title="t",
        message="m",
        location=Location(package="lodash", ecosystem="npm"),
        fingerprint="fp",
        cve="CVE-2024-1",
        cwe="CWE-79",
        fix_version="4.17.21",
        references=("https://example.com/a",),
        tool_version="10.2.0",
    )
    out = _parsed(RunResult(findings=(f,)))
    payload = out["findings"][0]
    assert payload["scanner"] == "deps"
    assert payload["rule_id"] == "CVE-2024-1"
    assert payload["severity"] == "high"
    assert payload["title"] == "t"
    assert payload["fingerprint"] == "fp"
    assert payload["cve"] == "CVE-2024-1"
    assert payload["cwe"] == "CWE-79"
    assert payload["fix_version"] == "4.17.21"
    assert payload["references"] == ["https://example.com/a"]
    assert payload["tool_version"] == "10.2.0"
    assert payload["location"]["package"] == "lodash"
    assert payload["location"]["ecosystem"] == "npm"


# --- security invariants ------------------------------------------------


def test_finding_raw_field_is_never_serialized() -> None:
    """Codex 17th review: ``Finding.raw`` must never leak into output.

    gitleaks raw payloads contain pre-redaction fields we have not
    audited for downstream consumption.
    """
    rr = RunResult(
        findings=(_finding(raw={"Secret": "should-not-leak", "Match": "...secret..."}),)
    )
    blob = format_json(rr, evaluate(rr, ProjectConfig()))
    # Direct: the key isn't in any finding.
    assert '"raw"' not in blob
    # Indirect: the secret string isn't anywhere in the output either.
    assert "should-not-leak" not in blob


def test_finding_raw_fingerprint_is_never_serialized() -> None:
    """raw_fingerprint can embed file paths that bypass orchestrator's
    path-stripping (gitleaks's Fingerprint field is "file:rule:line"
    using the gitleaks-side path). We deliberately don't include it."""
    rr = RunResult(
        findings=(_finding(raw_fingerprint="path/in/gitleaks/output:rule:1"),)
    )
    out = _parsed(rr)
    assert "raw_fingerprint" not in out["findings"][0]


# --- errors / warnings / skipped / suppressed --------------------------


def test_errors_appear_with_returncode() -> None:
    rr = RunResult(
        errors=(
            ScannerError(
                scanner="deps",
                reason="npm exited 2",
                stderr_excerpt="missing lockfile",
                returncode=2,
            ),
        )
    )
    out = _parsed(rr)
    (err,) = out["errors"]
    assert err["scanner"] == "deps"
    assert err["returncode"] == 2
    assert err["stderr_excerpt"] == "missing lockfile"


def test_warnings_and_skipped_lists_pass_through() -> None:
    rr = RunResult(warnings=("baseline entry expired",), skipped=("sast",))
    out = _parsed(rr)
    assert out["warnings"] == ["baseline entry expired"]
    assert out["skipped"] == ["sast"]


def test_suppressed_by_baseline_appears_in_dedicated_array() -> None:
    suppressed = _finding(rule_id="known-rule", fingerprint="sup")
    rr = RunResult(suppressed_by_baseline=(suppressed,))
    out = _parsed(rr)
    # Visible findings array stays empty; suppressed has its own bucket.
    assert out["findings"] == []
    assert len(out["suppressed_by_baseline"]) == 1
    assert out["suppressed_by_baseline"][0]["rule_id"] == "known-rule"


def test_output_is_valid_json_terminated_by_newline() -> None:
    rr = RunResult()
    blob = format_json(rr, evaluate(rr, ProjectConfig()))
    assert blob.endswith("\n")
    json.loads(blob)  # round-trips without raising


def test_output_sort_keys_for_deterministic_diffs() -> None:
    """We sort keys so diffs are stable across runs (useful for snapshot
    tests in downstream projects)."""
    rr = RunResult(findings=(_finding(),))
    blob = format_json(rr, evaluate(rr, ProjectConfig()))
    # Reparse + re-dump with sort_keys=True; should match.
    parsed = json.loads(blob)
    assert json.dumps(parsed, indent=2, sort_keys=True) + "\n" == blob


# --- multiple findings ordering ----------------------------------------


def test_findings_preserve_original_order() -> None:
    """The JSON formatter does NOT re-sort findings — the orchestrator
    handed them to us in scan order; downstream tools that want a
    different order can do it themselves with stable keys."""
    f1 = _finding(scanner="a", fingerprint="1")
    f2 = _finding(scanner="b", fingerprint="2")
    out = _parsed(RunResult(findings=(f1, f2)))
    assert [f["fingerprint"] for f in out["findings"]] == ["1", "2"]


def test_options_argument_is_accepted_but_does_not_affect_payload() -> None:
    """The JSON formatter currently has no user-facing toggles. Pin that
    passing options is harmless so we can grow this without callers
    needing updates."""
    from secscan.formatters.base import FormatOptions

    rr = RunResult(findings=(_finding(),))
    default_blob = format_json(rr, evaluate(rr, ProjectConfig()))
    custom_blob = format_json(
        rr,
        evaluate(rr, ProjectConfig()),
        FormatOptions(use_color=True, verbose=True, quiet=False),
    )
    assert default_blob == custom_blob
