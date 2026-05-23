"""Reporter tests.

These pin user-visible output. Failures here mean the operator sees something
different from what we promised, which is itself a regression.

Covered cases:
- No findings → "no findings" string present, exit code echoed.
- Findings show severity, scanner:rule, location.
- Findings sorted by severity desc.
- Errors and warnings render with their counts and content.
- Suppressed findings only show in verbose mode.
- Color escape sequences appear only when use_color=True.
- --quiet mode produces a single-line, machine-friendly summary.
"""

from __future__ import annotations

from secscan.config import ProjectConfig
from secscan.exit_codes import ExitCode
from secscan.models import (
    Finding,
    Location,
    RunResult,
    ScannerError,
    Severity,
)
from secscan.policy import evaluate
from secscan.reporter import ReportOptions, render_report


def _finding(
    *,
    scanner: str = "secrets",
    rule_id: str = "aws-key",
    severity: Severity = Severity.HIGH,
    file: str | None = "src/a.py",
    line: int | None = 10,
    fingerprint: str = "fp",
    title: str = "AWS key found",
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=title,
        location=Location(file=file, line=line) if file else None,
        fingerprint=fingerprint,
    )


def test_no_findings_renders_clean_summary() -> None:
    decision = evaluate(RunResult(), ProjectConfig())
    out = render_report(RunResult(), decision)
    assert "no findings" in out
    assert "exit code: 0" in out


def test_findings_show_severity_scanner_rule_and_location() -> None:
    rr = RunResult(findings=(_finding(),))
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision)
    assert "[HIGH]" in out
    assert "secrets:aws-key" in out
    assert "AWS key found" in out
    assert "src/a.py:10" in out


def test_findings_sort_highest_severity_first() -> None:
    low = _finding(severity=Severity.LOW, rule_id="low-rule", fingerprint="l")
    crit = _finding(severity=Severity.CRITICAL, rule_id="crit-rule", fingerprint="c")
    med = _finding(severity=Severity.MEDIUM, rule_id="med-rule", fingerprint="m")
    rr = RunResult(findings=(low, crit, med))
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision)
    idx_crit = out.find("crit-rule")
    idx_med = out.find("med-rule")
    idx_low = out.find("low-rule")
    assert 0 <= idx_crit < idx_med < idx_low


def test_summary_lists_counts_per_severity() -> None:
    rr = RunResult(
        findings=(
            _finding(severity=Severity.HIGH, fingerprint="1"),
            _finding(severity=Severity.HIGH, fingerprint="2"),
            _finding(severity=Severity.LOW, fingerprint="3"),
        )
    )
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision)
    assert "2 high" in out
    assert "1 low" in out


def test_unknown_warning_count_shown_when_present() -> None:
    # Default unknown policy for secrets is "fail" → no warn count.
    # Default for deps is "warn" → warn count appears in the summary.
    rr_secrets = RunResult(
        findings=(_finding(severity=Severity.UNKNOWN, fingerprint="u"),)
    )
    decision_secrets = evaluate(rr_secrets, ProjectConfig())
    out_secrets = render_report(rr_secrets, decision_secrets)
    # secrets unknown is counted as crossing, not in the "warn" footer.
    assert "1 unknown" in out_secrets

    rr_deps = RunResult(
        findings=(
            _finding(
                scanner="deps", severity=Severity.UNKNOWN, fingerprint="u2"
            ),
        )
    )
    decision_deps = evaluate(rr_deps, ProjectConfig())
    out_deps = render_report(rr_deps, decision_deps)
    # deps unknown shows the "not counted toward fail-on" note.
    assert "not counted toward fail-on" in out_deps


def test_errors_section_shows_reason_and_redacted_excerpt() -> None:
    rr = RunResult(
        errors=(
            ScannerError(
                scanner="secrets",
                reason="gitleaks exited with 2",
                stderr_excerpt="something broke",
                returncode=2,
            ),
        )
    )
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision)
    assert "scanner errors" in out
    assert "gitleaks exited with 2" in out
    assert "exit 2" in out
    assert "something broke" in out
    # Errors must drive the exit code to SCAN_ERROR even with no findings.
    assert f"exit code: {int(ExitCode.SCAN_ERROR)}" in out


def test_warnings_render_with_marker() -> None:
    rr = RunResult(warnings=("baseline entry expired",))
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision)
    assert "warnings (1)" in out
    assert "baseline entry expired" in out


def test_skipped_scanners_listed() -> None:
    rr = RunResult(skipped=("sast",))
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision)
    assert "skipped scanners: sast" in out


def test_suppressed_only_visible_in_verbose() -> None:
    suppressed = (_finding(rule_id="suppressed-rule", fingerprint="sup"),)
    rr = RunResult(suppressed_by_baseline=suppressed)
    decision = evaluate(rr, ProjectConfig())
    quiet = render_report(rr, decision, ReportOptions(verbose=False))
    verbose = render_report(rr, decision, ReportOptions(verbose=True))
    assert "suppressed-rule" not in quiet
    assert "suppressed-rule" in verbose


def test_color_escapes_only_when_use_color_true() -> None:
    rr = RunResult(findings=(_finding(),))
    decision = evaluate(rr, ProjectConfig())
    plain = render_report(rr, decision, ReportOptions(use_color=False))
    colored = render_report(rr, decision, ReportOptions(use_color=True))
    assert "\x1b[" not in plain
    assert "\x1b[" in colored


def test_quiet_mode_emits_single_machine_line() -> None:
    rr = RunResult(
        findings=(_finding(),),
        errors=(ScannerError(scanner="x", reason="r"),),
    )
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision, ReportOptions(quiet=True))
    lines = out.strip().splitlines()
    assert len(lines) == 1
    assert "findings=1" in out
    assert "errors=1" in out
    assert "exit=" in out


def test_threshold_label_displays_lowercase() -> None:
    rr = RunResult()
    decision = evaluate(rr, ProjectConfig(fail_on=Severity.MEDIUM))
    out = render_report(rr, decision)
    assert "threshold: medium" in out


def test_verbose_shows_message_and_references() -> None:
    f = Finding(
        scanner="deps",
        rule_id="CVE-1",
        severity=Severity.HIGH,
        title="Vulnerable lib",
        message="detailed explanation here",
        location=Location(package="lodash", ecosystem="npm"),
        fingerprint="d1",
        cve="CVE-2024-9999",
        references=("https://example.com/advisory",),
    )
    rr = RunResult(findings=(f,))
    decision = evaluate(rr, ProjectConfig())
    out = render_report(rr, decision, ReportOptions(verbose=True))
    assert "detailed explanation" in out
    assert "CVE-2024-9999" in out
    assert "example.com/advisory" in out
    # Package shown with ecosystem prefix.
    assert "npm:lodash" in out
