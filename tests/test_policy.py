"""Tests for fail-on / exit-code policy.

The threshold logic is small but security-critical: misclassifying a HIGH
finding as below threshold, or treating UNKNOWN as silently-clean, would be a
regression. We cover every branch of the decision tree:
- No findings → OK
- Findings below threshold → OK
- Findings at threshold → FINDINGS
- Findings above threshold → FINDINGS
- Scanner errors → SCAN_ERROR (wins over FINDINGS)
- UNKNOWN with policy=warn → never crosses
- UNKNOWN with policy=fail → crosses at threshold
- UNKNOWN with policy=ignore → excluded
- severity_overrides upgrade / downgrade
"""

from __future__ import annotations

from secscan.config import ProjectConfig, UnknownSeverityPolicy
from secscan.exit_codes import ExitCode
from secscan.models import (
    Finding,
    Location,
    RunResult,
    ScannerError,
    Severity,
)
from secscan.policy import apply_overrides, evaluate


def _finding(
    scanner: str = "secrets",
    rule_id: str = "r1",
    severity: Severity = Severity.HIGH,
    fingerprint: str = "fp",
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        title="t",
        message="m",
        location=Location(file="a.py", line=1),
        fingerprint=fingerprint,
    )


def _config(
    *,
    fail_on: Severity = Severity.HIGH,
    unknown: UnknownSeverityPolicy | None = None,
    overrides: dict[str, dict[str, Severity]] | None = None,
) -> ProjectConfig:
    return ProjectConfig(
        fail_on=fail_on,
        severity_unknown_policy=unknown or UnknownSeverityPolicy(),
        severity_overrides=overrides or {},
    )


# --- apply_overrides -------------------------------------------------------


def test_apply_overrides_upgrades_matching_rule() -> None:
    f = _finding(severity=Severity.MEDIUM, rule_id="aws-key")
    cfg = _config(overrides={"secrets": {"aws-key": Severity.CRITICAL}})
    (out,) = apply_overrides((f,), cfg)
    assert out.severity == Severity.CRITICAL


def test_apply_overrides_can_downgrade() -> None:
    f = _finding(severity=Severity.HIGH, rule_id="noisy-rule")
    cfg = _config(overrides={"secrets": {"noisy-rule": Severity.LOW}})
    (out,) = apply_overrides((f,), cfg)
    assert out.severity == Severity.LOW


def test_apply_overrides_leaves_unmatched_unchanged() -> None:
    f = _finding(severity=Severity.HIGH, rule_id="other")
    cfg = _config(overrides={"secrets": {"aws-key": Severity.CRITICAL}})
    (out,) = apply_overrides((f,), cfg)
    assert out.severity == Severity.HIGH


def test_apply_overrides_scoped_to_scanner() -> None:
    # Same rule_id across scanners — override should NOT bleed.
    f = _finding(scanner="sast", rule_id="shared-id", severity=Severity.MEDIUM)
    cfg = _config(overrides={"secrets": {"shared-id": Severity.CRITICAL}})
    (out,) = apply_overrides((f,), cfg)
    assert out.severity == Severity.MEDIUM


def test_apply_overrides_no_op_when_empty() -> None:
    f = _finding()
    out = apply_overrides((f,), _config())
    assert out == (f,)


# --- evaluate: thresholds --------------------------------------------------


def test_evaluate_ok_with_no_findings() -> None:
    decision = evaluate(RunResult(), _config())
    assert decision.exit_code == ExitCode.OK
    assert decision.crossing_findings == ()


def test_evaluate_ok_when_all_findings_below_threshold() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.MEDIUM),))
    decision = evaluate(rr, _config(fail_on=Severity.HIGH))
    assert decision.exit_code == ExitCode.OK


def test_evaluate_findings_at_threshold() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.HIGH),))
    decision = evaluate(rr, _config(fail_on=Severity.HIGH))
    assert decision.exit_code == ExitCode.FINDINGS
    assert len(decision.crossing_findings) == 1


def test_evaluate_findings_above_threshold() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.CRITICAL),))
    decision = evaluate(rr, _config(fail_on=Severity.HIGH))
    assert decision.exit_code == ExitCode.FINDINGS


def test_evaluate_scanner_error_wins_over_findings() -> None:
    rr = RunResult(
        findings=(_finding(severity=Severity.CRITICAL),),
        errors=(ScannerError(scanner="x", reason="boom"),),
    )
    decision = evaluate(rr, _config(fail_on=Severity.HIGH))
    # Inconclusive scans must NOT be reported as policy violation.
    assert decision.exit_code == ExitCode.SCAN_ERROR


# --- evaluate: UNKNOWN handling -------------------------------------------


def test_unknown_with_warn_policy_never_crosses() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.UNKNOWN),))
    cfg = _config(unknown=UnknownSeverityPolicy(secrets="warn"))
    decision = evaluate(rr, cfg)
    assert decision.exit_code == ExitCode.OK
    assert decision.unknown_warning_count == 1


def test_unknown_with_fail_policy_crosses_at_threshold() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.UNKNOWN),))
    cfg = _config(
        fail_on=Severity.HIGH,
        unknown=UnknownSeverityPolicy(secrets="fail"),
    )
    decision = evaluate(rr, cfg)
    assert decision.exit_code == ExitCode.FINDINGS
    assert decision.crossing_findings != ()


def test_unknown_with_ignore_policy_does_not_contribute() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.UNKNOWN),))
    cfg = _config(unknown=UnknownSeverityPolicy(secrets="ignore"))
    decision = evaluate(rr, cfg)
    assert decision.exit_code == ExitCode.OK
    assert decision.unknown_warning_count == 0
    assert decision.crossing_findings == ()


def test_fail_on_never_overrides_unknown_fail_policy() -> None:
    """Codex 15th review: ``--fail-on=none`` (= Severity.NEVER) must
    GUARANTEE exit 0 — including for UNKNOWN findings whose unknown
    policy is "fail". Previously the "fail" branch upgraded UNKNOWN to
    ``config.fail_on`` (=NEVER), and ``NEVER >= NEVER`` was True, so
    the finding crossed the threshold and the run exited 1. Pin the
    contract: when threshold is NEVER, NOTHING crosses."""
    rr = RunResult(
        findings=(
            _finding(severity=Severity.UNKNOWN, scanner="secrets"),
            _finding(severity=Severity.CRITICAL, fingerprint="c"),
        )
    )
    cfg = _config(
        fail_on=Severity.NEVER,
        unknown=UnknownSeverityPolicy(secrets="fail"),
    )
    decision = evaluate(rr, cfg)
    assert decision.exit_code == ExitCode.OK
    assert decision.crossing_findings == ()


def test_fail_on_never_still_propagates_scanner_errors() -> None:
    """The 'never' threshold still does not mask scanner errors —
    inconclusive scans remain exit 2 regardless of fail-on."""
    rr = RunResult(errors=(ScannerError(scanner="x", reason="r"),))
    cfg = _config(fail_on=Severity.NEVER)
    decision = evaluate(rr, cfg)
    assert decision.exit_code == ExitCode.SCAN_ERROR


def test_fail_on_never_still_counts_unknown_warnings_for_display() -> None:
    """The display footer should still show how many UNKNOWN findings
    the deps scanner produced even though the threshold accepts them."""
    rr = RunResult(
        findings=(
            _finding(scanner="deps", severity=Severity.UNKNOWN, fingerprint="d"),
        )
    )
    cfg = _config(
        fail_on=Severity.NEVER,
        unknown=UnknownSeverityPolicy(deps="warn"),
    )
    decision = evaluate(rr, cfg)
    assert decision.unknown_warning_count == 1


def test_unknown_policy_is_per_scanner() -> None:
    # secrets=fail, deps=warn → deps UNKNOWN doesn't trigger but secrets does.
    secrets_unknown = _finding(scanner="secrets", severity=Severity.UNKNOWN, fingerprint="s")
    deps_unknown = _finding(scanner="deps", severity=Severity.UNKNOWN, fingerprint="d")
    rr = RunResult(findings=(secrets_unknown, deps_unknown))
    cfg = _config(
        fail_on=Severity.HIGH,
        unknown=UnknownSeverityPolicy(deps="warn", secrets="fail"),
    )
    decision = evaluate(rr, cfg)
    assert decision.exit_code == ExitCode.FINDINGS
    # Only the secrets one crosses; deps stays in warn count.
    assert decision.unknown_warning_count == 1
    assert all(f.scanner == "secrets" for f in decision.crossing_findings)
