"""Threshold / exit-code policy.

Scanners produce findings; this module decides what counts as a "failure".
Keeping policy out of Scanner classes is deliberate — a scanner returning a
HIGH finding should not change behavior depending on what fail-on level the
user configured, and an ``all`` run should not run policy three times
inconsistently.

The decision tree:

1. Apply per-scanner ``severity_overrides`` to each finding's severity.
2. For each finding's severity:
   - If ``UNKNOWN``, consult ``severity_unknown_policy`` for that scanner.
     - ``"warn"``   → contributes to "we saw something" but never crosses
                      the threshold.
     - ``"fail"``   → treated as exactly the configured fail-on level.
     - ``"ignore"`` → still displayed (Reporter), but excluded from the
                      threshold check.
   - Otherwise compare to fail-on numerically.
3. If any finding crosses the threshold AND there are no scanner errors,
   exit code is FINDINGS.
4. If any scanner error occurred, exit code is SCAN_ERROR (severity-wise,
   inconclusive is worse than "policy violation" because CI operators must
   not mistake a broken scan for a clean scan).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .config import ProjectConfig
from .exit_codes import ExitCode
from .models import Finding, RunResult, Severity


@dataclass(frozen=True)
class PolicyDecision:
    exit_code: ExitCode
    threshold: Severity
    """The effective fail-on level (post-config)."""
    crossing_findings: tuple[Finding, ...]
    """Findings at-or-above threshold (after override + unknown policy)."""
    unknown_warning_count: int
    """Findings with UNKNOWN severity counted for display only ('warn')."""


def apply_overrides(findings: tuple[Finding, ...], config: ProjectConfig) -> tuple[Finding, ...]:
    """Apply ``[severity_overrides.<scanner>]`` mappings.

    Returns a new tuple of findings with possibly-modified severities. The
    Finding dataclass is frozen, so we construct replacements via ``dataclasses.replace``.
    """
    if not config.severity_overrides:
        return findings

    from dataclasses import replace

    result: list[Finding] = []
    for finding in findings:
        scanner_overrides = config.severity_overrides.get(finding.scanner)
        if scanner_overrides is None:
            result.append(finding)
            continue
        new_sev = scanner_overrides.get(finding.rule_id)
        if new_sev is None:
            result.append(finding)
            continue
        result.append(replace(finding, severity=new_sev))
    return tuple(result)


def evaluate(result: RunResult, config: ProjectConfig) -> PolicyDecision:
    """Compute the final exit code for a RunResult.

    ``threshold == Severity.NEVER`` (the ``--fail-on=none`` alias) means
    "never fail on findings" — no severity, including UNKNOWN under
    ``severity_unknown_policy="fail"``, can cross it. Codex 15th review
    flagged that the previous "fail" branch upgraded UNKNOWN to
    ``config.fail_on``, making ``NEVER >= NEVER`` true and producing a
    contract-violating exit 1.
    """
    threshold = config.fail_on
    crossing: list[Finding] = []
    unknown_warns = 0

    if threshold == Severity.NEVER:
        # Walk findings only to count UNKNOWN-warn entries for the display
        # footer; nothing can cross.
        for finding in result.findings:
            if finding.severity == Severity.UNKNOWN:
                policy = config.severity_unknown_policy.for_scanner(finding.scanner)
                if policy == "warn":
                    unknown_warns += 1
        exit_code = ExitCode.SCAN_ERROR if result.has_errors else ExitCode.OK
        return PolicyDecision(
            exit_code=exit_code,
            threshold=threshold,
            crossing_findings=(),
            unknown_warning_count=unknown_warns,
        )

    for finding in result.findings:
        effective = _effective_severity_for_policy(finding, config)
        if effective is None:
            # "ignore" policy: contributes nothing.
            continue
        if effective == "warn_only":
            unknown_warns += 1
            continue
        # mypy: ruled out None and the only string literal above.
        if effective >= threshold:
            crossing.append(finding)

    if result.has_errors:
        exit_code = ExitCode.SCAN_ERROR
    elif crossing:
        exit_code = ExitCode.FINDINGS
    else:
        exit_code = ExitCode.OK

    return PolicyDecision(
        exit_code=exit_code,
        threshold=threshold,
        crossing_findings=tuple(crossing),
        unknown_warning_count=unknown_warns,
    )


def _effective_severity_for_policy(
    finding: Finding, config: ProjectConfig
) -> Severity | Literal["warn_only"] | None:
    """Map a finding to its policy-effective severity.

    Returns:
    - A ``Severity`` if the finding participates in the threshold check.
    - The literal ``"warn_only"`` if it's an UNKNOWN counted for display.
    - ``None`` if it should be excluded entirely from the threshold (ignore
      policy, or fail_on=UNKNOWN-or-below).
    """
    if finding.severity == Severity.UNKNOWN:
        policy = config.severity_unknown_policy.for_scanner(finding.scanner)
        if policy == "ignore":
            return None
        if policy == "warn":
            return "warn_only"
        # "fail" → treat as the threshold itself
        return config.fail_on
    return finding.severity
