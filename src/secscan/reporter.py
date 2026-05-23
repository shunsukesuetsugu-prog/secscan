"""Terminal output.

Pure functions that turn a ``RunResult`` (plus a ``PolicyDecision``) into a
string for stdout. Pure-function style is intentional: tests assert on the
rendered string without capturing process stdout, and the CLI layer is the
only place that actually prints.

Color is opt-in via ``use_color=True``. We use raw ANSI escapes (no rich
dependency at this layer — rich pulls in too much for a single-purpose
report). ``isatty()`` checks belong to the CLI, not the reporter.
"""

from __future__ import annotations

from dataclasses import dataclass

from .baseline import BaselineApplication
from .models import Finding, RunResult, Severity
from .policy import PolicyDecision

# ANSI escapes — no dependency, easy to disable.
_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\x1b[1;31m",  # bold red
    Severity.HIGH: "\x1b[31m",         # red
    Severity.MEDIUM: "\x1b[33m",       # yellow
    Severity.LOW: "\x1b[36m",          # cyan
    Severity.INFO: "\x1b[34m",         # blue
    Severity.UNKNOWN: "\x1b[35m",      # magenta
}


@dataclass(frozen=True)
class ReportOptions:
    use_color: bool = False
    verbose: bool = False
    quiet: bool = False


# Module-level singleton — ReportOptions is frozen, so reusing one instance is
# safe and lets us satisfy the ``B008`` lint without making the call sites
# noisier with ``None``-then-default dances.
_DEFAULT_OPTIONS = ReportOptions()


def render_report(
    result: RunResult,
    decision: PolicyDecision,
    options: ReportOptions = _DEFAULT_OPTIONS,
) -> str:
    """Render the full report for a single secscan invocation."""
    if options.quiet:
        return _render_quiet(result, decision)

    lines: list[str] = []
    lines.append(_header("secscan results", options))
    lines.append("")

    if result.findings:
        lines.extend(_render_findings(result.findings, options))
        lines.append("")
    else:
        lines.append(_dim("no findings", options))
        lines.append("")

    if result.suppressed_by_baseline and options.verbose:
        lines.append(_header(
            f"suppressed by baseline ({len(result.suppressed_by_baseline)})",
            options,
        ))
        lines.extend(_render_findings(result.suppressed_by_baseline, options))
        lines.append("")

    if result.errors:
        lines.append(_header(f"scanner errors ({len(result.errors)})", options))
        for err in result.errors:
            head = f"  ✗ {err.scanner}: {err.reason}"
            if err.returncode is not None:
                head += f" (exit {err.returncode})"
            lines.append(_color(head, "\x1b[31m", options))
            if err.stderr_excerpt:
                for stderr_line in err.stderr_excerpt.splitlines():
                    lines.append(_dim(f"      {stderr_line}", options))
        lines.append("")

    if result.warnings:
        lines.append(_header(f"warnings ({len(result.warnings)})", options))
        for warning in result.warnings:
            lines.append(_color(f"  ! {warning}", "\x1b[33m", options))
        lines.append("")

    if result.skipped:
        lines.append(_dim(f"skipped scanners: {', '.join(result.skipped)}", options))
        lines.append("")

    lines.extend(_render_summary(result, decision, options))

    return "\n".join(lines)


def render_baseline_application(
    application: BaselineApplication, options: ReportOptions = _DEFAULT_OPTIONS
) -> str:
    """Convenience: format a stand-alone baseline diff for ``baseline list``."""
    lines: list[str] = []
    lines.append(_header("baseline summary", options))
    lines.append(f"  kept:       {len(application.kept)}")
    lines.append(f"  suppressed: {len(application.suppressed)}")
    for warning in application.warnings:
        lines.append(_color(f"  ! {warning}", "\x1b[33m", options))
    return "\n".join(lines)


# --- Internals -------------------------------------------------------------


def _render_findings(
    findings: tuple[Finding, ...], options: ReportOptions
) -> list[str]:
    """Order findings: highest severity first, then by scanner+file+line."""
    ordered = sorted(
        findings,
        key=lambda f: (
            -int(f.severity),
            f.scanner,
            (f.location.file or "") if f.location else "",
            (f.location.line or 0) if f.location else 0,
            f.rule_id,
        ),
    )
    lines: list[str] = []
    for finding in ordered:
        lines.extend(_render_finding(finding, options))
    return lines


def _render_finding(finding: Finding, options: ReportOptions) -> list[str]:
    color = _SEVERITY_COLOR.get(finding.severity, "")
    sev_label = _color(f"[{finding.severity.name}]", color, options)
    head = f"  {sev_label} {finding.scanner}:{finding.rule_id} — {finding.title}"
    lines = [head]
    if finding.location is not None:
        loc_parts: list[str] = []
        if finding.location.file:
            loc_str = finding.location.file
            if finding.location.line is not None:
                loc_str += f":{finding.location.line}"
                if finding.location.column is not None:
                    loc_str += f":{finding.location.column}"
            loc_parts.append(loc_str)
        if finding.location.package:
            pkg = finding.location.package
            if finding.location.ecosystem:
                pkg = f"{finding.location.ecosystem}:{pkg}"
            loc_parts.append(pkg)
        if loc_parts:
            lines.append(_dim(f"      at {' / '.join(loc_parts)}", options))
    if finding.fix_version:
        lines.append(_dim(f"      fix available in: {finding.fix_version}", options))
    if options.verbose:
        msg = finding.message
        if msg and msg != finding.title:
            lines.append(_dim(f"      {msg}", options))
        if finding.cve:
            lines.append(_dim(f"      CVE: {finding.cve}", options))
        if finding.references:
            for ref in finding.references[:3]:  # cap noise
                lines.append(_dim(f"      ref: {ref}", options))
    return lines


def _render_summary(
    result: RunResult, decision: PolicyDecision, options: ReportOptions
) -> list[str]:
    counts: dict[Severity, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts: list[str] = []
    # Walk highest → lowest for readability.
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.UNKNOWN,
    ):
        n = counts.get(sev, 0)
        if n:
            parts.append(
                _color(f"{n} {sev.name.lower()}", _SEVERITY_COLOR.get(sev, ""), options)
            )
    summary = ", ".join(parts) if parts else _dim("none", options)
    lines = [_header("summary", options), f"  findings:  {summary}"]
    if decision.unknown_warning_count:
        lines.append(
            _dim(
                f"  unknown:   {decision.unknown_warning_count} "
                f"(not counted toward fail-on={decision.threshold.name.lower()})",
                options,
            )
        )
    lines.append(
        f"  threshold: {decision.threshold.name.lower()}  "
        f"(exit code: {int(decision.exit_code)})"
    )
    if result.suppressed_by_baseline:
        lines.append(_dim(f"  suppressed: {len(result.suppressed_by_baseline)}", options))
    return lines


def _render_quiet(result: RunResult, decision: PolicyDecision) -> str:
    """Single-line summary for --quiet.

    Always non-empty so CI logs at least record the verdict.
    """
    return (
        f"secscan: findings={len(result.findings)} "
        f"errors={len(result.errors)} "
        f"crossing={len(decision.crossing_findings)} "
        f"exit={int(decision.exit_code)}"
    )


def _header(text: str, options: ReportOptions) -> str:
    if options.use_color:
        return f"{_BOLD}{text}{_RESET}"
    return f"{text}"


def _color(text: str, color: str, options: ReportOptions) -> str:
    if not options.use_color or not color:
        return text
    return f"{color}{text}{_RESET}"


def _dim(text: str, options: ReportOptions) -> str:
    if options.use_color:
        return f"{_DIM}{text}{_RESET}"
    return text
