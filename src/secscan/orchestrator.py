"""Orchestrator: run scanners and aggregate results.

The orchestrator owns the cross-cutting plumbing that no single Scanner
should know about:

- Resolving the scan root (path_safety).
- Discovering work units (discovery).
- Filtering by ``--skip`` config.
- Invoking each Scanner with the correct ScanConfig.
- Loading the baseline and partitioning findings into kept vs suppressed.
- Applying severity overrides (policy.apply_overrides).
- Computing the policy decision.
- Bundling everything into a RunResult.

Scanner errors do NOT abort the run. We collect them and continue so the
operator sees every issue at once.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace as dc_replace
from pathlib import Path
from types import MappingProxyType

from .baseline import (
    Baseline,
    apply_baseline,
    load_baseline,
)
from .config import ProjectConfig
from .discovery import discover_for_scanner
from .models import (
    Finding,
    RunResult,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    WorkUnit,
)
from .path_safety import ResolvedRoot
from .policy import PolicyDecision, apply_overrides, evaluate
from .redact import redact_text, truncate
from .runner import CommandRunner
from .scanners.base import Scanner, ToolNotFoundError


@dataclass(frozen=True)
class OrchestratorResult:
    """Bundle of everything the CLI needs to print and exit."""

    result: RunResult
    decision: PolicyDecision


def run_scanners(
    scanners: list[Scanner],
    *,
    scan_root: ResolvedRoot,
    config: ProjectConfig,
    runner: CommandRunner,
    only: tuple[str, ...] | None = None,
) -> OrchestratorResult:
    """Execute the requested scanners and aggregate results.

    ``only`` restricts the set of scanners to run (e.g. when the user invoked
    a single subcommand). ``config.skip`` further removes scanners from the
    plan. ``only`` always wins over skip — if the user explicitly asked for
    ``secscan secrets``, we run secrets regardless of skip config.
    """
    findings: list[Finding] = []
    errors: list[ScannerError] = []
    warnings: list[str] = []
    skipped: list[str] = []
    scanned: list[str] = []
    tool_versions: dict[str, str] = {}

    selected = _select_scanners(scanners, only=only, skip=config.skip)
    skipped.extend(s.name for s in scanners if s not in selected)

    for scanner in selected:
        scan_config = _scan_config_for(scanner.name, config)
        discovery = discover_for_scanner(scanner.name, scan_root)
        warnings.extend(discovery.warnings)

        applicable = [u for u in discovery.work_units if scanner.is_applicable(u)]
        if not applicable:
            # Discovery returned nothing the scanner can use (e.g. deps with
            # no manifests). Don't treat as skipped, just no findings; the
            # discovery warning already informs the user.
            continue

        # We are about to call scanner.scan() at least once. Record the
        # scanner as "actually ran" so the SARIF formatter can include a
        # run for it (Codex 18th review).
        scanned.append(scanner.name)
        for unit in applicable:
            try:
                outcome = scanner.scan(unit, runner, scan_config)
            except ToolNotFoundError as exc:
                errors.append(
                    ScannerError(
                        scanner=scanner.name,
                        reason=f"required tool not installed: {exc.tool}",
                        stderr_excerpt=exc.install_hint,
                        returncode=None,
                    )
                )
                continue
            except Exception as exc:
                # We intentionally catch broad exceptions: a single mis-
                # behaving scanner must not kill the whole run.
                # ``str(exc)`` may include scanned-file content / env values,
                # so redact FIRST (so credential-shaped values are caught
                # whole), then truncate.
                safe_reason = truncate(
                    redact_text(f"scanner crashed: {type(exc).__name__}: {exc}"),
                    limit=300,
                )
                errors.append(
                    ScannerError(
                        scanner=scanner.name,
                        reason=safe_reason,
                        stderr_excerpt=None,
                        returncode=None,
                    )
                )
                continue

            # Verify all reported file paths are inside the scan root.
            # External tools can be tricked or buggy; we don't display paths
            # we can't vouch for. Sanitization is WorkUnit-aware (Phase 2-B
            # / Codex 20th review): a relative path returned by a workspace
            # scanner is resolved against ``unit.root``, not ``scan_root``,
            # so monorepo members report repo-root-relative paths.
            outcome = _sanitize_outcome_paths(outcome, scan_root, unit)

            _accumulate(
                outcome,
                findings=findings,
                errors=errors,
                warnings=warnings,
                tool_versions=tool_versions,
            )

    # Apply overrides BEFORE baseline matching: a finding upgraded from
    # MEDIUM to CRITICAL still has the same fingerprint, so this ordering
    # does not change suppression behavior — but it does affect the
    # severity actually recorded in suppressed_by_baseline (a small but
    # consistent improvement to audit trail).
    overridden = apply_overrides(tuple(findings), config)

    baseline_obj = _load_baseline_safely(config.baseline.path)
    if baseline_obj is None:
        application = None
        kept = overridden
        suppressed: tuple[Finding, ...] = ()
    else:
        application = apply_baseline(
            overridden,
            baseline_obj,
            current_tool_versions=tool_versions or None,
            current_config_hash=None,  # config hash not wired in MVP
        )
        kept = application.kept
        suppressed = application.suppressed
        warnings.extend(application.warnings)

    result = RunResult(
        findings=kept,
        errors=tuple(errors),
        warnings=tuple(warnings),
        skipped=tuple(skipped),
        suppressed_by_baseline=suppressed,
        scanned_scanners=tuple(scanned),
    )
    decision = evaluate(result, config)
    return OrchestratorResult(result=result, decision=decision)


# --- Internals -------------------------------------------------------------


def _select_scanners(
    scanners: list[Scanner],
    *,
    only: tuple[str, ...] | None,
    skip: tuple[str, ...],
) -> list[Scanner]:
    if only is not None:
        wanted = set(only)
        return [s for s in scanners if s.name in wanted]
    skipped = set(skip)
    return [s for s in scanners if s.name not in skipped]


def _scan_config_for(scanner_name: str, config: ProjectConfig) -> ScanConfig:
    if scanner_name == "deps":
        return ScanConfig(
            timeout_seconds=config.deps.timeout_seconds,
            extra=MappingProxyType(
                {
                    "allow_missing_lockfile": config.deps.allow_missing_lockfile,
                    "ignore_dev_dependencies": config.deps.ignore_dev_dependencies,
                }
            ),
        )
    if scanner_name == "sast":
        return ScanConfig(
            timeout_seconds=config.sast.timeout_seconds,
            extra=MappingProxyType(
                {
                    "semgrep_config": config.sast.semgrep_config,
                    "allow_unverified_configs": config.sast.allow_unverified_configs,
                }
            ),
        )
    if scanner_name == "secrets":
        return ScanConfig(timeout_seconds=config.secrets.timeout_seconds)
    if scanner_name == "config":
        # Phase 2-L: Trivy IaC / config scanner. Like DAST it
        # runs via docker, so the import is local for the same
        # reason (test envs without docker should not pay the
        # import cost).
        from .scanners.config_scanner._pinned import DEFAULT_TRIVY_IMAGE

        cfg = config.config
        image = cfg.image.strip() or DEFAULT_TRIVY_IMAGE
        return ScanConfig(
            timeout_seconds=cfg.timeout_seconds,
            extra=MappingProxyType({"image": image}),
        )
    if scanner_name == "dast":
        # Local import: the dast package is optional in test envs that
        # don't have docker. Importing at module top would force every
        # orchestrator invocation to pull in zap.py.
        from .scanners.dast._pinned import DEFAULT_ZAP_IMAGE

        dast = config.dast
        image = dast.image.strip() or DEFAULT_ZAP_IMAGE
        return ScanConfig(
            timeout_seconds=dast.timeout_seconds,
            extra=MappingProxyType(
                {
                    "target": dast.target,
                    "image": image,
                    "ajax_spider": dast.ajax_spider,
                    "config_file": dast.config_file or None,
                    "network_mode": dast.network_mode,
                    "mode": dast.mode,
                    "auth_headers": dast.auth_headers,
                }
            ),
        )
    # Unknown scanner: pass defaults; orchestrator-internal contract.
    return ScanConfig()


def _accumulate(
    outcome: ScanOutcome,
    *,
    findings: list[Finding],
    errors: list[ScannerError],
    warnings: list[str],
    tool_versions: dict[str, str],
) -> None:
    if outcome.error is not None:
        errors.append(outcome.error)
    else:
        findings.extend(outcome.findings)
    # Per-scanner non-fatal warnings always surface, regardless of whether
    # the scanner succeeded or errored — semgrep's parse-failure notes
    # (Codex 12th review) are exactly this kind of "report is incomplete
    # but you still get something".
    warnings.extend(outcome.warnings)
    if outcome.tool_version:
        tool_versions[outcome.scanner] = outcome.tool_version


def _load_baseline_safely(path: Path) -> Baseline | None:
    """Load the baseline if present.

    A parse error is propagated; we do NOT silently ignore a broken baseline
    because that would be a sneaky way to disable suppression on purpose.
    The CLI catches the BaselineError and renders it as a scanner-level
    error with exit code SCAN_ERROR.
    """
    return load_baseline(path)


def _sanitize_outcome_paths(
    outcome: ScanOutcome,
    scan_root: ResolvedRoot,
    unit: WorkUnit | None = None,
) -> ScanOutcome:
    """Drop scanner Findings that reference files outside the scan root.

    External tools can be coaxed (via symlinks, mis-configured includes,
    or bugs) to report locations outside ``--path``. Showing those paths
    is a leak of host filesystem layout and undermines the scan-root
    contract. We mutate Finding.location.file to None for any unverified
    path; we do not drop the Finding entirely (a finding without a path
    is still a real finding worth reporting), but we DO strip the path
    so the user can't be misled.

    ``unit`` (Phase 2-B): when provided, relative paths are resolved
    against ``unit.root`` (which equals the scan root for single-project
    layouts and the repo root for workspace layouts — secscan always
    runs workspace audits from the repo root). The previous behavior of
    resolving everything against ``scan_root`` directly is preserved
    via the ``unit=None`` default for callers that don't have a unit.
    """
    if outcome.error is not None or not outcome.findings:
        return outcome
    cleaned: list[Finding] = [
        _sanitize_finding_path(finding, scan_root, unit) for finding in outcome.findings
    ]
    return dc_replace(outcome, findings=tuple(cleaned))


def _sanitize_finding_path(
    finding: Finding,
    scan_root: ResolvedRoot,
    unit: WorkUnit | None = None,
) -> Finding:
    if finding.location is None or finding.location.file is None:
        return finding
    raw = Path(finding.location.file)
    # Anchor relative paths against the WorkUnit's audit-root if we have
    # one; this matters in workspaces where ``unit.root`` is the repo
    # root and the scanner returned a member-relative path. For absolute
    # paths and units without a base, fall back to the scan root.
    base = unit.root if unit is not None else scan_root.resolved
    candidate = raw if raw.is_absolute() else (base / raw)
    if not scan_root.contains(candidate) or scan_root.is_ignored(candidate):
        # Codex 20th review: strip every position field, not just file
        # and line. A stale ``column``/``end_*`` would still leak the
        # original (unverified) location's intent.
        new_location = dc_replace(
            finding.location,
            file=None,
            line=None,
            end_line=None,
            column=None,
            end_column=None,
        )
        return dc_replace(finding, location=new_location)
    # Rewrite file to a forward-slash repo-root-relative form so reports
    # are consistent regardless of which WorkUnit produced the finding.
    rel = scan_root.relativize(candidate)
    new_location = dc_replace(finding.location, file=rel)
    return dc_replace(finding, location=new_location)
