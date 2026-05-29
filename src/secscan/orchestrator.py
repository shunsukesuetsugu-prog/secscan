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

Phase 2-X: scanners can run in parallel via a ThreadPoolExecutor.
The default ``parallel=True`` mode runs scanners concurrently subject
to:
  - a global ``max_workers`` cap (default ``min(cpu_count, plan_size, 8)``),
  - a Docker-scanner Semaphore (default 2) to keep the local Docker
    daemon from being oversubscribed by ``image`` + ``sbom`` + ``apifuzz``
    + ``config`` + ``dast`` + ``supply`` all firing at once.

Aggregation is rebuilt in plan (= scanner discovery + unit) order so
the resulting ``RunResult`` is byte-identical between serial and
parallel modes (Codex Phase 2-X design review MUST-FIX #3). This makes
``--no-parallel`` a strict performance dial, not a behaviour switch.
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import threading
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
from .diffscan import DiffBaseline
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
from .scanners.base import DiffMode, Scanner, ToolNotFoundError


@dataclass(frozen=True)
class OrchestratorResult:
    """Bundle of everything the CLI needs to print and exit."""

    result: RunResult
    decision: PolicyDecision


#: Default cap on simultaneous Docker-using scanners. The local Docker
#: daemon serialises image pulls under the hood and CPU/IO contention
#: from 5 parallel container starts costs more than it saves. 2 is the
#: empirical sweet spot on a typical developer laptop; expose later if
#: an operator needs to tune it.
DEFAULT_DOCKER_MAX_WORKERS = 2

#: Hard ceiling for the auto-resolved thread pool size. Even on 16-core
#: hosts we don't want to spawn 16 subprocess scanners simultaneously —
#: each scanner can be I/O-heavy on its own. Operators can override via
#: ``--max-workers``.
DEFAULT_MAX_WORKERS_CEILING = 8


@dataclass(frozen=True)
class _ItemResult:
    """The per-(scanner, unit) outcome of one execution slot.

    Parallel and serial paths both produce a list of these in plan order;
    the aggregation step then interleaves them with the side-band
    discovery warnings to recreate the original serial output ordering.
    """

    scanner_name: str
    error: ScannerError | None
    outcome: ScanOutcome | None  # None iff ``error`` is set


def _execute_item(
    scanner: Scanner,
    unit: WorkUnit,
    runner: CommandRunner,
    scan_config: ScanConfig,
    scan_root: ResolvedRoot,
    docker_sem: threading.Semaphore | None = None,
) -> _ItemResult:
    """Run one (scanner, unit) pair, catching errors and sanitising paths.

    When ``docker_sem`` is provided AND the scanner declares
    ``requires_docker = True``, the call is gated on the semaphore so
    no more than ``docker_max_workers`` Docker scanners run at once
    (Phase 2-X). Serial mode passes ``docker_sem=None`` and skips the
    gate entirely.

    All exceptions are converted to ``ScannerError`` so a misbehaving
    scanner cannot poison the parallel worker pool. ``ToolNotFoundError``
    is treated as a normal scanner failure here (different from the
    serial-only contract in earlier versions where it propagated) —
    the per-thread futures need every exception caught locally.
    """
    if docker_sem is not None and scanner.requires_docker:
        with docker_sem:
            return _execute_item_inner(scanner, unit, runner, scan_config, scan_root)
    return _execute_item_inner(scanner, unit, runner, scan_config, scan_root)


def _execute_item_inner(
    scanner: Scanner,
    unit: WorkUnit,
    runner: CommandRunner,
    scan_config: ScanConfig,
    scan_root: ResolvedRoot,
) -> _ItemResult:
    try:
        outcome = scanner.scan(unit, runner, scan_config)
    except ToolNotFoundError as exc:
        return _ItemResult(
            scanner_name=scanner.name,
            error=ScannerError(
                scanner=scanner.name,
                reason=f"required tool not installed: {exc.tool}",
                stderr_excerpt=exc.install_hint,
                returncode=None,
            ),
            outcome=None,
        )
    except Exception as exc:
        # Broad except: one misbehaving scanner must not abort the run.
        # ``str(exc)`` may include scanned-file content / env values, so
        # redact FIRST (so credential-shaped tokens are caught whole),
        # then truncate.
        safe_reason = truncate(
            redact_text(f"scanner crashed: {type(exc).__name__}: {exc}"),
            limit=300,
        )
        return _ItemResult(
            scanner_name=scanner.name,
            error=ScannerError(
                scanner=scanner.name,
                reason=safe_reason,
                stderr_excerpt=None,
                returncode=None,
            ),
            outcome=None,
        )

    # Codex Phase 2-X design review MUST-FIX #1: path sanitisation must
    # happen in the worker, before returning the outcome to the
    # aggregator. The previous loop-local sanitisation cannot be lost
    # when execution moves into a thread pool.
    sanitised = _sanitize_outcome_paths(outcome, scan_root, unit)
    return _ItemResult(scanner_name=scanner.name, error=None, outcome=sanitised)


def _resolve_max_workers(requested: int | None, n_scanners: int) -> int:
    """Compute the effective ThreadPoolExecutor size.

    Cap is keyed off ``n_scanners`` (= ``len(selected)``), NOT plan
    size. Within a single scanner, per-unit subprocess calls usually
    contend for the same external tool / Docker daemon, so over-
    provisioning beyond ``len(selected)`` workers spends threads
    without buying parallelism (Codex Phase 2-X diff review
    MUST-FIX #2).

    - ``requested=None`` → ``min(cpu_count or 4, n_scanners, ceiling=8)``.
    - ``requested>=1``   → ``min(requested, n_scanners)``.

    Codex Phase 2-X design review MUST-FIX #6 covered ``--max-workers``
    validation (>= 1); the caller enforces that before reaching here.
    The ``max(1, ...)`` guard keeps the executor argument valid even
    when called with zero selected scanners (defensive — the caller
    already short-circuits empty plans).
    """
    n_scanners = max(1, n_scanners)
    if requested is None:
        return min(os.cpu_count() or 4, n_scanners, DEFAULT_MAX_WORKERS_CEILING)
    return min(requested, n_scanners)


def run_scanners(
    scanners: list[Scanner],
    *,
    scan_root: ResolvedRoot,
    config: ProjectConfig,
    runner: CommandRunner,
    only: tuple[str, ...] | None = None,
    parallel: bool = True,
    max_workers: int | None = None,
    docker_max_workers: int = DEFAULT_DOCKER_MAX_WORKERS,
    diff_baseline: DiffBaseline | None = None,
) -> OrchestratorResult:
    """Execute the requested scanners and aggregate results.

    ``only`` restricts the set of scanners to run (e.g. when the user invoked
    a single subcommand). ``config.skip`` further removes scanners from the
    plan. ``only`` always wins over skip — if the user explicitly asked for
    ``secscan secrets``, we run secrets regardless of skip config.

    Phase 2-X parallel knobs:

    - ``parallel`` (default True): run scanners in a ThreadPoolExecutor.
      Scanners are I/O bound (subprocess.run), so threads suffice; no
      asyncio rewrite required.
    - ``max_workers`` (default None → auto): cap on total simultaneous
      scanner subprocesses. ``None`` resolves to
      ``min(cpu_count or 4, plan_size, 8)``.
    - ``docker_max_workers`` (default 2): cap on simultaneous Docker
      scanners specifically. Independent of ``max_workers`` so a large
      thread pool can still serialise the heavy ``docker run`` workers.

    Both modes produce **byte-identical RunResult** for the same input —
    parallel just runs faster. The serial path is preserved as a fallback
    for debugging and downstream-CI compatibility.

    **Known limitation (Phase 2-X v1, Codex Phase 2-X diff review
    follow-up)**: a ``KeyboardInterrupt`` raised while parallel
    scanners are mid-``subprocess.run`` returns control out of
    ``run_scanners()`` promptly (the executor is shut down with
    ``cancel_futures=True, wait=False``), but the interpreter's
    atexit hook will then wait for any non-daemon executor worker
    threads to finish their in-flight subprocess before the CLI
    process actually exits. Operators who need immediate SIGINT
    responsiveness should run with ``--no-parallel`` until a future
    phase adds runner-level subprocess termination.
    """
    if max_workers is not None and max_workers < 1:
        raise ValueError(f"max_workers must be >= 1, got {max_workers}")
    if docker_max_workers < 1:
        raise ValueError(
            f"docker_max_workers must be >= 1, got {docker_max_workers}"
        )

    findings: list[Finding] = []
    errors: list[ScannerError] = []
    warnings: list[str] = []
    skipped: list[str] = []
    scanned: list[str] = []
    tool_versions: dict[str, str] = {}

    selected = _select_scanners(scanners, only=only, skip=config.skip)
    skipped.extend(s.name for s in scanners if s not in selected)

    # Build the plan: list of (scanner_index, scanner, unit, scan_config).
    # ``scanner_index`` keys aggregation by *instance* identity, not
    # ``scanner.name`` — Codex Phase 2-X diff review MUST-FIX #3: two
    # scanner instances sharing a ``name`` (workspace edge case) would
    # otherwise have their results double-replayed during merge.
    # Discovery warnings carry the same index so the per-instance
    # output order matches the serial loop exactly.
    plan: list[tuple[int, Scanner, WorkUnit, ScanConfig]] = []
    discovery_warnings: list[tuple[int, tuple[str, ...]]] = []
    for sidx, scanner in enumerate(selected):
        scan_config = _scan_config_for(scanner.name, config)

        # Phase 2-Y: diff-mode dispatch. AGNOSTIC scanners are skipped
        # (recorded as skipped with a reason, NOT a clean pass — Codex
        # Phase 2-Y design review #5). NATIVE scanners get the baseline
        # OID injected so they run a true delta scan. ALWAYS scanners
        # (deps/supply) keep the full ScanConfig — their finding set
        # tracks an advisory DB, not the source diff.
        if diff_baseline is not None:
            if scanner.diff_mode is DiffMode.AGNOSTIC:
                skipped.append(scanner.name)
                warnings.append(
                    f"{scanner.name}: skipped in --since diff mode — this "
                    "scanner is not diff-aware (it targets an external "
                    "service or scans the whole tree/image, not a source "
                    "delta). Run a full scan (omit --since) to include it."
                )
                continue
            if scanner.diff_mode is DiffMode.NATIVE:
                scan_config = dc_replace(
                    scan_config,
                    diff_baseline_oid=diff_baseline.baseline_oid,
                )
            # DiffMode.ALWAYS: leave scan_config untouched (full scan).

        discovery = discover_for_scanner(scanner.name, scan_root)
        discovery_warnings.append((sidx, tuple(discovery.warnings)))

        applicable = [u for u in discovery.work_units if scanner.is_applicable(u)]
        if not applicable:
            # Discovery returned nothing the scanner can use (e.g. deps with
            # no manifests). Don't treat as skipped — the discovery warning
            # already informs the user.
            continue

        # We are about to call scanner.scan() at least once. Record the
        # scanner as "actually ran" so the SARIF formatter can include a
        # run for it (Codex 18th review).
        scanned.append(scanner.name)
        for unit in applicable:
            plan.append((sidx, scanner, unit, scan_config))

    # Execute the plan. Both modes produce ``results`` in plan order.
    # A single-item plan stays serial regardless of ``parallel`` —
    # ThreadPoolExecutor overhead would dominate the work.
    if parallel and len(plan) > 1:
        effective_workers = _resolve_max_workers(max_workers, len(selected))
        docker_sem = threading.Semaphore(docker_max_workers)
        results_by_idx: dict[int, _ItemResult] = {}
        ex = cf.ThreadPoolExecutor(max_workers=effective_workers)
        # Codex Phase 2-X diff review MUST-FIX #1: an implicit
        # ``with ex: ...`` block would call ``shutdown(wait=True)``
        # on any exception, including KeyboardInterrupt — meaning
        # ``run_scanners()`` would block inside the executor exit
        # path until every in-flight subprocess finishes. Manage
        # shutdown explicitly: on clean exit wait normally, on any
        # exception cancel pending futures and return fast.
        #
        # NOTE (Phase 2-X v1 limitation, see top-of-function
        # docstring): this returns control out of ``run_scanners()``
        # promptly, but CPython 3.11's ``ThreadPoolExecutor`` worker
        # threads are non-daemon, so the interpreter's atexit hook
        # still waits for currently-running ``subprocess.run`` calls
        # to finish before the process exits. Operators who need
        # immediate SIGINT responsiveness should use
        # ``--no-parallel``. A future phase will add runner-level
        # subprocess tracking so the CLI can kill in-flight scanner
        # subprocesses on shutdown.
        try:
            future_to_idx = {
                ex.submit(
                    _execute_item, s, u, runner, c, scan_root, docker_sem
                ): idx
                for idx, (_sidx, s, u, c) in enumerate(plan)
            }
            # ``as_completed`` lets us observe finish order for any future
            # logging; the actual aggregation re-sorts by plan index.
            for fut in cf.as_completed(future_to_idx):
                idx = future_to_idx[fut]
                results_by_idx[idx] = fut.result()
            ex.shutdown(wait=True)
        except BaseException:
            ex.shutdown(wait=False, cancel_futures=True)
            raise
        results = [results_by_idx[i] for i in range(len(plan))]
    else:
        # Serial path: no executor overhead, in-order execution.
        results = [
            _execute_item(s, u, runner, c, scan_root)
            for _sidx, s, u, c in plan
        ]

    # Aggregate in the original scanner-by-scanner order:
    # discovery_warnings(A) → outcomes(A's units) → discovery_warnings(B) → ...
    # This is the byte-identical-with-serial output guarantee.
    # Codex Phase 2-X diff review MUST-FIX #3: key by scanner *instance
    # index*, not name, so duplicate-named scanner instances don't
    # cause double-replay.
    results_by_sidx: dict[int, list[_ItemResult]] = {}
    for plan_idx, (sidx, _scanner, _unit, _cfg) in enumerate(plan):
        results_by_sidx.setdefault(sidx, []).append(results[plan_idx])

    for sidx, disc_warns in discovery_warnings:
        warnings.extend(disc_warns)
        for item in results_by_sidx.get(sidx, ()):
            if item.error is not None:
                errors.append(item.error)
                continue
            outcome = item.outcome
            if outcome is None:
                continue
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

    # Phase 2-Y banner. The banner MUST distinguish per-scanner
    # behaviour (Codex design review #6) AND reflect what ACTUALLY ran
    # (Codex diff review #3): if the operator did ``--skip secrets``,
    # the banner must not claim secrets was delta-scanned. We build the
    # clauses from ``scanned`` (what ran) and the scanner modes, so a
    # partial diff never reads as fully covered.
    if diff_baseline is not None:
        mode_by_name = {s.name: s.diff_mode for s in selected}
        delta_scanned = sorted(
            n for n in scanned if mode_by_name.get(n) is DiffMode.NATIVE
        )
        full_scanned = sorted(
            n for n in scanned if mode_by_name.get(n) is DiffMode.ALWAYS
        )
        clauses: list[str] = []
        if delta_scanned:
            clauses.append(
                f"{', '.join(delta_scanned)} scanned only the commit delta"
            )
        if full_scanned:
            clauses.append(
                f"{', '.join(full_scanned)} ran a FULL scan (advisory DB, "
                "not file changes)"
            )
        body = "; ".join(clauses) if clauses else "no diff-aware scanner ran"
        tail = (
            " This is a DELTA check — unchanged files were NOT scanned by "
            "the delta scanners."
            if delta_scanned
            else ""
        )
        warnings.insert(
            0,
            f"DIFF SCAN since {diff_baseline.user_ref} "
            f"(baseline {diff_baseline.baseline_oid[:12]}): {body}.{tail}",
        )

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
    if scanner_name == "supply":
        # Phase 2-Q: supply chain integrity (cosign + lockfile).
        # Local import keeps the optional module out of every
        # orchestrator call.
        from .scanners.supply._pinned import DEFAULT_COSIGN_IMAGE

        sup = config.supply
        cosign_image = sup.cosign_image.strip() or DEFAULT_COSIGN_IMAGE
        verify_dicts = [
            {
                "ref": v.ref,
                "signer_identity": v.signer_identity or None,
                "signer_identity_regexp": (
                    v.signer_identity_regexp or None
                ),
                "signer_issuer": v.signer_issuer,
            }
            for v in sup.verify_images
        ]
        return ScanConfig(
            timeout_seconds=sup.timeout_seconds,
            extra=MappingProxyType(
                {
                    "verify_images": tuple(verify_dicts),
                    "lockfiles": sup.lockfiles,
                    "cli_lockfiles": sup.cli_lockfiles,
                    "cosign_image": cosign_image,
                }
            ),
        )
    if scanner_name == "iast":
        # Phase 2-P: IAST harness. Local import to keep the
        # optional subprocess module out of every orchestrator
        # invocation.
        iast = config.iast
        return ScanConfig(
            timeout_seconds=iast.timeout_seconds,
            extra=MappingProxyType(
                {
                    "command": iast.command,
                    "probe_url": iast.probe_url,
                    "pyrasp_log": iast.pyrasp_log,
                    "allow_risky_probes": iast.allow_risky_probes,
                    "app_ready_timeout": iast.app_ready_timeout,
                    "shutdown_grace_seconds": iast.shutdown_grace_seconds,
                    "probe_timeout": iast.probe_timeout,
                }
            ),
        )
    if scanner_name == "apifuzz":
        # Phase 2-O: Schemathesis pipeline via docker. Local
        # import — optional in envs without docker.
        from .scanners.apifuzz._pinned import (
            DEFAULT_HELPER_IMAGE,
            DEFAULT_SCHEMATHESIS_IMAGE,
        )

        af = config.apifuzz
        scanner_image = af.scanner_image.strip() or DEFAULT_SCHEMATHESIS_IMAGE
        helper_image = af.helper_image.strip() or DEFAULT_HELPER_IMAGE
        return ScanConfig(
            timeout_seconds=af.timeout_seconds,
            extra=MappingProxyType(
                {
                    "api_url": af.api_url,
                    "schema": af.schema,
                    # Codex Phase 2-O design review MUST-FIX
                    # (security): these fields are CLI-only and
                    # cannot be set from config. The CLI override
                    # layer (``_apply_cli_overrides``) is the
                    # only writer.
                    "schema_from_cli": af.schema_from_cli,
                    "unconfine_cli_schema": af.unconfine_cli_schema,
                    "mode": af.mode,
                    "allow_active": af.allow_active,
                    "headers": af.headers,
                    "scanner_image": scanner_image,
                    "helper_image": helper_image,
                    "max_examples": af.max_examples,
                    "seed": af.seed,
                    "deterministic": af.deterministic,
                    "request_timeout": af.request_timeout,
                }
            ),
        )
    if scanner_name == "sbom":
        # Phase 2-N: Syft + Grype 2-step pipeline via docker.
        # Local import to keep the optional scanner out of every
        # orchestrator call.
        from .scanners.sbom._pinned import (
            DEFAULT_GRYPE_IMAGE,
            DEFAULT_SYFT_IMAGE,
            DEFAULT_TARGET_PLATFORM,
        )

        sbom_cfg = config.sbom
        syft_image = sbom_cfg.syft_image.strip() or DEFAULT_SYFT_IMAGE
        grype_image = sbom_cfg.grype_image.strip() or DEFAULT_GRYPE_IMAGE
        platform = sbom_cfg.platform.strip() or DEFAULT_TARGET_PLATFORM
        return ScanConfig(
            timeout_seconds=sbom_cfg.timeout_seconds,
            extra=MappingProxyType(
                {
                    # Codex Phase 2-N diff review MUST-FIX
                    # (security): pass the two target sets
                    # separately so the scanner can enforce
                    # confinement per-origin.
                    "targets": sbom_cfg.targets,
                    "cli_targets": sbom_cfg.cli_targets,
                    "unconfine_cli_targets": sbom_cfg.unconfine_cli_targets,
                    "syft_image": syft_image,
                    "grype_image": grype_image,
                    "platform": platform,
                    "cache_volume": sbom_cfg.cache_volume,
                }
            ),
        )
    if scanner_name == "image":
        # Phase 2-M: Trivy image-vulnerability scan. Local import
        # so test envs without docker don't pay the import cost.
        from .scanners.image._pinned import (
            DEFAULT_TARGET_PLATFORM,
            DEFAULT_TRIVY_IMAGE,
        )

        img = config.image
        scanner_image = img.image.strip() or DEFAULT_TRIVY_IMAGE
        platform = img.platform.strip() or DEFAULT_TARGET_PLATFORM
        return ScanConfig(
            timeout_seconds=img.timeout_seconds,
            extra=MappingProxyType(
                {
                    "refs": img.refs,
                    "scanner_image": scanner_image,
                    "platform": platform,
                    "cache_volume": img.cache_volume,
                }
            ),
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
