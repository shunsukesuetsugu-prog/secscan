"""The :class:`Scanner` adapter for the SBOM + CVE pipeline.

Phase 2-N: drives the Syft → Grype 2-step pipeline per target.

For each target:

1. If the target is a *SBOM file*: skip Syft, run Grype directly
   against the file (mounted read-only).
2. If the target is a *directory* or *image*: create a short-lived
   named docker volume, run Syft into it, validate the resulting
   SBOM size, then run Grype against the same volume mounted
   read-only. The volume is removed in a ``try/finally`` so a
   crash never leaves leftover state on the docker host.

Scanner-level invariants enforced here (Codex MUST-FIX coverage):

- Every docker invocation goes through the validated argv helpers
  (``syft.build_argv`` / ``grype.build_argv``). Subprocess uses
  ``shell=False``.
- All bind mounts are read-only EXCEPT the intermediate volume on
  the Syft step, which is removed at the end.
- Volume names use ``secrets.token_hex(16)`` so two concurrent
  runs (or a leftover from a crashed run) cannot collide.
- A failure on one target does NOT abort the rest; the first
  failure becomes ``ScanOutcome.error``, subsequent ones append
  warnings.

Best-effort note on volume leaks (Codex Phase 2-N diff review
MUST-FIX #1): the ``try/finally`` cleanup only runs on a normal
Python unwind. A SIGKILL or host crash mid-scan will leave one
``secscan-sbom-<32 hex>`` volume per killed run on the docker
host. We label every intermediate volume with ``secscan-tmp=1``
so the operator can sweep them via::

    docker volume prune -f --filter label=secscan-tmp=1

Run that periodically (or wire it into CI cleanup). We deliberately
do NOT auto-prune at scanner startup because two concurrent secscan
invocations would race on each other's in-flight volumes.
"""

from __future__ import annotations

import secrets
import shutil
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ...models import (
    Finding,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    WorkUnit,
)
from ...redact import redact_text, truncate
from ...runner import CommandRunner, decode_output
from ..base import Scanner, ToolNotFoundError
from ._pinned import (
    DEFAULT_GRYPE_IMAGE,
    DEFAULT_SYFT_IMAGE,
    DEFAULT_TARGET_PLATFORM,
)
from .grype import (
    GrypeInvocation,
    classify_grype_exit,
    parse_grype_report,
)
from .grype import (
    build_argv as grype_argv,
)
from .syft import (
    SyftInvocation,
    classify_syft_exit,
)
from .syft import (
    build_argv as syft_argv,
)
from .validators import (
    SbomFileTarget,
    SbomInputError,
    Target,
    assert_target_under_scan_root,
    classify_target,
)


@dataclass(frozen=True)
class SbomScannerSettings:
    """Resolved SBOM-scanner configuration for one ``scan()`` call."""

    config_targets: tuple[str, ...] = field(default_factory=tuple)
    """Targets from ``[sbom].targets`` in .secscan.toml. ALWAYS
    confined to the scan root (Codex Phase 2-N diff review
    MUST-FIX security carry-over)."""

    cli_targets: tuple[str, ...] = field(default_factory=tuple)
    """Targets from ``--target`` on the CLI. Confined unless
    ``unconfine_cli_targets`` is True."""

    unconfine_cli_targets: bool = False
    """The CLI-only ``--unsafe-allow-targets-outside-scan-root``
    flag. Applies ONLY to ``cli_targets``. Cannot be set from
    config — see ``config.SbomConfig`` for the rationale."""

    syft_image: str = DEFAULT_SYFT_IMAGE
    grype_image: str = DEFAULT_GRYPE_IMAGE
    platform: str = DEFAULT_TARGET_PLATFORM
    cache_volume: str = ""


class SbomScanner(Scanner):
    """Anchore Syft + Grype, wired as a single secscan scanner."""

    name = "sbom"
    tool_executable = "docker"
    install_hint = (
        "install Docker (https://docs.docker.com/engine/install/) and "
        "ensure the daemon is reachable. The Syft and Grype images are "
        "pulled on first use."
    )
    requires_docker = True

    def is_applicable(self, unit: WorkUnit) -> bool:
        # SBOM scanning targets are explicit — registry-side or
        # operator-supplied paths/files. The orchestrator passes the
        # root WorkUnit; we accept it once and ignore ``unit.root``
        # in the docker argv. We DO use ``unit.root`` as the
        # scan-root confinement anchor for path/SBOM targets.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        try:
            settings = _resolve_settings(config)
        except SbomInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        if not settings.config_targets and not settings.cli_targets:
            # Opt-in: no targets configured → no-op (DAST/image behaviour).
            return ScanOutcome(scanner=self.name)

        if shutil.which(self.tool_executable) is None:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)

        # Classify each target up front so we can fail fast on a
        # bad input before spinning up any docker container.
        # Codex Phase 2-N diff review MUST-FIX (security):
        # config-origin targets are ALWAYS confined; CLI-origin
        # targets are confined unless the operator passed the
        # CLI-only unconfine flag.
        classified: list[tuple[str, Target]] = []
        targets_with_origin: list[tuple[str, bool]] = (
            [(t, True) for t in settings.config_targets]
            + [(t, False) for t in settings.cli_targets]
        )
        for raw, is_config_origin in targets_with_origin:
            try:
                target = classify_target(raw, source="--target")
                # Confinement rule: config targets always; CLI
                # targets unless the operator explicitly unconfined.
                confine_this = (
                    is_config_origin or not settings.unconfine_cli_targets
                )
                if confine_this:
                    assert_target_under_scan_root(
                        target, scan_root=unit.root
                    )
            except SbomInputError as exc:
                return _error_outcome(
                    self.name,
                    reason=str(exc),
                    returncode=None,
                    stderr=b"",
                    duration=0.0,
                )
            classified.append((raw, target))

        findings: list[Finding] = []
        warnings: list[str] = []
        tool_version: str | None = None
        total_duration = 0.0
        seen_fingerprints: set[str] = set()
        first_error: ScannerError | None = None

        for raw, target in classified:
            outcome = self._scan_one(
                runner=runner,
                cwd=unit.root,
                target=target,
                target_label=raw,
                settings=settings,
                timeout=config.timeout_seconds,
            )
            total_duration += outcome.duration_seconds
            warnings.extend(outcome.warnings)
            if outcome.tool_version and not tool_version:
                tool_version = outcome.tool_version
            if outcome.error is not None:
                if first_error is None:
                    first_error = outcome.error
                else:
                    warnings.append(
                        f"sbom: {raw}: {outcome.error.reason}"
                    )
                continue
            for finding in outcome.findings:
                if finding.fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(finding.fingerprint)
                findings.append(finding)

        if first_error is not None and not findings:
            return ScanOutcome(
                scanner=self.name,
                error=first_error,
                warnings=tuple(warnings),
                tool_version=tool_version,
                duration_seconds=total_duration,
            )
        if first_error is not None:
            warnings.insert(0, f"sbom: {first_error.reason}")
        return ScanOutcome(
            scanner=self.name,
            findings=tuple(findings),
            warnings=tuple(warnings),
            tool_version=tool_version,
            duration_seconds=total_duration,
        )

    def _scan_one(
        self,
        *,
        runner: CommandRunner,
        cwd: Path,
        target: Target,
        target_label: str,
        settings: SbomScannerSettings,
        timeout: int,
    ) -> ScanOutcome:
        """Run the Syft → Grype pipeline (or just Grype) for one target."""
        if isinstance(target, SbomFileTarget):
            return self._run_grype_only(
                runner=runner,
                cwd=cwd,
                sbom_path=target.path,
                target_label=target_label,
                settings=settings,
                timeout=timeout,
            )
        return self._run_syft_then_grype(
            runner=runner,
            cwd=cwd,
            target=target,
            target_label=target_label,
            settings=settings,
            timeout=timeout,
        )

    def _run_grype_only(
        self,
        *,
        runner: CommandRunner,
        cwd: Path,
        sbom_path: Path,
        target_label: str,
        settings: SbomScannerSettings,
        timeout: int,
    ) -> ScanOutcome:
        argv = grype_argv(
            GrypeInvocation(
                scanner_image=settings.grype_image,
                sbom_file_path=str(sbom_path),
                cache_volume=settings.cache_volume,
            )
        )
        result = runner.run(argv, cwd=cwd, timeout_seconds=timeout)
        ok, reason = classify_grype_exit(
            result.returncode, timed_out=result.timed_out
        )
        if not ok:
            return _error_outcome(
                self.name,
                reason=f"{reason or 'grype failed'} for {target_label}",
                returncode=result.returncode,
                stderr=result.stderr,
                duration=result.duration_seconds,
            )
        parsed = parse_grype_report(
            result.stdout, target_label=target_label
        )
        return ScanOutcome(
            scanner=self.name,
            findings=parsed.findings,
            warnings=parsed.warnings,
            tool_version=parsed.tool_version,
            duration_seconds=result.duration_seconds,
        )

    def _run_syft_then_grype(
        self,
        *,
        runner: CommandRunner,
        cwd: Path,
        target: Target,
        target_label: str,
        settings: SbomScannerSettings,
        timeout: int,
    ) -> ScanOutcome:
        if isinstance(target, SbomFileTarget):  # pragma: no cover — caller routes
            raise SbomInputError(
                "_run_syft_then_grype called with SbomFileTarget"
            )
        volume = f"secscan-sbom-{secrets.token_hex(16)}"
        try:
            create = runner.run(
                ["docker", "volume", "create", "--label", "secscan-tmp=1", volume],
                cwd=cwd,
                timeout_seconds=60,
            )
            if create.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason=f"failed to create intermediate volume for {target_label}",
                    returncode=create.returncode,
                    stderr=create.stderr,
                    duration=create.duration_seconds,
                )

            syft_result = runner.run(
                syft_argv(
                    SyftInvocation(
                        target=target,
                        intermediate_volume=volume,
                        scanner_image=settings.syft_image,
                        platform=settings.platform,
                    )
                ),
                cwd=cwd,
                timeout_seconds=timeout,
            )
            ok, reason = classify_syft_exit(
                syft_result.returncode, timed_out=syft_result.timed_out
            )
            if not ok:
                return _error_outcome(
                    self.name,
                    reason=f"{reason or 'syft failed'} for {target_label}",
                    returncode=syft_result.returncode,
                    stderr=syft_result.stderr,
                    duration=syft_result.duration_seconds,
                )

            grype_result = runner.run(
                grype_argv(
                    GrypeInvocation(
                        scanner_image=settings.grype_image,
                        intermediate_volume=volume,
                        cache_volume=settings.cache_volume,
                    )
                ),
                cwd=cwd,
                timeout_seconds=timeout,
            )
            grype_ok, grype_reason = classify_grype_exit(
                grype_result.returncode, timed_out=grype_result.timed_out
            )
            total_duration = (
                create.duration_seconds
                + syft_result.duration_seconds
                + grype_result.duration_seconds
            )
            if not grype_ok:
                return _error_outcome(
                    self.name,
                    reason=f"{grype_reason or 'grype failed'} for {target_label}",
                    returncode=grype_result.returncode,
                    stderr=grype_result.stderr,
                    duration=total_duration,
                )
            parsed = parse_grype_report(
                grype_result.stdout, target_label=target_label
            )
            return ScanOutcome(
                scanner=self.name,
                findings=parsed.findings,
                warnings=parsed.warnings,
                tool_version=parsed.tool_version,
                duration_seconds=total_duration,
            )
        finally:
            # Always best-effort cleanup. ``-f`` ensures the volume
            # is removed even if a container that referenced it
            # didn't exit cleanly.
            runner.run(
                ["docker", "volume", "rm", "-f", volume],
                cwd=cwd,
                timeout_seconds=60,
            )


def _resolve_settings(config: ScanConfig) -> SbomScannerSettings:
    extra = config.extra

    def _list(key: str, label: str) -> tuple[str, ...]:
        raw = extra.get(key)
        if raw is None:
            return ()
        if not isinstance(raw, (list, tuple)):
            raise SbomInputError(f"sbom.{label} must be a list of strings")
        cleaned: list[str] = []
        for i, item in enumerate(raw):
            if not isinstance(item, str):
                raise SbomInputError(f"sbom.{label}[{i}] must be a string")
            stripped = item.strip()
            if stripped:
                cleaned.append(stripped)
        seen: set[str] = set()
        deduped: list[str] = []
        for t in cleaned:
            if t in seen:
                continue
            seen.add(t)
            deduped.append(t)
        return tuple(deduped)

    config_targets = _list("targets", "targets")
    cli_targets = _list("cli_targets", "cli_targets")

    def _str_or_default(key: str, default: str) -> str:
        raw = extra.get(key)
        if raw is None:
            return default
        if not isinstance(raw, str):
            raise SbomInputError(f"sbom.{key} must be a string")
        stripped = raw.strip()
        return stripped or default

    unconfine_raw = extra.get("unconfine_cli_targets", False)
    if not isinstance(unconfine_raw, bool):
        raise SbomInputError("sbom.unconfine_cli_targets must be a bool")

    return SbomScannerSettings(
        config_targets=config_targets,
        cli_targets=cli_targets,
        unconfine_cli_targets=unconfine_raw,
        syft_image=_str_or_default("syft_image", DEFAULT_SYFT_IMAGE),
        grype_image=_str_or_default("grype_image", DEFAULT_GRYPE_IMAGE),
        platform=_str_or_default("platform", DEFAULT_TARGET_PLATFORM),
        cache_volume=_str_or_default("cache_volume", ""),
    )


def _error_outcome(
    scanner: str,
    *,
    reason: str,
    returncode: int | None,
    stderr: bytes,
    duration: float,
) -> ScanOutcome:
    excerpt = truncate(redact_text(decode_output(stderr)))
    return ScanOutcome(
        scanner=scanner,
        error=ScannerError(
            scanner=scanner,
            reason=reason,
            stderr_excerpt=excerpt or None,
            returncode=returncode,
        ),
        duration_seconds=duration,
    )


def _materialize_iter(values: Iterable[str]) -> tuple[str, ...]:
    out = tuple(values)
    return out
