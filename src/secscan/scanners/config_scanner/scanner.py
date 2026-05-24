"""The :class:`Scanner` adapter for Trivy config scan.

Drives ``docker run aquasec/trivy@sha256:... config /work`` via
the shared ``CommandRunner`` Protocol. Mirrors the DAST scanner's
overall shape but is much simpler because Trivy config scanning:

- only reads the bind-mounted scan root (no writable volume),
- emits its JSON report on stdout (no extraction-via-helper dance),
- doesn't need an alpine helper for UID gymnastics — the read-only
  bind mount works on Linux/Docker Desktop/colima alike (verified
  during Phase 2-L smoke tests).

Critical invariants:

- ``shell=False`` + argv list, ``--cap-drop=ALL``,
  ``--security-opt=no-new-privileges``, ``--network=none``.
- Read-only bind mount (``:ro``).
- Image ref must be digest-pinned (validated before docker is
  invoked).
- Scan path must be an absolute directory under the operator's
  control (validated before docker is invoked).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from ...models import (
    ScanConfig,
    ScannerError,
    ScanOutcome,
    WorkUnit,
)
from ...redact import redact_text, truncate
from ...runner import CommandRunner, decode_output
from ..base import Scanner, ToolNotFoundError
from ._pinned import DEFAULT_TRIVY_IMAGE
from .trivy import (
    ConfigInputError,
    TrivyInvocation,
    build_argv,
    classify_trivy_exit,
    parse_trivy_report,
    validate_image_ref,
    validate_scan_path,
)


@dataclass(frozen=True)
class ConfigScannerSettings:
    """Resolved config-scanner configuration for one invocation."""

    image_ref: str = DEFAULT_TRIVY_IMAGE


class ConfigScanner(Scanner):
    """Trivy config scanner (IaC / k8s / Dockerfile / Helm)."""

    name = "config"
    tool_executable = "docker"
    install_hint = (
        "install Docker (https://docs.docker.com/engine/install/) and "
        "ensure the daemon is reachable. The Trivy image is pulled on "
        "first use."
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # Config scanning is path-based, not language-based. The
        # orchestrator passes the single root WorkUnit; we accept
        # that one only. Trivy itself autodetects which files are
        # k8s / TF / Dockerfile / Helm / etc.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        try:
            settings = _resolve_settings(config)
        except ConfigInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        if shutil.which(self.tool_executable) is None:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)

        try:
            image_ref = validate_image_ref(settings.image_ref)
            scan_root = validate_scan_path(unit.root)
        except ConfigInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        invocation = TrivyInvocation(scan_root=scan_root, image_ref=image_ref)
        try:
            argv = build_argv(invocation)
        except ConfigInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        result = runner.run(
            argv,
            cwd=unit.root,
            timeout_seconds=config.timeout_seconds,
        )
        ok, reason = classify_trivy_exit(
            result.returncode, timed_out=result.timed_out
        )
        if not ok:
            return _error_outcome(
                self.name,
                reason=reason or "trivy config failed",
                returncode=result.returncode,
                stderr=result.stderr,
                duration=result.duration_seconds,
            )

        parsed = parse_trivy_report(result.stdout, scan_root=scan_root)
        return ScanOutcome(
            scanner=self.name,
            findings=parsed.findings,
            warnings=parsed.warnings,
            tool_version=parsed.tool_version,
            duration_seconds=result.duration_seconds,
        )


def _resolve_settings(config: ScanConfig) -> ConfigScannerSettings:
    extra = config.extra
    image_raw = extra.get("image")
    if image_raw is None:
        image_ref = DEFAULT_TRIVY_IMAGE
    elif isinstance(image_raw, str):
        stripped = image_raw.strip()
        image_ref = stripped or DEFAULT_TRIVY_IMAGE
    else:
        raise ConfigInputError("config.image must be a string")
    return ConfigScannerSettings(image_ref=image_ref)


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
