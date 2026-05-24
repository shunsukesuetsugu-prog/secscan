"""The :class:`Scanner` adapter for Trivy image-vulnerability scan.

Phase 2-M: drives ``docker run aquasec/trivy@sha256:... image
<target>`` once per target image listed in ``[image].refs`` (or via
``--image`` on the CLI). Each invocation produces a Trivy JSON
report; the parser normalizes those into Finding objects keyed by
CVE ID + package.

Like DAST, this scanner is **opt-in**:

- If no image refs are configured, the scanner returns a no-op
  ScanOutcome (zero findings, no warnings) and the orchestrator
  treats it as "ran with nothing to do".
- The dedicated ``secscan image`` subcommand requires ``--image``
  at the CLI layer (argparse-level enforcement) OR a non-empty
  ``[image].refs`` in ``.secscan.toml``; the dispatcher rejects
  the call upfront when neither is present.

Critical invariants:

- ``shell=False`` + argv list, ``--cap-drop=ALL``,
  ``--security-opt=no-new-privileges``.
- ``--network=bridge`` (Trivy MUST reach the registry).
- Target image refs are digest-pinned (validated before docker
  is invoked).
- ``--platform`` is set on both the docker layer and the Trivy
  CLI layer so multi-arch index digests resolve identically on
  every host.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field

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
from ._pinned import DEFAULT_TARGET_PLATFORM, DEFAULT_TRIVY_IMAGE
from .trivy import (
    ImageInputError,
    TrivyImageInvocation,
    build_argv,
    classify_trivy_image_exit,
    parse_trivy_image_report,
    validate_image_ref,
    validate_platform,
)


@dataclass(frozen=True)
class ImageScannerSettings:
    """Resolved image-scanner configuration for one ``scan()`` call."""

    scanner_image: str = DEFAULT_TRIVY_IMAGE
    platform: str = DEFAULT_TARGET_PLATFORM
    cache_volume: str = ""
    target_refs: tuple[str, ...] = field(default_factory=tuple)


class ImageScanner(Scanner):
    """Trivy image-mode scanner (OS + language-package CVEs)."""

    name = "image"
    tool_executable = "docker"
    install_hint = (
        "install Docker (https://docs.docker.com/engine/install/) and "
        "ensure the daemon is reachable. The Trivy image is pulled on "
        "first use; the target images are pulled by Trivy."
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # Image scanning is registry-side, not workspace-side. The
        # orchestrator passes the root WorkUnit; we accept it once
        # and ignore ``unit.root`` entirely. Trivy's argv has no
        # bind mount on the host filesystem in this mode.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        try:
            settings = _resolve_settings(config)
        except ImageInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        if not settings.target_refs:
            # Phase 2-M design pin: opt-in. Mirrors DAST behaviour.
            return ScanOutcome(scanner=self.name)

        if shutil.which(self.tool_executable) is None:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)

        try:
            scanner_image = validate_image_ref(
                settings.scanner_image, label="scanner_image"
            )
            platform = validate_platform(settings.platform)
            validated_targets = tuple(
                validate_image_ref(t, label="--image")
                for t in settings.target_refs
            )
        except ImageInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        findings: list[Finding] = []
        warnings: list[str] = []
        tool_version: str | None = None
        total_duration = 0.0
        seen_fingerprints: set[str] = set()
        # We loop over targets and aggregate. A failure on one target
        # does NOT abort the rest: the operator wants to see findings
        # from every reachable image. The first failure becomes the
        # ScanOutcome.error so the orchestrator records it; subsequent
        # failures append a warning.
        first_error: ScannerError | None = None
        for target in validated_targets:
            invocation = TrivyImageInvocation(
                target_image=target,
                scanner_image=scanner_image,
                platform=platform,
                cache_volume=settings.cache_volume,
            )
            try:
                argv = build_argv(invocation)
            except ImageInputError as exc:
                if first_error is None:
                    first_error = ScannerError(
                        scanner=self.name,
                        reason=str(exc),
                        stderr_excerpt=None,
                        returncode=None,
                    )
                else:
                    warnings.append(
                        f"image: {target}: argv build failed: {exc}"
                    )
                continue
            result = runner.run(
                argv,
                cwd=unit.root,
                timeout_seconds=config.timeout_seconds,
            )
            total_duration += result.duration_seconds
            ok, reason = classify_trivy_image_exit(
                result.returncode, timed_out=result.timed_out
            )
            if not ok:
                excerpt = truncate(redact_text(decode_output(result.stderr)))
                err = ScannerError(
                    scanner=self.name,
                    reason=f"{reason or 'trivy image failed'} for {target}",
                    stderr_excerpt=excerpt or None,
                    returncode=result.returncode,
                )
                if first_error is None:
                    first_error = err
                else:
                    warnings.append(
                        f"image: {target}: {err.reason}"
                    )
                continue
            parsed = parse_trivy_image_report(
                result.stdout, target_image=target
            )
            if parsed.tool_version and not tool_version:
                tool_version = parsed.tool_version
            warnings.extend(parsed.warnings)
            for finding in parsed.findings:
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
            # Partial success: surface the first failure as a warning
            # so the operator notices, but keep the successful targets'
            # findings.
            warnings.insert(0, f"image: {first_error.reason}")
        return ScanOutcome(
            scanner=self.name,
            findings=tuple(findings),
            warnings=tuple(warnings),
            tool_version=tool_version,
            duration_seconds=total_duration,
        )


def _resolve_settings(config: ScanConfig) -> ImageScannerSettings:
    extra = config.extra
    scanner_image_raw = extra.get("scanner_image")
    if scanner_image_raw is None:
        scanner_image = DEFAULT_TRIVY_IMAGE
    elif isinstance(scanner_image_raw, str):
        scanner_image = scanner_image_raw.strip() or DEFAULT_TRIVY_IMAGE
    else:
        raise ImageInputError("image.scanner_image must be a string")

    platform_raw = extra.get("platform")
    if platform_raw is None:
        platform = DEFAULT_TARGET_PLATFORM
    elif isinstance(platform_raw, str):
        platform = platform_raw.strip() or DEFAULT_TARGET_PLATFORM
    else:
        raise ImageInputError("image.platform must be a string")

    cache_volume_raw = extra.get("cache_volume")
    if cache_volume_raw is None:
        cache_volume = ""
    elif isinstance(cache_volume_raw, str):
        cache_volume = cache_volume_raw.strip()
    else:
        raise ImageInputError("image.cache_volume must be a string")

    refs_raw = extra.get("refs")
    if refs_raw is None:
        target_refs: tuple[str, ...] = ()
    elif isinstance(refs_raw, (list, tuple)):
        out: list[str] = []
        for i, item in enumerate(refs_raw):
            if not isinstance(item, str):
                raise ImageInputError(
                    f"image.refs[{i}] must be a string"
                )
            stripped = item.strip()
            if stripped:
                out.append(stripped)
        # Codex Phase 2-M design pin: preserve order but dedupe so
        # an operator who lists the same image twice doesn't get the
        # same CVEs reported twice.
        seen: set[str] = set()
        deduped: list[str] = []
        for t in out:
            if t in seen:
                continue
            seen.add(t)
            deduped.append(t)
        target_refs = tuple(deduped)
    else:
        raise ImageInputError("image.refs must be a list of strings")

    return ImageScannerSettings(
        scanner_image=scanner_image,
        platform=platform,
        cache_volume=cache_volume,
        target_refs=target_refs,
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
