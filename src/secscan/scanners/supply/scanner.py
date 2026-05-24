"""The :class:`Scanner` adapter for supply-chain integrity.

Phase 2-Q: two independent verification paths, both optional:

1. **Cosign image signature verify** (one or more
   ``verify_images``). Each invocation runs ``docker run
   cosign verify ...`` under hardened defaults; a non-zero
   exit becomes one Finding classified by
   ``classify_cosign_failure``.
2. **Lockfile self-consistency** (one or more ``lockfiles``).
   Each lockfile is parsed in-process (no subprocess) by the
   appropriate ecosystem helper.

Both are opt-in. Empty ``verify_images`` AND empty
``lockfiles`` → ``secscan all`` silently skips this scanner;
direct ``secscan supply`` with both empty → usage error
(the CLI dispatcher emits that earlier — this scanner just
returns a no-op outcome as a belt-and-braces guard).
"""

from __future__ import annotations

import shutil
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
from ._pinned import DEFAULT_COSIGN_IMAGE
from .cosign import (
    CosignVerification,
    build_argv,
    classify_cosign_failure,
    finding_for_cosign_failure,
)
from .lockfile import check_lockfile
from .validators import (
    SupplyInputError,
    classify_lockfile,
    validate_image_ref,
    validate_signer_identity,
    validate_signer_identity_regexp,
    validate_signer_issuer,
)


@dataclass(frozen=True)
class CosignTargetSpec:
    target_image: str
    signer_identity: str | None = None
    signer_identity_regexp: str | None = None
    signer_issuer: str = ""


@dataclass(frozen=True)
class SupplyScannerSettings:
    verify_images: tuple[CosignTargetSpec, ...] = field(default_factory=tuple)
    config_lockfiles: tuple[str, ...] = field(default_factory=tuple)
    cli_lockfiles: tuple[str, ...] = field(default_factory=tuple)
    cosign_image: str = DEFAULT_COSIGN_IMAGE


class SupplyScanner(Scanner):
    """Supply-chain integrity: cosign verify + lockfile consistency."""

    name = "supply"
    tool_executable = "docker"
    install_hint = (
        "install Docker (https://docs.docker.com/engine/install/) to "
        "use --verify-image. Lockfile consistency checks have no "
        "external tool dependency."
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        try:
            settings = _resolve_settings(config)
        except SupplyInputError as exc:
            return _error_outcome(self.name, reason=str(exc))

        if not settings.verify_images and not (
            settings.config_lockfiles or settings.cli_lockfiles
        ):
            # Opt-in: nothing configured → no-op.
            return ScanOutcome(scanner=self.name)

        findings: list[Finding] = []
        warnings: list[str] = []
        total_duration = 0.0
        seen_fingerprints: set[str] = set()
        first_error: ScannerError | None = None

        # --- Lockfile consistency (no docker required) ---
        for raw, scan_root_for_check in _iter_lockfile_targets(
            settings, scan_root=unit.root
        ):
            try:
                target = classify_lockfile(
                    raw, scan_root=scan_root_for_check
                )
            except SupplyInputError as exc:
                warnings.append(f"supply: {exc}")
                continue
            parsed = check_lockfile(target)
            warnings.extend(parsed.warnings)
            for finding in parsed.findings:
                if finding.fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(finding.fingerprint)
                findings.append(finding)

        # --- Cosign image verification (docker required) ---
        if settings.verify_images:
            if shutil.which(self.tool_executable) is None:
                raise ToolNotFoundError(
                    self.tool_executable, self.install_hint
                )
            for spec in settings.verify_images:
                outcome = _run_one_cosign(
                    runner=runner,
                    cwd=unit.root,
                    spec=spec,
                    cosign_image=settings.cosign_image,
                    timeout_seconds=config.timeout_seconds,
                )
                total_duration += outcome.duration
                if outcome.error is not None:
                    if first_error is None:
                        first_error = outcome.error
                    else:
                        warnings.append(f"supply: {outcome.error.reason}")
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
                duration_seconds=total_duration,
            )
        if first_error is not None:
            warnings.insert(0, f"supply: {first_error.reason}")
        return ScanOutcome(
            scanner=self.name,
            findings=tuple(findings),
            warnings=tuple(warnings),
            duration_seconds=total_duration,
        )


def _iter_lockfile_targets(
    settings: SupplyScannerSettings, *, scan_root: Path
) -> list[tuple[str, Path | None]]:
    """Yield ``(raw_path, scan_root_for_check)`` per lockfile.

    Config-origin lockfile paths get confined to the scan root.
    CLI-origin paths bypass the confinement (operator typed the
    path themselves).
    """
    out: list[tuple[str, Path | None]] = []
    for raw in settings.config_lockfiles:
        out.append((raw, scan_root))
    for raw in settings.cli_lockfiles:
        out.append((raw, None))
    return out


@dataclass(frozen=True)
class _CosignRunOutcome:
    findings: tuple[Finding, ...] = ()
    error: ScannerError | None = None
    duration: float = 0.0


def _run_one_cosign(
    *,
    runner: CommandRunner,
    cwd: Path,
    spec: CosignTargetSpec,
    cosign_image: str,
    timeout_seconds: int,
) -> _CosignRunOutcome:
    """Run one ``cosign verify`` invocation."""
    try:
        target_image = validate_image_ref(spec.target_image)
        issuer = validate_signer_issuer(spec.signer_issuer)
        if spec.signer_identity is not None:
            literal = validate_signer_identity(spec.signer_identity)
            regex = None
        elif spec.signer_identity_regexp is not None:
            literal = None
            regex = validate_signer_identity_regexp(
                spec.signer_identity_regexp
            )
        else:
            raise SupplyInputError(
                "exactly one of signer_identity / signer_identity_regexp "
                "must be set"
            )
        invocation = CosignVerification(
            target_image=target_image,
            signer_identity=literal,
            signer_identity_regexp=regex,
            signer_issuer=issuer,
            cosign_image=cosign_image,
            timeout_seconds=timeout_seconds,
        )
        argv = build_argv(invocation)
    except SupplyInputError as exc:
        err = ScannerError(
            scanner="supply",
            reason=f"cosign input invalid for {spec.target_image}: {exc}",
            stderr_excerpt=None,
            returncode=None,
        )
        return _CosignRunOutcome(error=err)

    # Codex Phase 2-Q design review MUST-FIX: strip SIGSTORE_* /
    # COSIGN_* env vars before invoking subprocess. An attacker
    # with control of the operator's env could otherwise redirect
    # cosign at a fake Sigstore root (SIGSTORE_ROOT_FILE) or a
    # fake Rekor instance.
    clean_env: dict[str, str] = {}
    # PATH must be preserved for ``docker`` lookup. Nothing else
    # is needed — cosign reads everything from CLI flags.
    import os

    clean_env["PATH"] = os.environ.get("PATH", "")
    clean_env["HOME"] = os.environ.get("HOME", "")

    result = runner.run(
        argv,
        cwd=cwd,
        env=clean_env,
        timeout_seconds=timeout_seconds,
    )

    if result.timed_out:
        rule_id = "cosign-verification-network-failure"
        finding = finding_for_cosign_failure(
            target_image=spec.target_image,
            rule_id=rule_id,
            stderr=result.stderr,
            expected_identity=(
                literal or regex or "<unset>"
            ),
            issuer=spec.signer_issuer,
        )
        return _CosignRunOutcome(
            findings=(finding,),
            duration=result.duration_seconds,
        )

    if result.returncode == 0:
        return _CosignRunOutcome(duration=result.duration_seconds)

    rule_id = classify_cosign_failure(
        returncode=result.returncode,
        stderr=result.stderr,
        timed_out=False,
    )
    finding = finding_for_cosign_failure(
        target_image=spec.target_image,
        rule_id=rule_id,
        stderr=result.stderr,
        expected_identity=(literal or regex or "<unset>"),
        issuer=spec.signer_issuer,
    )
    return _CosignRunOutcome(
        findings=(finding,),
        duration=result.duration_seconds,
    )


def _resolve_settings(config: ScanConfig) -> SupplyScannerSettings:
    extra = config.extra

    cosign_image_raw = extra.get("cosign_image")
    if cosign_image_raw is None:
        cosign_image = DEFAULT_COSIGN_IMAGE
    elif isinstance(cosign_image_raw, str):
        cosign_image = cosign_image_raw.strip() or DEFAULT_COSIGN_IMAGE
    else:
        raise SupplyInputError("supply.cosign_image must be a string")

    verify_raw = extra.get("verify_images")
    images: list[CosignTargetSpec] = []
    if verify_raw is not None:
        if not isinstance(verify_raw, (list, tuple)):
            raise SupplyInputError("supply.verify_images must be a list")
        for i, item in enumerate(verify_raw):
            if not isinstance(item, dict):
                raise SupplyInputError(
                    f"supply.verify_images[{i}] must be a table / dict"
                )
            target = item.get("ref") or item.get("target_image") or ""
            if not isinstance(target, str) or not target.strip():
                raise SupplyInputError(
                    f"supply.verify_images[{i}].ref must be a non-empty string"
                )
            issuer = item.get("signer_issuer") or ""
            ident = item.get("signer_identity")
            ident_regex = item.get("signer_identity_regexp")
            if ident is not None and not isinstance(ident, str):
                raise SupplyInputError(
                    f"supply.verify_images[{i}].signer_identity must be a string"
                )
            if ident_regex is not None and not isinstance(ident_regex, str):
                raise SupplyInputError(
                    f"supply.verify_images[{i}].signer_identity_regexp "
                    "must be a string"
                )
            images.append(
                CosignTargetSpec(
                    target_image=target.strip(),
                    signer_identity=(ident.strip() if isinstance(ident, str) else None) or None,
                    signer_identity_regexp=(
                        ident_regex.strip()
                        if isinstance(ident_regex, str)
                        else None
                    )
                    or None,
                    signer_issuer=(
                        issuer.strip() if isinstance(issuer, str) else ""
                    ),
                )
            )

    def _list(key: str, label: str) -> tuple[str, ...]:
        raw = extra.get(key)
        if raw is None:
            return ()
        if not isinstance(raw, (list, tuple)):
            raise SupplyInputError(
                f"supply.{label} must be a list of strings"
            )
        out: list[str] = []
        for i, item in enumerate(raw):
            if not isinstance(item, str):
                raise SupplyInputError(
                    f"supply.{label}[{i}] must be a string"
                )
            stripped = item.strip()
            if stripped:
                out.append(stripped)
        seen: set[str] = set()
        deduped: list[str] = []
        for v in out:
            if v not in seen:
                seen.add(v)
                deduped.append(v)
        return tuple(deduped)

    return SupplyScannerSettings(
        verify_images=tuple(images),
        config_lockfiles=_list("lockfiles", "lockfiles"),
        cli_lockfiles=_list("cli_lockfiles", "cli_lockfiles"),
        cosign_image=cosign_image,
    )


def _error_outcome(
    scanner: str,
    *,
    reason: str,
    returncode: int | None = None,
    stderr: bytes = b"",
    duration: float = 0.0,
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
