"""The :class:`Scanner` adapter for DAST.

Drives ``docker run zaproxy/zap-stable@sha256:...`` via the shared
``CommandRunner`` Protocol so the test suite can swap in a
``FakeCommandRunner`` that returns canned stdout/stderr/exit codes.

Critical invariants (see also ``docs/_design/phase2d_dast_design.md``):

- The scanner does NOT run by default. It only runs when the user
  explicitly passes ``--target`` (CLI) or supplies a ``dast.target``
  in config. ``is_applicable`` returns False otherwise so
  ``secscan all`` is a no-op for DAST unless explicitly configured.
- All input (``--target``, ``--zap-image``) goes through the
  validators in ``zap.py`` BEFORE it reaches docker.
- ``shell=False`` + argv list (enforced by ``SubprocessCommandRunner``).
- The Finding location is set to a SAFE relative URI; the original
  alert URL never leaves this process in JSON/SARIF output.
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
from ._pinned import DEFAULT_ZAP_IMAGE
from .zap import (
    DastInputError,
    ZapInvocation,
    build_argv,
    parse_zap_report,
    validate_image_ref,
    validate_target_url,
)

# ZAP baseline exit-code conventions:
#   0: clean, no alerts
#   1: warn-level alerts only
#   2: fail-level alerts present
# Other codes indicate a tool failure. ZAP overloads exit codes so we
# treat 0/1/2 all as "tool ran successfully, parse the JSON for the
# real story" and reserve everything else for ``ScannerError``.
_ZAP_SUCCESS_EXIT_CODES = frozenset({0, 1, 2})


@dataclass(frozen=True)
class DastConfig:
    """Resolved DAST configuration for one scan invocation."""

    target_url: str
    image_ref: str = DEFAULT_ZAP_IMAGE
    ajax_spider: bool = False
    config_file: str | None = None
    network_mode: str = "bridge"


class DastScanner(Scanner):
    name = "dast"
    tool_executable = "docker"
    install_hint = (
        "install Docker (https://docs.docker.com/engine/install/) and ensure "
        "the daemon is reachable. The OWASP ZAP image is pulled on first use."
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # DAST is per-deployment, not per-source-tree. The orchestrator
        # passes the single root WorkUnit; we accept that one only, and
        # the CLI / config layer is responsible for deciding whether to
        # add the scanner to the registered list. The actual ``--target``
        # validation happens inside ``scan()`` because by the time we
        # reach this point the config is available.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        try:
            dast_config = _resolve_dast_config(config)
        except DastInputError as exc:
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
            canonical_target, target_host, target_warnings = validate_target_url(
                dast_config.target_url
            )
            image_ref = validate_image_ref(dast_config.image_ref)
        except DastInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        invocation = ZapInvocation(
            target_url=canonical_target,
            image_ref=image_ref,
            ajax_spider=dast_config.ajax_spider,
            config_file=dast_config.config_file,
            network_mode=dast_config.network_mode,
        )
        try:
            argv = build_argv(invocation)
        except DastInputError as exc:
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

        if result.timed_out:
            return _error_outcome(
                self.name,
                reason="ZAP scan timed out",
                returncode=result.returncode,
                stderr=result.stderr,
                duration=result.duration_seconds,
            )

        if result.returncode not in _ZAP_SUCCESS_EXIT_CODES:
            return _error_outcome(
                self.name,
                reason=f"docker/ZAP exited with {result.returncode}",
                returncode=result.returncode,
                stderr=result.stderr,
                duration=result.duration_seconds,
            )

        parsed = parse_zap_report(result.stdout, target_host=target_host)
        all_warnings: tuple[str, ...] = tuple(target_warnings) + parsed.warnings
        return ScanOutcome(
            scanner=self.name,
            findings=parsed.findings,
            warnings=all_warnings,
            tool_version=parsed.zap_version,
            duration_seconds=result.duration_seconds,
        )


def _resolve_dast_config(config: ScanConfig) -> DastConfig:
    """Read DAST settings out of the per-scanner ScanConfig.extra mapping.

    Codex Phase-2-D diff review flagged that lenient coercion
    (``bool(extra.get(...))`` for ajax_spider, no strip on
    ``image`` / ``config_file``) silently turned typos into accepted
    values. We now require exact types and treat empty / whitespace
    strings on ``image`` and ``config_file`` as the "use default" /
    "absent" sentinel rather than passing them through to the docker
    argv as ``-n ""``.
    """
    extra = config.extra
    target = extra.get("target")
    if not isinstance(target, str) or not target.strip():
        raise DastInputError(
            "DAST scanner requires a --target URL (or dast.target in config)"
        )

    image_raw = extra.get("image")
    if image_raw is None:
        image_ref = DEFAULT_ZAP_IMAGE
    elif isinstance(image_raw, str):
        stripped_image = image_raw.strip()
        image_ref = stripped_image or DEFAULT_ZAP_IMAGE
    else:
        raise DastInputError("dast.image must be a string")

    ajax_raw = extra.get("ajax_spider", False)
    if not isinstance(ajax_raw, bool):
        raise DastInputError("dast.ajax_spider must be a boolean")
    ajax_spider = ajax_raw

    config_file_raw = extra.get("config_file")
    if config_file_raw is None:
        config_file: str | None = None
    elif isinstance(config_file_raw, str):
        stripped_cf = config_file_raw.strip()
        config_file = stripped_cf or None
    else:
        raise DastInputError("dast.config_file must be a string when set")

    network_mode_raw = extra.get("network_mode", "bridge")
    if not isinstance(network_mode_raw, str):
        raise DastInputError("dast.network_mode must be a string")
    network_mode = network_mode_raw.strip().lower()
    if network_mode not in ("bridge", "host"):
        raise DastInputError(
            f"dast.network_mode must be 'bridge' or 'host', got {network_mode!r}"
        )
    return DastConfig(
        target_url=target.strip(),
        image_ref=image_ref,
        ajax_spider=ajax_spider,
        config_file=config_file,
        network_mode=network_mode,
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
