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

import secrets as _secrets
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
    HELPER_IMAGE,
    ZAP_CONTAINER_GID,
    ZAP_CONTAINER_UID,
    DastInputError,
    ZapInvocation,
    build_argv,
    parse_zap_report,
    validate_docker_object_name,
    validate_image_ref,
    validate_target_url,
)

# Helper-container argv builders. Kept as module-level so unit tests
# can call them without spawning real docker.

_VOL_MOUNT_RW = "/wrk"


def _vol_create_argv(vol: str) -> list[str]:
    validate_docker_object_name(vol, kind="volume")
    return ["docker", "volume", "create", vol]


def _vol_chown_argv(vol: str) -> list[str]:
    """Run an Alpine helper to chown the volume to the ZAP UID/GID
    so the scan container (running with ``--cap-drop=ALL``) can
    write its report.

    Codex Phase 2-H diff review tightening: ``--cap-drop=ALL`` then
    ``--cap-add=CHOWN``. ``chown`` needs CAP_CHOWN; FOWNER is not
    required when changing UID/GID on a fresh empty volume root.
    Restricting to the single capability shrinks the helper's
    privilege envelope dramatically (no NET_BIND_SERVICE,
    SYS_ADMIN, etc. available to it). Helper also runs with
    ``--network=none`` so it has no outbound reachability.
    """
    validate_docker_object_name(vol, kind="volume")
    return [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--cap-add=CHOWN",
        "--security-opt=no-new-privileges",
        "-v",
        f"{vol}:{_VOL_MOUNT_RW}:rw",
        "--",
        HELPER_IMAGE,
        "chown",
        f"{ZAP_CONTAINER_UID}:{ZAP_CONTAINER_GID}",
        _VOL_MOUNT_RW,
    ]


def _vol_extract_argv(vol: str) -> list[str]:
    """Run an Alpine helper to ``cat`` the ZAP report to stdout, so
    we can capture it via ``CommandResult.stdout`` without bind-
    mounting a host path (avoiding the colima/Docker Desktop UID
    mapping problem). Read-only mount, dropped caps, no network.
    """
    validate_docker_object_name(vol, kind="volume")
    return [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-v",
        f"{vol}:{_VOL_MOUNT_RW}:ro",
        "--",
        HELPER_IMAGE,
        "cat",
        f"{_VOL_MOUNT_RW}/report.json",
    ]


def _vol_remove_argv(vol: str) -> list[str]:
    validate_docker_object_name(vol, kind="volume")
    return ["docker", "volume", "rm", "--force", vol]

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
    mode: str = "baseline"


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

        # Phase 2-H: use a docker named volume + Alpine helper
        # containers so the report path round-trip works on
        # colima/Docker Desktop (which map host bind-mounts to root
        # in-container regardless of host permissions) as well as
        # native Linux Docker. Lifecycle:
        #
        #   1. ``docker volume create <vol>``
        #   2. ``docker run alpine chown 1000:1000 /wrk`` (prep)
        #   3. ``docker run zap zap-baseline.py -J report.json``
        #   4. ``docker run alpine cat /wrk/report.json`` (extract)
        #   5. ``docker volume rm <vol>``  (in finally)
        #
        # Volume name uses ``token_hex(8)`` for unguessability so a
        # concurrent run on the same daemon can't collide with us.
        volume_name = f"secscan-zap-{_secrets.token_hex(8)}"
        # Defence in depth: the generator above only uses hex, but
        # validating once here catches any future change that might
        # accidentally widen the charset.
        validate_docker_object_name(volume_name, kind="volume")
        report_bytes = b""
        scan_result = None
        # Codex Phase 2-H diff review: only attempt ``docker volume rm``
        # if the create actually succeeded — otherwise the finally
        # branch would try to remove a non-existent volume and the
        # operator gets a spurious "Error: No such volume" stderr
        # warning on every failed-startup path.
        volume_created = False
        try:
            # Step 1: create volume.
            create_res = runner.run(
                _vol_create_argv(volume_name),
                cwd=unit.root,
                timeout_seconds=60,
            )
            if create_res.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason="docker volume create failed",
                    returncode=create_res.returncode,
                    stderr=create_res.stderr,
                    duration=create_res.duration_seconds,
                )
            volume_created = True

            # Step 2: chown volume to ZAP UID.
            chown_res = runner.run(
                _vol_chown_argv(volume_name),
                cwd=unit.root,
                timeout_seconds=120,
            )
            if chown_res.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason="alpine helper chown failed",
                    returncode=chown_res.returncode,
                    stderr=chown_res.stderr,
                    duration=chown_res.duration_seconds,
                )

            # Step 3: the actual ZAP scan.
            invocation = ZapInvocation(
                target_url=canonical_target,
                image_ref=image_ref,
                ajax_spider=dast_config.ajax_spider,
                config_file=dast_config.config_file,
                network_mode=dast_config.network_mode,
                report_volume=volume_name,
                mode=dast_config.mode,
            )
            try:
                scan_argv = build_argv(invocation)
            except DastInputError as exc:
                return _error_outcome(
                    self.name,
                    reason=str(exc),
                    returncode=None,
                    stderr=b"",
                    duration=0.0,
                )
            scan_result = runner.run(
                scan_argv,
                cwd=unit.root,
                timeout_seconds=config.timeout_seconds,
            )
            if scan_result.timed_out:
                return _error_outcome(
                    self.name,
                    reason="ZAP scan timed out",
                    returncode=scan_result.returncode,
                    stderr=scan_result.stderr,
                    duration=scan_result.duration_seconds,
                )

            # Step 4: extract report via alpine helper.
            # Run extract even if ZAP exited non-zero — the JSON may
            # still exist (warnings or partial results) and the
            # parser will surface that. We only short-circuit on
            # genuinely unrecoverable ZAP failures below.
            extract_res = runner.run(
                _vol_extract_argv(volume_name),
                cwd=unit.root,
                timeout_seconds=60,
            )
            if extract_res.returncode == 0:
                report_bytes = extract_res.stdout

            if scan_result.returncode not in _ZAP_SUCCESS_EXIT_CODES:
                return _error_outcome(
                    self.name,
                    reason=f"docker/ZAP exited with {scan_result.returncode}",
                    returncode=scan_result.returncode,
                    stderr=scan_result.stderr,
                    duration=scan_result.duration_seconds,
                )

            parsed = parse_zap_report(report_bytes, target_host=target_host)
            all_warnings: tuple[str, ...] = (
                tuple(target_warnings) + parsed.warnings
            )
            return ScanOutcome(
                scanner=self.name,
                findings=parsed.findings,
                warnings=all_warnings,
                tool_version=parsed.zap_version,
                duration_seconds=scan_result.duration_seconds,
            )
        finally:
            # Step 5: tear down volume. Best-effort; if rm fails the
            # operator can list orphans with
            # ``docker volume ls -q --filter name=secscan-zap-``.
            if volume_created:
                try:
                    rm_res = runner.run(
                        _vol_remove_argv(volume_name),
                        cwd=unit.root,
                        timeout_seconds=30,
                    )
                    if rm_res.returncode != 0:
                        import sys as _sys

                        _sys.stderr.write(
                            f"secscan: warning: failed to remove ZAP report "
                            f"volume {volume_name!r}; remove manually with "
                            f"`docker volume rm {volume_name}`\n"
                        )
                except Exception:
                    # Defensive: ``runner.run`` is itself a subprocess
                    # wrapper; if it raises (e.g. unforeseen OSError on
                    # the rm path), we still want the scan result the
                    # caller is waiting for. The operator can prune
                    # leftover volumes with
                    # ``docker volume prune --filter label=...``.
                    pass


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

    mode_raw = extra.get("mode", "baseline")
    if not isinstance(mode_raw, str):
        raise DastInputError("dast.mode must be a string")
    mode = mode_raw.strip().lower()
    if mode not in ("baseline", "active"):
        raise DastInputError(
            f"dast.mode must be 'baseline' or 'active', got {mode!r}"
        )

    return DastConfig(
        target_url=target.strip(),
        image_ref=image_ref,
        ajax_spider=ajax_spider,
        config_file=config_file,
        network_mode=network_mode,
        mode=mode,
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
