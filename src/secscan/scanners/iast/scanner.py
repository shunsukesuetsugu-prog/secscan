"""The :class:`Scanner` adapter for the IAST harness.

Phase 2-P: drives spawn-app → wait-for-port → send-probes →
terminate-process-group → parse-pyrasp-log.

Architectural notes (these differ from every other secscan
scanner, see Phase 2-P design review for rationale):

- The harness spawns ``--command`` directly as a subprocess
  under operator credentials. There is NO docker isolation.
- ``--command``, ``--probe-url``, and ``--pyrasp-log`` are
  **CLI-only** — the config parser refuses to set them. This
  is the Codex MUST-FIX #1 mitigation against config-origin
  RCE via a tampered ``.secscan.toml``.
- ``secscan all`` does NOT run this scanner. The CLI's
  ``_build_scanner_instances`` filters IastScanner out
  whenever ``command != "iast"``. Operators run IAST
  explicitly via ``secscan iast`` only.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from ...models import (
    ScanConfig,
    ScannerError,
    ScanOutcome,
    WorkUnit,
)
from ...redact import redact_text, truncate
from ...runner import CommandRunner
from ..base import Scanner
from ._pinned import (
    DEFAULT_APP_READY_TIMEOUT_SECONDS,
    DEFAULT_IAST_TIMEOUT_SECONDS,
    DEFAULT_SHUTDOWN_GRACE_SECONDS,
)
from .harness import (
    send_probes,
    spawn_app,
    terminate_process_group,
    wait_for_port,
)
from .parser import parse_pyrasp_log
from .probes import select_probes
from .validators import (
    IastInputError,
    validate_command_argv,
    validate_probe_url,
    validate_pyrasp_log_path,
)


@dataclass(frozen=True)
class IastScannerSettings:
    command_raw: str = ""
    probe_url: str = ""
    pyrasp_log_path: str = ""
    allow_risky_probes: bool = False
    app_ready_timeout: float = DEFAULT_APP_READY_TIMEOUT_SECONDS
    shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS
    probe_timeout: float = 10.0
    extra_env: tuple[tuple[str, str], ...] = field(default_factory=tuple)


class IastScanner(Scanner):
    """pyrasp-aware IAST test harness (Phase 2-P)."""

    name = "iast"
    tool_executable = ""  # No external binary to which()
    install_hint = (
        "secscan does not install pyrasp. Add `pyrasp` to your "
        "Python app's requirements and call `pyrasp.init(app, ...)` "
        "in your app startup. See README 'Phase 2-P: IAST harness' "
        "for the operator setup."
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # IAST is opt-in and per-invocation. The CLI wires it to
        # ``secscan iast`` only; the orchestrator passes the scan
        # root WorkUnit and we accept it.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        # The IAST harness does NOT use the CommandRunner — it
        # spawns the operator's app directly via subprocess.Popen
        # with process-group leadership (the runner abstraction
        # doesn't expose start_new_session). ``runner`` is part
        # of the Scanner protocol contract; we accept it for
        # signature compatibility and ignore it.
        del runner

        try:
            settings = _resolve_settings(config)
        except IastInputError as exc:
            return _error_outcome(self.name, reason=str(exc))

        if not (
            settings.command_raw
            and settings.probe_url
            and settings.pyrasp_log_path
        ):
            # Opt-in: any missing required input → no-op. The CLI
            # dispatcher rejects this case with a usage error
            # *before* reaching the scanner; this branch is a
            # belt-and-braces guard for programmatic invocation.
            return ScanOutcome(scanner=self.name)

        try:
            command = validate_command_argv(settings.command_raw)
            probe_url = validate_probe_url(settings.probe_url)
            log_path = validate_pyrasp_log_path(
                settings.pyrasp_log_path, scan_root=unit.root
            )
        except IastInputError as exc:
            return _error_outcome(self.name, reason=str(exc))

        run_id = secrets.token_hex(16)
        probes = select_probes(allow_risky=settings.allow_risky_probes)

        env = os.environ.copy()
        for k, v in settings.extra_env:
            env[k] = v
        # Always inform the operator's app that we expect it to
        # write events to ``log_path`` and to record the run-id
        # header. The app is free to ignore these — it's the
        # operator's responsibility to wire pyrasp accordingly.
        env["SECSCAN_PYRASP_LOG"] = str(log_path)
        env["SECSCAN_RUN_ID"] = run_id

        handle = None
        try:
            try:
                handle = spawn_app(command, env=env, cwd=unit.root)
            except Exception as exc:
                return _error_outcome(
                    self.name,
                    reason=f"failed to spawn app: {exc}",
                )

            if not wait_for_port(
                probe_url,
                timeout_seconds=settings.app_ready_timeout,
            ):
                return _error_outcome(
                    self.name,
                    reason=(
                        f"app did not accept TCP connections on "
                        f"{probe_url} within {settings.app_ready_timeout}s"
                    ),
                )

            # Send the probe traffic. Each probe is independent;
            # we don't abort the rest if one errors (network
            # errors are recorded in ProbeResult.error but don't
            # block the next probe).
            send_probes(
                probes,
                probe_url=probe_url,
                run_id=run_id,
                timeout_seconds=settings.probe_timeout,
            )
        finally:
            if handle is not None:
                terminate_process_group(
                    handle,
                    grace_seconds=settings.shutdown_grace_seconds,
                )

        # Parse pyrasp log. We require the run_id to filter; an
        # event without the run_id (stale or third-party) is
        # surfaced as a warning, not a Finding.
        parsed = parse_pyrasp_log(log_path, run_id=run_id)
        return ScanOutcome(
            scanner=self.name,
            findings=parsed.findings,
            warnings=parsed.warnings,
            tool_version=parsed.tool_version,
        )


def _resolve_settings(config: ScanConfig) -> IastScannerSettings:
    extra = config.extra

    def _str(key: str, default: str = "") -> str:
        raw = extra.get(key)
        if raw is None:
            return default
        if not isinstance(raw, str):
            raise IastInputError(f"iast.{key} must be a string")
        return raw.strip() or default

    def _bool(key: str, default: bool) -> bool:
        raw = extra.get(key, default)
        if not isinstance(raw, bool):
            raise IastInputError(f"iast.{key} must be a bool")
        return raw

    def _num(key: str, default: float) -> float:
        raw = extra.get(key, default)
        if (
            not isinstance(raw, (int, float))
            or isinstance(raw, bool)
            or raw <= 0
        ):
            raise IastInputError(f"iast.{key} must be a positive number")
        return float(raw)

    extra_env_raw = extra.get("extra_env", ())
    if not isinstance(extra_env_raw, (list, tuple)):
        raise IastInputError("iast.extra_env must be a list of [key,value] pairs")
    extra_env: list[tuple[str, str]] = []
    for i, pair in enumerate(extra_env_raw):
        if (
            not isinstance(pair, (list, tuple))
            or len(pair) != 2
            or not all(isinstance(x, str) for x in pair)
        ):
            raise IastInputError(
                f"iast.extra_env[{i}] must be a [string, string] pair"
            )
        extra_env.append((pair[0], pair[1]))

    return IastScannerSettings(
        command_raw=_str("command"),
        probe_url=_str("probe_url"),
        pyrasp_log_path=_str("pyrasp_log"),
        allow_risky_probes=_bool("allow_risky_probes", False),
        app_ready_timeout=_num(
            "app_ready_timeout",
            float(DEFAULT_APP_READY_TIMEOUT_SECONDS),
        ),
        shutdown_grace_seconds=_num(
            "shutdown_grace_seconds",
            float(DEFAULT_SHUTDOWN_GRACE_SECONDS),
        ),
        probe_timeout=_num("probe_timeout", 10.0),
        extra_env=tuple(extra_env),
    )


def _error_outcome(scanner: str, *, reason: str) -> ScanOutcome:
    safe = truncate(redact_text(reason))
    return ScanOutcome(
        scanner=scanner,
        error=ScannerError(
            scanner=scanner,
            reason=safe,
            stderr_excerpt=None,
            returncode=None,
        ),
    )


# Reference DEFAULT_IAST_TIMEOUT_SECONDS so static analysers don't
# strip it out of the import (it's needed for the public re-export).
_ = DEFAULT_IAST_TIMEOUT_SECONDS

__all__ = ("IastScanner", "IastScannerSettings")
