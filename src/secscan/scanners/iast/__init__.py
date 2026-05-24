"""pyrasp-aware IAST test harness (Phase 2-P).

``secscan iast --command <argv> --probe-url <URL> --pyrasp-log <path>``
spawns the operator-supplied app subprocess (pyrasp instrumentation
expected, but installed/configured by the operator — not secscan),
sends a curated set of canary HTTP probes (OWASP Top 10 categories),
then parses the pyrasp event log for runtime detections.

Phase 2-P is **CLI-only**. ``[iast]`` keys in ``.secscan.toml`` are
rejected by the config parser, ``secscan all`` filters this scanner
out unconditionally, and ``allow_active`` / ``allow_risky_probes``
must come from explicit CLI flags. This is the Codex Phase 2-P
design review MUST-FIX #1 mitigation against config-origin RCE
via a tampered config file.

Public surface:

- :class:`IastScanner` — Scanner subclass registered by the CLI.
- ``probes.SAFE_PROBES`` / ``probes.RISKY_PROBES`` — bundled
  payloads (non-destructive by default; ``RISKY_PROBES`` are
  gated behind ``--allow-risky-probes``).
- ``parser.parse_pyrasp_log`` — pure NDJSON / array parser,
  unit-tested without subprocess.
- ``harness.spawn_app`` / ``send_probes`` /
  ``terminate_process_group`` — subprocess + HTTP primitives.
- ``validators.*`` — input validators (URL loopback gate,
  command argv split, log path scan-root confinement).
"""

from __future__ import annotations

from ._pinned import (
    DEFAULT_APP_READY_TIMEOUT_SECONDS,
    DEFAULT_IAST_TIMEOUT_SECONDS,
    DEFAULT_PINNED_AT,
    DEFAULT_PYRASP_SDIST_SHA256,
    DEFAULT_PYRASP_VERSION,
    DEFAULT_SHUTDOWN_GRACE_SECONDS,
)
from .harness import (
    ProbeResult,
    ProcessHandle,
    send_probes,
    spawn_app,
    terminate_process_group,
    wait_for_port,
)
from .parser import PyraspLogParse, parse_pyrasp_log
from .probes import (
    RISKY_PROBES,
    SAFE_PROBES,
    Probe,
    select_probes,
    severity_for_category,
)
from .scanner import IastScanner, IastScannerSettings
from .validators import (
    MAX_PYRASP_LOG_BYTES,
    CommandSpec,
    IastInputError,
    validate_command_argv,
    validate_probe_url,
    validate_pyrasp_log_path,
    validate_run_id,
)

__all__ = [
    "DEFAULT_APP_READY_TIMEOUT_SECONDS",
    "DEFAULT_IAST_TIMEOUT_SECONDS",
    "DEFAULT_PINNED_AT",
    "DEFAULT_PYRASP_SDIST_SHA256",
    "DEFAULT_PYRASP_VERSION",
    "DEFAULT_SHUTDOWN_GRACE_SECONDS",
    "MAX_PYRASP_LOG_BYTES",
    "RISKY_PROBES",
    "SAFE_PROBES",
    "CommandSpec",
    "IastInputError",
    "IastScanner",
    "IastScannerSettings",
    "Probe",
    "ProbeResult",
    "ProcessHandle",
    "PyraspLogParse",
    "parse_pyrasp_log",
    "select_probes",
    "send_probes",
    "severity_for_category",
    "spawn_app",
    "terminate_process_group",
    "validate_command_argv",
    "validate_probe_url",
    "validate_pyrasp_log_path",
    "validate_run_id",
    "wait_for_port",
]
