"""External command execution.

The ``CommandRunner`` Protocol is the only seam between secscan and the
outside world for subprocess execution. Scanners depend on this Protocol,
not on ``subprocess`` directly, so tests can substitute a fake runner that
returns canned stdout/stderr/returncode for any argv.

Design decisions, all driven by the Codex reviews:

- ``stdout`` and ``stderr`` are ``bytes``. Decoding is the parser's job, with
  ``errors="surrogateescape"`` so non-UTF-8 bytes survive a round-trip
  without raising. Decoding here would lose data on exotic filesystems.
- ``timed_out`` is a separate field, not a sentinel ``returncode``. Some
  external tools use the same exit code for "error" and "killed", so we
  carry the timeout signal explicitly.
- ``argv`` is returned for diagnostic display only — never re-shell-quoted
  and never executed again. Scanners pass list-of-strings (no shell=True);
  the runner enforces that at the implementation level.
- We do not stream output. For our scanners, peak output is on the order of
  a few MB of JSON, which fits comfortably in memory. Streaming would
  complicate the parser contract (must accept incremental JSON) without
  observable benefit at our scale.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    timed_out: bool


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        """Execute ``argv`` and return the result.

        Implementations must:

        - Never invoke a shell (no ``shell=True``).
        - Never raise on non-zero returncode — Scanners decide what
          non-zero means for their specific tool.
        - Surface timeouts via ``CommandResult.timed_out=True`` AND
          (by convention) a non-zero returncode, not by raising.
        - Return whatever stdout/stderr was captured before timeout.
        """
        ...


class SubprocessCommandRunner:
    """Production CommandRunner backed by ``subprocess.run``.

    No shell, no command-string concatenation, no env inheritance shortcuts.
    The caller passes the exact ``argv`` list; we forward it untouched.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        argv_tuple = tuple(argv)
        if not argv_tuple:
            raise ValueError("argv must not be empty")
        if any(not isinstance(a, str) for a in argv_tuple):
            raise TypeError("argv must be a sequence of str")

        start = time.monotonic()
        try:
            completed = subprocess.run(
                argv_tuple,
                cwd=str(cwd),
                env=dict(env) if env is not None else None,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
            duration = time.monotonic() - start
            return CommandResult(
                argv=argv_tuple,
                returncode=completed.returncode,
                stdout=completed.stdout or b"",
                stderr=completed.stderr or b"",
                duration_seconds=duration,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            return CommandResult(
                argv=argv_tuple,
                # Convention: -1 means "did not exit normally".
                returncode=-1,
                stdout=exc.stdout or b"",
                stderr=exc.stderr or b"",
                duration_seconds=duration,
                timed_out=True,
            )
        except FileNotFoundError as exc:
            # The executable itself was not on PATH. Scanners translate this
            # into a ToolNotFound error with install instructions.
            duration = time.monotonic() - start
            message = f"executable not found: {exc.filename or argv_tuple[0]}"
            return CommandResult(
                argv=argv_tuple,
                returncode=127,  # POSIX convention for "command not found"
                stdout=b"",
                stderr=message.encode("utf-8"),
                duration_seconds=duration,
                timed_out=False,
            )


def decode_output(data: bytes) -> str:
    """Decode stdout/stderr bytes with surrogateescape.

    The opposite-direction encode is also surrogateescape-safe, so any path
    that round-trips through this stays lossless even on non-UTF-8 bytes.
    """
    return data.decode("utf-8", errors="surrogateescape")
