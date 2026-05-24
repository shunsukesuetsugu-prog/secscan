"""Subprocess lifecycle + probe traffic for the IAST harness.

Phase 2-P (Codex MUST-FIX coverage) + Phase 2-W (cross-platform):

- ``Popen(... shell=False, stdout=DEVNULL, stderr=DEVNULL)`` — no
  pipe-deadlock. The POSIX branch adds ``start_new_session=True``
  to make the child a session leader so ``killpg`` reaches the
  whole tree (Flask reloader children etc.). The Windows branch
  adds ``CREATE_NEW_PROCESS_GROUP`` and relies on
  ``psutil.children(recursive=True)`` to enumerate descendants.
- ``terminate_process_group`` is graceful on POSIX (SIGTERM →
  grace → SIGKILL). On Windows ``psutil.terminate()`` maps to
  ``TerminateProcess`` which is **NOT graceful** — it's the
  Windows equivalent of SIGKILL. We document this asymmetry
  rather than pretend Windows has SIGTERM-equivalence.
- Codex Phase 2-W MUST-FIX #3 carry-over: Windows containment
  via ``CREATE_NEW_PROCESS_GROUP + psutil.children`` is
  **best-effort**, NOT a Job-Object-grade hard boundary.
  Detached descendants and parent-exits-first races can leak
  on Windows; this is documented and accepted at v0.18.0.
- Probe HTTP uses a custom ``urllib`` opener that DROPS the
  ``HTTPRedirectHandler`` and ``ProxyHandler`` — Codex
  MUST-FIX #4: no 3xx follow, no proxy env-var leak.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import psutil

from ...portability import IS_WINDOWS
from .probes import Probe
from .validators import (
    CommandSpec,
    IastInputError,
    validate_command_argv,
    validate_probe_url,
    validate_run_id,
)


@dataclass(frozen=True)
class ProcessHandle:
    """Live reference to a spawned app subprocess.

    Only the harness wires up this dataclass; tests construct it
    directly with mock ``proc`` objects to exercise the lifecycle
    helpers in isolation.

    ``process_group`` is the POSIX process group id (== leader
    pid when ``start_new_session=True``) on Linux/macOS, and is
    set to ``proc.pid`` on Windows where the concept doesn't
    apply directly. ``psutil_proc`` is the snapshot captured at
    spawn time — using it (instead of looking up by pid later)
    avoids PID-reuse races during cleanup.
    """

    proc: subprocess.Popen[bytes]
    argv: tuple[str, ...]
    pid: int
    process_group: int
    psutil_proc: psutil.Process | None


# ---------------------------------------------------------------------------
# Subprocess lifecycle
# ---------------------------------------------------------------------------


def spawn_app(
    command: CommandSpec,
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> ProcessHandle:
    """Spawn the operator-supplied app under cross-platform process
    grouping.

    POSIX (Linux/macOS):
        ``start_new_session=True`` puts the child in a fresh
        session + process group. ``os.killpg`` reaches every
        descendant — Flask's reloader children, gunicorn workers,
        etc.

    Windows:
        ``creationflags=CREATE_NEW_PROCESS_GROUP`` lets us send
        ``CTRL_BREAK_EVENT`` to a process group, but Python's
        ``psutil`` walks the parent-child tree more reliably,
        so the cleanup path uses that. The Windows "process
        group" returned here is a sentinel (= leader pid) for
        API uniformity with POSIX.
    """
    if cwd is not None and not cwd.is_dir():
        raise IastInputError(f"cwd {cwd} does not exist or is not a dir")
    # mypy: Popen's kwargs are not portable as a dict[str, object]
    # because each kw has its own type. We branch the call.
    proc: subprocess.Popen[bytes]
    if IS_WINDOWS:
        # CREATE_NEW_PROCESS_GROUP: lets CTRL_BREAK_EVENT target
        # the new group instead of inheriting the parent's.
        # ``getattr`` because mypy on POSIX doesn't see this
        # Windows-only attribute statically.
        #
        # Codex Phase 2-W diff review MUST-FIX: if this attribute
        # is unexpectedly missing (very old Python, embedded
        # build, etc.), refuse to silently fall back to ``0`` —
        # that would let the child inherit the parent's process
        # group and defeat the isolation contract documented in
        # the harness module docstring.
        create_new_group = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", None
        )
        if create_new_group is None:
            raise RuntimeError(
                "subprocess.CREATE_NEW_PROCESS_GROUP is not available "
                "on this Python build. The IAST harness cannot create "
                "an isolated process group on Windows without it. "
                "Upgrade Python or run IAST on a POSIX host."
            )
        proc = subprocess.Popen(
            list(command.argv),
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            creationflags=create_new_group,
        )
    else:
        proc = subprocess.Popen(
            list(command.argv),
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            start_new_session=True,
        )
    # Capture the psutil snapshot AT SPAWN TIME — using this
    # later avoids PID-reuse races (Codex Phase 2-W diff review
    # FIX_NEEDED #2 carry-over). If psutil cannot see the
    # process for some reason, we still want a sensible handle.
    ps_proc: psutil.Process | None
    try:
        ps_proc = psutil.Process(proc.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        ps_proc = None

    # Windows has no pgid; use leader pid as sentinel for API uniformity.
    pgid = proc.pid if IS_WINDOWS else os.getpgid(proc.pid)
    return ProcessHandle(
        proc=proc,
        argv=command.argv,
        pid=proc.pid,
        process_group=pgid,
        psutil_proc=ps_proc,
    )


def terminate_process_group(
    handle: ProcessHandle, *, grace_seconds: float = 5.0
) -> int | None:
    """Best-effort cleanup of the spawned app and its descendants.

    POSIX (graceful):
        ``killpg(pgid, SIGTERM)`` → poll for ``grace_seconds``
        → ``killpg(pgid, SIGKILL)`` regardless. The SIGKILL step
        runs even if the leader has already exited (Codex Phase
        2-P diff review MUST-FIX) so no orphan descendants
        survive in the process group.

    Windows (NOT graceful — ``psutil.terminate()`` maps to
    ``TerminateProcess``, the OS-level force-kill):
        Enumerate the process tree via ``psutil.children(
        recursive=True)`` and call ``terminate()`` (== kill) on
        each. Then ``wait_procs`` for the grace window. Then
        ``kill()`` again as a no-op to satisfy the API.

        Caveat (Codex Phase 2-W MUST-FIX #3): if the leader
        exits BEFORE we enumerate children, detached descendants
        can be missed. A full no-orphan boundary on Windows
        requires Job Objects; v0.18.0 deliberately defers that.

    Returns the final exit code of the LEADER (None if it was
    already gone or if ``wait()`` timed out).
    """
    if IS_WINDOWS:
        return _terminate_windows(handle, grace_seconds=grace_seconds)
    return _terminate_posix(handle, grace_seconds=grace_seconds)


def _terminate_posix(
    handle: ProcessHandle, *, grace_seconds: float
) -> int | None:
    # ProcessLookupError = child already exited; OSError covers
    # the "process group is gone" race. Either case is fine — we
    # fall through and let ``proc.poll`` confirm exit.
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(handle.process_group, signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, grace_seconds)
    while time.monotonic() < deadline:
        if handle.proc.poll() is not None:
            # Codex Phase 2-P diff review MUST-FIX: the LEADER may
            # exit promptly after SIGTERM while descendants in the
            # same process group are still running. Don't ``return``
            # here — break out of the wait loop and ALWAYS run the
            # group-wide SIGKILL below to ensure no orphan
            # descendants survive.
            break
        time.sleep(0.1)
    # Best-effort SIGKILL on the WHOLE process group, regardless
    # of whether the leader has already reaped. ProcessLookupError
    # on an empty group is the success case.
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(handle.process_group, signal.SIGKILL)
    try:
        return handle.proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        return None


def _terminate_windows(
    handle: ProcessHandle, *, grace_seconds: float
) -> int | None:
    # On Windows ``psutil.terminate()`` maps to ``TerminateProcess``
    # which is OS-level force-kill — there is no SIGTERM-equivalent
    # graceful shutdown. Operators relying on graceful Werkzeug
    # reloader shutdown should switch to a POSIX runner; on
    # Windows the harness will hard-kill the tree.
    procs: list[psutil.Process] = []
    if handle.psutil_proc is not None:
        try:
            procs.append(handle.psutil_proc)
            procs.extend(handle.psutil_proc.children(recursive=True))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    for p in procs:
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            p.terminate()
    # ``wait_procs`` returns the procs that finished and those
    # still alive; we don't act on alive ones differently — the
    # kill() loop below is a no-op for procs already gone.
    psutil.wait_procs(procs, timeout=max(0.1, grace_seconds))
    for p in procs:
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            p.kill()
    try:
        return handle.proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        return None


def wait_for_port(
    probe_url: str, *, timeout_seconds: float = 60.0
) -> bool:
    """Poll a TCP connect on the probe URL's host:port until ready.

    Returns True on success, False on timeout. The probe URL is
    re-validated (loopback-only) here so a test that builds a
    URL by string concatenation can't accidentally bypass the
    earlier validator.
    """
    validated = validate_probe_url(probe_url)
    parsed = urlparse(validated)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme == "http" else 443
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (TimeoutError, OSError):
            time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# Probe traffic
# ---------------------------------------------------------------------------


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Raise on every 3xx so urllib never follows a redirect.

    ``build_opener`` adds a default ``HTTPRedirectHandler`` to its
    handler chain regardless of what we pass it. To block redirect
    following we have to install our OWN handler with the same
    method names — this subclass overrides each ``http_error_3XX``
    to re-raise the response as an ``HTTPError``, which the
    probe-send loop catches and reports as a probe error (not a
    crash).
    """

    def http_error_301(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
    ) -> object:
        raise urllib.error.HTTPError(
            req.get_full_url(), code, "redirect blocked", headers, fp  # type: ignore[arg-type]
        )

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _safe_opener() -> urllib.request.OpenerDirector:
    """Codex Phase 2-P design review MUST-FIX #4: redirects and
    proxy lookups are off. ``build_opener`` always adds default
    handlers; we explicitly install a no-redirect handler and an
    empty ``ProxyHandler({})`` so any proxy environment variables
    are ignored. Equivalent to ``requests.Session(trust_env=False,
    allow_redirects=False)``.
    """
    return urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        _NoRedirectHandler(),
        urllib.request.ProxyHandler({}),
    )


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one probe HTTP request — used only for logging /
    aggregate reporting, NOT for Findings (those come from pyrasp's
    log)."""

    probe: Probe
    response_status: int | None
    response_bytes: int
    error: str | None


def send_probes(
    probes: Iterable[Probe],
    *,
    probe_url: str,
    run_id: str,
    timeout_seconds: float = 10.0,
) -> Sequence[ProbeResult]:
    """Send each probe to the operator-supplied probe URL.

    Codex MUST-FIX #4: no redirect follow, no proxy lookup.
    Codex MUST-FIX #5: every probe carries the run_id (header +
    query) so the pyrasp parser can filter for *this* run's events.
    """
    base = validate_probe_url(probe_url)
    run_id = validate_run_id(run_id)
    opener = _safe_opener()
    out: list[ProbeResult] = []
    for probe in probes:
        result = _send_one_probe(
            opener,
            probe=probe,
            base_url=base,
            run_id=run_id,
            timeout_seconds=timeout_seconds,
        )
        out.append(result)
    return out


def _send_one_probe(
    opener: urllib.request.OpenerDirector,
    *,
    probe: Probe,
    base_url: str,
    run_id: str,
    timeout_seconds: float,
) -> ProbeResult:
    # Build the URL: base + path_template. Currently every
    # built-in probe uses ``/`` as path_template — we still
    # compose via ``urljoin`` so a future path-bearing probe
    # works correctly without re-introducing string concat
    # bugs.
    if not probe.path_template.startswith("/"):
        raise IastInputError(
            f"probe {probe.probe_id} path_template {probe.path_template!r} "
            "must start with '/'"
        )
    target = base_url.rstrip("/") + probe.path_template

    query: dict[str, str] = {"secscan_run": run_id}
    # Build query string parameters.
    if probe.injection_site == "query":
        query["q"] = probe.payload
    elif probe.injection_site == "path":
        # ``{payload}`` placeholder substitution. ``urlencode`` is
        # applied to the value so a payload like ``../../etc/x``
        # is URL-escaped before going on the wire.
        replaced = probe.path_template.replace(
            "{payload}", urllib.parse.quote(probe.payload, safe="")
        )
        target = base_url.rstrip("/") + replaced
    elif probe.injection_site == "header":
        # Header-only injection: payload is sent as a probe-
        # specific custom header. Used for SSRF via Host rewrites
        # etc.
        pass
    else:
        raise IastInputError(
            f"probe {probe.probe_id} has unknown injection_site "
            f"{probe.injection_site!r}"
        )

    encoded = urllib.parse.urlencode(query)
    full_url = f"{target}{'&' if '?' in target else '?'}{encoded}"

    req = urllib.request.Request(
        url=full_url,
        method=probe.method,
        headers={
            "X-Secscan-Run-Id": run_id,
            "X-Secscan-Probe-Id": probe.probe_id,
            "User-Agent": "secscan-iast/0.17.0 (+pyrasp-aware)",
        },
    )
    if probe.injection_site == "header":
        # Header-style injection: e.g. a custom probe header that
        # an SSRF rule might consume. We add the payload to a
        # secscan-private header so we don't accidentally
        # override a standard one like Host.
        req.add_header("X-Secscan-Probe-Payload", probe.payload)

    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            body = resp.read()
        return ProbeResult(
            probe=probe,
            response_status=getattr(resp, "status", None),
            response_bytes=len(body),
            error=None,
        )
    except urllib.error.HTTPError as exc:
        return ProbeResult(
            probe=probe,
            response_status=exc.code,
            response_bytes=0,
            error=f"HTTPError {exc.code}",
        )
    except urllib.error.URLError as exc:
        return ProbeResult(
            probe=probe,
            response_status=None,
            response_bytes=0,
            error=f"URLError: {exc.reason}",
        )
    except TimeoutError:
        return ProbeResult(
            probe=probe,
            response_status=None,
            response_bytes=0,
            error="timeout",
        )


__all__: tuple[str, ...] = (
    "ProbeResult",
    "ProcessHandle",
    "send_probes",
    "spawn_app",
    "terminate_process_group",
    "wait_for_port",
)


# Imports kept at module scope so they remain top-level in the
# eventual ``__init__.py`` re-export.
_ = validate_command_argv
