"""Cross-platform compatibility helpers (Phase 2-W).

Centralises the Windows-vs-POSIX differences so the rest of the
codebase can stay platform-neutral.

Two main concerns live here:

1. **Docker bind-mount path conversion.** Docker Desktop on Windows
   accepts Unix-style paths (``/c/Users/foo``) but NOT the native
   Windows form (``C:\\Users\\foo``) — the colon in the drive
   letter collides with the ``-v <src>:<dst>:<opts>`` separator.
   :func:`to_docker_host_path` converts the host path to the form
   docker accepts on the current OS. Named volumes are passed
   through unchanged.

2. **Subprocess lifecycle constants.** Windows has no
   ``SIGTERM``-equivalent that triggers graceful shutdown — the
   nearest is ``CTRL_BREAK_EVENT`` for processes spawned with
   ``CREATE_NEW_PROCESS_GROUP``. The IAST harness chooses
   spawn-time flags and termination strategy based on
   :data:`IS_WINDOWS`.

Codex Phase 2-W design review MUST-FIX coverage:
- ``to_docker_host_path`` uses the ``/c/Users/...`` Unix-style form,
  not ``C:/Users/...``, to avoid colon-delimiter ambiguity in
  ``docker -v <src>:<dst>:<opts>``.
- Named volumes (no path separators, no drive letter) pass through
  untouched.
"""

from __future__ import annotations

import sys
from pathlib import Path, PureWindowsPath

IS_WINDOWS = sys.platform == "win32"
"""Module-level constant — tests can monkeypatch this to simulate
the other OS without spawning a different Python interpreter.

``sys.platform == "win32"`` is the canonical Python check (it
returns ``"win32"`` on both 32-bit and 64-bit Windows). Macros like
``os.name == "nt"`` are subtly different (Cygwin returns
``posix`` for ``sys.platform`` but ``nt`` for ``os.name``); we use
the more specific signal."""


class PortabilityError(ValueError):
    """Raised when an input cannot be safely converted to a docker
    bind-mount path on the current OS.

    Phase 2-W diff review MUST-FIX: relative paths and UNC paths
    are refused because docker's ``-v <src>:<dst>`` semantics
    treat bare names as named volumes (silent surprise) and UNC
    paths are not a proven Docker Desktop bind syntax.
    """


def to_docker_host_path(p: Path | str) -> str:
    """Return the path string Docker expects for ``-v <p>:<dst>``.

    POSIX (Linux, macOS): ``/Users/foo/bar`` → ``"/Users/foo/bar"``
        no transformation. Absolute paths only.

    Windows: ``C:\\Users\\foo\\bar`` → ``"/c/Users/foo/bar"``
        Docker Desktop's documented Unix-style convention. The
        drive letter is lowercased and re-prefixed with ``/``,
        removing the colon that would otherwise collide with the
        ``-v`` argument separator. Drive-letter paths only —
        UNC (``\\\\server\\share``) is refused (Codex Phase 2-W
        diff review MUST-FIX).

    Codex Phase 2-W diff review MUST-FIX: relative paths are
    refused on both OSes because docker ``-v relative/path:/dst``
    would be interpreted as a NAMED VOLUME named ``relative``,
    not a bind mount. Callers must pass an absolute path.
    Callers that legitimately want to mount a named volume
    should pass that string directly to argv, NOT through this
    helper.
    """
    if isinstance(p, Path):
        path_str = str(p)
    elif isinstance(p, str):
        path_str = p
    else:
        raise TypeError(
            f"to_docker_host_path expected Path or str, got {type(p).__name__}"
        )

    if not path_str:
        raise PortabilityError("path must not be empty")

    if not IS_WINDOWS:
        # POSIX: require absolute path. Relative paths would be
        # interpreted as named volumes by docker.
        if not path_str.startswith("/"):
            raise PortabilityError(
                f"to_docker_host_path requires an absolute path; got "
                f"{path_str!r}. Pass an absolute path or, for a named "
                "volume, build the argv element directly without this helper."
            )
        return path_str

    # Windows side. Use ``PureWindowsPath`` so we parse drive
    # letters consistently even when running on a non-Windows
    # host (for testability).
    win = PureWindowsPath(path_str)
    drive = win.drive  # e.g. "C:" or "\\\\server\\share" (UNC) or ""

    if not drive:
        # No drive letter and no UNC prefix — a bare relative
        # path. Refuse to keep docker's named-volume semantics
        # from biting us.
        raise PortabilityError(
            f"to_docker_host_path requires an absolute Windows path; "
            f"got relative {path_str!r}. A relative path passed to "
            "docker -v would be interpreted as a named volume."
        )

    if not drive.endswith(":"):
        # UNC path: ``\\\\server\\share``. Docker Desktop's
        # documentation does not list a proven Unix-style
        # conversion for UNC, so refuse. Operators with a real
        # need can mount the UNC share to a drive letter first.
        raise PortabilityError(
            f"UNC paths are not supported by to_docker_host_path; "
            f"got {path_str!r}. Map the UNC share to a drive letter "
            "first (``net use Z: \\\\\\\\server\\\\share``)."
        )

    drive_letter = drive[0].lower()
    # ``win.as_posix()`` returns ``C:/Users/foo/bar``. Strip
    # the drive segment and re-prefix with ``/c``.
    posix = win.as_posix()
    # posix looks like ``C:/Users/foo/bar`` or just ``C:``.
    after_drive = posix[len(drive):]  # ``/Users/foo/bar`` or ``""``
    if not after_drive.startswith("/"):
        after_drive = "/" + after_drive if after_drive else ""
    return f"/{drive_letter}{after_drive}"


def is_windows_path(s: str) -> bool:
    """Cheap heuristic: does ``s`` look like a Windows absolute path?

    Used by validators to decide whether to apply Windows-style
    relaxation to the path charset (drive colon, backslash) or
    the strict POSIX gate. Examples that return True:

    - ``"C:\\Users\\foo"``
    - ``"D:/Projects/bar"``
    - ``"\\\\server\\share"``  (UNC path)

    Examples that return False:

    - ``"/Users/foo"``  (POSIX absolute)
    - ``"./relative"``
    - ``"named-volume-only"``
    """
    if not isinstance(s, str) or len(s) < 2:
        return False
    # Drive-letter prefix: ``X:\`` or ``X:/``
    if len(s) >= 3 and s[1] == ":" and s[0].isalpha() and s[2] in ("\\", "/"):
        return True
    # UNC path
    return bool(s.startswith("\\\\"))


def path_charset_check(s: str, *, allow_windows: bool | None = None) -> bool:
    """Cross-platform replacement for the per-scanner forbidden-
    char set.

    Returns True if ``s`` is safe to feed into a docker bind-mount
    argv element AFTER conversion via :func:`to_docker_host_path`.

    ``allow_windows`` defaults to :data:`IS_WINDOWS`. When True,
    Windows-specific chars (drive ``:``, backslash separator) are
    tolerated. Other dangerous chars (NUL, newline, embedded
    control chars, leading dash) are always rejected.

    Codex Phase 2-W MUST-FIX #1: the previous per-scanner
    validators forbade ``:``/``\\``/whitespace pre-conversion,
    which rejected every legitimate Windows path. This helper is
    the single source of truth for "what is a docker-mountable
    host path string".
    """
    if not isinstance(s, str) or not s:
        return False
    if allow_windows is None:
        allow_windows = IS_WINDOWS

    is_winpath = allow_windows and is_windows_path(s)

    for i, ch in enumerate(s):
        # NUL / CR / LF / control chars are never acceptable.
        if ord(ch) < 0x20 and ch not in ("\t",) and not is_winpath:
            return False
        if ord(ch) < 0x20 and ch not in ("\t",) and is_winpath:
            return False
        # Tab is never useful in a path; reject everywhere.
        if ch == "\t":
            return False
        # Backslash: allowed only on Windows paths.
        if ch == "\\" and not is_winpath:
            return False
        # Colon: allowed only at position 1 (drive letter) on Windows.
        if ch == ":":
            if is_winpath and i == 1:
                continue
            return False
        # Whitespace: allowed in Windows paths (e.g. ``Program
        # Files``); rejected on POSIX (operator-typed paths
        # generally don't contain spaces, and shell expansion
        # is bypassed by shell=False but ``-v`` parsing might
        # still misinterpret a space).
        if ch.isspace() and not is_winpath:
            return False
        if not ch.isprintable():
            return False
    return True
