"""Input validators for the IAST harness.

Phase 2-P deals with the most operator-trust-sensitive surface
of any secscan scanner: it spawns ``--command`` as a subprocess
under operator credentials and sends probe traffic to
``--probe-url``. All three inputs (``command``, ``probe-url``,
``pyrasp-log``) are CLI-only and CANNOT be set from
``.secscan.toml`` (Codex Phase 2-P design review MUST-FIX #1 —
config-origin RCE would be catastrophic).

Validation layers:

1. ``validate_command_argv`` — accepts a shell-style string and
   ``shlex.split`` it into an argv list. shell=False is the
   caller's contract. argv[0] is checked for empty / dash /
   NUL / control chars.
2. ``validate_probe_url`` — ALL resolved IPs must be loopback
   (IPv4 ``127.0.0.0/8`` or IPv6 ``::1``). Scheme http/https
   only. No userinfo / query / fragment.
3. ``validate_pyrasp_log_path`` — must be a non-existing path
   inside the scan root (so pyrasp creates a fresh file under
   secscan's control; stale events from a previous run cannot
   poison the parse).
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class IastInputError(ValueError):
    """Caller-supplied input we refuse for the IAST harness."""


MAX_PYRASP_LOG_BYTES = 32 * 1024 * 1024


_FORBIDDEN_PATH_CHARS = frozenset(
    [":", "\\", "\x00", "\n", "\r", "\t", "\v", "\f"]
)


def _path_charset_ok(s: str) -> bool:
    for ch in s:
        if ch in _FORBIDDEN_PATH_CHARS:
            return False
        if ch.isspace():
            return False
        if not ch.isprintable():
            return False
    return True


# ---------------------------------------------------------------------------
# Command (subprocess argv) validator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandSpec:
    """A validated subprocess argv list, ready for ``Popen``.

    ``raw`` keeps the original shell-style string for logging /
    error messages. ``argv`` is the ``shlex.split`` result.
    """

    raw: str
    argv: tuple[str, ...]


def validate_command_argv(raw: str) -> CommandSpec:
    """Parse a shell-style command string into an argv list.

    Codex Phase 2-P design review FIX_NEEDED #1: shlex.split +
    shell=False means a literal ``"$(cat /etc/passwd)"`` token
    is harmlessly forwarded as one argv string — shell expansion
    does NOT occur. The remaining concern is malformed quoting,
    which ``shlex.split`` raises ``ValueError`` for; we re-wrap
    as ``IastInputError`` so the CLI sees a usage error rather
    than a Python traceback.

    ``argv[0]`` is checked separately so an empty or dash-leading
    command (which Popen would otherwise treat as a flag in some
    shell wrappers) is rejected loudly.
    """
    if not isinstance(raw, str):
        raise IastInputError("--command must be a string")
    candidate = raw.strip()
    if not candidate:
        raise IastInputError("--command must not be empty")
    try:
        argv = shlex.split(candidate, posix=True)
    except ValueError as exc:
        raise IastInputError(
            f"--command could not be tokenised: {exc}"
        ) from exc
    if not argv:
        raise IastInputError("--command produced an empty argv")
    head = argv[0]
    if not head:
        raise IastInputError("--command argv[0] is empty")
    if head.startswith("-"):
        raise IastInputError(
            f"--command argv[0] {head!r} must not start with '-' "
            "(would be flag-interpreted by some Popen wrappers)"
        )
    for token in argv:
        if "\x00" in token:
            raise IastInputError("--command contains a NUL byte")
        for ch in token:
            # Reject control chars but allow tabs/spaces (shlex
            # already split on whitespace, so any whitespace left
            # inside a token came from a quoted segment and is
            # legitimate — except control chars which never are).
            if ord(ch) < 0x20 and ch != " ":
                raise IastInputError(
                    f"--command contains a control character "
                    f"(0x{ord(ch):02x}) inside an argv token"
                )
    return CommandSpec(raw=candidate, argv=tuple(argv))


# ---------------------------------------------------------------------------
# Probe URL validator (loopback enforced)
# ---------------------------------------------------------------------------


_ALLOWED_LOOPBACK_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)


def validate_probe_url(url: str) -> str:
    """Validate ``--probe-url`` for loopback-only addressing.

    Codex Phase 2-P diff review MUST-FIX (DNS-rebind TOCTOU): when
    the operator passes a hostname like ``localhost``, we resolve
    it once HERE and substitute the LITERAL loopback IP back into
    the URL. Probes then target the IP, NOT the hostname — closing
    the window where a local DNS swap between validation and probe
    send could redirect traffic off-loopback.

    Additional defences:

    - ``getaddrinfo`` collects EVERY resolved address (IPv4 + IPv6).
      All must be loopback; ANY non-loopback aborts.
    - IPv4-mapped IPv6 addresses (``::ffff:8.8.8.8``) are rejected
      by ``ipaddress.is_loopback`` returning False on the mapped
      v4 — we don't have to special-case this.
    - Hostname allow-list still applies (``localhost``,
      ``ip6-localhost``, etc.) — only those are eligible for
      resolution.

    Strict scheme / userinfo / query / fragment policy mirrors
    Phase 2-O ``validate_api_url``.
    """
    if not isinstance(url, str):
        raise IastInputError("--probe-url must be a string")
    candidate = url.strip()
    if not candidate:
        raise IastInputError("--probe-url must not be empty")
    if candidate.startswith("-"):
        raise IastInputError(
            "--probe-url must not start with '-'"
        )
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise IastInputError(
            f"--probe-url scheme must be http or https; got "
            f"{parsed.scheme!r}"
        )
    if not parsed.hostname:
        raise IastInputError("--probe-url is missing the host")
    if parsed.username or parsed.password:
        raise IastInputError(
            "--probe-url must not contain userinfo "
            "(no credentials in the URL)"
        )
    if parsed.query:
        raise IastInputError("--probe-url must not contain a query string")
    if parsed.fragment:
        raise IastInputError("--probe-url must not contain a fragment")

    host = parsed.hostname
    pinned_ip = _resolve_loopback_ip(host)
    if pinned_ip is None:
        raise IastInputError(
            f"--probe-url host {host!r} does not resolve EXCLUSIVELY "
            "to loopback addresses — refusing to send probes to a "
            "non-loopback target. Use secscan dast / apifuzz for "
            "non-local targets."
        )
    # Substitute the literal IP back into the URL so the probe
    # connects to a snapshot, not to a re-resolved hostname.
    if pinned_ip == host:
        return candidate
    # Format port and rebuild the netloc. IPv6 literals must be
    # bracketed.
    port = parsed.port
    ip_lit = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    netloc = f"{ip_lit}:{port}" if port is not None else ip_lit
    path = parsed.path or ""
    return f"{parsed.scheme}://{netloc}{path}"


def _resolve_loopback_ip(host: str) -> str | None:
    """Return a literal loopback IP for ``host`` (the input itself
    if it was already a literal), or ``None`` if any resolved
    address is non-loopback.

    Codex Phase 2-P diff review MUST-FIX (DNS rebind): resolve
    ONCE and pin the result. The caller substitutes the returned
    IP back into the URL.
    """
    # Literal IP: just check it.
    try:
        ip = ipaddress.ip_address(host)
        return host if ip.is_loopback else None
    except ValueError:
        pass

    # Curated hostname allow-list: avoids DNS rebind via a malicious
    # ``foo`` record that happens to point at 127.0.0.1.
    if host.lower() not in _ALLOWED_LOOPBACK_HOSTNAMES:
        return None

    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    if not addrs:
        return None
    loopback_ip: str | None = None
    for _family, *_rest, sockaddr in addrs:
        raw_ip = sockaddr[0]
        if not isinstance(raw_ip, str):
            return None
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            return None
        if not ip_obj.is_loopback:
            # Any non-loopback address means the hostname is
            # split-horizon; refuse the whole URL.
            return None
        # Prefer IPv4 loopback if available (more compatible).
        if loopback_ip is None or "." in raw_ip:
            loopback_ip = raw_ip
    return loopback_ip


# ---------------------------------------------------------------------------
# pyrasp log file validator
# ---------------------------------------------------------------------------


def validate_pyrasp_log_path(
    raw: str, *, scan_root: Path, allow_existing: bool = False
) -> Path:
    """Validate ``--pyrasp-log`` as a scan-root-confined path.

    Codex Phase 2-P design review MUST-FIX #5: by default the
    file must NOT already exist — secscan refuses to overwrite
    or merge with a stale log. ``allow_existing=True`` is for
    tests that pre-stage a fixture.

    The path is also checked against the same charset rules as
    Phase 2-N (no ``:``, no whitespace, no backslash, no control
    chars) so a bind-mount-unsafe path cannot reach docker layer
    handling we share with other scanners.
    """
    if not isinstance(raw, str):
        raise IastInputError("--pyrasp-log must be a string")
    candidate = raw.strip()
    if not candidate:
        raise IastInputError("--pyrasp-log must not be empty")
    if candidate.startswith("-"):
        raise IastInputError("--pyrasp-log must not start with '-'")
    if not _path_charset_ok(candidate):
        raise IastInputError(
            "--pyrasp-log contains a forbidden character "
            "(':', whitespace, control char, '\\\\', etc.)"
        )
    # Reject symlinks BEFORE resolving — ``.resolve()`` follows
    # symlinks, so checking is_symlink() on the resolved Path
    # always returns False.
    pre_resolve = Path(candidate)
    if pre_resolve.is_symlink():
        raise IastInputError(
            f"--pyrasp-log {candidate!r} is a symlink; refusing to follow"
        )
    p = pre_resolve.resolve()
    if p.exists() and not allow_existing:
        raise IastInputError(
            f"--pyrasp-log {candidate!r} already exists; remove it before "
            "running secscan iast (stale events from a previous run would "
            "poison the parse)"
        )
    try:
        p.relative_to(scan_root.resolve())
    except ValueError as exc:
        raise IastInputError(
            f"--pyrasp-log {candidate!r} escapes the scan root "
            f"{scan_root} — refusing to write outside the operator-"
            "supplied tree"
        ) from exc
    return p


# ---------------------------------------------------------------------------
# Run-id (used to tag every probe and filter pyrasp events)
# ---------------------------------------------------------------------------


_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def validate_run_id(run_id: str) -> str:
    """Validate a 32-hex-char run id.

    Generated by the harness via ``secrets.token_hex(16)``; this
    check is a regression guard against future wiring that
    accidentally sources the id from external input.
    """
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise IastInputError(
            "run_id must be a 32-character hex string"
        )
    return run_id
