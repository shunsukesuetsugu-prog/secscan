"""Pure helpers for the OWASP ZAP / docker DAST adapter.

Everything in this module is side-effect-free and exhaustively
unit-tested. The :class:`secscan.scanners.dast.scanner.DastScanner`
imports these helpers and combines them with subprocess execution.

The split exists because the security-critical pieces (input
validators, argv construction, JSON parsing, URI sanitization) must
remain testable WITHOUT requiring docker on the test host.

Codex 2nd review for Phase 2-D pinned several invariants that are
encoded directly here:

- Image refs must be ``<repo>[:tag]@sha256:<hex>`` form, and the
  leading character MUST NOT be ``-`` (would otherwise be parsed by
  ``docker run`` as a flag if argv ordering ever regressed).
- ``docker run <opts> -- <image> <cmd>`` MUST include the ``--``
  separator so the image value is never flag-interpreted.
- The ZAP-reported URL is NEVER reconstructed into an external
  artifact location. We export only a sanitized relative URI of the
  form ``dast/<urlencoded-path>``; host + query + fragment are
  dropped from any externally visible representation.
- Fingerprints include a normalized ``param_token`` (``NO_PARAM``
  sentinel, list values sort+uniq'd, foreign types warned-and-fallback).
- Each Finding carries a coarse alias fingerprint so a baseline accept
  on ``(pluginid, path)`` suppresses the ``param``-bearing variant as
  well.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass

from ...models import Finding, Location, Severity
from ...redact import redact_text, truncate
from ...runner import decode_output
from ._pinned import DEFAULT_ZAP_IMAGE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCANNER_NAME = "dast"

# ZAP riskcode 0..3 = Informational/Low/Medium/High. We also accept the
# string form (``riskdesc``) for robustness across ZAP versions.
_RISKDESC_TO_SEVERITY = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}
_RISKCODE_TO_SEVERITY = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
}

# OCI image reference accepting digest pinning only. The regex
# intentionally:
#   - forbids a leading ``-`` (would be parsed as a docker flag);
#   - forbids whitespace;
#   - requires ``@sha256:<64 hex>`` so untagged / untagged+digested
#     and ``:tag``+digest both work, but a bare tag does not.
_IMAGE_REF_RE = re.compile(
    r"^"
    r"(?P<repo>[a-z0-9][a-z0-9._\-]*"  # first path segment (no leading -)
    r"(?:/[a-z0-9][a-z0-9._\-]*)*)"   # additional path segments
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}))?"
    r"@sha256:(?P<digest>[0-9a-f]{64})"
    r"$"
)

# Network ranges that are interesting enough to warn about when the
# user targets them. We do not refuse the scan — pointing DAST at a
# staging service on the corporate LAN is legitimate; we just want
# operators to notice if they accidentally targeted localhost.
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    )
)
_LOOPBACK_HOSTS = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost"}
)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


class DastInputError(ValueError):
    """Raised by validators for any caller-supplied input we refuse.

    Distinct from ``ValueError`` so the CLI can map it to a specific
    exit code with an informative message.
    """


def validate_image_ref(image: str) -> str:
    """Reject anything that is not a digest-pinned OCI image ref.

    Codex 2nd review: ``--zap-image`` flows into a subprocess argv
    list. Even with ``shell=False`` we must not let the value masquerade
    as a flag (e.g. ``--rm``), and we must not let an untagged image
    silently fall through to ``:latest``. We require:

    1. No leading ``-`` (also enforced by the regex).
    2. OCI-style ``[host/]repo[:tag]@sha256:<64 hex>`` form.
    3. ASCII, no whitespace, no control characters.

    Returns the trimmed, validated string. Raises ``DastInputError``
    on any violation, with a message that does NOT echo the offending
    value verbatim (it could include adversarial control characters).
    """
    if not isinstance(image, str):
        raise DastInputError("--zap-image must be a string")
    candidate = image.strip()
    if not candidate:
        raise DastInputError("--zap-image must not be empty")
    if candidate.startswith("-"):
        # Defensive: the regex also rejects this, but we keep the
        # explicit check so the error message is informative.
        raise DastInputError(
            "--zap-image must not start with '-' (would be interpreted "
            "as a docker flag)"
        )
    if any(ch.isspace() or not ch.isprintable() for ch in candidate):
        raise DastInputError("--zap-image must not contain whitespace or control characters")
    if not _IMAGE_REF_RE.match(candidate):
        raise DastInputError(
            "--zap-image must be of the form "
            "'<repo>[:tag]@sha256:<64 hex>' (digest pinning is required)"
        )
    return candidate


def validate_target_url(url: str) -> tuple[str, str, tuple[str, ...]]:
    """Parse and constrain ``--target``.

    Returns ``(canonical_url, host_for_fingerprint, warnings)``.

    Constraints:
    - scheme must be ``http`` or ``https`` (no ``file:``, ``javascript:``, etc.);
    - URL must have a hostname;
    - host must not start with ``-`` (defense in depth — even though we
      pass through argv, some downstream tools split URLs internally);
    - URL must be ASCII-encodable after IDNA normalization;
    - control characters / whitespace inside the URL are rejected.

    Warnings are non-fatal — currently only "target is on a private
    or loopback network".
    """
    if not isinstance(url, str):
        raise DastInputError("--target must be a string")
    raw = url.strip()
    if not raw:
        raise DastInputError("--target must not be empty")
    if any(not ch.isprintable() or ch.isspace() for ch in raw):
        raise DastInputError("--target must not contain whitespace or control characters")

    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        raise DastInputError(f"--target is not a valid URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise DastInputError(
            f"--target scheme must be http or https (got {scheme!r})"
        )

    hostname = parsed.hostname
    if not hostname:
        raise DastInputError("--target must include a hostname")
    if hostname.startswith("-"):
        raise DastInputError("--target hostname must not start with '-'")
    try:
        host_ascii = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DastInputError(f"--target hostname is not IDNA-encodable: {exc}") from exc

    # Rebuild a canonical URL with the lowercased host so fingerprints
    # are stable across case variants (e.g. ``Example.COM`` vs ``example.com``).
    netloc = host_ascii.lower()
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        # Credentials in the URL get redacted from external output, but
        # we let them through here because some authenticated DAST runs
        # require basic auth. The orchestrator's redact pass will scrub
        # display strings; baseline fingerprints derive from host only.
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"
    canonical = urllib.parse.urlunsplit(
        (scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment)
    )

    fingerprint_host = host_ascii.lower()
    if parsed.port is not None:
        fingerprint_host = f"{fingerprint_host}:{parsed.port}"

    warnings: list[str] = []
    if _is_private_or_loopback(host_ascii):
        warnings.append(
            "DAST target appears to be on a private or loopback network; "
            "make sure this is intentional"
        )

    return canonical, fingerprint_host, tuple(warnings)


def _is_private_or_loopback(host: str) -> bool:
    """Whether the host string represents a private / loopback target."""
    h = host.lower()
    if h in _LOOPBACK_HOSTS or h.endswith(".local") or h.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in _PRIVATE_NETWORKS)


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ZapInvocation:
    """Resolved inputs for a single ZAP invocation."""

    target_url: str
    image_ref: str
    ajax_spider: bool = False
    config_file: str | None = None
    network_mode: str = "bridge"
    """``bridge`` (default) or ``host``. ``host`` is only honored when
    the operator passes ``--zap-network host``."""
    report_host_dir: str | None = None
    """Host directory bind-mounted into the container at the documented
    ZAP work dir (``/zap/wrk``). Kept for backwards-compatible test
    invocations of ``build_argv``; production code now prefers
    ``report_volume`` (Phase 2-H attempt 2) because bind mounts on
    macOS/colima map the host directory to root:root inside the
    container regardless of host permissions, and ``--cap-drop=ALL``
    leaves the ZAP user (UID 1000) unable to write there.
    """

    report_volume: str | None = None
    """Docker named volume mounted at ``/zap/wrk`` in the container.

    Phase 2-H: the DastScanner creates this volume, ``chown``s it
    to the ZAP image's UID (1000) via an Alpine helper container,
    runs the ZAP scan against it, then ``cat``s the report out via
    a second Alpine helper and finally ``docker volume rm``s it.
    Named volumes (unlike bind mounts) honour the in-container
    ownership the helper sets, so this works the same on native
    Linux Docker, Docker Desktop, and colima.

    Set EITHER ``report_host_dir`` OR ``report_volume`` (not both).
    Tests that exercise argv shape without docker may set neither.
    """

    mode: str = "baseline"
    """``"baseline"`` (default) or ``"active"``.

    Phase 2-J: ``baseline`` runs ``zap-baseline.py`` (purely
    passive — HTTP header / cookie / CSP observation). ``active``
    runs ``zap-full-scan.py`` which sends payloads (SQLi / XSS /
    auth-bypass attempts / weak-password trials). Active mode
    catches CWE-287-style auth flaws the baseline misses but is
    10x slower and **must NOT be pointed at production targets**:
    it will send malformed input that can degrade service or
    create test rows in user-facing tables.

    The DastScanner refuses any other value loudly so a misspelled
    ``"acttive"`` doesn't silently fall back to baseline.
    """

    auth_headers: tuple[str, ...] = ()
    """Phase 2-K: HTTP headers to inject into every ZAP request.

    Each entry is a ``Name: Value`` pair (e.g.
    ``"Authorization: Bearer <jwt>"``). secscan converts them into
    ZAP's ``replacer`` config via ``-z -config replacer.full_list``
    entries so every probe ZAP sends carries the header.

    The motivating use case is JWT-authenticated DAST: the
    caller (typically the bench's ``--dast-authflow`` path)
    performs a login HTTP request against the target, extracts
    the bearer token, and passes it here. With the header
    injected, ZAP reaches protected endpoints (e.g. ``/api/Users``
    on Juice Shop) and the active-mode payload probes can attempt
    auth-after exploits like IDOR (CWE-639), authenticated CSRF
    (CWE-352), and post-login XSS (CWE-79).

    Each header is validated through ``validate_auth_header``
    before it can flow into the argv.
    """


# Container-side mount point. ZAP's image uses ``/zap/wrk`` as the
# documented working directory for input contexts and output reports
# (https://www.zaproxy.org/docs/docker/baseline-scan/). Mounting our
# host tempdir at that path keeps ZAP's relative path resolution
# happy and keeps the container's view minimal.
_ZAP_WORK_DIR = "/zap/wrk"
_ZAP_REPORT_NAME = "report.json"

# In-container UID of the ZAP user. The image's documented user is
# ``zap`` (UID 1000); the Alpine helper container chowns the named
# volume to this UID before we hand it to the scan container so that
# ZAP (running with ``--cap-drop=ALL``) can write its report.
ZAP_CONTAINER_UID = 1000
ZAP_CONTAINER_GID = 1000

# Small, well-known image used to chown the volume before ZAP runs
# and to ``cat`` the report out afterwards. Digest-pinned for the
# same supply-chain reasons we pin the ZAP image. ``alpine:3.20`` is
# the latest LTS line at fixture-creation time; rotate via the same
# process described in ``_pinned.py``.
HELPER_IMAGE = (
    "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)

# Docker object names (containers, volumes) accept a narrow charset
# per the docker CLI grammar. We restrict our generated names to the
# safe subset so an attacker can never inject argv via the name.
_DOCKER_OBJECT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")


def validate_docker_object_name(name: str, *, kind: str) -> str:
    """Reject docker container/volume names outside the safe charset."""
    if not isinstance(name, str) or not _DOCKER_OBJECT_NAME_RE.match(name):
        raise DastInputError(
            f"{kind} name {name!r} contains characters outside the docker "
            "object-name charset ([a-zA-Z0-9][a-zA-Z0-9_.-]{0,127})"
        )
    return name


# HTTP header name grammar (RFC 7230): visible ASCII excluding
# separators and CTLs. We're conservative and allow only the
# "token" subset; that covers every header any auth scheme uses.
_HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._\-]{0,127}$")


@dataclass(frozen=True)
class _ParsedAuthHeader:
    name: str
    value: str


def validate_auth_header(raw: str) -> _ParsedAuthHeader:
    """Parse and constrain a ``Name: Value`` header for injection.

    Phase 2-K: each ``--auth-header`` argument flows from CLI →
    ZapInvocation → ``-z -config replacer.full_list(N)...`` in
    the docker argv. The string lands inside ZAP's config
    expressions, so anything that could break out of the
    expected key/value position must be rejected.

    Rules:
    - non-empty, separable by the first ``:`` (a colon is
      mandatory; the name precedes, the value follows).
    - name matches the conservative "token" subset
      (``^[A-Za-z][A-Za-z0-9._-]{0,127}$``). This rules out
      whitespace, control characters, and ZAP's config syntax
      sigils (``,``, ``=``, parentheses).
    - value: free-form but no control / non-printable characters
      and no embedded newlines / CR.
    - **never** an empty value (use ``--no-auth-header`` to clear
      a previously-set header rather than passing an empty
      string).
    """
    if not isinstance(raw, str):
        raise DastInputError("--auth-header must be a string")
    text = raw.strip()
    if ":" not in text:
        raise DastInputError(
            "--auth-header must be of the form 'Name: Value' "
            "(missing ':')"
        )
    name, _, value = text.partition(":")
    name = name.strip()
    value = value.lstrip()
    if not _HEADER_NAME_RE.match(name):
        raise DastInputError(
            f"--auth-header name {name!r} contains characters outside "
            "the safe HTTP token charset [A-Za-z][A-Za-z0-9._-]{0,127}"
        )
    if not value:
        raise DastInputError(
            f"--auth-header {name!r} has an empty value; "
            "pass a non-empty token"
        )
    for ch in value:
        if ch in ("\r", "\n"):
            raise DastInputError(
                f"--auth-header {name!r} value contains CR/LF — "
                "header smuggling defence"
            )
        if ch == "'":
            # We wrap the value in single quotes when forwarding
            # to ZAP's ``-z`` config (the only way to preserve
            # spaces in Bearer tokens). An embedded single quote
            # would close the wrap early and let the rest of the
            # value parse as additional config tokens — reject.
            raise DastInputError(
                f"--auth-header {name!r} value contains a single quote — "
                "not currently supported (ZAP -z config quoting limitation)"
            )
        if not ch.isprintable() and ch != " " and ch != "\t":
            raise DastInputError(
                f"--auth-header {name!r} value contains a non-printable "
                "character"
            )
    return _ParsedAuthHeader(name=name, value=value)


def build_argv(invocation: ZapInvocation) -> list[str]:
    """Construct the ``docker run`` argv list.

    The argv is built so that the image reference and the ZAP command
    line are positionally on the RIGHT side of a ``--`` separator,
    making any future flag-shaped image value (which validation
    already forbids) unable to bleed into docker's option parsing.

    When ``invocation.report_host_dir`` is set, the host directory is
    bind-mounted into the container at ``/zap/wrk`` and ZAP is told
    to write ``report.json`` there. The caller is responsible for
    creating the tempdir (0700) and reading the report back after
    the container exits.
    """
    if invocation.network_mode not in ("bridge", "host"):
        raise DastInputError(
            f"network_mode must be 'bridge' or 'host', got {invocation.network_mode!r}"
        )

    # Re-validate at argv build time. Callers in DastScanner have
    # already validated, but tests sometimes hand us a ZapInvocation
    # directly and we want a single point of truth.
    image_ref = validate_image_ref(invocation.image_ref)

    argv: list[str] = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        f"--network={invocation.network_mode}",
    ]
    if invocation.report_host_dir is not None and invocation.report_volume is not None:
        raise DastInputError(
            "set EITHER report_host_dir OR report_volume; "
            "passing both is ambiguous"
        )
    if invocation.report_host_dir is not None:
        # Phase 2-W: convert the host path to docker's expected form
        # on the current OS (POSIX paths pass through, Windows paths
        # become /c/Users/...). path_charset_check rejects NUL/CR/LF/
        # control chars on every OS; on Windows drive-colons and
        # backslashes are tolerated because the conversion strips them.
        from ...portability import path_charset_check, to_docker_host_path

        if not path_charset_check(invocation.report_host_dir):
            raise DastInputError(
                "report_host_dir contains a character that cannot be "
                "safely used as a docker bind-mount source"
            )
        argv.extend(
            [
                "-v",
                f"{to_docker_host_path(invocation.report_host_dir)}:"
                f"{_ZAP_WORK_DIR}:rw",
            ]
        )
        argv.extend(["--security-opt=no-new-privileges"])
    elif invocation.report_volume is not None:
        validate_docker_object_name(invocation.report_volume, kind="volume")
        argv.extend(
            ["-v", f"{invocation.report_volume}:{_ZAP_WORK_DIR}:rw"]
        )
        argv.extend(["--security-opt=no-new-privileges"])
    # Phase 2-J: choose the ZAP entrypoint by mode.
    if invocation.mode == "baseline":
        zap_entrypoint = "zap-baseline.py"
    elif invocation.mode == "active":
        zap_entrypoint = "zap-full-scan.py"
    else:
        raise DastInputError(
            f"mode must be 'baseline' or 'active', got {invocation.mode!r}"
        )
    argv.extend(
        [
            "-t",
            "--",
            image_ref,
            zap_entrypoint,
            "-t",
            invocation.target_url,
        ]
    )
    if (
        invocation.report_host_dir is not None
        or invocation.report_volume is not None
    ):
        # zap-baseline.py resolves ``-J`` paths relative to /zap/wrk
        # inside the container, so the bare filename is correct.
        argv.extend(["-J", _ZAP_REPORT_NAME])

    if invocation.ajax_spider:
        argv.append("-j")

    if invocation.config_file is not None:
        # ZAP context file path lives inside the container; the operator
        # is expected to mount it themselves (we deliberately don't add
        # an additional bind mount for it — that's the operator's
        # responsibility outside the report tempdir).
        argv.extend(["-n", invocation.config_file])

    # Phase 2-K: HTTP header injection via ZAP's ``-z`` config
    # forwarding. Each ``--auth-header`` becomes a ``replacer``
    # entry — ZAP rewrites every outgoing request to carry the
    # header.
    #
    # ZAP's ``-z`` value is a SINGLE string that ZAP splits
    # internally on whitespace. That tokenization breaks for
    # values containing spaces (the standard "Bearer <jwt>"
    # shape!), so we wrap each ``key=value`` pair in single
    # quotes — ZAP's argument parser respects quoting around
    # config tokens. The validator already rejects single
    # quotes inside the header value, so the closing quote is
    # unambiguous.
    if invocation.auth_headers:
        z_tokens: list[str] = []
        for index, raw in enumerate(invocation.auth_headers):
            parsed = validate_auth_header(raw)
            z_tokens.extend(
                [
                    "-config",
                    f"'replacer.full_list({index}).description=secscan-auth-{index}'",
                    "-config",
                    f"'replacer.full_list({index}).enabled=true'",
                    "-config",
                    f"'replacer.full_list({index}).matchtype=REQ_HEADER'",
                    "-config",
                    f"'replacer.full_list({index}).matchstr={parsed.name}'",
                    "-config",
                    f"'replacer.full_list({index}).regex=false'",
                    "-config",
                    f"'replacer.full_list({index}).replacement={parsed.value}'",
                ]
            )
        argv.extend(["-z", " ".join(z_tokens)])

    return argv


# ---------------------------------------------------------------------------
# URI normalization (for SARIF / JSON / text output)
# ---------------------------------------------------------------------------


def normalize_alert_uri(alert_url: str | None) -> str:
    """Compute the safe relative URI we emit to external consumers.

    Returns ``dast/<urlencoded-path>``. Host, query, and fragment are
    dropped so the external artifact reference cannot leak host names
    or session-id-bearing query strings.

    Codex 2nd review: the input may legitimately be ``None`` (some
    site-level ZAP alerts have no URL); fall back to ``dast/`` in
    that case.
    """
    if not alert_url:
        return "dast/"
    try:
        parsed = urllib.parse.urlsplit(alert_url)
    except ValueError:
        return "dast/"
    path = parsed.path or "/"
    # ``urllib.parse.quote`` with no safe characters percent-encodes
    # everything except RFC 3986 unreserved characters. That kills
    # ``/``, ``..``, ``:`` and prevents path-traversal-looking URIs.
    encoded = urllib.parse.quote(path, safe="")
    return f"dast/{encoded}"


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

_NO_PARAM = "NO_PARAM"


def _normalize_param_token(
    raw_param: object,
    *,
    warnings: list[str],
) -> str:
    """Codex 2nd review's ``param_token`` normalization.

    Rules:
    - ``None`` / empty string / missing → ``NO_PARAM``
    - ``str`` → stripped value (empty → ``NO_PARAM``)
    - ``list`` → comma-joined sorted unique stringified non-empty
      scalar elements. Non-scalar elements (dict / None / nested
      list) are skipped AND counted in a warning so the operator
      knows the ZAP report contained something we didn't model.
    - other types → ``NO_PARAM`` and emit a warning
    """
    if raw_param is None:
        return _NO_PARAM
    if isinstance(raw_param, str):
        stripped = raw_param.strip()
        return stripped or _NO_PARAM
    if isinstance(raw_param, list):
        cleaned: set[str] = set()
        skipped = 0
        for item in raw_param:
            # ``bool`` is technically a subclass of ``int`` but we
            # don't want True/False to look like the strings "True" /
            # "False"; that would silently merge unrelated findings.
            if isinstance(item, bool) or not isinstance(item, (str, int, float)):
                skipped += 1
                continue
            text = str(item).strip()
            if text:
                cleaned.add(text)
        if skipped:
            warnings.append(
                f"dast: skipped {skipped} non-scalar element(s) in ZAP "
                f"alert 'param' list (only str/int/float are normalized)"
            )
        return ",".join(sorted(cleaned)) if cleaned else _NO_PARAM
    warnings.append(
        f"dast: ignoring unexpected param type {type(raw_param).__name__} "
        f"in ZAP alert (treated as NO_PARAM)"
    )
    return _NO_PARAM


def _sorted_query_keys(alert_url: str | None) -> str:
    """Sorted, comma-joined query keys (values dropped)."""
    if not alert_url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(alert_url)
    except ValueError:
        return ""
    if not parsed.query:
        return ""
    keys = sorted(
        {
            key
            for key, _ in urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True
            )
            if key
        }
    )
    return ",".join(keys)


def _url_path(alert_url: str | None) -> str:
    if not alert_url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(alert_url)
    except ValueError:
        return ""
    return parsed.path or ""


def compute_fingerprint(
    *,
    pluginid: str,
    target_host: str,
    alert_url: str | None,
    param_token: str,
) -> str:
    """Fine-grained fingerprint per the Phase 2-D design."""
    if not pluginid:
        raise DastInputError("pluginid must be non-empty for DAST fingerprint")
    payload = "\x00".join(
        (
            "dast",
            pluginid,
            target_host,
            _url_path(alert_url),
            _sorted_query_keys(alert_url),
            param_token,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_coarse_fingerprint(
    *,
    pluginid: str,
    target_host: str,
    alert_url: str | None,
) -> str:
    """Coarse alias: drops both query keys and param.

    Used as a ``fingerprint_aliases`` entry so a baseline accept on
    the ``(pluginid, path)`` granularity suppresses both ``param``-
    bearing and ``param``-less variants of the same advisory.
    """
    return compute_fingerprint(
        pluginid=pluginid,
        target_host=target_host,
        alert_url=_url_for_coarse(alert_url),
        param_token=_NO_PARAM,
    )


def _url_for_coarse(alert_url: str | None) -> str | None:
    """Strip query+fragment for the coarse fingerprint."""
    if not alert_url:
        return alert_url
    try:
        parsed = urllib.parse.urlsplit(alert_url)
    except ValueError:
        return alert_url
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", "")
    )


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ZapReportParse:
    """Result of parsing a ZAP report."""

    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    zap_version: str | None


def parse_zap_report(
    stdout: bytes,
    *,
    target_host: str,
) -> ZapReportParse:
    """Parse a ZAP JSON report into normalized Findings + warnings.

    ZAP has no formally versioned JSON schema, so we tolerate small
    shape drifts:

    - Top-level may be either ``{"site": [...]}`` or a bare ``{...}``
      with ``site`` missing (clean run).
    - Each site has an ``alerts`` array; missing → treat as 0 alerts.
    - Each alert needs ``pluginid``, ``name``, and a risk indicator
      (either ``riskcode`` (0..3) or ``riskdesc`` starting with one
      of our known severity words). Missing alerts get warned-and-skipped.
    """
    text = decode_output(stdout)
    if not text.strip():
        # ZAP can produce an empty report for some failure modes;
        # surface it as a warning so the scanner returns an error
        # outcome and the operator notices.
        return ZapReportParse(
            findings=(),
            warnings=("dast: ZAP report was empty",),
            zap_version=None,
        )

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return ZapReportParse(
            findings=(),
            warnings=(f"dast: ZAP report was not valid JSON ({exc.msg})",),
            zap_version=None,
        )

    if not isinstance(payload, dict):
        return ZapReportParse(
            findings=(),
            warnings=("dast: ZAP report root was not a JSON object",),
            zap_version=None,
        )

    sites = payload.get("site")
    if sites is None:
        # No 'site' at all → either clean or unknown shape. Treat as
        # clean but warn so the operator can investigate.
        return ZapReportParse(
            findings=(),
            warnings=("dast: ZAP report had no 'site' field",),
            zap_version=None,
        )
    if not isinstance(sites, list):
        return ZapReportParse(
            findings=(),
            warnings=("dast: ZAP report 'site' was not a list",),
            zap_version=None,
        )

    zap_version: str | None = _first_str(payload.get("@version"))
    findings_by_key: dict[str, Finding] = {}
    warnings: list[str] = []

    for site in sites:
        if not isinstance(site, dict):
            warnings.append("dast: ZAP report site entry was not an object; skipped")
            continue
        if zap_version is None:
            zap_version = _first_str(site.get("@version"))
        alerts = site.get("alerts")
        if alerts is None:
            continue
        if not isinstance(alerts, list):
            warnings.append("dast: ZAP report site.alerts was not a list; skipped")
            continue
        for alert in alerts:
            finding = _finding_from_alert(
                alert,
                target_host=target_host,
                warnings=warnings,
            )
            if finding is None:
                continue
            # Same (pluginid, path, query_keys, param) → merge by max
            # severity. The "max" comparison uses the IntEnum ordering.
            existing = findings_by_key.get(finding.fingerprint)
            if existing is None or finding.severity > existing.severity:
                findings_by_key[finding.fingerprint] = finding

    return ZapReportParse(
        findings=tuple(findings_by_key.values()),
        warnings=tuple(warnings),
        zap_version=zap_version,
    )


def _finding_from_alert(
    alert: object,
    *,
    target_host: str,
    warnings: list[str],
) -> Finding | None:
    if not isinstance(alert, dict):
        warnings.append("dast: alert was not an object; skipped")
        return None

    pluginid = _first_str(alert.get("pluginid")) or _first_str(alert.get("pluginId"))
    if not pluginid:
        warnings.append("dast: alert missing 'pluginid'; skipped")
        return None
    pluginid = pluginid.strip()

    name = _first_str(alert.get("name")) or pluginid
    severity = _severity_from_alert(alert)
    if severity is None:
        warnings.append(
            f"dast: alert {pluginid} had no recognizable severity; using UNKNOWN"
        )
        severity = Severity.UNKNOWN

    # ZAP groups instances inside a single alert object. We pick the
    # first instance URL as the representative location. If instances
    # is missing, fall back to the top-level ``url`` field that older
    # ZAP versions emit.
    instances = alert.get("instances")
    instance: dict[str, object] | None = None
    if isinstance(instances, list):
        for candidate in instances:
            if isinstance(candidate, dict):
                instance = candidate
                break
    alert_url = _first_str((instance or {}).get("uri")) or _first_str(
        alert.get("url")
    )

    raw_param: object = (instance or {}).get("param") if instance else alert.get("param")
    param_token = _normalize_param_token(raw_param, warnings=warnings)

    fingerprint = compute_fingerprint(
        pluginid=pluginid,
        target_host=target_host,
        alert_url=alert_url,
        param_token=param_token,
    )
    coarse = compute_coarse_fingerprint(
        pluginid=pluginid,
        target_host=target_host,
        alert_url=alert_url,
    )
    # Aliases must NOT contain the primary fingerprint itself —
    # ``apply_baseline`` would try the same key twice otherwise.
    aliases: tuple[str, ...] = () if coarse == fingerprint else (coarse,)

    description = _first_str(alert.get("desc")) or _first_str(alert.get("description"))
    solution = _first_str(alert.get("solution"))
    message_parts: list[str] = []
    if description:
        message_parts.append(description)
    if solution:
        message_parts.append(f"Suggested fix: {solution}")
    message = truncate(redact_text("\n\n".join(message_parts) or name))

    cwe_field = alert.get("cweid")
    cwe: str | None = None
    if isinstance(cwe_field, (str, int)) and not isinstance(cwe_field, bool):
        cwe_str = str(cwe_field).strip()
        if cwe_str and cwe_str != "-1":
            cwe = f"CWE-{cwe_str}"

    references = _references_from_alert(alert)

    safe_uri = normalize_alert_uri(alert_url)

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=pluginid,
        severity=severity,
        title=truncate(redact_text(name)),
        message=message,
        location=Location(file=safe_uri),
        fingerprint=fingerprint,
        fingerprint_aliases=aliases,
        cwe=cwe,
        references=references,
    )


def _severity_from_alert(alert: dict[str, object]) -> Severity | None:
    riskcode = alert.get("riskcode")
    if isinstance(riskcode, int) and not isinstance(riskcode, bool):
        sev = _RISKCODE_TO_SEVERITY.get(riskcode)
        if sev is not None:
            return sev
    if isinstance(riskcode, str):
        try:
            as_int = int(riskcode)
        except ValueError:
            as_int = None
        if as_int is not None:
            sev = _RISKCODE_TO_SEVERITY.get(as_int)
            if sev is not None:
                return sev
    riskdesc = alert.get("riskdesc")
    if isinstance(riskdesc, str):
        # ``riskdesc`` is usually "High (Medium)" — word is the first token.
        head = riskdesc.strip().split(None, 1)[0].lower() if riskdesc.strip() else ""
        sev = _RISKDESC_TO_SEVERITY.get(head)
        if sev is not None:
            return sev
    risk = alert.get("risk")
    if isinstance(risk, str):
        sev = _RISKDESC_TO_SEVERITY.get(risk.strip().lower())
        if sev is not None:
            return sev
    return None


_REFERENCE_LIMIT = 5
_REFERENCE_URL_RE = re.compile(r"https?://[^\s\"<>]+")


def _references_from_alert(alert: dict[str, object]) -> tuple[str, ...]:
    """Extract http(s) references from ZAP's free-form ``reference`` blob.

    ZAP packs references as newline-joined URLs inside a single string.
    We extract distinct http(s) URLs (max 5) and pass each through the
    redactor so credential-shaped strings (e.g. ``?api_key=...``) are
    scrubbed before they hit external output.
    """
    refs: list[str] = []
    reference = alert.get("reference")
    if not isinstance(reference, str):
        return ()
    seen: set[str] = set()
    for match in _REFERENCE_URL_RE.findall(reference):
        url = match.rstrip(".,;:)")
        url = redact_text(url)
        if url in seen:
            continue
        seen.add(url)
        refs.append(url)
        if len(refs) >= _REFERENCE_LIMIT:
            break
    return tuple(refs)


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


__all__: Sequence[str] = (
    "DEFAULT_ZAP_IMAGE",
    "DastInputError",
    "ZapInvocation",
    "ZapReportParse",
    "build_argv",
    "compute_coarse_fingerprint",
    "compute_fingerprint",
    "normalize_alert_uri",
    "parse_zap_report",
    "validate_image_ref",
    "validate_target_url",
)
