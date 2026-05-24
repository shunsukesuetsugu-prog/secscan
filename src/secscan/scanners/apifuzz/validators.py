"""Input validators for the apifuzz scanner.

Phase 2-O classification (mirrors Phase 2-N's discipline):

A ``--schema`` argument can be one of:

1. An ``http(s)://...`` URL — Schemathesis fetches it from the
   network in its own container.
2. An existing local file with ``.yaml``/``.yml``/``.json``
   extension — bind-mounted read-only into the Schemathesis
   container.

Inline schemas are NOT supported in Phase 2-O (Codex design
review FIX_NEEDED #3 — scope reduction).

The ``--api-url`` argument is validated separately: it must be an
``http(s)://`` URL with no userinfo / query / fragment.

The ``--mode active`` flag requires a second opt-in
(``--allow-active``) per Codex Phase 2-O design review MUST-FIX
#2. The allow flag is CLI-only — it CANNOT be set from config,
so an attacker-controlled ``.secscan.toml`` cannot enable active
fuzzing on a production target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ApifuzzInputError(ValueError):
    """Caller-supplied input we refuse for the apifuzz scanner."""


# Cap on the OpenAPI schema file (and the Schemathesis NDJSON
# report) — same 32 MiB ceiling as every other phase. Even a large
# REST API schema with dozens of resources rarely tops 5 MiB.
MAX_SCHEMA_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024


# Path-charset rules: delegate to the cross-platform helper in
# ``portability.py`` (Phase 2-W). Same OS-aware policy as the
# SBOM validators — Windows paths get drive-colon + backslash
# tolerance, POSIX paths get the strict gate.
from ...portability import path_charset_check as _path_charset_ok  # noqa: E402

_SCHEMA_FILE_EXTENSIONS = (".yaml", ".yml", ".json")


@dataclass(frozen=True)
class SchemaUrl:
    """A remote ``http(s)://`` OpenAPI schema. Schemathesis fetches
    it directly from inside its container."""

    url: str


@dataclass(frozen=True)
class SchemaFile:
    """An existing local OpenAPI schema file mounted RO into the
    Schemathesis container at ``/schema/openapi.<ext>``."""

    path: Path


Schema = SchemaUrl | SchemaFile


def classify_schema(raw: str, *, source: str = "--schema") -> Schema:
    """Classify a ``--schema`` argument as URL or local file.

    Order (per Codex Phase 2-O design review):

    1. ``http://`` or ``https://`` prefix → ``SchemaUrl``.
    2. ``Path.exists()`` + recognized extension → ``SchemaFile``.
    3. Anything else → ``ApifuzzInputError``.

    Notably, a string that looks like a URL but starts with an
    unsupported scheme (``file://``, ``ftp://``) is rejected — we
    do not let Schemathesis follow arbitrary protocols.
    """
    if not isinstance(raw, str):
        raise ApifuzzInputError(f"{source} must be a string")
    candidate = raw.strip()
    if not candidate:
        raise ApifuzzInputError(f"{source} must not be empty")
    if candidate.startswith("-"):
        raise ApifuzzInputError(
            f"{source} must not start with '-' "
            "(would be flag-interpreted by docker)"
        )

    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return _validate_schema_url(candidate, source=source)

    p = Path(candidate)
    if not p.exists():
        raise ApifuzzInputError(
            f"{source}: {candidate!r} is neither an http(s) URL nor an "
            f"existing file"
        )
    if p.is_symlink():
        raise ApifuzzInputError(
            f"{source}: refusing to follow top-level symlink {candidate!r}"
        )
    if not p.is_file():
        raise ApifuzzInputError(
            f"{source}: {candidate!r} exists but is not a regular file"
        )
    return _validate_schema_file(p, source=source)


def _validate_schema_url(url: str, *, source: str) -> SchemaUrl:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ApifuzzInputError(
            f"{source}: URL scheme must be http or https; got "
            f"{parsed.scheme!r}"
        )
    if not parsed.netloc:
        raise ApifuzzInputError(f"{source}: URL is missing the host")
    if parsed.username or parsed.password:
        raise ApifuzzInputError(
            f"{source}: URL must not contain userinfo (credentials in "
            "the URL leak in logs; pass them via --auth-header instead)"
        )
    return SchemaUrl(url=url)


def _validate_schema_file(p: Path, *, source: str) -> SchemaFile:
    resolved = p.resolve()
    s = str(resolved)
    if not _path_charset_ok(s):
        raise ApifuzzInputError(
            f"{source}: schema file path {s!r} contains a forbidden "
            "character (':', whitespace, control char, '\\\\', etc.)"
        )
    name = resolved.name.lower()
    if not any(name.endswith(ext) for ext in _SCHEMA_FILE_EXTENSIONS):
        raise ApifuzzInputError(
            f"{source}: {p} exists but does not have a recognized "
            f"OpenAPI schema extension ({_SCHEMA_FILE_EXTENSIONS})"
        )
    size = resolved.stat().st_size
    if size > MAX_SCHEMA_BYTES:
        raise ApifuzzInputError(
            f"{source}: schema file {p} is {size} bytes, exceeds the "
            f"{MAX_SCHEMA_BYTES}-byte cap (refusing to load)"
        )
    if size == 0:
        raise ApifuzzInputError(f"{source}: schema file {p} is empty")
    return SchemaFile(path=resolved)


def assert_schema_file_under_scan_root(
    schema: Schema, *, scan_root: Path
) -> None:
    """Confine a config-supplied schema FILE to the scan root.

    Codex Phase 2-N MUST-FIX carry-over: an attacker-controlled
    ``.secscan.toml`` setting ``[apifuzz].schema = "/etc/foo.yaml"``
    would otherwise trick secscan into bind-mounting ``/etc/foo.yaml``
    into the Schemathesis container. URL schemas are not subject to
    this check — they're not bind-mounted.

    CLI-supplied schemas bypass this gate via the CLI-only
    ``--unsafe-allow-schema-outside-scan-root`` flag; the caller
    decides whether to invoke this helper.
    """
    if isinstance(schema, SchemaUrl):
        return
    try:
        schema.path.resolve().relative_to(scan_root.resolve())
    except ValueError as exc:
        raise ApifuzzInputError(
            f"config schema {schema.path} escapes the scan root "
            f"{scan_root} — refusing to bind-mount outside the "
            "operator-supplied tree"
        ) from exc


# ---------------------------------------------------------------------------
# API URL validator
# ---------------------------------------------------------------------------


def validate_api_url(url: str) -> str:
    """Validate the ``--api-url`` value.

    Codex Phase 2-O design review FIX_NEEDED #2: stricter than the
    DAST URL validator — reject query, fragment, and userinfo.
    The base path (if any) is preserved and becomes the trust
    boundary for outside-scope alerts.
    """
    if not isinstance(url, str):
        raise ApifuzzInputError("--api-url must be a string")
    candidate = url.strip()
    if not candidate:
        raise ApifuzzInputError("--api-url must not be empty")
    if candidate.startswith("-"):
        raise ApifuzzInputError(
            "--api-url must not start with '-' "
            "(would be flag-interpreted by docker)"
        )
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise ApifuzzInputError(
            f"--api-url scheme must be http or https; got "
            f"{parsed.scheme!r}"
        )
    if not parsed.netloc:
        raise ApifuzzInputError("--api-url is missing the host")
    if parsed.username or parsed.password:
        raise ApifuzzInputError(
            "--api-url must not contain userinfo "
            "(pass credentials via --auth-header instead)"
        )
    if parsed.query:
        raise ApifuzzInputError(
            "--api-url must not contain a query string"
        )
    if parsed.fragment:
        raise ApifuzzInputError(
            "--api-url must not contain a fragment"
        )
    return candidate


# ---------------------------------------------------------------------------
# Mode validator
# ---------------------------------------------------------------------------


_VALID_MODES = ("baseline", "active")


def validate_mode(mode: str, *, allow_active: bool) -> str:
    """Validate the ``--mode`` flag.

    Codex Phase 2-O design review MUST-FIX #2: ``active`` requires
    a second opt-in (``allow_active=True``). The ``allow_active``
    flag is CLI-only — it is NOT readable from ``.secscan.toml``,
    so an attacker-controlled config cannot enable active fuzzing
    against a production endpoint.
    """
    if not isinstance(mode, str):
        raise ApifuzzInputError("--mode must be a string")
    if mode not in _VALID_MODES:
        raise ApifuzzInputError(
            f"--mode must be one of {_VALID_MODES}; got {mode!r}"
        )
    if mode == "active" and not allow_active:
        raise ApifuzzInputError(
            "--mode=active requires the second-opt-in flag "
            "--allow-active (CLI-only — config cannot set this). "
            "Active mode sends POST/PUT/PATCH/DELETE requests that "
            "mutate target state; do NOT point at production."
        )
    return mode


# ---------------------------------------------------------------------------
# Volume name validators (mirrors Phase 2-N)
# ---------------------------------------------------------------------------


_VOLUME_NAME_RE = re.compile(r"^secscan-apifuzz-[0-9a-f]{32}$")


def validate_intermediate_volume_name(name: str) -> str:
    """Validate the name of the short-lived NDJSON-report volume.

    Generated by the scanner adapter via ``secrets.token_hex(16)``;
    this is a self-check / regression guard against future changes
    that wire a config flag into the volume name argv slot.
    """
    if not isinstance(name, str):
        raise ApifuzzInputError("intermediate volume name must be a string")
    if not _VOLUME_NAME_RE.match(name):
        raise ApifuzzInputError(
            f"intermediate volume name {name!r} does not match the "
            "expected 'secscan-apifuzz-<32 hex>' shape"
        )
    return name


# ---------------------------------------------------------------------------
# Auth header validator (re-exported from the DAST module)
# ---------------------------------------------------------------------------


def validate_auth_header(raw: str) -> tuple[str, str]:
    """Parse ``"Name: Value"`` into ``(name, value)``.

    Phase 2-K's DAST validator is the canonical implementation; we
    delegate to it so the security properties (CR/LF rejection,
    safe HTTP token charset, single-quote rejection) stay in one
    place. The ``-H`` flag Schemathesis accepts has the same
    semantics, so no per-scanner divergence is needed.
    """
    # Lazy import to avoid pulling the dast module at top-level.
    from ..dast.zap import DastInputError
    from ..dast.zap import validate_auth_header as _dast_validate

    try:
        parsed = _dast_validate(raw)
    except DastInputError as exc:
        raise ApifuzzInputError(
            f"--auth-header: {exc} (validator inherited from Phase 2-K)"
        ) from exc
    return parsed.name, parsed.value
