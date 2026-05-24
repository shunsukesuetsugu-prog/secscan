"""Input validators for the SBOM scanner.

Phase 2-N target classification (Codex MUST-FIX #1):

A ``--target`` argument can be:

1. An existing **SBOM JSON file** (``.cdx.json`` / ``.spdx.json`` /
   ``.json``) — Syft is skipped, Grype reads it directly.
2. An existing **local directory** — Syft generates an SBOM
   from the directory contents; Grype matches against it.
3. A non-existing string that **looks like a digest-pinned OCI
   image ref** — Syft fetches the image from the registry,
   Grype matches.

Classification ORDER is critical: ``Path.exists()`` first, then
extension check for file, then image-ref regex. A naive
``"@sha256:"`` substring check (the original Phase 2-N draft) would
misclassify any local file whose name contains that substring.

Path targets that come from ``.secscan.toml`` are additionally
restricted to live under the operator-supplied scan root, so an
attacker-controlled config file cannot trick secscan into
bind-mounting ``/etc`` or ``/Users/<other>`` into the Syft
container. CLI-supplied path targets bypass that gate (the
operator typed the path themselves, so they own the choice).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..image.trivy import (
    ImageInputError,
)
from ..image.trivy import (
    validate_image_ref as _validate_image_ref_strict,
)


class SbomInputError(ValueError):
    """Caller-supplied input we refuse for the SBOM scanner."""


# Cap on the SBOM file we accept as input — both for ``Target ==
# SbomFile`` and for the intermediate SBOM Syft writes for Grype to
# consume. Same 32 MiB ceiling as Phase 2-L / 2-M; even a SBOM
# describing a multi-thousand-package monorepo rarely tops 5 MiB.
MAX_SBOM_BYTES = 32 * 1024 * 1024

# Path-charset rules for bind-mount sources: ``:`` (would break
# docker ``-v <src>:<dst>`` syntax), whitespace (would split argv),
# control / non-printable chars, and ``\`` (Windows-style separator
# that confuses docker on Linux containers) are all rejected.
# We deliberately ALLOW Unicode letters — paths containing
# non-ASCII (e.g. Japanese, European accented characters) are
# common on real developer filesystems and have no docker-argv
# implication beyond the explicit deny list. Codex Phase 2-L pin:
# any whitespace or control char is rejected.
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

# Accepted SBOM-file extensions. CycloneDX (``.cdx.json``) is the
# default Syft format and the one we feed to Grype internally; we
# also accept SPDX JSON (``.spdx.json``) and the bare ``.json``
# extension because real-world fixtures often drop the format
# prefix. The file's *content* is then schema-sniffed by Grype.
_SBOM_FILE_EXTENSIONS = (".cdx.json", ".spdx.json", ".json")


@dataclass(frozen=True)
class SbomFileTarget:
    """An existing CycloneDX / SPDX JSON file Grype will consume directly."""

    path: Path


@dataclass(frozen=True)
class DirectoryTarget:
    """A local directory Syft will scan for installed packages."""

    path: Path


@dataclass(frozen=True)
class ImageTarget:
    """An OCI image reference Syft will fetch from the registry."""

    ref: str


Target = SbomFileTarget | DirectoryTarget | ImageTarget


def classify_target(raw: str, *, source: str = "--target") -> Target:
    """Return the target kind for one ``--target`` value.

    Order (per Codex MUST-FIX #1):

    1. ``Path.exists()`` — if yes:
       a. File → extension check, size check, charset check.
       b. Directory → charset check.
       c. Something else (symlink to nowhere, FIFO, etc.) → reject.
    2. Path doesn't exist → fall through to image-ref regex.

    The ``source`` parameter only flavours error messages.
    """
    if not isinstance(raw, str):
        raise SbomInputError(f"{source} must be a string")
    candidate = raw.strip()
    if not candidate:
        raise SbomInputError(f"{source} must not be empty")
    if candidate.startswith("-"):
        # Defence in depth: even if Path.exists() returns True for
        # a file literally named ``-foo``, we refuse — a path that
        # starts with ``-`` would be argv-interpreted by docker.
        raise SbomInputError(
            f"{source} must not start with '-' "
            "(would be flag-interpreted by docker)"
        )

    p = Path(candidate)
    if p.exists():
        # Reject symlinks at the top level. We could ``.resolve()``
        # them but that would silently widen the bind-mount scope —
        # better to fail loud.
        if p.is_symlink():
            raise SbomInputError(
                f"{source}: refusing to follow top-level symlink {candidate!r}"
            )
        if p.is_file():
            return _validate_sbom_file(p, source=source)
        if p.is_dir():
            return _validate_directory(p, source=source)
        raise SbomInputError(
            f"{source}: {candidate!r} exists but is neither a regular "
            "file nor a directory"
        )

    # Path doesn't exist — only an image ref is acceptable from here.
    try:
        ref = _validate_image_ref_strict(candidate, label=source)
    except ImageInputError as exc:
        raise SbomInputError(
            f"{source}: {candidate!r} is neither an existing path nor a "
            f"digest-pinned image ref ({exc})"
        ) from exc
    return ImageTarget(ref=ref)


def _validate_sbom_file(p: Path, *, source: str) -> SbomFileTarget:
    resolved = p.resolve()
    s = str(resolved)
    if not _path_charset_ok(s):
        raise SbomInputError(
            f"{source}: SBOM file path {s!r} contains a forbidden "
            "character (':', whitespace, control char, '\\\\', etc.)"
        )
    lowered = resolved.name.lower()
    if not any(lowered.endswith(ext) for ext in _SBOM_FILE_EXTENSIONS):
        raise SbomInputError(
            f"{source}: {p} exists but does not have a recognized SBOM "
            f"extension ({_SBOM_FILE_EXTENSIONS})"
        )
    # Size cap (Codex MUST-FIX #4) — Grype will happily attempt to
    # parse a multi-gigabyte SBOM and OOM the host.
    size = resolved.stat().st_size
    if size > MAX_SBOM_BYTES:
        raise SbomInputError(
            f"{source}: SBOM file {p} is {size} bytes, exceeds the "
            f"{MAX_SBOM_BYTES}-byte cap (refusing to load)"
        )
    if size == 0:
        raise SbomInputError(f"{source}: SBOM file {p} is empty")
    return SbomFileTarget(path=resolved)


def _validate_directory(p: Path, *, source: str) -> DirectoryTarget:
    resolved = p.resolve()
    s = str(resolved)
    if not _path_charset_ok(s):
        raise SbomInputError(
            f"{source}: directory path {s!r} contains a forbidden "
            "character (':', whitespace, control char, '\\\\', etc.)"
        )
    return DirectoryTarget(path=resolved)


def assert_target_under_scan_root(
    target: Target, *, scan_root: Path
) -> None:
    """Confine config-supplied path targets to the scan root.

    Codex MUST-FIX #2 carry-over: an attacker-controlled
    ``.secscan.toml`` setting ``[sbom].targets = ["/etc"]`` would
    otherwise trick secscan into bind-mounting ``/etc`` into the
    Syft container. We refuse path targets that escape the scan
    root. Image targets and SBOM file targets are out of scope —
    image targets don't bind-mount the host filesystem at all, and
    SBOM file targets get an explicit ``--sbom-file`` review step
    documented in the README.

    CLI-supplied targets bypass this check (the operator typed
    the path themselves on the command line; they own that
    choice). The caller is responsible for passing the right
    targets to this helper.
    """
    if isinstance(target, ImageTarget):
        return
    # ``Target`` is a closed union (SbomFileTarget | DirectoryTarget |
    # ImageTarget); having ruled out ImageTarget, mypy narrows the
    # remaining type to the two path-bearing variants.
    path = target.path
    try:
        path.resolve().relative_to(scan_root.resolve())
    except ValueError as exc:
        raise SbomInputError(
            f"config target {path} escapes the scan root {scan_root} — "
            "refusing to bind-mount outside the operator-supplied tree"
        ) from exc


def validate_platform(platform: str) -> str:
    """Forward-only validator for the ``--platform`` value passed to
    the Syft CLI for image targets.

    Same regex as Phase 2-M; duplicated here to keep the SBOM
    module a leaf with no cross-module coupling.
    """
    if not isinstance(platform, str):
        raise SbomInputError("--platform must be a string")
    candidate = platform.strip()
    if not candidate:
        raise SbomInputError("--platform must not be empty")
    if candidate.startswith("-"):
        raise SbomInputError(
            "--platform must not start with '-' "
            "(would be flag-interpreted by docker)"
        )
    if not re.fullmatch(
        r"[a-z0-9][a-z0-9._\-]*(/[a-z0-9][a-z0-9._\-]*){1,2}", candidate
    ):
        raise SbomInputError(
            f"--platform value {candidate!r} is not a valid docker "
            "platform string (expected '<os>/<arch>[/<variant>]')"
        )
    return candidate


# Volume names use ``secscan-sbom-`` prefix + 32 hex chars (16
# bytes from secrets.token_hex). The regex below matches that
# exact shape and rejects anything else — defence in depth so a
# tampered config can't smuggle a docker flag through the volume
# name argv slot.
_VOLUME_NAME_RE = re.compile(r"^secscan-sbom-[0-9a-f]{32}$")
_GENERIC_VOLUME_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$"
)


def validate_intermediate_volume_name(name: str) -> str:
    """Validate the name of the short-lived volume that carries the
    SBOM from Syft to Grype.

    Generated by the scanner adapter via ``secrets.token_hex(16)``
    so this is normally a self-check; rejecting a malformed value
    nevertheless catches future regressions (e.g. someone wiring
    a config flag into the volume name).
    """
    if not isinstance(name, str):
        raise SbomInputError("intermediate volume name must be a string")
    if not _VOLUME_NAME_RE.match(name):
        raise SbomInputError(
            f"intermediate volume name {name!r} does not match the "
            "expected 'secscan-sbom-<32 hex>' shape"
        )
    return name


def validate_cache_volume_name(name: str) -> str:
    """Validate a Grype DB cache volume name (operator/bench-provided).

    Looser than the intermediate-volume check because the bench
    constant ``GRYPE_CACHE_VOLUME = 'secscan-grype-cache'`` doesn't
    have the random suffix shape. Still rejects ``/``, leading
    ``-``, and charset escapes.
    """
    if not isinstance(name, str):
        raise SbomInputError("cache volume name must be a string")
    candidate = name.strip()
    if not candidate:
        raise SbomInputError("cache volume name must not be empty")
    if "/" in candidate or candidate.startswith("-"):
        raise SbomInputError(
            f"cache volume name {candidate!r} must be a docker volume "
            "name, not a path (no '/'), and must not start with '-'"
        )
    if not _GENERIC_VOLUME_NAME_RE.match(candidate):
        raise SbomInputError(
            f"cache volume name {candidate!r} contains characters "
            "outside the docker volume-name charset [A-Za-z0-9_.-]"
        )
    return candidate
