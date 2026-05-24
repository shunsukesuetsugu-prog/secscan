"""Input validators for the supply-chain integrity scanner.

Phase 2-Q boundaries:

- ``validate_image_ref``: same digest-pin form as Phase 2-D / 2-M
  (``<repo>[:tag]@sha256:<64 hex>``). Tag-only refs are rejected
  for both target images and the cosign scanner image so a
  ``--cosign-image gcr.io/projectsigstore/cosign:v2.4.1`` cannot
  pin us to a mutable tag.
- ``validate_signer_identity``: the identity string passed to
  cosign as ``--certificate-identity``. Strict by default
  (literal match; no regex), so the operator must explicitly
  opt in to a regex via the separate
  ``validate_signer_identity_regexp``.
- ``validate_signer_issuer``: the OIDC issuer URL. Must be
  https with no userinfo/query/fragment — same posture as
  Phase 2-O ``--api-url`` validator.
- ``validate_lockfile_path``: scan-root-confined, charset-safe
  (cross-platform via ``portability.path_charset_check``), file
  must already exist (we don't create lockfiles).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ...portability import path_charset_check
from ..image.trivy import (
    ImageInputError,
)
from ..image.trivy import (
    validate_image_ref as _validate_image_ref_strict,
)


class SupplyInputError(ValueError):
    """Caller-supplied input we refuse for the supply scanner."""


# ---------------------------------------------------------------------------
# Image ref validator (re-exported via the trivy validator)
# ---------------------------------------------------------------------------


def validate_image_ref(image: str, *, label: str = "--verify-image") -> str:
    """Reject anything that is not a digest-pinned OCI image ref.

    Delegates to Phase 2-M's ``validate_image_ref`` so the regex
    + leading-dash check + whitespace policy stays in one place.
    We re-wrap the error class so callers don't import from a
    sibling scanner module.
    """
    try:
        return _validate_image_ref_strict(image, label=label)
    except ImageInputError as exc:
        raise SupplyInputError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Signer identity validators
# ---------------------------------------------------------------------------


# A cosign certificate identity is one of:
#  - email: ``foo@bar.com``
#  - DNS name: ``builds.example.com``
#  - URI: ``https://github.com/.../release.yml@refs/tags/v1.0``
# We accept any printable string but require:
#  - non-empty
#  - no whitespace
#  - no NUL / control chars
#  - no leading dash (argv flag injection)
_IDENT_PRINTABLE_RE = re.compile(r"^[!-~]+$")  # ASCII 0x21..0x7E, no spaces


def validate_signer_identity(raw: str) -> str:
    """Validate ``--signer-identity`` (literal-match, cosign
    ``--certificate-identity``).

    Codex Phase 2-Q design review MUST-FIX #2: literal match is
    the default. A regex must come through
    ``validate_signer_identity_regexp`` explicitly so an operator
    cannot accidentally pass an unintended regex that matches an
    attacker's identity too.
    """
    if not isinstance(raw, str):
        raise SupplyInputError("--signer-identity must be a string")
    candidate = raw.strip()
    if not candidate:
        raise SupplyInputError("--signer-identity must not be empty")
    if candidate.startswith("-"):
        raise SupplyInputError(
            "--signer-identity must not start with '-' "
            "(would be flag-interpreted by docker / cosign)"
        )
    if not _IDENT_PRINTABLE_RE.match(candidate):
        raise SupplyInputError(
            f"--signer-identity {candidate!r} contains whitespace, "
            "control, or non-printable characters"
        )
    return candidate


def validate_signer_identity_regexp(raw: str) -> str:
    """Validate ``--signer-identity-regexp`` (cosign
    ``--certificate-identity-regexp``).

    Same charset rules as the literal version (no whitespace, no
    control chars, no leading dash). We do NOT compile the regex
    ourselves — that's cosign's job — so a malformed regex
    surfaces as a cosign failure with the operator's pattern in
    the message, which is more useful than re.error here.
    """
    if not isinstance(raw, str):
        raise SupplyInputError("--signer-identity-regexp must be a string")
    candidate = raw.strip()
    if not candidate:
        raise SupplyInputError(
            "--signer-identity-regexp must not be empty"
        )
    if candidate.startswith("-"):
        raise SupplyInputError(
            "--signer-identity-regexp must not start with '-'"
        )
    if not _IDENT_PRINTABLE_RE.match(candidate):
        raise SupplyInputError(
            f"--signer-identity-regexp {candidate!r} contains "
            "whitespace, control, or non-printable characters"
        )
    return candidate


# ---------------------------------------------------------------------------
# Signer issuer (OIDC URL) validator
# ---------------------------------------------------------------------------


def validate_signer_issuer(raw: str) -> str:
    """Validate ``--signer-issuer`` (cosign
    ``--certificate-oidc-issuer``).

    Must be an ``https://`` URL with no userinfo/query/fragment.
    The exact URL form is part of the cosign trust chain — a
    typo here means cosign rejects the signature, which is the
    safe outcome.
    """
    if not isinstance(raw, str):
        raise SupplyInputError("--signer-issuer must be a string")
    candidate = raw.strip()
    if not candidate:
        raise SupplyInputError("--signer-issuer must not be empty")
    if candidate.startswith("-"):
        raise SupplyInputError("--signer-issuer must not start with '-'")
    parsed = urlparse(candidate)
    if parsed.scheme not in ("https",):
        raise SupplyInputError(
            f"--signer-issuer scheme must be https; got {parsed.scheme!r}"
        )
    if not parsed.netloc:
        raise SupplyInputError("--signer-issuer is missing the host")
    if parsed.username or parsed.password:
        raise SupplyInputError(
            "--signer-issuer must not contain userinfo"
        )
    if parsed.query:
        raise SupplyInputError(
            "--signer-issuer must not contain a query string"
        )
    if parsed.fragment:
        raise SupplyInputError(
            "--signer-issuer must not contain a fragment"
        )
    return candidate


# ---------------------------------------------------------------------------
# Lockfile path validator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LockfileTarget:
    """A validated path to a lockfile (npm/pip/uv) to scan for
    self-consistency."""

    path: Path
    ecosystem: str  # "npm" | "pip" | "uv"


_SUPPORTED_LOCKFILES = {
    "package-lock.json": "npm",
    "Pipfile.lock": "pip",
    "uv.lock": "uv",
}


def classify_lockfile(raw: str, *, scan_root: Path | None = None) -> LockfileTarget:
    """Validate a ``--check-lockfile`` argument and classify it
    by ecosystem.

    Codex Phase 2-Q design review MUST-FIX #2 carry-over:
    config-origin lockfile paths must live under the scan root.
    The ``scan_root`` argument is required for config-origin
    invocations; ``None`` allows the CLI-supplied bypass when
    the operator explicitly opts in.
    """
    if not isinstance(raw, str):
        raise SupplyInputError("--check-lockfile must be a string")
    candidate = raw.strip()
    if not candidate:
        raise SupplyInputError("--check-lockfile must not be empty")
    if candidate.startswith("-"):
        raise SupplyInputError(
            "--check-lockfile must not start with '-'"
        )
    if not path_charset_check(candidate):
        raise SupplyInputError(
            f"--check-lockfile {candidate!r} contains a forbidden "
            "character"
        )
    p = Path(candidate)
    if not p.exists():
        raise SupplyInputError(
            f"--check-lockfile {candidate!r} does not exist"
        )
    if p.is_symlink():
        raise SupplyInputError(
            f"--check-lockfile {candidate!r} is a symlink — refusing "
            "to follow"
        )
    if not p.is_file():
        raise SupplyInputError(
            f"--check-lockfile {candidate!r} is not a regular file"
        )
    resolved = p.resolve()
    if scan_root is not None:
        try:
            resolved.relative_to(scan_root.resolve())
        except ValueError as exc:
            raise SupplyInputError(
                f"--check-lockfile {candidate!r} escapes the scan "
                f"root {scan_root} — config-supplied lockfile paths "
                "are confined to the scan tree"
            ) from exc
    ecosystem = _SUPPORTED_LOCKFILES.get(resolved.name)
    if ecosystem is None:
        raise SupplyInputError(
            f"--check-lockfile {candidate!r}: unsupported lockfile "
            f"format. Phase 2-Q supports {sorted(_SUPPORTED_LOCKFILES)}. "
            "yarn / pnpm / cargo / go.sum will be added in a future phase."
        )
    return LockfileTarget(path=resolved, ecosystem=ecosystem)


__all__ = [
    "LockfileTarget",
    "SupplyInputError",
    "classify_lockfile",
    "validate_image_ref",
    "validate_signer_identity",
    "validate_signer_identity_regexp",
    "validate_signer_issuer",
]
