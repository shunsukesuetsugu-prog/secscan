"""Shared types + helpers for the per-ecosystem lockfile parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class LockfileIssue:
    """One self-consistency anomaly found in a lockfile.

    ``severity`` is a string label (``"medium"``/``"low"``) that
    the scanner adapter maps to the ``Severity`` enum. We use a
    string here so the parsers don't import the models module.

    ``rule_id`` is a stable identifier the operator can use to
    suppress the finding via ``baseline accept``.

    ``ecosystem`` is the lockfile family (``npm``/``pip``/``uv``)
    — added by the dispatcher, parsers don't fill it.

    ``location_hint`` is a free-text description of where in the
    lockfile the issue lives (e.g. ``"node_modules/foo"`` for
    npm). The adapter incorporates this into the
    ``Finding.location.file`` label.
    """

    rule_id: str
    severity: str
    title: str
    message: str
    location_hint: str = ""


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------


# SRI integrity value: ``<algorithm>-<base64>``. Algorithms cosign /
# npm / pnpm use are sha256 / sha384 / sha512. base64 chars include
# ``+/=`` plus alphanumerics.
_SRI_RE = re.compile(r"^(sha256|sha384|sha512)-[A-Za-z0-9+/=]+$")


def looks_like_sri(value: object) -> bool:
    """Return True if ``value`` is a syntactically valid SRI hash."""
    if not isinstance(value, str):
        return False
    return bool(_SRI_RE.match(value))


# Sha256 hex value used by uv / cargo / Pipfile.lock.
_SHA256_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def looks_like_sha256_hex(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return bool(_SHA256_HEX_RE.match(value))


# Canonical-registry URL prefixes per ecosystem. A resolved URL
# that doesn't start with one of these is a potential supply-chain
# concern (private registry, malicious mirror, tarball-from-tarball
# attack, etc.). The check is informational (severity LOW) rather
# than a hard reject — operators legitimately use private
# registries.
_CANONICAL_REGISTRIES = {
    "npm": (
        "https://registry.npmjs.org/",
        # Some lockfiles use the deprecated http:// form; we treat
        # that as out-of-scope (the dispatcher might emit a LOW
        # finding for that too).
    ),
    "pip": (
        "https://files.pythonhosted.org/",
        "https://pypi.org/",
    ),
    "uv": (
        "https://files.pythonhosted.org/",
        "https://pypi.org/",
    ),
}


def is_canonical_registry_url(url: object, ecosystem: str) -> bool:
    """Return True iff ``url`` points at one of the canonical
    public registry prefixes for ``ecosystem``.

    Used to flag "resolved URL is not registry.npmjs.org" as a
    LOW supply-chain anomaly — could be benign (private mirror)
    but worth surfacing in CI output.
    """
    if not isinstance(url, str):
        return False
    prefixes = _CANONICAL_REGISTRIES.get(ecosystem, ())
    return any(url.startswith(p) for p in prefixes)
