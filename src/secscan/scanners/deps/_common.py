"""Shared helpers for dependency-CVE adapters.

Tight, side-effect-free utilities. All adapters reuse the same severity
normalization and fingerprint construction so cross-ecosystem behavior is
consistent.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ...models import Severity

# Map npm/pnpm severity strings to our normalized enum. Kept conservative:
# anything outside this map becomes UNKNOWN, which Policy's
# severity_unknown_policy will handle (defaults to "warn" for deps).
_NPM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "none": Severity.INFO,
}


def severity_from_npm_label(label: object) -> Severity:
    """Normalize npm/pnpm's severity strings.

    Non-string / unknown inputs become UNKNOWN rather than guessing a level
    — guessing a severity for a finding we don't recognize would either
    under-report (LOW) or over-report (HIGH) silently.
    """
    if not isinstance(label, str):
        return Severity.UNKNOWN
    return _NPM_SEVERITY_MAP.get(label.strip().lower(), Severity.UNKNOWN)


def deps_fingerprint(
    *,
    ecosystem: str,
    package: str,
    advisory_id: str,
    workspace_id: str | None = None,
) -> str:
    """Compose a stable fingerprint for a dependency vulnerability.

    The fingerprint is independent of file paths and lockfile contents so
    moving a project or regenerating the lockfile does not invalidate
    baseline suppression. We deliberately do NOT include the affected
    version: a "still vulnerable in a newer range" event SHOULD be
    indistinguishable from the original finding, because the action (fix
    or accept) is the same.

    ``workspace_id`` scopes the fingerprint to a single workspace member
    in monorepos. Codex 20th review pinned this: without it, the same
    ``lodash + GHSA`` finding in ``packages/api`` and ``packages/web``
    would collide on one fingerprint, and ``baseline accept`` of one
    would silently suppress the other. The root-only scan (no
    workspace) keeps the legacy ``deps:...`` prefix so existing
    baselines stay valid; workspace scans use ``deps-ws:...``.
    """
    if not ecosystem or not package or not advisory_id:
        raise ValueError("ecosystem, package, and advisory_id must all be non-empty")
    if workspace_id:
        payload = "\x00".join(
            (
                "deps-ws",
                ecosystem,
                workspace_id.lower(),
                package.lower(),
                advisory_id.upper(),
            )
        )
    else:
        payload = "\x00".join(("deps", ecosystem, package.lower(), advisory_id.upper()))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdvisoryHints:
    """Best-effort metadata pulled from an advisory blob.

    Each adapter fills in what it can; the Finding constructor in the
    DepsScanner uses these to populate ``cve`` / ``cwe`` / ``fix_version`` /
    ``references`` on the normalized Finding.
    """

    title: str
    advisory_id: str
    """A stable identifier: CVE-/GHSA-/PYSEC-/MAL- /(npm) "advisory" object url."""
    severity: Severity
    cve: str | None = None
    cwe: str | None = None
    fix_version: str | None = None
    references: tuple[str, ...] = ()
    message: str = ""
