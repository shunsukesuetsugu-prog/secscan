"""Lockfile-integrity dispatch.

Given a validated ``LockfileTarget``, read the file (capped at
32 MiB), pick the right parser (npm/pip/uv), and return a list
of :class:`Finding` objects.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field

from ...models import Finding, Location, Severity
from ...redact import redact_text, truncate
from ._pinned import MAX_LOCKFILE_BYTES
from .parsers import check_npm_lockfile, check_pipfile_lock, check_uv_lock
from .parsers._common import LockfileIssue
from .validators import LockfileTarget

_SCANNER_NAME = "supply"

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


@dataclass(frozen=True)
class LockfileParse:
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    extra: dict[str, object] = field(default_factory=dict)


def check_lockfile(target: LockfileTarget) -> LockfileParse:
    """Read the lockfile, parse, and turn issues into Findings."""
    try:
        size = target.path.stat().st_size
    except OSError as exc:
        return LockfileParse(
            warnings=(
                f"supply: could not stat {target.path}: {exc.strerror}",
            ),
        )
    if size > MAX_LOCKFILE_BYTES:
        return LockfileParse(
            warnings=(
                f"supply: lockfile {target.path} is {size} bytes, "
                f"exceeds the {MAX_LOCKFILE_BYTES}-byte cap "
                "(refusing to parse)",
            ),
        )
    if size == 0:
        return LockfileParse(
            warnings=(f"supply: lockfile {target.path} is empty",),
        )

    text = target.path.read_text(encoding="utf-8", errors="replace")

    if target.ecosystem == "npm":
        issues, metadata = check_npm_lockfile(text)
    elif target.ecosystem == "pip":
        issues, metadata = check_pipfile_lock(text)
    elif target.ecosystem == "uv":
        issues, metadata = check_uv_lock(text)
    else:
        return LockfileParse(
            warnings=(
                f"supply: lockfile ecosystem {target.ecosystem!r} is not "
                "supported in this version",
            ),
        )

    findings = tuple(
        _finding_from_issue(target=target, issue=i) for i in issues
    )
    return LockfileParse(findings=findings, extra=metadata)


def _finding_from_issue(
    *, target: LockfileTarget, issue: LockfileIssue
) -> Finding:
    severity = _SEVERITY_MAP.get(issue.severity.lower(), Severity.LOW)
    title = truncate(redact_text(issue.title))
    message = truncate(redact_text(issue.message))
    safe_ecosystem = "".join(
        ch for ch in target.ecosystem if ch.isalnum() or ch in "-_"
    )
    location_label = f"supply/lockfile/{safe_ecosystem}"
    if issue.location_hint:
        safe_hint = "".join(
            ch for ch in issue.location_hint if ch.isprintable()
        )
        location_label = f"{location_label}/{safe_hint}"

    fingerprint_parts = (
        "supply",
        "lockfile",
        target.ecosystem,
        issue.rule_id,
        str(target.path),
        issue.location_hint,
    )
    fingerprint = hashlib.sha256(
        "\x00".join(fingerprint_parts).encode("utf-8")
    ).hexdigest()
    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=issue.rule_id,
        severity=severity,
        title=title,
        message=message,
        location=Location(file=location_label),
        fingerprint=fingerprint,
    )


__all__: Sequence[str] = ("LockfileParse", "check_lockfile")
