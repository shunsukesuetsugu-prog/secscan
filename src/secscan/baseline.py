"""Baseline (known-issue suppression) management.

Baseline is the most security-sensitive feature in secscan. A malicious or
careless ``baseline accept`` can hide every finding in a repo. The design
mitigates this in several layers:

- Every entry records ``accepted_by``, ``reason`` (non-empty), ``added_at``,
  ``expires_at``, ``secscan_version``, and ``raw_fingerprint``.
- ``accept`` in CI mode (``SECSCAN_CI=1``) is refused.
- ``accept`` requires ``--fingerprint <hash>...`` or ``--all`` — never an
  implicit "accept everything seen recently".
- Expired entries are NOT auto-removed; they simply stop suppressing. The
  user must run ``baseline prune`` deliberately.
- A change in ``tool_versions`` or ``config_hash`` between the baseline and
  the current run emits a warning, surfaced to the reporter.

JSON schema is versioned. Unknown ``version`` is rejected; we never try to
"best-effort" parse an unknown future format.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__ as SECSCAN_VERSION
from .models import Finding

BASELINE_VERSION = 1
CI_ENV_VAR = "SECSCAN_CI"


class BaselineError(ValueError):
    """Raised on malformed baseline files or invalid accept requests."""


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    scanner: str
    rule_id: str
    reason: str
    accepted_by: str
    added_at: datetime
    expires_at: datetime
    secscan_version: str
    title: str | None = None
    raw_fingerprint: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    source_location: str | None = None
    """Display-friendly "file:line" or "package@version" for audit logs."""

    def is_expired(self, *, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        return moment >= self.expires_at


@dataclass(frozen=True)
class Baseline:
    """In-memory representation of a baseline file."""

    version: int = BASELINE_VERSION
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    created_by: str = ""
    tool_versions: dict[str, str] = field(default_factory=dict)
    config_hash: str | None = None
    entries: tuple[BaselineEntry, ...] = ()

    def by_fingerprint(self) -> dict[str, BaselineEntry]:
        return {entry.fingerprint: entry for entry in self.entries}


@dataclass(frozen=True)
class BaselineApplication:
    """Result of applying a baseline to a sequence of findings."""

    kept: tuple[Finding, ...]
    """Findings that were NOT suppressed."""

    suppressed: tuple[Finding, ...]
    """Findings suppressed by a (still-valid) baseline entry."""

    warnings: tuple[str, ...]
    """Non-fatal notes: expired entries, tool_version drift, etc."""


# --- I/O -------------------------------------------------------------------


def load_baseline(path: Path) -> Baseline | None:
    """Load a baseline from disk. Returns None if the file does not exist."""
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"could not read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"invalid JSON in baseline {path}: {exc}") from exc

    return _parse_baseline(raw, source=path)


def save_baseline(baseline: Baseline, path: Path) -> None:
    """Atomically write the baseline to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _serialize_baseline(baseline)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _parse_baseline(raw: object, source: Path) -> Baseline:
    if not isinstance(raw, dict):
        raise BaselineError(f"baseline {source}: root must be an object")

    version = raw.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"baseline {source}: unsupported version {version!r} "
            f"(expected {BASELINE_VERSION})"
        )

    entries_raw = raw.get("entries", [])
    if not isinstance(entries_raw, list):
        raise BaselineError(f"baseline {source}: 'entries' must be a list")

    entries: list[BaselineEntry] = []
    for i, entry_raw in enumerate(entries_raw):
        entries.append(_parse_entry(entry_raw, source, i))

    tool_versions_raw = raw.get("tool_versions", {})
    if not isinstance(tool_versions_raw, dict):
        raise BaselineError(f"baseline {source}: 'tool_versions' must be an object")
    tool_versions: dict[str, str] = {}
    for k, v in tool_versions_raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise BaselineError(
                f"baseline {source}: tool_versions entries must be string -> string"
            )
        tool_versions[k] = v

    return Baseline(
        version=version,
        created_at=_parse_dt(raw.get("created_at"), f"baseline {source}: created_at"),
        created_by=_require_str(raw.get("created_by", ""), f"baseline {source}: created_by"),
        tool_versions=tool_versions,
        config_hash=_optional_str(
            raw.get("config_hash"), f"baseline {source}: config_hash"
        ),
        entries=tuple(entries),
    )


def _parse_entry(raw: object, source: Path, index: int) -> BaselineEntry:
    where = f"baseline {source}: entries[{index}]"
    if not isinstance(raw, dict):
        raise BaselineError(f"{where} must be an object")
    return BaselineEntry(
        fingerprint=_require_str(raw.get("fingerprint"), f"{where}.fingerprint"),
        scanner=_require_str(raw.get("scanner"), f"{where}.scanner"),
        rule_id=_require_str(raw.get("rule_id"), f"{where}.rule_id"),
        reason=_require_non_empty_str(raw.get("reason"), f"{where}.reason"),
        accepted_by=_require_str(raw.get("accepted_by", ""), f"{where}.accepted_by"),
        added_at=_parse_dt(raw.get("added_at"), f"{where}.added_at"),
        expires_at=_parse_dt(raw.get("expires_at"), f"{where}.expires_at"),
        secscan_version=_require_str(
            raw.get("secscan_version", ""), f"{where}.secscan_version"
        ),
        title=_optional_str(raw.get("title"), f"{where}.title"),
        raw_fingerprint=_optional_str(
            raw.get("raw_fingerprint"), f"{where}.raw_fingerprint"
        ),
        package=_optional_str(raw.get("package"), f"{where}.package"),
        ecosystem=_optional_str(raw.get("ecosystem"), f"{where}.ecosystem"),
        source_location=_optional_str(
            raw.get("source_location"), f"{where}.source_location"
        ),
    )


def _serialize_baseline(baseline: Baseline) -> dict[str, Any]:
    return {
        "version": baseline.version,
        "created_at": _format_dt(baseline.created_at),
        "created_by": baseline.created_by,
        "tool_versions": baseline.tool_versions,
        "config_hash": baseline.config_hash,
        "entries": [_serialize_entry(e) for e in baseline.entries],
    }


def _serialize_entry(entry: BaselineEntry) -> dict[str, Any]:
    return {
        "fingerprint": entry.fingerprint,
        "scanner": entry.scanner,
        "rule_id": entry.rule_id,
        "title": entry.title,
        "raw_fingerprint": entry.raw_fingerprint,
        "package": entry.package,
        "ecosystem": entry.ecosystem,
        "source_location": entry.source_location,
        "reason": entry.reason,
        "accepted_by": entry.accepted_by,
        "added_at": _format_dt(entry.added_at),
        "expires_at": _format_dt(entry.expires_at),
        "secscan_version": entry.secscan_version,
    }


# --- Apply / accept / prune ------------------------------------------------


def apply_baseline(
    findings: tuple[Finding, ...],
    baseline: Baseline | None,
    *,
    current_tool_versions: dict[str, str] | None = None,
    current_config_hash: str | None = None,
    now: datetime | None = None,
) -> BaselineApplication:
    """Split findings into kept vs. suppressed, with audit warnings.

    A baseline entry matches a finding only when ALL of fingerprint, scanner,
    and rule_id match. Codex 3rd review flagged fingerprint-only matching as
    a cross-scanner suppression risk (a hash collision across scanners would
    silently silence both).

    Expired entries do NOT suppress; an "expired baseline entry" warning is
    emitted instead, so reviewers know the suppression has lapsed. This is
    deliberate — we want loud lapses rather than silent re-detection.
    """
    if baseline is None or not baseline.entries:
        return BaselineApplication(kept=findings, suppressed=(), warnings=())

    moment = now or datetime.now(UTC)
    # Index by the full (fingerprint, scanner, rule_id) tuple — never on
    # fingerprint alone.
    by_key: dict[tuple[str, str, str], BaselineEntry] = {
        (e.fingerprint, e.scanner, e.rule_id): e for e in baseline.entries
    }
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    expired_seen: set[str] = set()

    for finding in findings:
        # Phase 2-D / Codex 2nd review: DAST findings carry alias
        # fingerprints (coarse + fine) so a single baseline accept on
        # either granularity suppresses both representations. We try
        # the primary fingerprint first (the one the user is most
        # likely to see in reports), then any aliases in declared order.
        entry: BaselineEntry | None = None
        candidates: tuple[str, ...] = (finding.fingerprint, *finding.fingerprint_aliases)
        for fp in candidates:
            entry = by_key.get((fp, finding.scanner, finding.rule_id))
            if entry is not None:
                break
        if entry is None:
            kept.append(finding)
            continue
        if entry.is_expired(now=moment):
            kept.append(finding)
            expired_seen.add(entry.fingerprint)
            continue
        suppressed.append(finding)

    warnings: list[str] = []
    # Build a fingerprint→entry index just for the warning lookup. Multiple
    # baseline entries could share a fingerprint across (scanner, rule_id);
    # we surface one warning per fingerprint to keep noise bounded.
    by_fp_for_warnings: dict[str, BaselineEntry] = {e.fingerprint: e for e in baseline.entries}
    for fp in expired_seen:
        entry = by_fp_for_warnings[fp]
        warnings.append(
            f"baseline entry expired and no longer suppressing: "
            f"{entry.scanner}:{entry.rule_id} ({entry.fingerprint[:12]}...)"
        )

    if current_tool_versions is not None and baseline.tool_versions:
        for tool, expected in baseline.tool_versions.items():
            actual = current_tool_versions.get(tool)
            if actual is not None and actual != expected:
                warnings.append(
                    f"tool version drift: {tool} baseline={expected} current={actual} "
                    f"(consider re-creating the baseline)"
                )

    if (
        current_config_hash is not None
        and baseline.config_hash is not None
        and current_config_hash != baseline.config_hash
    ):
        warnings.append(
            "config hash changed since baseline was created "
            "(consider re-creating the baseline)"
        )

    return BaselineApplication(
        kept=tuple(kept),
        suppressed=tuple(suppressed),
        warnings=tuple(warnings),
    )


def is_ci_environment() -> bool:
    """Whether SECSCAN_CI=1 is set, blocking interactive baseline writes."""
    return os.environ.get(CI_ENV_VAR, "").strip() == "1"


def build_entry(
    finding: Finding,
    *,
    reason: str,
    accepted_by: str,
    expiry_days: int,
    now: datetime | None = None,
) -> BaselineEntry:
    """Build a primary BaselineEntry from a Finding.

    ``reason`` must be non-empty (also enforced by the parser).

    Note: this returns ONLY the primary entry. For findings that carry
    ``fingerprint_aliases`` (currently DAST), the
    :func:`build_entries_for_accept` helper expands the alias set so
    one ``baseline accept`` covers every variant.
    """
    if not reason.strip():
        raise BaselineError("reason must not be empty")
    moment = now or datetime.now(UTC)
    location = finding.location
    source_location: str | None = None
    if location is not None:
        if location.file and location.line is not None:
            source_location = f"{location.file}:{location.line}"
        elif location.package:
            source_location = location.package
        elif location.file:
            source_location = location.file

    return BaselineEntry(
        fingerprint=finding.fingerprint,
        scanner=finding.scanner,
        rule_id=finding.rule_id,
        reason=reason.strip(),
        accepted_by=accepted_by,
        added_at=moment,
        expires_at=moment + timedelta(days=expiry_days),
        secscan_version=SECSCAN_VERSION,
        title=finding.title or None,
        raw_fingerprint=finding.raw_fingerprint,
        package=location.package if location else None,
        ecosystem=location.ecosystem if location else None,
        source_location=source_location,
    )


def build_entries_for_accept(
    finding: Finding,
    *,
    reason: str,
    accepted_by: str,
    expiry_days: int,
    now: datetime | None = None,
) -> tuple[BaselineEntry, ...]:
    """Build every baseline entry needed to suppress a finding.

    For most scanners this is a single-entry tuple matching the
    fine-grained ``finding.fingerprint``. For findings that declare
    ``fingerprint_aliases`` (Phase 2-D DAST: a coarse ``(pluginid,
    path)`` alias alongside the fine ``(pluginid, path, query_keys,
    param)`` primary), we also persist the coarse alias as its own
    entry — Codex 2nd review's "fine-accept→coarse-suppress" property
    only holds if BOTH keys are written.

    All emitted entries share the same ``reason``, ``accepted_by``,
    and ``expires_at`` so the audit trail stays coherent: an operator
    reading the baseline sees the same justification on every variant.
    """
    primary = build_entry(
        finding,
        reason=reason,
        accepted_by=accepted_by,
        expiry_days=expiry_days,
        now=now,
    )
    entries: list[BaselineEntry] = [primary]
    # Deduplicate against the primary fingerprint to avoid emitting
    # two entries with the same fingerprint key (load/save would dedupe
    # them downstream, but emitting them in the first place would
    # confuse audit logs).
    seen: set[str] = {primary.fingerprint}
    for alias_fp in finding.fingerprint_aliases:
        if not alias_fp or alias_fp in seen:
            continue
        seen.add(alias_fp)
        entries.append(
            BaselineEntry(
                fingerprint=alias_fp,
                scanner=primary.scanner,
                rule_id=primary.rule_id,
                reason=primary.reason,
                accepted_by=primary.accepted_by,
                added_at=primary.added_at,
                expires_at=primary.expires_at,
                secscan_version=primary.secscan_version,
                title=primary.title,
                # raw_fingerprint belongs to the tool's own primary
                # identity — copying it onto coarse aliases would
                # falsely claim ZAP emitted that exact alias as
                # a stable id. Leave it None on aliases.
                raw_fingerprint=None,
                package=primary.package,
                ecosystem=primary.ecosystem,
                source_location=primary.source_location,
            )
        )
    return tuple(entries)


def merge_entries(
    existing: Baseline | None,
    new_entries: tuple[BaselineEntry, ...],
    *,
    tool_versions: dict[str, str] | None = None,
    config_hash: str | None = None,
    accepted_by: str = "",
) -> Baseline:
    """Merge new entries into an existing baseline.

    Same-fingerprint entries are replaced (latest wins). Other metadata is
    refreshed: a baseline's "created_at" tracks the last accept run.
    """
    by_fp: dict[str, BaselineEntry] = {}
    if existing is not None:
        by_fp = {e.fingerprint: e for e in existing.entries}
    for entry in new_entries:
        by_fp[entry.fingerprint] = entry

    return Baseline(
        version=BASELINE_VERSION,
        created_at=datetime.now(UTC),
        created_by=accepted_by,
        tool_versions=tool_versions or {},
        config_hash=config_hash,
        entries=tuple(by_fp.values()),
    )


def prune_expired(baseline: Baseline, *, now: datetime | None = None) -> Baseline:
    """Return a baseline with expired entries removed."""
    moment = now or datetime.now(UTC)
    kept = tuple(e for e in baseline.entries if not e.is_expired(now=moment))
    return Baseline(
        version=baseline.version,
        created_at=baseline.created_at,
        created_by=baseline.created_by,
        tool_versions=baseline.tool_versions,
        config_hash=baseline.config_hash,
        entries=kept,
    )


# --- Validation helpers ----------------------------------------------------


def _require_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise BaselineError(f"{name}: expected string, got {type(value).__name__}")
    return value


def _require_non_empty_str(value: object, name: str) -> str:
    s = _require_str(value, name)
    if not s.strip():
        raise BaselineError(f"{name}: must be a non-empty string")
    return s


def _optional_str(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _require_str(value, name)


def _parse_dt(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise BaselineError(f"{name}: expected ISO 8601 string")
    try:
        # ``datetime.fromisoformat`` handles "Z" suffix from Python 3.11+.
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BaselineError(f"{name}: invalid datetime {value!r} ({exc})") from exc
    # Treat naive datetimes as UTC. Comparing naive against tz-aware later
    # (in ``is_expired``) would raise ``TypeError``, which Codex 3rd review
    # flagged as a baseline-parse crash path.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _format_dt(value: datetime) -> str:
    """ISO 8601 with timezone, second precision."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
