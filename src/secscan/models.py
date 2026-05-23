"""Core data model.

These dataclasses are the contract between layers:

    Scanner --(Finding/ScanOutcome)--> Orchestrator --(RunResult)--> Reporter
                                                                  --> Policy --> ExitCode

All Findings carry an explicit ``Severity`` (including ``UNKNOWN``) and a
``fingerprint`` so the Baseline layer can suppress known issues. Scanner-specific
fingerprint construction lives in each Scanner (see scanners/secrets.py etc.) —
this module only defines the shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Normalized severity.

    ``UNKNOWN`` is distinct from any other level: pip-audit JSON has no
    severity field at all, and forcing it to MEDIUM (the original draft) was
    flagged as misleading. Policy decides whether ``UNKNOWN`` participates in
    the fail-on threshold; it never silently becomes a known level.
    """

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """Case-insensitive lookup; raises ValueError on unknown name."""
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity name: {name!r}") from exc


@dataclass(frozen=True)
class Location:
    """Where a finding is located.

    All fields are optional because scanners have different notions of location:
    deps findings name a package, sast findings name a file/line, future DAST
    findings would name a URL. A finding may legitimately have no location at
    all (e.g. a configuration-level finding).
    """

    file: str | None = None
    """Path relative to the scan root (forward-slash separated)."""

    line: int | None = None
    """1-based start line."""

    end_line: int | None = None
    """1-based end line (inclusive)."""

    column: int | None = None
    """1-based start column."""

    end_column: int | None = None
    """1-based end column."""

    package: str | None = None
    """Package name for dependency findings."""

    ecosystem: str | None = None
    """"npm" | "pypi" | ... for dependency findings."""

    url: str | None = None
    """Reserved for DAST findings (Phase 2)."""


@dataclass(frozen=True)
class Finding:
    """A single normalized vulnerability/policy violation.

    Findings are immutable and hashable. ``fingerprint`` identifies the same
    issue across runs for baseline suppression; ``raw_fingerprint`` preserves
    the upstream tool's own fingerprint (gitleaks, semgrep AppSec) when
    available, so we can cross-reference with native ignore mechanisms.
    """

    scanner: str
    rule_id: str
    severity: Severity
    title: str
    message: str
    location: Location | None
    fingerprint: str
    raw_fingerprint: str | None = None
    cve: str | None = None
    cwe: str | None = None
    fix_version: str | None = None
    references: tuple[str, ...] = ()
    tool_version: str | None = None
    raw: dict[str, object] | None = None


@dataclass(frozen=True)
class WorkUnit:
    """A discrete scan target produced by ProjectDiscovery.

    For MVP we expect at most one or two WorkUnits per ``--path`` (one node,
    one python). Future workspace support will yield many. ``manifest`` and
    ``lockfile`` are scanner hints; ``ecosystem`` is None for scanners that
    don't care about language (secrets, broad SAST).
    """

    root: Path
    ecosystem: str | None = None
    manifest: Path | None = None
    lockfile: Path | None = None


@dataclass(frozen=True)
class ScannerError:
    """A scanner that failed to complete.

    ``stderr_excerpt`` is a short (already-truncated) snippet for the report.
    Full stderr should not be retained: it may contain secrets, credentials,
    or tokens from the scanned project's environment.
    """

    scanner: str
    reason: str
    stderr_excerpt: str | None = None
    returncode: int | None = None


@dataclass(frozen=True)
class ScanOutcome:
    """Per-scanner result.

    Either ``findings`` is populated (and ``error`` is None), or ``error`` is
    populated (and ``findings`` is empty). The two are mutually exclusive at
    the scanner boundary — partial-success is represented at the Orchestrator
    level by RunResult.
    """

    scanner: str
    findings: tuple[Finding, ...] = ()
    error: ScannerError | None = None
    tool_version: str | None = None
    duration_seconds: float = 0.0

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class RunResult:
    """Aggregated result across all scanners for a single secscan invocation.

    Carries findings AND errors AND warnings simultaneously so the user sees
    everything: a scanner that errored does not silence findings from
    scanners that succeeded.
    """

    findings: tuple[Finding, ...] = ()
    errors: tuple[ScannerError, ...] = ()
    warnings: tuple[str, ...] = ()
    """Non-fatal notes: baseline expiry, tool_version drift, etc."""

    skipped: tuple[str, ...] = ()
    """Scanner names skipped via --skip or is_applicable=False."""

    suppressed_by_baseline: tuple[Finding, ...] = ()
    """Findings removed by baseline; kept for --verbose display."""

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


@dataclass(frozen=True)
class ScanConfig:
    """Per-scanner runtime config passed into Scanner.scan().

    Decoupled from the full project config (config.py) so scanners do not
    need to know about the global ``.secscan.toml`` shape.
    """

    timeout_seconds: int = 300
    extra: dict[str, object] = field(default_factory=dict)
    """Scanner-specific typed options. Each Scanner documents the keys it
    consumes; unknown keys are ignored. We intentionally do NOT accept a
    free-form ``extra_args`` list — Codex flagged this as a command-injection
    / argument-escape risk."""
