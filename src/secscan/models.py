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

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from types import MappingProxyType


class Severity(IntEnum):
    """Normalized severity.

    ``UNKNOWN`` is distinct from any other level: pip-audit JSON has no
    severity field at all, and forcing it to MEDIUM (the original draft) was
    flagged as misleading. Policy decides whether ``UNKNOWN`` participates in
    the fail-on threshold; it never silently becomes a known level.

    ``NEVER`` is a sentinel **only used as the fail-on threshold** — it is
    intentionally above every real severity value so the comparison
    ``finding.severity >= Severity.NEVER`` is always ``False``. Scanners must
    never emit findings with ``severity == NEVER`` (this is asserted at the
    edges in Scanner subclasses).
    """

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    NEVER = 100

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """Case-insensitive lookup; raises ValueError on unknown name.

        The CLI-visible alias ``"none"`` maps to ``Severity.NEVER`` so users
        can write ``--fail-on=none`` to mean "never fail the build".
        """
        normalized = name.strip().upper()
        if normalized == "NONE":
            return cls.NEVER
        try:
            return cls[normalized]
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

    Findings are immutable AND hashable: the ``raw`` field (which can hold a
    mutable dict for SARIF/forensics) is excluded from ``__hash__`` /
    ``__eq__`` via ``field(hash=False, compare=False)``. Identity for
    deduplication and equality is therefore driven by the structured fields
    (scanner, rule_id, severity, ..., fingerprint), not by raw payload.

    ``fingerprint`` identifies the same issue across runs for baseline
    suppression; ``raw_fingerprint`` preserves the upstream tool's own
    fingerprint (gitleaks, semgrep AppSec) when available, so we can
    cross-reference with native ignore mechanisms.
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
    fingerprint_aliases: tuple[str, ...] = ()
    """Additional baseline-suppression keys for this finding.

    Phase 2-D added DAST (OWASP ZAP) findings where the same vulnerability
    is often reported twice by ZAP — once with ``param`` set (e.g. ``q``)
    and once with ``param`` absent. The Codex 2nd review for Phase 2-D
    flagged that splitting on ``param`` alone would double the baseline:
    one ``baseline accept`` would not suppress the other report.

    ``fingerprint_aliases`` solves this by letting a Finding declare
    additional, coarser fingerprints (e.g. the same finding with
    ``NO_PARAM``). ``baseline.apply_baseline`` matches a Finding when ANY
    of (``fingerprint``, *aliases*) matches a baseline entry — so a
    single ``baseline accept`` on either key suppresses both
    representations of the same vulnerability.

    Scanners that don't need this (deps, secrets, sast) leave it empty;
    only DAST currently populates it. Order matters for stability:
    aliases are emitted in coarsest-to-finest order so that audits and
    SARIF "partial fingerprints" remain deterministic across runs.
    """
    raw: dict[str, object] | None = field(default=None, hash=False, compare=False)


@dataclass(frozen=True)
class WorkUnit:
    """A discrete scan target produced by ProjectDiscovery.

    For MVP we expect at most one or two WorkUnits per ``--path`` (one node,
    one python). Future workspace support will yield many. ``manifest`` and
    ``lockfile`` are scanner hints; ``ecosystem`` is None for scanners that
    don't care about language (secrets, broad SAST).

    ``package_manager`` is a finer-grained discriminator within an ecosystem.
    Codex's 3rd review flagged that pushing both ``npm`` and ``pnpm`` under
    ``ecosystem="npm"`` would break Phase 1B because the two tools have
    materially different ``--audit-level`` semantics. We carry the package
    manager explicitly so Scanner adapters can pick the right CLI shape.
    """

    root: Path
    ecosystem: str | None = None
    manifest: Path | None = None
    lockfile: Path | None = None
    package_manager: str | None = None
    """For npm-ecosystem: "npm" | "pnpm". For pypi: "pip" | "uv" | "pdm" |
    "pip-requirements". None when ``ecosystem`` is None or the package
    manager could not be determined."""

    workspace_id: str | None = None
    """In a monorepo, the workspace member's selector (e.g. the package
    name for npm/pnpm). Forwarded to ``npm audit --workspace <id>`` or
    ``pnpm audit --filter <id>`` so the audit is scoped to the member
    even though the run happens at the repo root (Phase 2-B / Codex
    20th review). None for single-project layouts and for any ecosystem
    where workspace splitting is not implemented."""

    workspace_member_path: Path | None = None
    """The workspace member's directory, relative to the scan root.
    Used for display and to disambiguate findings in reports. None for
    single-project layouts."""


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

    ``warnings`` carries non-fatal scanner-level notes that the user should
    see — e.g. semgrep's top-level ``errors`` array (rule-parse failures
    that did not abort the run). These are NOT findings; they signal that
    the report itself is incomplete or potentially noisy. The Orchestrator
    forwards them to ``RunResult.warnings`` so the reporter surfaces them.
    """

    scanner: str
    findings: tuple[Finding, ...] = ()
    error: ScannerError | None = None
    warnings: tuple[str, ...] = ()
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

    scanned_scanners: tuple[str, ...] = ()
    """Names of scanners whose ``scan()`` was actually invoked.

    The SARIF formatter uses this to distinguish "scanner ran and found
    nothing" from "scanner was skipped / unregistered". Codex 18th
    review flagged that emitting empty runs for skipped scanners can
    make GitHub Code Scanning mark previously-reported alerts as fixed."""

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


_EMPTY_EXTRA: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True)
class ScanConfig:
    """Per-scanner runtime config passed into Scanner.scan().

    Decoupled from the full project config (config.py) so scanners do not
    need to know about the global ``.secscan.toml`` shape.
    """

    timeout_seconds: int = 300
    extra: Mapping[str, object] = field(default_factory=lambda: _EMPTY_EXTRA)
    """Scanner-specific typed options. Each Scanner documents the keys it
    consumes; unknown keys are ignored. We intentionally do NOT accept a
    free-form ``extra_args`` list — Codex flagged this as a command-injection
    / argument-escape risk.

    Exposed as ``Mapping`` (read-only contract). Construction sites should
    pass either ``MappingProxyType({...})`` or an immutable mapping; the
    field itself does not enforce immutability beyond the type contract."""
