"""SARIF 2.1.0 formatter.

Designed primarily for upload to GitHub Code Scanning, which has stricter
requirements than the OASIS schema alone. Codex 17th review pinned the
following SARIF-specific contracts:

- Each scanner gets its own ``run`` (so the upstream tool's identity is
  preserved as ``tool.driver.name``).
- ``run.tool.driver.rules`` is populated; each ``result.ruleIndex``
  points back into that array.
- ``result.level`` maps from Severity:
    CRITICAL/HIGH → "error", MEDIUM → "warning",
    LOW/INFO/UNKNOWN → "note".
- All file URIs are RELATIVE to the project root (no leading ``/``).
- ``result.locations[].physicalLocation.region.endColumn`` is converted
  from secscan's inclusive end_column to SARIF's exclusive convention
  (i.e. value + 1).
- Deps findings get an artifact location pointing at the manifest /
  lockfile when no file/line is available (otherwise GitHub silently
  drops the result).
- ``partialFingerprints.secscanV1`` carries our composite fingerprint.
  ``partialFingerprints.primaryLocationLineHash`` is added for GitHub
  Code Scanning's de-duplication.
- Source ``contents`` / ``snippet`` are NEVER included. These would
  echo source code (including any pre-redaction tokens) into the
  artifact uploaded to GitHub.
- Baseline-suppressed results are EXCLUDED by default
  (``include_suppressed=False``). GitHub does not consistently honor
  SARIF suppressions, so emitting them by default would re-surface
  acknowledged findings. ``--sarif-include-suppressed`` opts in.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .. import __version__ as SECSCAN_VERSION
from ..models import Finding, RunResult, ScannerError, Severity
from ..policy import PolicyDecision
from .base import DEFAULT_OPTIONS, FormatOptions, _register

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)

# SARIF "level" is a small open vocabulary; we use only the three primary
# values. "none" exists in the spec but Codex 17th review flagged that
# GitHub Code Scanning drops level=none results, so UNKNOWN goes to "note"
# instead.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.UNKNOWN: "note",
}


def format_sarif(
    result: RunResult,
    decision: PolicyDecision,
    options: FormatOptions = DEFAULT_OPTIONS,
) -> str:
    """Serialize the run as a SARIF 2.1.0 document.

    The returned string ends with a newline.
    """
    findings = _partition_findings_by_scanner(result.findings)
    if options.include_suppressed_in_sarif and result.suppressed_by_baseline:
        suppressed = _partition_findings_by_scanner(result.suppressed_by_baseline)
    else:
        suppressed = {}

    # Codex 18th review: emit a SARIF run ONLY for scanners that actually
    # ran. Emitting empty success runs for skipped scanners causes
    # GitHub Code Scanning to mark previously-reported alerts as fixed
    # when in fact the scanner did not check anything. A scanner that
    # ERRORED also counts as having run — the user needs to see the
    # notification, and GitHub treats erroring tools as "ran, no
    # results" rather than skipped.
    actually_ran = set(result.scanned_scanners)
    errored = {e.scanner for e in result.errors}
    scanner_names = sorted(
        actually_ran | errored | set(findings) | set(suppressed)
    )

    runs = [
        _build_run(
            scanner=name,
            findings=findings.get(name, ()),
            suppressed=suppressed.get(name, ()),
            errors=tuple(e for e in result.errors if e.scanner == name),
            warnings=_warnings_for_scanner(result, name),
        )
        for name in scanner_names
    ]

    payload: dict[str, Any] = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": runs,
    }
    # The exit_code / threshold are NOT standard SARIF; we attach them as
    # properties so downstream tooling can read them without rewriting the
    # SARIF parser.
    payload["properties"] = {
        "secscan_version": SECSCAN_VERSION,
        "exit_code": int(decision.exit_code),
        "threshold": decision.threshold.name.lower(),
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


# --- Run construction -----------------------------------------------------


def _build_run(
    *,
    scanner: str,
    findings: tuple[Finding, ...],
    suppressed: tuple[Finding, ...],
    errors: tuple[ScannerError, ...],
    warnings: tuple[str, ...],
) -> dict[str, Any]:
    rules, rule_index_of = _build_rules(findings + suppressed)
    results = [_build_result(f, rule_index_of, suppressed=False) for f in findings]
    results.extend(
        _build_result(f, rule_index_of, suppressed=True) for f in suppressed
    )

    invocation: dict[str, Any] = {
        "executionSuccessful": not errors,
        "toolExecutionNotifications": (
            [_notification_from_error(e) for e in errors]
            + [_notification_from_warning(w, scanner) for w in warnings]
        ),
    }

    return {
        "tool": {
            "driver": {
                "name": f"secscan-{scanner}",
                "informationUri": "https://github.com/",  # placeholder; updated when published
                "version": SECSCAN_VERSION,
                "rules": rules,
            },
        },
        "invocations": [invocation],
        "results": results,
    }


def _build_rules(
    findings: tuple[Finding, ...],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build the ``tool.driver.rules`` array AND a rule_id → index lookup.

    SARIF result entries reference rules via ``ruleIndex``. The same rule
    may produce many results; we deduplicate by rule_id while preserving
    the order rules first appear in the findings list.
    """
    rules: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    for f in findings:
        if f.rule_id in index_of:
            continue
        index_of[f.rule_id] = len(rules)
        rules.append(
            {
                "id": f.rule_id,
                # ``name`` is optional but useful for the GitHub UI.
                "name": f.rule_id,
                "shortDescription": {"text": f.title or f.rule_id},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            }
        )
    return rules, index_of


def _build_result(
    finding: Finding,
    rule_index_of: dict[str, int],
    *,
    suppressed: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index_of[finding.rule_id],
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message or finding.title or finding.rule_id},
        "locations": [_build_location(finding)],
        "partialFingerprints": _build_fingerprints(finding),
    }
    if suppressed:
        # Source "external" indicates the suppression came from outside
        # the tool's own data (i.e. our baseline file). SARIF lets us
        # attach a justification; we keep it constant since per-finding
        # reasons live in baseline.json itself.
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": "suppressed by secscan baseline",
            }
        ]
    return result


def _build_location(finding: Finding) -> dict[str, Any]:
    """Build a SARIF Location for the finding.

    Falls back to a manifest-style URI for deps findings that have no
    file (Codex 17th review: GitHub silently drops results without a
    location).
    """
    uri = _uri_for(finding)
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}

    loc = finding.location
    if loc is not None:
        region: dict[str, Any] = {}
        if loc.line is not None:
            region["startLine"] = loc.line
        if loc.column is not None:
            region["startColumn"] = loc.column
        if loc.end_line is not None:
            region["endLine"] = loc.end_line
        if loc.end_column is not None:
            # secscan's end_column is INCLUSIVE; SARIF's is EXCLUSIVE.
            region["endColumn"] = loc.end_column + 1
        if region:
            physical["region"] = region

    return {"physicalLocation": physical}


def _uri_for(finding: Finding) -> str:
    """Pick the artifact URI for a finding.

    Priority:
    1. ``location.file`` if set AND it passes the safety check.
    2. A synthetic ``deps:<ecosystem>/<package>`` URI for deps findings
       that have no file but do have package metadata. We use a custom
       scheme so it can't be mistaken for a real file path.
    3. ``"unknown"`` as a last resort.

    Codex 18th review (HIGH): a ``..`` segment or backslash in
    ``loc.file`` would survive into the SARIF URI even though
    orchestrator's path-stripping is meant to prevent root-escape. The
    SARIF artifact URI is the artifact's identity in GitHub Code
    Scanning — a misattributed URI corrupts dedup. We sanitize hard.
    """
    loc = finding.location
    if loc is None:
        return "unknown"
    if loc.file:
        safe = _safe_relative_uri(loc.file)
        if safe is not None:
            return safe
    if loc.package and loc.ecosystem:
        return f"deps:{loc.ecosystem}/{loc.package}"
    if loc.package:
        return f"deps:{loc.package}"
    return "unknown"


def _safe_relative_uri(raw: str) -> str | None:
    """Convert a scanner-reported file path to a safe SARIF URI.

    Returns ``None`` if the path is unsafe (contains traversal segments,
    a URI scheme of its own, a Windows drive letter, a NUL byte, or is
    absolute). The caller falls back to a synthetic / "unknown" URI in
    that case.
    """
    if not raw or "\x00" in raw:
        return None
    # Normalize separators first so the rest of the checks see forward
    # slashes only. We accept Windows-style ``\`` *as a separator* but
    # nothing else.
    candidate = raw.replace("\\", "/")
    # Absolute path? Reject — SARIF artifact URIs must be relative to
    # the project root.
    if candidate.startswith("/"):
        return None
    # URI scheme (e.g. ``file:`` / ``http:``) before the first path
    # component? Reject — we never want a SARIF location to point at an
    # arbitrary URL.
    first_segment = candidate.split("/", 1)[0]
    if ":" in first_segment:
        return None
    # Path traversal? Reject any segment exactly equal to ``..``.
    if any(seg == ".." for seg in candidate.split("/")):
        return None
    return candidate


def _build_fingerprints(finding: Finding) -> dict[str, str]:
    """Two partial fingerprints: our own + a GitHub-aware one.

    ``secscanV1`` is our composite fingerprint (stable across runs;
    drives baseline matching). ``primaryLocationLineHash`` is what
    GitHub Code Scanning uses to de-duplicate alerts.
    """
    uri = _uri_for(finding)
    line = (finding.location.line if finding.location else None) or 0
    primary_seed = "\x00".join((finding.rule_id, uri, str(line)))
    primary = hashlib.sha256(primary_seed.encode("utf-8")).hexdigest()
    return {
        "secscanV1": finding.fingerprint,
        "primaryLocationLineHash": primary,
    }


# --- Notifications --------------------------------------------------------


def _notification_from_error(err: ScannerError) -> dict[str, Any]:
    """A SARIF toolExecutionNotification representing a scanner error."""
    text_parts = [err.reason]
    if err.returncode is not None:
        text_parts.append(f"(exit {err.returncode})")
    text = " ".join(text_parts)
    return {
        "level": "error",
        "message": {"text": text},
    }


def _notification_from_warning(warning: str, scanner: str) -> dict[str, Any]:
    return {
        "level": "warning",
        "message": {"text": f"{scanner}: {warning}"},
    }


def _warnings_for_scanner(result: RunResult, scanner: str) -> tuple[str, ...]:
    """Best-effort match of free-form warnings to a scanner.

    ``RunResult.warnings`` is a flat list of strings; we route to a run by
    looking for the scanner name in the warning text. Unmatched warnings
    are skipped per-run but still appear in the top-level secscan-json
    output.
    """
    return tuple(w for w in result.warnings if scanner in w)


def _partition_findings_by_scanner(
    findings: tuple[Finding, ...],
) -> dict[str, tuple[Finding, ...]]:
    buckets: dict[str, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(f.scanner, []).append(f)
    return {k: tuple(v) for k, v in buckets.items()}


_register("sarif", format_sarif)
