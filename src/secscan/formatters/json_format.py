"""secscan-json v1 formatter.

A stable structured format we own. The ``schema`` and ``format_version``
fields exist so downstream tools can route by schema identifier and so we
can evolve the shape without breaking parsers (v2 will introduce a new
identifier rather than mutating v1 in place).

Invariants pinned by Codex 17th review:
- ``Finding.raw`` is NEVER serialized. The field exists for forensic
  in-process use; emitting it would inflate output and risk leaking
  upstream-tool fields we haven't audited.
- ``Finding.raw_fingerprint`` is NEVER serialized. gitleaks-style raw
  fingerprints embed file paths; emitting them bypasses orchestrator's
  path-stripping for out-of-root or ignored paths.
- ``baseline_suppressed_by_baseline`` is included in its own array so
  operators can audit what was filtered, but the policy-decided
  ``exit_code`` reflects the post-suppression state — same as the text
  formatter.
"""

from __future__ import annotations

import json
from typing import Any

from .. import __version__ as SECSCAN_VERSION
from ..models import Finding, RunResult, Severity
from ..policy import PolicyDecision
from .base import DEFAULT_OPTIONS, FormatOptions, _register

SCHEMA_NAME = "secscan-json"
FORMAT_VERSION = 1


def format_json(
    result: RunResult,
    decision: PolicyDecision,
    options: FormatOptions = DEFAULT_OPTIONS,
) -> str:
    """Serialize the run as a single JSON document.

    Returns a string ending with a newline so writes via ``stdout.write``
    behave like the text formatter and like most CLI conventions.
    """
    payload: dict[str, Any] = {
        "schema": SCHEMA_NAME,
        "format_version": FORMAT_VERSION,
        "secscan_version": SECSCAN_VERSION,
        "exit_code": int(decision.exit_code),
        "threshold": decision.threshold.name.lower(),
        "summary": _summary(result, decision),
        "findings": [_finding(f) for f in result.findings],
        "errors": [_error(e) for e in result.errors],
        "warnings": list(result.warnings),
        "skipped": list(result.skipped),
        "suppressed_by_baseline": [
            _finding(f) for f in result.suppressed_by_baseline
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _summary(result: RunResult, decision: PolicyDecision) -> dict[str, Any]:
    counts: dict[str, int] = {sev.name.lower(): 0 for sev in Severity}
    for f in result.findings:
        counts[f.severity.name.lower()] += 1
    return {
        "counts_by_severity": counts,
        "findings_total": len(result.findings),
        "errors_total": len(result.errors),
        "warnings_total": len(result.warnings),
        "skipped_total": len(result.skipped),
        "suppressed_by_baseline_total": len(result.suppressed_by_baseline),
        "crossing_total": len(decision.crossing_findings),
        "unknown_warning_count": decision.unknown_warning_count,
    }


def _finding(finding: Finding) -> dict[str, Any]:
    """Serialize a Finding.

    Strictly does NOT emit ``raw`` or ``raw_fingerprint`` (Codex 17th
    review). Tests pin this invariant.
    """
    loc = finding.location
    location_payload: dict[str, Any] | None = None
    if loc is not None:
        location_payload = {
            "file": loc.file,
            "line": loc.line,
            "end_line": loc.end_line,
            "column": loc.column,
            "end_column": loc.end_column,
            "package": loc.package,
            "ecosystem": loc.ecosystem,
            "url": loc.url,
        }
    payload: dict[str, Any] = {
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "severity": finding.severity.name.lower(),
        "title": finding.title,
        "message": finding.message,
        "location": location_payload,
        "fingerprint": finding.fingerprint,
        "cve": finding.cve,
        "cwe": finding.cwe,
        "fix_version": finding.fix_version,
        "references": list(finding.references),
        "tool_version": finding.tool_version,
    }
    # Phase 2-Z: additive opt-in field. Present ONLY when AI triage ran
    # (--triage); absent otherwise, so existing JSON v1 consumers that
    # never used --triage see an unchanged shape (Codex design review #6).
    if finding.ai_triage is not None:
        payload["ai_triage"] = {
            "classification": finding.ai_triage.classification.value,
            "rationale": finding.ai_triage.rationale,
            "model": finding.ai_triage.model,
        }
    return payload


def _error(err: object) -> dict[str, Any]:
    # err is a ScannerError; we don't import it here to keep the module
    # boundary tight. Field access via getattr handles forward-compat with
    # any future scanner-error subclassing.
    return {
        "scanner": getattr(err, "scanner", None),
        "reason": getattr(err, "reason", None),
        "stderr_excerpt": getattr(err, "stderr_excerpt", None),
        "returncode": getattr(err, "returncode", None),
    }


_register("json", format_json)
