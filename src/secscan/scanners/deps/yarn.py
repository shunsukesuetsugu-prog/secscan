"""Yarn Berry (v2+) audit adapter.

Yarn Berry exposes ``yarn npm audit`` which queries the npm registry's
advisory bulk endpoint and produces NDJSON. For per-workspace audits we
go through ``yarn workspace <name> npm audit --json --recursive`` —
recursive includes transitive dependencies, and the per-workspace
selector scopes the report to the member named by ``workspace_id``.

Codex 28th review pinned several invariants:
- We do NOT pass ``--all``. ``--all`` joins every workspace into one
  report; we want per-member units so the policy + baseline layer can
  treat them independently.
- The parser tolerates two emitted shapes — Yarn 3's ``{"advisories":
  {...}}`` map and the package-keyed bulk-advisory shape that Yarn 4
  sometimes forwards from the registry. Both decode line-by-line.
- An empty audit emits a single ``{}`` JSON object; treat that as a
  clean success.
- Exit 0 = no findings; exit 1 = findings present; any other exit is
  a tool error (not a finding count). We never use exit codes to
  derive severities.

Yarn Classic (v1) is intentionally NOT handled here — the JSON shape
and per-workspace story are different enough that we surface a Classic
warning in ``workspaces.detect_yarn_unsupported`` instead.
"""

from __future__ import annotations

import json
from typing import Any

from ...models import Finding, Location
from ...runner import CommandResult, decode_output
from ._common import AdvisoryHints, deps_fingerprint, severity_from_npm_label


def yarn_audit_argv(*, workspace_id: str) -> tuple[str, ...]:
    """Build the Yarn Berry per-workspace audit invocation.

    The audit runs from the repo root (where ``yarn.lock`` lives);
    ``yarn workspace <id>`` scopes it to a single workspace member.
    ``--recursive`` walks transitive dependencies so we catch the same
    advisories npm/pnpm would.
    """
    return (
        "yarn",
        "workspace",
        workspace_id,
        "npm",
        "audit",
        "--json",
        "--recursive",
    )


def classify_yarn_audit_exit(result: CommandResult) -> tuple[bool, str | None]:
    """Yarn Berry returns 0 (clean) or 1 (findings) on success.

    Any other exit code is a tool failure — typically a missing
    ``yarn.lock`` or a registry/network error. We surface that as a
    ScannerError so the operator sees the underlying cause.
    """
    if result.timed_out:
        return False, "yarn audit timed out"
    if result.returncode in (0, 1):
        return True, None
    return False, f"yarn audit exited {result.returncode}"


def build_findings_from_yarn_audit(
    stdout: bytes, *, workspace_id: str
) -> tuple[Finding, ...]:
    """Parse Yarn Berry's NDJSON audit output into normalized Findings.

    Codex 28th review: handle two observed envelope shapes:

    1. Yarn 3-ish: each line is ``{"advisories": {<id>: <advisory>, ...}}``
       (and sometimes plain ``{}`` for clean runs).

    2. Yarn 4 / registry bulk forward: each line is a top-level mapping
       of ``{<package_name>: [<advisory>, ...]}``.

    Lines that fail json.loads are dropped — Yarn occasionally emits
    progress markers that aren't valid JSON; we don't want one
    malformed line to invalidate a whole audit run.
    """
    text = decode_output(stdout)
    if not text.strip():
        return ()

    findings: list[Finding] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or not payload:
            # Empty object means "audited, nothing to report" — success.
            continue
        # Detect shape: advisories-keyed (Yarn 3) vs package-keyed.
        advisories_block = payload.get("advisories")
        if isinstance(advisories_block, dict) and advisories_block:
            for raw_id, adv in advisories_block.items():
                if not isinstance(adv, dict):
                    continue
                _append_from_advisory(
                    adv,
                    raw_fallback_id=str(raw_id),
                    workspace_id=workspace_id,
                    findings=findings,
                    seen=seen,
                )
            continue
        # Otherwise: assume package-keyed top-level mapping. Skip
        # bookkeeping keys that some Yarn versions intermix
        # (``"vulnerabilities"`` counts, ``"metadata"``, etc.).
        for key, value in payload.items():
            if not isinstance(value, list):
                continue
            for adv in value:
                if not isinstance(adv, dict):
                    continue
                _append_from_advisory(
                    adv,
                    raw_fallback_id=str(key),
                    workspace_id=workspace_id,
                    findings=findings,
                    seen=seen,
                    package_hint=str(key),
                )
    return tuple(findings)


def _append_from_advisory(
    advisory: dict[str, Any],
    *,
    raw_fallback_id: str,
    workspace_id: str,
    findings: list[Finding],
    seen: set[str],
    package_hint: str | None = None,
) -> None:
    """Add one normalized Finding for an advisory blob, with dedup.

    ``package_hint`` lets the package-keyed parser shape (Yarn 4 / bulk
    forward) supply the top-level key as the package name when the
    advisory object itself omits ``module_name`` / ``name``. Codex 29th
    review flagged that omitting this fallback silently dropped
    findings in that shape.
    """
    package = (
        _first_str(advisory.get("module_name"))
        or _first_str(advisory.get("name"))
        or package_hint
    )
    if not package:
        return
    hints = _hints_from_advisory(advisory, fallback_id=raw_fallback_id)
    if hints is None:
        return
    fingerprint = deps_fingerprint(
        ecosystem="npm",  # Yarn audits against the npm registry namespace.
        package=package,
        advisory_id=hints.advisory_id,
        workspace_id=workspace_id,
    )
    if fingerprint in seen:
        return
    seen.add(fingerprint)
    findings.append(
        Finding(
            scanner="deps",
            rule_id=hints.advisory_id,
            severity=hints.severity,
            title=hints.title or f"{package}: {hints.advisory_id}",
            message=hints.message or hints.title,
            location=Location(package=package, ecosystem="npm"),
            fingerprint=fingerprint,
            cve=hints.cve,
            cwe=hints.cwe,
            fix_version=hints.fix_version,
            references=hints.references,
        )
    )


def _hints_from_advisory(
    advisory: dict[str, Any], *, fallback_id: str
) -> AdvisoryHints | None:
    advisory_id = (
        _first_str(advisory.get("ghsa_id"))
        or _first_str(advisory.get("id"))
        or _first_str(advisory.get("url"))
        or _first_cve(advisory.get("cves"))
        or fallback_id
    )
    if not advisory_id:
        return None
    cve = _first_cve(advisory.get("cves"))
    cwe = _first_str(advisory.get("cwe"))
    severity = severity_from_npm_label(advisory.get("severity"))
    title = _first_str(advisory.get("title")) or advisory_id
    message = (
        _first_str(advisory.get("overview"))
        or _first_str(advisory.get("title"))
        or ""
    )
    fix_version = _first_str(advisory.get("patched_versions"))
    refs: list[str] = []
    url = _first_str(advisory.get("url"))
    if url:
        refs.append(url)
    extra_refs = advisory.get("references")
    if isinstance(extra_refs, list):
        for ref in extra_refs:
            if isinstance(ref, str) and ref and ref not in refs:
                refs.append(ref)
    return AdvisoryHints(
        title=title,
        advisory_id=advisory_id,
        severity=severity,
        cve=cve,
        cwe=cwe,
        fix_version=fix_version,
        references=tuple(refs[:5]),
        message=message,
    )


def _first_cve(value: object) -> str | None:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.startswith("CVE-"):
                return item
    if isinstance(value, str) and value.startswith("CVE-"):
        return value
    return None


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
