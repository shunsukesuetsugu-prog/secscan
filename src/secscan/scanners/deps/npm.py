"""npm audit adapter (npm v7+).

We run npm with ``--audit-level=none`` so the exit code reflects only
"the tool ran successfully" — not whether vulnerabilities were found. The
threshold decision is secscan's job (policy.py), not npm's. This is the
opposite of pnpm, where ``--audit-level`` filters output; the two CLIs
look similar but disagree on the semantics. Codex 2nd review flagged this
specifically.

npm v7+ JSON shape (the only shape we target — v6 had a different schema):

    {
      "vulnerabilities": {
        "<package>": {
          "name": "<package>",
          "severity": "low|moderate|high|critical|info",
          "via": [advisory_object | "<other package name>", ...],
          "range": "<vulnerable semver>",
          "fixAvailable": false | true | { "name": ..., "version": ... },
          ...
        },
        ...
      },
      "metadata": { ... }
    }

``via`` entries that are dicts represent actual advisories; string entries
are meta-vulnerabilities (this package is only vulnerable because a
transitive dep is). MVP emits one Finding per advisory dict and silently
folds meta entries into the vulnerable-package list to avoid noise.
"""

from __future__ import annotations

import json
from typing import Any

from ...models import Finding, Location
from ...runner import CommandResult, decode_output
from ._common import AdvisoryHints, deps_fingerprint, severity_from_npm_label

NPM_AUDIT_ARGV: tuple[str, ...] = (
    "npm",
    "audit",
    "--json",
    "--audit-level=none",
)


def npm_audit_argv(
    *,
    allow_missing_lockfile: bool = False,
    omit_dev: bool = False,
    workspace_id: str | None = None,
) -> tuple[str, ...]:
    """Construct the npm audit invocation.

    - ``allow_missing_lockfile``: appends ``--no-package-lock`` so npm
      audits the package.json's stated dependencies without requiring a
      package-lock.json on disk. Codex 8th review flagged that the
      ``--allow-missing-lockfile`` CLI flag previously had no actual effect.
    - ``omit_dev``: appends ``--omit=dev`` to skip devDependencies from
      the audit, matching the config's ``ignore_dev_dependencies`` key.
    - ``workspace_id``: when set, runs the audit scoped to a single
      workspace member via ``--workspace <id>``. The audit is invoked
      from the repo root so npm finds the authoritative lockfile, but
      results are filtered to the member's dependency closure. Codex
      20th review demanded this — ``cwd=member`` alone would let npm
      walk up to the root lockfile but produce an unfiltered report.
    """
    argv = list(NPM_AUDIT_ARGV)
    if workspace_id is not None:
        argv.extend(("--workspace", workspace_id))
    if allow_missing_lockfile:
        argv.append("--no-package-lock")
    if omit_dev:
        argv.append("--omit=dev")
    return tuple(argv)


def classify_npm_audit_exit(result: CommandResult) -> tuple[bool, str | None]:
    """Decide whether the npm audit run succeeded.

    Returns ``(succeeded, error_reason_or_None)``. We do NOT trust the
    exit code alone; npm's exit code can be non-zero even on a clean
    parse (network warnings, etc.). The authoritative signal is "did
    stdout contain a JSON object with the expected top-level keys?"
    """
    if result.timed_out:
        return False, "npm audit timed out"
    text = decode_output(result.stdout).strip()
    if not text:
        # Genuine failure (e.g. lockfile missing) — stderr carries the reason.
        return False, f"npm audit produced no JSON output (exit {result.returncode})"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, f"npm audit JSON was malformed: {exc}"
    if not isinstance(data, dict):
        return False, "npm audit JSON top-level was not an object"
    # We only support npm v7+ output (the ``vulnerabilities`` shape). npm
    # v6 used a top-level ``advisories`` map with a different schema and we
    # do not parse it — accepting it here would silently produce zero
    # findings for v6 users. The presence of ``advisories`` on its own is a
    # strong signal for v6, even if ``metadata`` is also present (Codex
    # 10th review flagged that ``metadata`` alone passed the previous gate).
    if "advisories" in data and "vulnerabilities" not in data:
        return False, (
            "npm audit output appears to be from npm v6 (top-level "
            "'advisories'). secscan supports npm v7+ only — please "
            "upgrade your Node.js / npm version."
        )
    if "vulnerabilities" not in data:
        return False, "npm audit JSON did not contain expected report fields"
    return True, None


def build_findings_from_npm_audit(
    stdout: bytes, *, workspace_id: str | None = None
) -> tuple[Finding, ...]:
    """Parse ``npm audit --json`` stdout into normalized Findings.

    Caller has already verified the stdout is a well-formed report (via
    ``classify_npm_audit_exit``). This function focuses on the v7+ JSON
    structure and never raises on shape variance — unknown / partial
    advisory objects are skipped, not exploded.

    ``workspace_id`` is forwarded into the per-finding fingerprint so
    that the same advisory in two different workspace members produces
    two distinct baseline keys (Codex 20th review).
    """
    text = decode_output(stdout)
    if not text.strip():
        return ()
    data = json.loads(text)
    if not isinstance(data, dict):
        return ()
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        return ()

    findings: list[Finding] = []
    seen_fingerprints: set[str] = set()

    for pkg_name, pkg_info in vulnerabilities.items():
        if not isinstance(pkg_name, str) or not isinstance(pkg_info, dict):
            continue
        via = pkg_info.get("via")
        if not isinstance(via, list):
            continue
        pkg_fix_version = _extract_fix_version(pkg_info.get("fixAvailable"))
        for advisory in via:
            if not isinstance(advisory, dict):
                # Meta-vulnerability (string reference to another package).
                # We elide these in MVP to keep one Finding per real advisory.
                continue
            hints = _hints_from_advisory(advisory, pkg_fix_version)
            if hints is None:
                continue
            fingerprint = deps_fingerprint(
                ecosystem="npm",
                package=pkg_name,
                advisory_id=hints.advisory_id,
                workspace_id=workspace_id,
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            findings.append(
                Finding(
                    scanner="deps",
                    rule_id=hints.advisory_id,
                    severity=hints.severity,
                    title=hints.title or f"{pkg_name}: {hints.advisory_id}",
                    message=hints.message or hints.title,
                    location=Location(package=pkg_name, ecosystem="npm"),
                    fingerprint=fingerprint,
                    cve=hints.cve,
                    cwe=hints.cwe,
                    fix_version=hints.fix_version,
                    references=hints.references,
                )
            )
    return tuple(findings)


def _hints_from_advisory(
    advisory: dict[str, Any], pkg_fix_version: str | None
) -> AdvisoryHints | None:
    """Extract the fields we display from an npm advisory object.

    Codex 29th review: prefer GHSA > CVE > URL > source so that the same
    advisory in an npm vs pnpm vs yarn report produces the SAME
    advisory_id (and therefore the same fingerprint). Earlier the order
    started with ``url`` which made cross-tool baselines diverge
    silently.
    """
    advisory_id = (
        _first_str(advisory.get("ghsa_id"))
        or _first_str(advisory.get("cve"))
        or _extract_cve_from_url(advisory.get("url"))
        or _first_str(advisory.get("url"))
        or _coerce_str(advisory.get("source"))
    )
    if not advisory_id:
        return None
    cve = _first_str(advisory.get("cve")) or _extract_cve_from_url(advisory.get("url"))
    # npm advisories report ``cwe`` as either a string or a list; accept both.
    cwe_raw = advisory.get("cwe")
    cwe: str | None
    if isinstance(cwe_raw, list):
        cwe = next((c for c in cwe_raw if isinstance(c, str) and c), None)
    else:
        cwe = _first_str(cwe_raw)
    title = _first_str(advisory.get("title")) or advisory_id
    message = _first_str(advisory.get("title")) or ""
    severity = severity_from_npm_label(advisory.get("severity"))
    references = _collect_references(advisory)
    fix_version = pkg_fix_version
    return AdvisoryHints(
        title=title,
        advisory_id=advisory_id,
        severity=severity,
        cve=cve,
        cwe=cwe,
        fix_version=fix_version,
        references=references,
        message=message,
    )


def _extract_fix_version(fix_available: object) -> str | None:
    """``fixAvailable`` is False / True / {name, version, ...}."""
    if isinstance(fix_available, dict):
        version = fix_available.get("version")
        if isinstance(version, str) and version:
            return version
    return None


def _extract_cve_from_url(url: object) -> str | None:
    if isinstance(url, str) and "CVE-" in url:
        # GitHub advisory URLs sometimes embed the CVE id.
        marker = url.find("CVE-")
        return url[marker : marker + len("CVE-YYYY-NNNNN")]
    return None


def _collect_references(advisory: dict[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    url = _first_str(advisory.get("url"))
    if url:
        refs.append(url)
    references = advisory.get("references")
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, str) and ref and ref not in refs:
                refs.append(ref)
    return tuple(refs[:5])  # cap noise


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coerce_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None
