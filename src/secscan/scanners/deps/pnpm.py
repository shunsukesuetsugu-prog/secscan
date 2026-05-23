"""pnpm audit adapter (pnpm v8/v9/v10).

Critical semantic difference from npm: ``pnpm audit --audit-level=<level>``
filters OUTPUT to advisories at-or-above the given level. We must request
``--audit-level=low`` so the JSON contains every finding regardless of
severity — secscan's policy layer makes the threshold call later.

pnpm's JSON shape is similar to (older) npm v6's:

    {
      "advisories": {
        "<id>": {
          "id": <int>,
          "title": "...",
          "module_name": "...",
          "vulnerable_versions": "...",
          "patched_versions": "...",
          "severity": "low|moderate|high|critical",
          "cves": ["CVE-XXXX-NNNNN", ...],
          "cwe": "CWE-NNN" | ["CWE-..."]
          "url": "https://...",
          ...
        },
        ...
      },
      "metadata": {...}
    }

The exact shape evolves between pnpm versions; we treat everything as
best-effort and skip advisories without a stable identifier.
"""

from __future__ import annotations

import json
from typing import Any

from ...models import Finding, Location
from ...runner import CommandResult, decode_output
from ._common import AdvisoryHints, deps_fingerprint, severity_from_npm_label

# audit-level=low ensures all advisories appear in the output regardless
# of severity. Codex 2nd review pinned this requirement explicitly.
PNPM_AUDIT_ARGV: tuple[str, ...] = (
    "pnpm",
    "audit",
    "--json",
    "--audit-level=low",
)


def classify_pnpm_audit_exit(result: CommandResult) -> tuple[bool, str | None]:
    """Decide whether the pnpm audit run succeeded.

    pnpm uses non-zero exit codes for both "leaks found" and "registry
    error", so the only reliable signal is "did stdout parse to a JSON
    object that contains an advisories table (even an empty one)?".
    """
    if result.timed_out:
        return False, "pnpm audit timed out"
    text = decode_output(result.stdout).strip()
    if not text:
        return False, f"pnpm audit produced no JSON output (exit {result.returncode})"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, f"pnpm audit JSON was malformed: {exc}"
    if not isinstance(data, dict):
        return False, "pnpm audit JSON top-level was not an object"
    if "advisories" not in data and "metadata" not in data:
        return False, "pnpm audit JSON did not contain expected report fields"
    return True, None


def build_findings_from_pnpm_audit(stdout: bytes) -> tuple[Finding, ...]:
    text = decode_output(stdout)
    if not text.strip():
        return ()
    data = json.loads(text)
    if not isinstance(data, dict):
        return ()
    advisories = data.get("advisories")
    if not isinstance(advisories, dict):
        return ()

    findings: list[Finding] = []
    seen: set[str] = set()
    for raw_id, advisory in advisories.items():
        if not isinstance(advisory, dict):
            continue
        hints = _hints_from_advisory(advisory, fallback_id=str(raw_id))
        if hints is None:
            continue
        package_name = _first_str(advisory.get("module_name")) or "<unknown>"
        fingerprint = deps_fingerprint(
            ecosystem="npm",  # pnpm publishes to the same ecosystem
            package=package_name,
            advisory_id=hints.advisory_id,
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(
            Finding(
                scanner="deps",
                rule_id=hints.advisory_id,
                severity=hints.severity,
                title=hints.title or f"{package_name}: {hints.advisory_id}",
                message=hints.message or hints.title,
                location=Location(package=package_name, ecosystem="npm"),
                fingerprint=fingerprint,
                cve=hints.cve,
                cwe=hints.cwe,
                fix_version=hints.fix_version,
                references=hints.references,
            )
        )
    return tuple(findings)


def _hints_from_advisory(
    advisory: dict[str, Any], fallback_id: str
) -> AdvisoryHints | None:
    advisory_id = (
        _first_str(advisory.get("ghsa_id"))
        or _first_cve(advisory.get("cves"))
        or _first_str(advisory.get("url"))
        or _coerce_str(advisory.get("id"))
        or fallback_id
    )
    if not advisory_id:
        return None
    cve = _first_cve(advisory.get("cves"))
    cwe = _first_cwe(advisory.get("cwe"))
    severity = severity_from_npm_label(advisory.get("severity"))
    title = _first_str(advisory.get("title")) or advisory_id
    message = _first_str(advisory.get("overview")) or _first_str(
        advisory.get("title")
    ) or ""
    fix_version = _first_str(advisory.get("patched_versions"))
    refs: list[str] = []
    url = _first_str(advisory.get("url"))
    if url:
        refs.append(url)
    refs_field = advisory.get("references")
    if isinstance(refs_field, str) and refs_field:
        # pnpm sometimes uses a newline-joined string here.
        for line in refs_field.splitlines():
            line = line.strip()
            if line and line not in refs:
                refs.append(line)
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


def _first_cwe(value: object) -> str | None:
    if isinstance(value, str) and value.startswith("CWE"):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.startswith("CWE"):
                return item
    return None


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
