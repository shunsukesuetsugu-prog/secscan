"""pip-audit adapter (pypa/pip-audit v2.7+).

pip-audit produces a JSON array (or, with `--format json`, an object that
wraps one). It does NOT supply a severity field — Codex 2nd review and
Kimi's tool survey both confirmed this. We therefore emit findings with
``Severity.UNKNOWN``; the user's ``severity_unknown_policy`` then decides
whether to fail the build.

JSON shape we accept:

    {
      "dependencies": [
        {
          "name": "<pkg>",
          "version": "<installed-version>",
          "vulns": [
            {
              "id": "PYSEC-XXXX-NNNN" | "GHSA-..." | "CVE-...",
              "fix_versions": ["x.y.z", ...],
              "aliases": [...],
              "description": "..."
            }
          ]
        }
      ]
    }

We also accept the older top-level-list shape (pip-audit < 2.10) so users
on older releases still get findings.

Exit codes (per pip-audit docs and Kimi survey):
- 0: no vulnerabilities
- 1: vulnerabilities found
- other non-zero: internal error / dependency resolution failure

We classify 0 and 1 as "success" (the JSON is authoritative for the count)
and treat anything else as a ScannerError.
"""

from __future__ import annotations

import json
from typing import Any

from ...models import Finding, Location, Severity
from ...runner import CommandResult, decode_output
from ._common import AdvisoryHints, deps_fingerprint


class PipAuditInputMode:
    """Input modes pip-audit supports. The dispatcher in deps_scanner.py
    selects a mode from the WorkUnit and we build argv accordingly.

    These are exposed as classvar-like constants (not an enum) to keep the
    deps_scanner module's branching shallow.
    """

    REQUIREMENTS = "requirements"
    """``-r <file>`` mode. The file is a requirements.txt or pylock.toml."""

    PROJECT = "project"
    """``<project-path>`` mode. Lets pip-audit walk the project's
    pyproject + lockfiles. Phase 1B uses this for pyproject-only projects
    so we audit the project, NOT the current Python environment."""


def pip_audit_argv_for_requirements(path: str) -> tuple[str, ...]:
    """argv for the ``-r <file>`` form (requirements.txt or pylock.toml)."""
    return ("pip-audit", "--format", "json", "--strict", "--requirement", path)


def pip_audit_argv_for_project(path: str) -> tuple[str, ...]:
    """argv for the project-path form.

    pip-audit accepts a positional path to a pyproject-bearing directory
    and audits the project's dependencies — NOT the current interpreter's
    environment, which was the bug Codex 8th review flagged.
    """
    return ("pip-audit", "--format", "json", "--strict", path)


def classify_pip_audit_exit(result: CommandResult) -> tuple[bool, str | None]:
    """Decide whether the pip-audit run succeeded.

    Exit code 0 = clean, 1 = findings, anything else = error. We still
    require a parseable JSON payload for 0/1 because pip-audit can fail
    after partially writing output (e.g. dependency-resolution warnings).
    """
    if result.timed_out:
        return False, "pip-audit timed out"
    if result.returncode not in (0, 1):
        stderr_lines = decode_output(result.stderr).strip().splitlines()
        last_line = stderr_lines[-1] if stderr_lines else ""
        return False, (
            f"pip-audit exited {result.returncode}: {last_line}"
            if last_line
            else f"pip-audit exited {result.returncode}"
        )
    text = decode_output(result.stdout).strip()
    if not text:
        return False, "pip-audit produced no JSON output"
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return False, f"pip-audit JSON was malformed: {exc}"
    return True, None


def build_findings_from_pip_audit(
    stdout: bytes, *, workspace_id: str | None = None
) -> tuple[Finding, ...]:
    """Parse pip-audit JSON into normalized Findings.

    ``workspace_id`` (Phase 2-C-1) scopes the finding's fingerprint to a
    uv workspace member when present, mirroring the npm/pnpm convention.
    Root-only pip-audit scans pass ``workspace_id=None`` and keep the
    legacy fingerprint format.
    """
    text = decode_output(stdout)
    if not text.strip():
        return ()
    data = json.loads(text)

    # Two shapes:
    # - {"dependencies": [...]} (pip-audit 2.10+)
    # - [...] directly (older).
    if isinstance(data, dict):
        deps = data.get("dependencies")
        if not isinstance(deps, list):
            return ()
        records = deps
    elif isinstance(data, list):
        records = data
    else:
        return ()

    findings: list[Finding] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        name = _first_str(record.get("name"))
        if not name:
            continue
        installed_version = _first_str(record.get("version"))
        vulns = record.get("vulns")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            hints = _hints_from_vuln(vuln, package=name)
            if hints is None:
                continue
            fingerprint = deps_fingerprint(
                ecosystem="pypi",
                package=name,
                advisory_id=hints.advisory_id,
                workspace_id=workspace_id,
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append(
                Finding(
                    scanner="deps",
                    rule_id=hints.advisory_id,
                    severity=hints.severity,
                    title=hints.title or f"{name}: {hints.advisory_id}",
                    message=hints.message or hints.title,
                    location=Location(
                        package=name if installed_version is None
                        else f"{name}@{installed_version}",
                        ecosystem="pypi",
                    ),
                    fingerprint=fingerprint,
                    cve=hints.cve,
                    fix_version=hints.fix_version,
                    references=hints.references,
                )
            )
    return tuple(findings)


def _hints_from_vuln(vuln: dict[str, Any], *, package: str) -> AdvisoryHints | None:
    advisory_id = _first_str(vuln.get("id"))
    if not advisory_id:
        return None
    # pip-audit aliases include GHSA / CVE ids; surface the CVE for display.
    aliases_raw = vuln.get("aliases")
    aliases: list[Any] = aliases_raw if isinstance(aliases_raw, list) else []
    cve = None
    for alias in aliases:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            cve = alias
            break
    if cve is None and advisory_id.startswith("CVE-"):
        cve = advisory_id
    fix_versions = vuln.get("fix_versions")
    fix_version: str | None = None
    if isinstance(fix_versions, list) and fix_versions:
        first = fix_versions[0]
        if isinstance(first, str) and first:
            fix_version = first
    description = _first_str(vuln.get("description")) or ""
    title = description.splitlines()[0] if description else f"{package}: {advisory_id}"
    return AdvisoryHints(
        title=title[:200],  # truncate noisy descriptions
        advisory_id=advisory_id,
        severity=Severity.UNKNOWN,  # pip-audit does not provide severity
        cve=cve,
        cwe=None,
        fix_version=fix_version,
        references=(),
        message=description[:500],
    )


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
