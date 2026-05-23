"""Tests for the Yarn Berry audit adapter.

The adapter never spawns yarn itself; we drive it with canned
``CommandResult`` objects so we can exercise both successful and
malformed output paths without a real yarn install. NDJSON is
particularly tricky because Yarn emits different envelope shapes
across versions; both branches have dedicated tests.
"""

from __future__ import annotations

import json

from secscan.models import Severity
from secscan.runner import CommandResult
from secscan.scanners.deps.yarn import (
    build_findings_from_yarn_audit,
    classify_yarn_audit_exit,
    yarn_audit_argv,
)


def _result(
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        argv=("yarn",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.0,
        timed_out=timed_out,
    )


# --- argv -----------------------------------------------------------------


def test_argv_uses_workspace_selector_and_recursive() -> None:
    """Codex 28th review: per-member audit must be
    ``yarn workspace <name> npm audit --json --recursive`` —
    NOT ``--all`` (which would join all workspaces) and NOT plain
    ``yarn npm audit`` (which would audit the active workspace only)."""
    argv = yarn_audit_argv(workspace_id="@org/api")
    assert argv[0] == "yarn"
    assert "workspace" in argv
    ws_idx = argv.index("workspace")
    assert argv[ws_idx + 1] == "@org/api"
    assert "audit" in argv
    assert "--json" in argv
    assert "--recursive" in argv
    assert "--all" not in argv


# --- classify_yarn_audit_exit --------------------------------------------


def test_classify_clean_exit_is_success() -> None:
    ok, err = classify_yarn_audit_exit(_result(returncode=0))
    assert ok and err is None


def test_classify_findings_exit_is_success() -> None:
    """Yarn Berry returns exit 1 when findings are present. That's a
    successful audit, not a tool error."""
    ok, err = classify_yarn_audit_exit(_result(returncode=1))
    assert ok
    assert err is None


def test_classify_other_exit_is_failure() -> None:
    ok, err = classify_yarn_audit_exit(_result(returncode=2))
    assert not ok
    assert err is not None
    assert "yarn audit exited" in err


def test_classify_timeout_is_failure() -> None:
    ok, err = classify_yarn_audit_exit(_result(timed_out=True))
    assert not ok
    assert err is not None
    assert "timed out" in err


# --- build_findings_from_yarn_audit --------------------------------------


def test_parses_advisories_shape_ndjson() -> None:
    """Yarn 3-style envelope: each line is ``{"advisories": {...}}``."""
    line1 = json.dumps(
        {
            "advisories": {
                "1234": {
                    "id": 1234,
                    "ghsa_id": "GHSA-AAAA-BBBB",
                    "module_name": "underscore",
                    "title": "RCE in underscore",
                    "severity": "critical",
                    "cves": ["CVE-2024-7777"],
                    "url": "https://github.com/advisories/GHSA-AAAA-BBBB",
                    "patched_versions": ">=1.13.0",
                }
            }
        }
    )
    stdout = (line1 + "\n").encode()
    findings = build_findings_from_yarn_audit(stdout, workspace_id="@org/api")
    (f,) = findings
    assert f.scanner == "deps"
    assert f.severity == Severity.CRITICAL
    assert f.location is not None
    assert f.location.package == "underscore"
    assert f.location.ecosystem == "npm"
    assert f.cve == "CVE-2024-7777"
    assert f.fix_version == ">=1.13.0"


def test_parses_package_keyed_shape_ndjson() -> None:
    """Yarn 4 forwards the npm registry bulk shape: top-level keys are
    package names whose value is a list of advisory blobs."""
    line1 = json.dumps(
        {
            "underscore": [
                {
                    "id": "GHSA-AAAA-BBBB",
                    "module_name": "underscore",
                    "title": "RCE in underscore",
                    "severity": "high",
                    "cves": ["CVE-2024-7777"],
                    "patched_versions": ">=1.13.0",
                    "url": "https://github.com/advisories/GHSA-AAAA-BBBB",
                }
            ]
        }
    )
    findings = build_findings_from_yarn_audit(
        (line1 + "\n").encode(), workspace_id="@org/api"
    )
    (f,) = findings
    assert f.severity == Severity.HIGH
    assert f.location is not None
    assert f.location.package == "underscore"


def test_package_keyed_shape_uses_top_level_key_when_module_name_missing() -> None:
    """Codex 29th review BLOCKER: in the package-keyed envelope, the
    top-level key IS the package name and the inner advisory may omit
    ``module_name`` / ``name``. We must fall back to the key, not
    silently drop the finding."""
    line = json.dumps(
        {
            "lodash": [
                {
                    "ghsa_id": "GHSA-XYZ",
                    "title": "Vulnerable lodash",
                    "severity": "high",
                    # NOTE: no module_name / name fields.
                }
            ]
        }
    )
    findings = build_findings_from_yarn_audit(
        (line + "\n").encode(), workspace_id="@org/api"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.location is not None
    assert f.location.package == "lodash"


def test_empty_object_is_clean_success() -> None:
    """Yarn emits ``{}`` for an audit that found nothing. That must
    parse as zero findings, not a malformed report."""
    findings = build_findings_from_yarn_audit(b"{}\n", workspace_id="api")
    assert findings == ()


def test_empty_stdout_yields_no_findings() -> None:
    assert build_findings_from_yarn_audit(b"", workspace_id="api") == ()


def test_malformed_line_is_skipped_not_fatal() -> None:
    """Yarn occasionally emits progress markers that aren't valid JSON.
    The parser should drop those lines and still surface real findings
    from the rest of the stream."""
    valid_line = json.dumps(
        {
            "advisories": {
                "1": {
                    "id": 1,
                    "ghsa_id": "GHSA-X",
                    "module_name": "pkg",
                    "title": "t",
                    "severity": "high",
                }
            }
        }
    )
    stdout = ("not-json-line\n" + valid_line + "\n").encode()
    findings = build_findings_from_yarn_audit(stdout, workspace_id="api")
    assert len(findings) == 1


def test_duplicate_advisory_id_is_deduped_within_workspace() -> None:
    """Same advisory listed twice in the same workspace's report must
    not produce two Findings."""
    body = json.dumps(
        {
            "advisories": {
                "1": {
                    "id": 1,
                    "ghsa_id": "GHSA-DUP",
                    "module_name": "pkg",
                    "title": "t",
                    "severity": "high",
                },
                "2": {
                    "id": 2,
                    "ghsa_id": "GHSA-DUP",
                    "module_name": "pkg",
                    "title": "t",
                    "severity": "critical",
                },
            }
        }
    )
    findings = build_findings_from_yarn_audit(
        (body + "\n").encode(), workspace_id="api"
    )
    assert len(findings) == 1


def test_workspace_id_scopes_fingerprint() -> None:
    """The same advisory in two different workspace members produces
    distinct fingerprints (Codex 20th's deps-ws scoping applies)."""
    line = json.dumps(
        {
            "advisories": {
                "1": {
                    "id": 1,
                    "ghsa_id": "GHSA-AAAA",
                    "module_name": "underscore",
                    "title": "t",
                    "severity": "high",
                }
            }
        }
    )
    api = build_findings_from_yarn_audit(
        (line + "\n").encode(), workspace_id="@org/api"
    )[0]
    web = build_findings_from_yarn_audit(
        (line + "\n").encode(), workspace_id="@org/web"
    )[0]
    assert api.fingerprint != web.fingerprint


def test_advisory_without_identifier_is_skipped() -> None:
    line = json.dumps(
        {
            "advisories": {
                "no-id-pkg": {
                    "module_name": "pkg",
                    "title": "missing id",
                    "severity": "low",
                }
            }
        }
    )
    findings = build_findings_from_yarn_audit(
        (line + "\n").encode(), workspace_id="api"
    )
    # Falls back to the key as the advisory id, so we DO get one finding
    # but with the key as rule_id.
    assert len(findings) == 1
    assert findings[0].rule_id == "no-id-pkg"
