"""Tests for shared dependency-scanner helpers."""

from __future__ import annotations

import pytest

from secscan.models import Severity
from secscan.scanners.deps._common import (
    deps_fingerprint,
    severity_from_npm_label,
)

# --- severity_from_npm_label ----------------------------------------------


@pytest.mark.parametrize(
    "label,expected",
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("info", Severity.INFO),
        ("none", Severity.INFO),
    ],
)
def test_known_severity_labels(label: str, expected: Severity) -> None:
    assert severity_from_npm_label(label) == expected


def test_unknown_severity_label_returns_unknown() -> None:
    assert severity_from_npm_label("critically-severe") == Severity.UNKNOWN


def test_non_string_severity_returns_unknown() -> None:
    assert severity_from_npm_label(None) == Severity.UNKNOWN
    assert severity_from_npm_label(42) == Severity.UNKNOWN
    assert severity_from_npm_label(True) == Severity.UNKNOWN


# --- deps_fingerprint ------------------------------------------------------


def test_fingerprint_is_stable_for_same_inputs() -> None:
    a = deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="CVE-2024-1")
    b = deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="CVE-2024-1")
    assert a == b


def test_fingerprint_changes_with_ecosystem() -> None:
    npm_fp = deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="GHSA-x")
    pypi_fp = deps_fingerprint(ecosystem="pypi", package="lodash", advisory_id="GHSA-x")
    assert npm_fp != pypi_fp


def test_fingerprint_changes_with_advisory_id() -> None:
    a = deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="GHSA-x")
    b = deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="GHSA-y")
    assert a != b


def test_fingerprint_is_case_insensitive_in_package_and_advisory() -> None:
    """``Lodash`` and ``lodash`` are the same npm package; an attacker who
    can choose the case in lockfile output must not be able to bypass a
    baseline entry just by changing the casing."""
    a = deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="ghsa-x")
    b = deps_fingerprint(ecosystem="npm", package="LODASH", advisory_id="GHSA-X")
    assert a == b


def test_fingerprint_rejects_empty_inputs() -> None:
    with pytest.raises(ValueError):
        deps_fingerprint(ecosystem="", package="lodash", advisory_id="GHSA-x")
    with pytest.raises(ValueError):
        deps_fingerprint(ecosystem="npm", package="", advisory_id="GHSA-x")
    with pytest.raises(ValueError):
        deps_fingerprint(ecosystem="npm", package="lodash", advisory_id="")


def test_cross_tool_baseline_compatibility() -> None:
    """Codex 29th review: the same advisory (same GHSA) reported by
    npm, pnpm, and yarn must produce identical fingerprints so a
    ``baseline accept`` from one tool also suppresses the same finding
    when the project migrates between package managers."""
    import json

    from secscan.scanners.deps.npm import (
        build_findings_from_npm_audit,
    )
    from secscan.scanners.deps.pnpm import (
        build_findings_from_pnpm_audit,
    )
    from secscan.scanners.deps.yarn import (
        build_findings_from_yarn_audit,
    )

    npm_payload = json.dumps(
        {
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
                            "title": "lodash RCE",
                            "severity": "high",
                            "url": "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC",
                        }
                    ],
                    "fixAvailable": False,
                }
            }
        }
    ).encode()
    pnpm_payload = json.dumps(
        {
            "advisories": {
                "1": {
                    "id": 1,
                    "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
                    "module_name": "lodash",
                    "title": "lodash RCE",
                    "severity": "high",
                }
            }
        }
    ).encode()
    yarn_payload = (
        json.dumps(
            {
                "advisories": {
                    "1": {
                        "id": 1,
                        "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
                        "module_name": "lodash",
                        "title": "lodash RCE",
                        "severity": "high",
                    }
                }
            }
        )
        + "\n"
    ).encode()

    (npm_finding,) = build_findings_from_npm_audit(npm_payload)
    (pnpm_finding,) = build_findings_from_pnpm_audit(pnpm_payload)
    (yarn_finding,) = build_findings_from_yarn_audit(
        yarn_payload, workspace_id=""
    )
    # All three must agree on the fingerprint so a single baseline
    # accept survives a tool migration.
    assert npm_finding.fingerprint == pnpm_finding.fingerprint
    assert npm_finding.fingerprint == yarn_finding.fingerprint


def test_cross_tool_baseline_compatibility_cve_only() -> None:
    """Codex 30th review: cross-tool compatibility must also hold when
    only a CVE is present (no GHSA). Previously, npm picked URL first
    while yarn picked ``id`` first, so a CVE-only advisory diverged
    between adapters."""
    import json

    from secscan.scanners.deps.npm import (
        build_findings_from_npm_audit,
    )
    from secscan.scanners.deps.pnpm import (
        build_findings_from_pnpm_audit,
    )
    from secscan.scanners.deps.yarn import (
        build_findings_from_yarn_audit,
    )

    npm_payload = json.dumps(
        {
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "cve": "CVE-2024-9999",
                            "title": "lodash CVE",
                            "severity": "high",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                        }
                    ],
                    "fixAvailable": False,
                }
            }
        }
    ).encode()
    pnpm_payload = json.dumps(
        {
            "advisories": {
                "1": {
                    "id": 1,
                    "cves": ["CVE-2024-9999"],
                    "module_name": "lodash",
                    "title": "lodash CVE",
                    "severity": "high",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                }
            }
        }
    ).encode()
    yarn_payload = (
        json.dumps(
            {
                "advisories": {
                    "1": {
                        "id": 1,
                        "cves": ["CVE-2024-9999"],
                        "module_name": "lodash",
                        "title": "lodash CVE",
                        "severity": "high",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                    }
                }
            }
        )
        + "\n"
    ).encode()

    (npm_finding,) = build_findings_from_npm_audit(npm_payload)
    (pnpm_finding,) = build_findings_from_pnpm_audit(pnpm_payload)
    (yarn_finding,) = build_findings_from_yarn_audit(
        yarn_payload, workspace_id=""
    )
    assert npm_finding.fingerprint == pnpm_finding.fingerprint
    assert npm_finding.fingerprint == yarn_finding.fingerprint
    # All three carry the CVE identifier (not URL).
    assert npm_finding.rule_id == "CVE-2024-9999"
    assert pnpm_finding.rule_id == "CVE-2024-9999"
    assert yarn_finding.rule_id == "CVE-2024-9999"
