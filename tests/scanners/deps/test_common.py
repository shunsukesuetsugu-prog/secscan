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
