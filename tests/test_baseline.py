"""Tests for baseline (known-issue suppression).

This module is the most security-sensitive, so the tests are correspondingly
thorough:
- Round-trip (save → load) preserves all fields including timezone-aware
  timestamps.
- ``apply_baseline`` suppresses matched findings and surfaces expired entries
  as warnings (not silent re-detection, not silent suppression).
- Tool-version drift and config-hash drift produce warnings.
- Unknown baseline ``version`` is rejected (we never best-effort parse a
  future format).
- ``build_entry`` requires a non-empty reason and sets expiry correctly.
- ``is_ci_environment`` honors ``SECSCAN_CI=1`` exactly.
- ``prune_expired`` only removes expired entries.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secscan import __version__ as SECSCAN_VERSION
from secscan.baseline import (
    BASELINE_VERSION,
    Baseline,
    BaselineEntry,
    BaselineError,
    apply_baseline,
    build_entry,
    is_ci_environment,
    load_baseline,
    merge_entries,
    prune_expired,
    save_baseline,
)
from secscan.models import Finding, Location, Severity

# --- Helpers ---------------------------------------------------------------


UTC = UTC


def _entry(
    *,
    fingerprint: str = "fp1",
    reason: str = "accepted for X",
    added: datetime | None = None,
    expires: datetime | None = None,
) -> BaselineEntry:
    # Defaults are placed far in the future so that fixtures aren't expired
    # by wall-clock drift between when the tests are written and when they
    # are run. Tests that need expiry semantics pass explicit ``expires``.
    added_at = added or datetime(2026, 1, 1, tzinfo=UTC)
    expires_at = expires or datetime(2099, 1, 1, tzinfo=UTC)
    return BaselineEntry(
        fingerprint=fingerprint,
        scanner="secrets",
        rule_id="aws-key",
        reason=reason,
        accepted_by="alice",
        added_at=added_at,
        expires_at=expires_at,
        secscan_version=SECSCAN_VERSION,
        title="AWS Key",
        raw_fingerprint="raw1",
    )


def _finding(fingerprint: str = "fp1", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        scanner="secrets",
        rule_id="aws-key",
        severity=severity,
        title="AWS Key",
        message="found",
        location=Location(file="src/a.py", line=1),
        fingerprint=fingerprint,
        raw_fingerprint="raw1",
    )


# --- Round-trip I/O --------------------------------------------------------


def test_save_then_load_roundtrip(tmp_path: Path) -> None:
    baseline = Baseline(
        created_by="alice",
        tool_versions={"gitleaks": "8.18.0"},
        config_hash="sha256:abc",
        entries=(_entry(),),
    )
    p = tmp_path / "bl.json"
    save_baseline(baseline, p)
    loaded = load_baseline(p)
    assert loaded is not None
    assert loaded.version == BASELINE_VERSION
    assert loaded.created_by == "alice"
    assert loaded.tool_versions == {"gitleaks": "8.18.0"}
    assert loaded.config_hash == "sha256:abc"
    assert len(loaded.entries) == 1
    assert loaded.entries[0].fingerprint == "fp1"
    assert loaded.entries[0].reason == "accepted for X"
    assert loaded.entries[0].added_at.tzinfo is not None


def test_save_writes_atomically(tmp_path: Path) -> None:
    p = tmp_path / "bl.json"
    baseline = Baseline(entries=(_entry(),))
    save_baseline(baseline, p)
    # Tmp file should not linger.
    assert not p.with_suffix(p.suffix + ".tmp").exists()
    assert p.exists()


def test_load_returns_none_when_missing(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "nope.json") is None


# --- Parsing errors --------------------------------------------------------


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "bl.json"
    p.write_text("{this is not json")
    with pytest.raises(BaselineError, match="invalid JSON"):
        load_baseline(p)


def test_load_rejects_unknown_version(tmp_path: Path) -> None:
    p = tmp_path / "bl.json"
    p.write_text(json.dumps({"version": 99, "entries": []}))
    with pytest.raises(BaselineError, match="unsupported version"):
        load_baseline(p)


def test_load_rejects_non_object_root(tmp_path: Path) -> None:
    p = tmp_path / "bl.json"
    p.write_text("[]")
    with pytest.raises(BaselineError, match="root must be an object"):
        load_baseline(p)


def test_load_rejects_entries_not_list(tmp_path: Path) -> None:
    p = tmp_path / "bl.json"
    p.write_text(json.dumps({"version": BASELINE_VERSION, "entries": {}}))
    with pytest.raises(BaselineError, match="'entries' must be a list"):
        load_baseline(p)


def test_load_rejects_empty_reason(tmp_path: Path) -> None:
    payload = {
        "version": BASELINE_VERSION,
        "created_at": "2026-01-01T00:00:00Z",
        "entries": [
            {
                "fingerprint": "f",
                "scanner": "secrets",
                "rule_id": "r",
                "reason": "   ",  # whitespace only
                "accepted_by": "alice",
                "added_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-04-01T00:00:00Z",
                "secscan_version": "0.1.0",
            }
        ],
    }
    p = tmp_path / "bl.json"
    p.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="non-empty"):
        load_baseline(p)


# --- apply_baseline --------------------------------------------------------


def test_apply_baseline_with_no_baseline_keeps_everything() -> None:
    fs = (_finding("a"), _finding("b"))
    app = apply_baseline(fs, baseline=None)
    assert app.kept == fs
    assert app.suppressed == ()
    assert app.warnings == ()


def test_apply_baseline_suppresses_matching_fingerprint() -> None:
    bl = Baseline(entries=(_entry(fingerprint="fp1"),))
    fs = (_finding("fp1"), _finding("fp2"))
    app = apply_baseline(fs, bl)
    assert len(app.kept) == 1
    assert app.kept[0].fingerprint == "fp2"
    assert len(app.suppressed) == 1
    assert app.suppressed[0].fingerprint == "fp1"


def test_apply_baseline_expired_entry_does_not_suppress() -> None:
    past = datetime(2025, 1, 1, tzinfo=UTC)
    bl = Baseline(
        entries=(
            _entry(
                fingerprint="fp1",
                added=past - timedelta(days=200),
                expires=past,
            ),
        )
    )
    fs = (_finding("fp1"),)
    app = apply_baseline(fs, bl, now=datetime(2026, 1, 1, tzinfo=UTC))
    assert app.kept == fs
    assert app.suppressed == ()
    assert any("expired" in w for w in app.warnings)


def test_apply_baseline_warns_on_tool_version_drift() -> None:
    bl = Baseline(
        tool_versions={"gitleaks": "8.18.0"},
        entries=(_entry(),),
    )
    app = apply_baseline(
        (_finding("other"),),
        bl,
        current_tool_versions={"gitleaks": "8.20.1"},
    )
    assert any("tool version drift" in w for w in app.warnings)


def test_apply_baseline_warns_on_config_hash_drift() -> None:
    bl = Baseline(config_hash="sha256:old", entries=(_entry(),))
    app = apply_baseline(
        (_finding("other"),),
        bl,
        current_config_hash="sha256:new",
    )
    assert any("config hash" in w for w in app.warnings)


def test_apply_baseline_no_warning_when_versions_match() -> None:
    bl = Baseline(
        tool_versions={"gitleaks": "8.18.0"},
        config_hash="sha256:same",
        entries=(_entry(),),
    )
    app = apply_baseline(
        (_finding("other"),),
        bl,
        current_tool_versions={"gitleaks": "8.18.0"},
        current_config_hash="sha256:same",
    )
    assert app.warnings == ()


# --- build_entry -----------------------------------------------------------


def test_build_entry_rejects_empty_reason() -> None:
    with pytest.raises(BaselineError, match="reason"):
        build_entry(_finding(), reason="  ", accepted_by="x", expiry_days=30)


def test_build_entry_uses_expiry_days() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    entry = build_entry(
        _finding(), reason="needed", accepted_by="alice", expiry_days=30, now=now
    )
    assert entry.expires_at == now + timedelta(days=30)


def test_build_entry_populates_source_location_from_file_line() -> None:
    entry = build_entry(
        _finding(), reason="r", accepted_by="a", expiry_days=10
    )
    assert entry.source_location == "src/a.py:1"


def test_build_entry_uses_package_when_no_file() -> None:
    f = Finding(
        scanner="deps",
        rule_id="CVE-1",
        severity=Severity.HIGH,
        title="t",
        message="m",
        location=Location(package="lodash", ecosystem="npm"),
        fingerprint="dep1",
    )
    entry = build_entry(f, reason="r", accepted_by="a", expiry_days=10)
    assert entry.source_location == "lodash"
    assert entry.package == "lodash"
    assert entry.ecosystem == "npm"


# --- merge_entries ---------------------------------------------------------


def test_merge_entries_replaces_same_fingerprint() -> None:
    existing = Baseline(entries=(_entry(fingerprint="fp1", reason="old"),))
    new = (_entry(fingerprint="fp1", reason="new"),)
    merged = merge_entries(existing, new)
    assert len(merged.entries) == 1
    assert merged.entries[0].reason == "new"


def test_merge_entries_into_empty_baseline() -> None:
    merged = merge_entries(None, (_entry(),))
    assert len(merged.entries) == 1


# --- prune_expired ---------------------------------------------------------


def test_prune_removes_expired_entries() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    fresh = _entry(
        fingerprint="fresh",
        added=now - timedelta(days=1),
        expires=now + timedelta(days=80),
    )
    expired = _entry(
        fingerprint="old",
        added=now - timedelta(days=200),
        expires=now - timedelta(days=1),
    )
    bl = Baseline(entries=(fresh, expired))
    pruned = prune_expired(bl, now=now)
    assert {e.fingerprint for e in pruned.entries} == {"fresh"}


# --- CI guard --------------------------------------------------------------


def test_is_ci_environment_true_when_var_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECSCAN_CI", "1")
    assert is_ci_environment()


def test_is_ci_environment_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECSCAN_CI", raising=False)
    assert not is_ci_environment()


def test_is_ci_environment_false_when_not_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECSCAN_CI", "true")  # only "1" counts
    assert not is_ci_environment()
