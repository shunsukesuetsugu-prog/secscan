"""``Finding.fingerprint_aliases`` ↔ baseline-suppression interaction.

Phase 2-D added alias fingerprints so a single ``baseline accept``
on a DAST advisory suppresses BOTH the ``param``-bearing and the
``param``-less variants. The matrix below verifies the contract
without relying on the DAST scanner itself — we hand-build Findings
and exercise ``apply_baseline`` directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secscan import __version__ as SECSCAN_VERSION
from secscan.baseline import (
    Baseline,
    BaselineEntry,
    apply_baseline,
    build_entries_for_accept,
    build_entry,
)
from secscan.models import Finding, Severity


def _entry(
    *, fingerprint: str, expires_at: datetime | None = None
) -> BaselineEntry:
    return BaselineEntry(
        fingerprint=fingerprint,
        scanner="dast",
        rule_id="10038",
        reason="accepted for testing",
        accepted_by="tester",
        added_at=datetime.now(UTC),
        expires_at=expires_at or (datetime.now(UTC) + timedelta(days=30)),
        secscan_version=SECSCAN_VERSION,
    )


def _finding(
    *,
    fingerprint: str,
    aliases: tuple[str, ...] = (),
    rule_id: str = "10038",
) -> Finding:
    return Finding(
        scanner="dast",
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        title="finding",
        message="finding",
        location=None,
        fingerprint=fingerprint,
        fingerprint_aliases=aliases,
    )


class TestFingerprintAliases:
    def test_primary_match_still_works(self) -> None:
        baseline = Baseline(entries=(_entry(fingerprint="primary"),))
        result = apply_baseline((_finding(fingerprint="primary"),), baseline)
        assert result.suppressed and not result.kept

    def test_alias_match_suppresses(self) -> None:
        """The Codex 2nd review scenario: a baseline accepted on the
        coarse (no-param) variant must suppress the fine (with-param)
        finding too."""
        baseline = Baseline(entries=(_entry(fingerprint="coarse"),))
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        result = apply_baseline((finding,), baseline)
        assert result.suppressed and not result.kept

    def test_no_match_kept(self) -> None:
        baseline = Baseline(entries=(_entry(fingerprint="other"),))
        finding = _finding(fingerprint="primary", aliases=("alias",))
        result = apply_baseline((finding,), baseline)
        assert result.kept and not result.suppressed

    def test_alias_matches_only_when_scanner_and_rule_also_match(self) -> None:
        """A baseline entry's (scanner, rule_id) must still match —
        we do NOT widen suppression on alias collisions across
        scanners."""
        baseline = Baseline(
            entries=(
                BaselineEntry(
                    fingerprint="coarse",
                    scanner="secrets",  # different scanner!
                    rule_id="10038",
                    reason="x",
                    accepted_by="x",
                    added_at=datetime.now(UTC),
                    expires_at=datetime.now(UTC) + timedelta(days=30),
                    secscan_version=SECSCAN_VERSION,
                ),
            )
        )
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        result = apply_baseline((finding,), baseline)
        assert result.kept, "cross-scanner alias collision must NOT suppress"

    def test_expired_alias_does_not_suppress(self) -> None:
        baseline = Baseline(
            entries=(
                _entry(
                    fingerprint="coarse",
                    expires_at=datetime.now(UTC) - timedelta(days=1),
                ),
            )
        )
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        result = apply_baseline((finding,), baseline)
        assert result.kept, "an expired baseline alias must NOT suppress"
        # And we emit a warning so the operator notices.
        assert any("expired" in w for w in result.warnings)

    def test_primary_match_wins_over_alias(self) -> None:
        """If both the primary AND an alias appear in the baseline,
        the primary takes precedence (so the audit trail points at
        the more-specific entry the operator likely added first)."""
        baseline = Baseline(
            entries=(
                _entry(fingerprint="fine"),
                _entry(fingerprint="coarse"),
            )
        )
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        result = apply_baseline((finding,), baseline)
        assert result.suppressed
        # We don't expose which entry matched directly, but the warning
        # set should be empty (both are valid, neither expired).
        assert result.warnings == ()


class TestBuildEntriesForAccept:
    """Codex Phase 2-D diff review pinned: ``baseline accept`` of a
    DAST finding MUST persist both the fine fingerprint AND each
    declared coarse alias, otherwise the alias-suppression contract
    only holds when the operator happened to accept on the coarse
    granularity in the first place."""

    def test_single_entry_for_no_aliases(self) -> None:
        finding = _finding(fingerprint="fine")
        entries = build_entries_for_accept(
            finding, reason="x", accepted_by="me", expiry_days=30
        )
        assert len(entries) == 1
        assert entries[0].fingerprint == "fine"

    def test_expands_to_primary_plus_each_alias(self) -> None:
        finding = _finding(
            fingerprint="fine", aliases=("coarse-1", "coarse-2")
        )
        entries = build_entries_for_accept(
            finding, reason="x", accepted_by="me", expiry_days=30
        )
        fingerprints = [e.fingerprint for e in entries]
        assert fingerprints == ["fine", "coarse-1", "coarse-2"]

    def test_duplicate_aliases_are_collapsed(self) -> None:
        """An accidental ``aliases=(coarse, coarse)`` (or
        ``aliases`` that happens to include the primary) must not
        produce duplicate baseline entries."""
        finding = _finding(
            fingerprint="fine",
            aliases=("coarse", "coarse", "fine"),
        )
        entries = build_entries_for_accept(
            finding, reason="x", accepted_by="me", expiry_days=30
        )
        fingerprints = [e.fingerprint for e in entries]
        assert fingerprints == ["fine", "coarse"]

    def test_alias_entries_carry_same_audit_metadata(self) -> None:
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        entries = build_entries_for_accept(
            finding,
            reason="documented exception",
            accepted_by="security@example.com",
            expiry_days=14,
        )
        assert len({e.reason for e in entries}) == 1
        assert all(e.reason == "documented exception" for e in entries)
        assert len({e.accepted_by for e in entries}) == 1
        assert len({e.expires_at for e in entries}) == 1
        # And every alias-derived entry has raw_fingerprint=None so we
        # don't falsely claim the upstream tool emitted the alias.
        _primary, *aliases = entries
        for alias_entry in aliases:
            assert alias_entry.raw_fingerprint is None

    def test_round_trip_with_apply_baseline(self) -> None:
        """End-to-end: accept on fine → apply suppresses BOTH fine
        and the alias-bearing variant. This is the Codex-flagged
        invariant the new ``build_entries_for_accept`` helper exists
        to enforce."""
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        entries = build_entries_for_accept(
            finding, reason="ok", accepted_by="me", expiry_days=30
        )
        baseline = Baseline(entries=entries)

        # The fine variant the user accepted.
        fine_finding = _finding(fingerprint="fine", aliases=("coarse",))
        # The coarse variant the user did NOT explicitly accept but
        # which represents the same advisory (param-less reporting).
        coarse_finding = _finding(fingerprint="coarse")

        result = apply_baseline((fine_finding, coarse_finding), baseline)
        assert result.suppressed == (fine_finding, coarse_finding)
        assert result.kept == ()

    def test_build_entry_unchanged_for_legacy_callers(self) -> None:
        """``build_entry`` (the pre-Phase-2-D API) must still return a
        single primary entry — Codex flagged that quietly changing
        its return type would break every existing caller."""
        finding = _finding(fingerprint="fine", aliases=("coarse",))
        entry = build_entry(
            finding, reason="x", accepted_by="me", expiry_days=30
        )
        assert isinstance(entry, BaselineEntry)
        assert entry.fingerprint == "fine"
