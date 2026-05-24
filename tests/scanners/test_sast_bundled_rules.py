"""Tests for the Phase 2-G bundled semgrep rules.

We verify three properties:

1. The ``secscan:extra`` sentinel resolves to the bundled rules
   directory on disk (smoke-test).
2. The sentinel passes the ``_reject_unsafe_configs`` safety gate
   without ``allow_unverified_configs`` being set.
3. The shipped rules fire on the curated vulnerable fixtures AND
   stay quiet on the curated safe / borderline fixtures (no FP).

The third check is the only regression-test we have that proves
secscan reaches 100% recall on the Python SAST bench fixture —
otherwise a quiet refactor of the rule patterns could silently
drop the new coverage.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from secscan.scanners.sast import (
    BUNDLED_RULES_SENTINEL,
    _bundled_rules_dir,
    _expand_bundled_sentinels,
    _reject_unsafe_configs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PY_FIXTURES = REPO_ROOT / "bench" / "fixtures" / "sast" / "python"


class TestSentinel:
    def test_bundled_dir_exists(self) -> None:
        assert _bundled_rules_dir().is_dir()
        ymls = sorted(p.name for p in _bundled_rules_dir().glob("*.yml"))
        assert ymls, "no rules shipped under src/secscan/rules"

    def test_expansion_replaces_sentinel(self) -> None:
        out = _expand_bundled_sentinels(
            [BUNDLED_RULES_SENTINEL, "p/default", "p/python"]
        )
        # Sentinel becomes an absolute path; other entries unchanged.
        assert out[0] == str(_bundled_rules_dir())
        assert out[1:] == ["p/default", "p/python"]

    def test_expansion_idempotent_on_non_sentinel(self) -> None:
        inputs = ["p/default", "rules/local.yml", "https://evil"]
        assert _expand_bundled_sentinels(inputs) == inputs

    def test_expansion_omits_missing_bundled_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """If the bundled rules dir doesn't exist (broken install),
        the sentinel is silently dropped — operators still get
        their other rulesets."""
        bogus = tmp_path / "nonexistent"
        monkeypatch.setattr(
            "secscan.scanners.sast._bundled_rules_dir", lambda: bogus
        )
        out = _expand_bundled_sentinels([BUNDLED_RULES_SENTINEL, "p/default"])
        assert out == ["p/default"]


class TestSafetyGate:
    def test_sentinel_accepted_without_opt_in(self, tmp_path: Path) -> None:
        rejected = _reject_unsafe_configs(
            [BUNDLED_RULES_SENTINEL],
            scan_root=tmp_path,
            allow_unverified=False,
        )
        assert rejected == ()

    def test_arbitrary_string_still_rejected(self, tmp_path: Path) -> None:
        """A look-alike that ISN'T the exact sentinel must NOT be
        accepted by the gate just because it shares a prefix."""
        rejected = _reject_unsafe_configs(
            ["secscan:evil", "secscan:extra-extra"],
            scan_root=tmp_path,
            allow_unverified=False,
        )
        assert set(rejected) == {"secscan:evil", "secscan:extra-extra"}

    @pytest.mark.parametrize(
        "variant",
        [
            "Secscan:Extra",  # mixed case
            "SECSCAN:EXTRA",  # all caps
            " secscan:extra",  # leading whitespace
            "secscan:extra ",  # trailing whitespace
            "secscan:extra\t",  # tab
            "secscan:extras",  # plural — different identifier
            "secscan:extra\n",  # newline (would slip via "starts with" checks)
        ],
    )
    def test_case_and_whitespace_variants_rejected(
        self, tmp_path: Path, variant: str
    ) -> None:
        """Codex Phase 2-G diff review: the sentinel whitelist must
        be exact-match — case-insensitive comparison or stripping
        could be exploited by a malicious ``.secscan.toml`` to slip
        an arbitrary string past the safety gate."""
        rejected = _reject_unsafe_configs(
            [variant], scan_root=tmp_path, allow_unverified=False
        )
        assert rejected == (variant,), (
            f"variant {variant!r} should be rejected by the gate"
        )

    def test_url_still_rejected_with_sentinel_present(
        self, tmp_path: Path
    ) -> None:
        """The sentinel whitelist must not weaken the URL guard."""
        rejected = _reject_unsafe_configs(
            [BUNDLED_RULES_SENTINEL, "https://evil/rules.yml"],
            scan_root=tmp_path,
            allow_unverified=False,
        )
        assert rejected == ("https://evil/rules.yml",)


class TestBundledRulesEndToEnd:
    """Direct semgrep invocations against the bench fixtures.

    These tests are skipped when ``semgrep`` is not installed; on
    CI / dev machines that have semgrep, they prove the bundled
    rules still detect what we ship them to detect.
    """

    @pytest.fixture(autouse=True)
    def skip_without_semgrep(self) -> None:
        if shutil.which("semgrep") is None:
            pytest.skip("semgrep not on PATH")

    def _run(self, *paths: Path) -> list[dict[str, object]]:
        argv = [
            "semgrep",
            "--config",
            str(_bundled_rules_dir()),
            "--json",
            "--quiet",
            "--metrics=off",
            *[str(p) for p in paths],
        ]
        proc = subprocess.run(
            argv, capture_output=True, check=False, timeout=120
        )
        assert proc.returncode in (
            0,
            1,
            2,
        ), proc.stderr.decode("utf-8", errors="replace")
        return list(json.loads(proc.stdout).get("results", []))

    def test_yaml_load_fixture_detected(self) -> None:
        fixture = PY_FIXTURES / "cwe502_yaml_load.py"
        results = self._run(fixture)
        rule_ids = {r["check_id"].split(".")[-1] for r in results}
        assert "secscan-python-dangerous-yaml-load" in rule_ids

    def test_safe_yaml_load_not_flagged(self) -> None:
        """``yaml.safe_load`` and ``yaml.load(..., Loader=SafeLoader)``
        must not fire the rule. Codex pinned the safe-loader exemption."""
        fixture = PY_FIXTURES / "safe_yaml.py"
        results = self._run(fixture)
        assert results == [], results

    def test_hardcoded_credential_fixture_detected(self) -> None:
        fixture = PY_FIXTURES / "cwe798_hardcoded.py"
        results = self._run(fixture)
        rule_ids = {r["check_id"].split(".")[-1] for r in results}
        assert "secscan-python-hardcoded-credential" in rule_ids

    def test_safe_subprocess_not_flagged(self) -> None:
        """A safely-built subprocess argv must not trip ANY bundled
        rule. Acts as a sanity FP check."""
        fixture = PY_FIXTURES / "safe_subprocess.py"
        results = self._run(fixture)
        assert results == [], results

    def test_no_findings_on_borderline_aws_lookalike(
        self, tmp_path: Path
    ) -> None:
        """A Python file with a credential-named variable assigned to
        an OBVIOUS placeholder string (``"changeme"`` etc.) must NOT
        trigger the hardcoded-credential rule. False positives there
        are the most user-visible failure mode."""
        sample = tmp_path / "placeholder.py"
        sample.write_text(
            "PASSWORD = \"changeme\"\n"
            "SECRET = \"\"\n"
            "API_KEY = \"todo\"\n"
            "EXAMPLE_PASSWORD = \"abcd1234efgh5678\"\n"
        )
        results = self._run(sample)
        assert results == [], results

    def test_no_findings_on_word_boundary_lookalikes(
        self, tmp_path: Path
    ) -> None:
        """Codex Phase 2-G diff review: a variable whose name
        *contains* ``password`` / ``secret`` as a substring but where
        the keyword is NOT on a Python identifier word boundary must
        NOT trigger the rule. Plural / hash / list / column-name
        variants are the most common FP source."""
        sample = tmp_path / "boundaries.py"
        sample.write_text(
            # plural: this is a list / set of label strings, not "the password"
            "PASSWORDS_LIST = \"abcd1234efgh5678\"\n"
            # hash of a password — not the password itself
            "KEY_PASSWORD_HASH = \"abcd1234efgh5678\"\n"
            # column name in a SQL schema, not a credential
            "PASSWORDED_USERS_TABLE = \"abcd1234efgh5678\"\n"
            # a secret-prefixed non-credential identifier
            "SECRETLY_FUNNY = \"abcd1234efgh5678\"\n"
            # boundary on the right but not the left
            "ANTI_PASSWORDS = \"abcd1234efgh5678\"\n"
        )
        results = self._run(sample)
        assert results == [], results

    def test_real_credential_variants_still_caught(
        self, tmp_path: Path
    ) -> None:
        """The word-boundary tightening must not weaken detection of
        the common credential-variable shapes operators actually
        write."""
        sample = tmp_path / "creds.py"
        sample.write_text(
            "DB_PASSWORD = \"ZqL9bN3kR7mV2pX1\"\n"
            "password = \"ZqL9bN3kR7mV2pX1\"\n"
            "API_KEY = \"ZqL9bN3kR7mV2pX1\"\n"
            "apikey = \"ZqL9bN3kR7mV2pX1\"\n"
            "auth_token = \"ZqL9bN3kR7mV2pX1\"\n"
            "ACCESS_TOKEN = \"ZqL9bN3kR7mV2pX1\"\n"
        )
        results = self._run(sample)
        assert len(results) == 6, [r["check_id"] for r in results]
