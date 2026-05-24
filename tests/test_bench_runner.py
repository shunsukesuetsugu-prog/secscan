"""Regression tests for ``bench/run.py``.

The bench is a measurement tool, not production code, but its
security-relevant pieces (path containment, secret-manifest
verification, subprocess argv shape) should still be unit-tested.
We import the module directly so the path-safety helpers are
exercised without spawning subprocesses.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_RUN = REPO_ROOT / "bench" / "run.py"


@pytest.fixture(scope="module")
def bench_module():
    """Load bench/run.py as a module (it lives outside the package)."""
    spec = importlib.util.spec_from_file_location("bench_run", BENCH_RUN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_run"] = module
    spec.loader.exec_module(module)
    return module


class TestPathSafety:
    def test_accepts_fixture_under_root(self, bench_module) -> None:
        p = bench_module.SAFE_FIXTURE_ROOT / "deps" / "npm-vulnerable"
        out = bench_module._assert_under_fixture_root(p)
        assert out.is_relative_to(bench_module.SAFE_FIXTURE_ROOT)

    def test_rejects_outside_root(self, bench_module, tmp_path: Path) -> None:
        with pytest.raises(bench_module.BenchError, match="outside"):
            bench_module._assert_under_fixture_root(tmp_path)

    def test_rejects_parent_traversal(self, bench_module) -> None:
        outside = bench_module.SAFE_FIXTURE_ROOT / ".." / "src"
        with pytest.raises(bench_module.BenchError, match="outside"):
            bench_module._assert_under_fixture_root(outside)

    def test_rejects_dash_prefixed_path(
        self, bench_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fixture whose resolved posix path starts with ``-`` (or
        contains ``/-`` as a component prefix) is rejected so it
        cannot be flag-interpreted downstream."""
        dash_dir = bench_module.SAFE_FIXTURE_ROOT / "-suspicious"
        dash_dir.mkdir(exist_ok=True)
        try:
            with pytest.raises(bench_module.BenchError, match="leading '-'"):
                bench_module._assert_under_fixture_root(dash_dir)
        finally:
            dash_dir.rmdir()


class TestSecretManifest:
    def test_manifest_verification_passes_on_committed_fixtures(
        self, bench_module
    ) -> None:
        # The committed manifest must match the committed file hashes
        # — this is the first line of defence against accidental edits.
        bench_module._verify_secret_manifest()

    def test_manifest_verification_fails_on_hash_mismatch(
        self, bench_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Build a tiny fake secrets/synthetic directory with a known
        # mismatching hash and re-point SAFE_FIXTURE_ROOT at it.
        synthetic = tmp_path / "secrets" / "synthetic"
        synthetic.mkdir(parents=True)
        secret_file = synthetic / "fake.txt"
        secret_file.write_text("hello world\n")
        manifest = {
            "fixtures": [
                {
                    "file": "fake.txt",
                    "sha256": "0" * 64,  # deliberately wrong
                    "source": "test",
                    "invalidity_reason": "test",
                    "added_at": "2026-05-24",
                }
            ]
        }
        (synthetic / "_manifest.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(bench_module, "SAFE_FIXTURE_ROOT", tmp_path)
        with pytest.raises(bench_module.BenchError, match="DO NOT TRUST"):
            bench_module._verify_secret_manifest()

    def test_manifest_verification_succeeds_on_correct_hash(
        self, bench_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        synthetic = tmp_path / "secrets" / "synthetic"
        synthetic.mkdir(parents=True)
        secret_file = synthetic / "fake.txt"
        secret_file.write_text("hello world\n")
        actual_hash = hashlib.sha256(secret_file.read_bytes()).hexdigest()
        manifest = {
            "fixtures": [
                {
                    "file": "fake.txt",
                    "sha256": actual_hash,
                    "source": "test",
                    "invalidity_reason": "test",
                    "added_at": "2026-05-24",
                }
            ]
        }
        (synthetic / "_manifest.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(bench_module, "SAFE_FIXTURE_ROOT", tmp_path)
        # Should not raise.
        bench_module._verify_secret_manifest()

    def test_manifest_catches_unmanifest_fixture(
        self, bench_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex diff review: a new secret-shaped file added to
        secrets/synthetic/ without a manifest entry must NOT slip
        past hash verification — the bidirectional check should
        detect it."""
        synthetic = tmp_path / "secrets" / "synthetic"
        synthetic.mkdir(parents=True)
        listed = synthetic / "listed.txt"
        listed.write_text("hello world\n")
        unmanifest = synthetic / "rogue.txt"
        unmanifest.write_text("secret-shaped-but-undeclared\n")
        manifest = {
            "fixtures": [
                {
                    "file": "listed.txt",
                    "sha256": hashlib.sha256(listed.read_bytes()).hexdigest(),
                    "source": "test",
                    "invalidity_reason": "test",
                    "added_at": "2026-05-24",
                }
            ]
        }
        (synthetic / "_manifest.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(bench_module, "SAFE_FIXTURE_ROOT", tmp_path)
        with pytest.raises(bench_module.BenchError, match=r"rogue\.txt"):
            bench_module._verify_secret_manifest()

    def test_manifest_catches_missing_listed_file(
        self, bench_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex diff review: a manifest entry whose file was deleted
        should produce an explicit BenchError, not a bare exception."""
        synthetic = tmp_path / "secrets" / "synthetic"
        synthetic.mkdir(parents=True)
        manifest = {
            "fixtures": [
                {
                    "file": "absent.txt",
                    "sha256": "0" * 64,
                    "source": "test",
                    "invalidity_reason": "test",
                    "added_at": "2026-05-24",
                }
            ]
        }
        (synthetic / "_manifest.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(bench_module, "SAFE_FIXTURE_ROOT", tmp_path)
        with pytest.raises(bench_module.BenchError, match=r"absent\.txt"):
            bench_module._verify_secret_manifest()

    def test_manifest_ignores_expected_json(
        self, bench_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``expected.json`` is the matcher driver, not a secret fixture
        — it must be exempt from the "must be in manifest" rule."""
        synthetic = tmp_path / "secrets" / "synthetic"
        synthetic.mkdir(parents=True)
        listed = synthetic / "listed.txt"
        listed.write_text("hello\n")
        (synthetic / "expected.json").write_text("{}")
        manifest = {
            "fixtures": [
                {
                    "file": "listed.txt",
                    "sha256": hashlib.sha256(listed.read_bytes()).hexdigest(),
                    "source": "test",
                    "invalidity_reason": "test",
                    "added_at": "2026-05-24",
                }
            ]
        }
        (synthetic / "_manifest.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(bench_module, "SAFE_FIXTURE_ROOT", tmp_path)
        # Should not raise — expected.json is exempt.
        bench_module._verify_secret_manifest()


class TestFixtureResult:
    def test_recall_handles_zero_expected(self, bench_module) -> None:
        r = bench_module.FixtureResult(
            scanner="x",
            fixture_name="empty",
            expected_count=0,
            detected_count=0,
        )
        assert r.recall == 1.0

    def test_ge_best_uses_raw_count_not_detected(self, bench_module) -> None:
        """The ≥ Best column compares RAW finding count to the
        comparison tool's count — never detected-against-expected."""
        r = bench_module.FixtureResult(
            scanner="deps",
            fixture_name="x",
            expected_count=2,
            detected_count=2,  # matched 2 expected
            raw_finding_count=8,  # but actually saw 8 findings
            comparison_count=6,
            comparison_tool="npm audit",
        )
        # raw=8 >= compare=6 → parity OK.
        assert r.ge_best_single_tool is True

    def test_ge_best_none_when_comparison_absent(self, bench_module) -> None:
        r = bench_module.FixtureResult(
            scanner="x",
            fixture_name="y",
            expected_count=1,
            detected_count=0,
        )
        assert r.ge_best_single_tool is None


class TestRenderMarkdown:
    def test_skipped_fixture_renders_with_reason(self, bench_module) -> None:
        r = bench_module.FixtureResult(
            scanner="secrets",
            fixture_name="synthetic",
            expected_count=0,
            detected_count=0,
            skipped_reason="gitleaks not installed",
        )
        out = bench_module.render_markdown([r])
        assert "SKIPPED" in out
        assert "gitleaks not installed" in out

    def test_run_fixture_renders_recall_pct(self, bench_module) -> None:
        r = bench_module.FixtureResult(
            scanner="deps",
            fixture_name="npm",
            expected_count=4,
            detected_count=3,
            raw_finding_count=5,
            comparison_count=5,
            comparison_tool="npm audit",
        )
        out = bench_module.render_markdown([r])
        assert "75.0%" in out
        assert "✅" in out

    def test_methodology_section_present(self, bench_module) -> None:
        out = bench_module.render_markdown([])
        assert "Methodology" in out
