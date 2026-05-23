"""CLI integration tests.

We invoke ``main([...])`` directly (no subprocess) and stub the network of
collaborators (gitleaks via shutil.which + monkeypatched SubprocessCommandRunner)
where needed. Goals:

- Each subcommand parses, runs, and returns the right exit code.
- ``--no-baseline`` disables baseline application.
- ``--fail-on`` overrides config-level threshold.
- ``baseline accept`` requires --fingerprint or --all, refuses in CI, writes
  the file with audit metadata.
- ``baseline list`` and ``prune`` work on absent and present baselines.
- Argparse handles invalid input by exiting; we don't need to test argparse
  itself, but we verify our subcommand structure.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secscan import __version__ as SECSCAN_VERSION
from secscan import cli
from secscan.baseline import (
    Baseline,
    BaselineEntry,
    save_baseline,
)
from secscan.exit_codes import ExitCode
from secscan.runner import CommandResult

UTC = UTC


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    """A bare project root."""
    return tmp_path


@pytest.fixture()
def stub_gitleaks_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend gitleaks is on PATH."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: "/usr/local/bin/gitleaks")


class _ScriptedRunner:
    """Replay canned CommandResults. Each .run() pops the next one."""

    def __init__(self) -> None:
        self.responses: list[CommandResult] = []

    def queue(
        self,
        *,
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        timed_out: bool = False,
    ) -> None:
        self.responses.append(
            CommandResult(
                argv=(),
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=0.01,
                timed_out=timed_out,
            )
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        if not self.responses:
            return CommandResult(
                argv=tuple(argv),
                returncode=0,
                stdout=b"",
                stderr=b"",
                duration_seconds=0.0,
                timed_out=False,
            )
        canned = self.responses.pop(0)
        return replace(canned, argv=tuple(argv))


@pytest.fixture()
def scripted_runner(monkeypatch: pytest.MonkeyPatch) -> _ScriptedRunner:
    runner = _ScriptedRunner()
    monkeypatch.setattr(
        cli, "SubprocessCommandRunner", lambda: runner
    )
    return runner


# --- Basic subcommand smoke -------------------------------------------------


def test_secrets_clean_run_exits_zero(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # gitleaks invocation: returncode 0 (no leaks). Plus a version check.
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8.18.0")
    rc = cli.main(["secrets", "--path", str(project)])
    captured = capsys.readouterr()
    assert rc == int(ExitCode.OK)
    assert "no findings" in captured.out


def test_secrets_with_findings_exits_one(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    leak = json.dumps(
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS",
                "StartLine": 10,
                "EndLine": 10,
                "StartColumn": 1,
                "EndColumn": 20,
                "File": "src/cfg.py",
                "Secret": "REDACTED",
                "Match": "REDACTED",
                "Fingerprint": "src/cfg.py:aws:10",
            }
        ]
    ).encode()
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"v8.18.0")
    rc = cli.main(["secrets", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.FINDINGS)
    assert "aws-access-token" in out
    assert "src/cfg.py:10" in out


def test_tool_not_installed_exits_with_scan_error(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)
    rc = cli.main(["secrets", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "scanner errors" in out


def test_all_warns_and_fails_when_deps_or_sast_missing(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # In Phase 1A, secrets is registered but deps/sast are not. The user
    # asked for "all"; getting a quiet exit 0 would be a false green. The
    # CLI must surface the gap and refuse to claim success.
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"")
    rc = cli.main(["all", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "partial scan" in out
    # Both missing scanners listed in the warning, deps + sast.
    assert "deps" in out
    assert "sast" in out


def test_quiet_emits_single_line(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"")
    rc = cli.main(["secrets", "--path", str(project), "--quiet"])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    # Quiet output is one machine-readable line followed by a newline.
    assert len(out.strip().splitlines()) == 1
    assert "findings=0" in out
    assert "exit=0" in out


def test_fail_on_critical_does_not_flag_high(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # gitleaks returns HIGH; --fail-on=critical → still OK.
    leak = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "x",
                "StartLine": 1,
                "File": "a.py",
                "Secret": "REDACTED",
                "Match": "REDACTED",
            }
        ]
    ).encode()
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    rc = cli.main(["secrets", "--path", str(project), "--fail-on", "critical"])
    assert rc == int(ExitCode.OK)


def test_no_baseline_disables_baseline(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Write a baseline that would suppress everything by fingerprint…
    secscan_dir = project / ".secscan"
    secscan_dir.mkdir()
    leak_fp = _expected_secrets_fingerprint("x", "a.py", 1, 1)
    save_baseline(
        Baseline(
            entries=(
                BaselineEntry(
                    fingerprint=leak_fp,
                    scanner="secrets",
                    rule_id="x",
                    reason="REQUIRED",
                    accepted_by="alice",
                    added_at=datetime(2026, 1, 1, tzinfo=UTC),
                    expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                    secscan_version=SECSCAN_VERSION,
                ),
            )
        ),
        secscan_dir / "baseline.json",
    )

    leak = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "x",
                "StartLine": 1,
                "StartColumn": 1,
                "File": "a.py",
                "Secret": "REDACTED",
                "Match": "REDACTED",
            }
        ]
    ).encode()
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")

    # WITHOUT --no-baseline: baseline suppresses; exit OK.
    rc1 = cli.main(["secrets", "--path", str(project)])
    capsys.readouterr()
    assert rc1 == int(ExitCode.OK)

    # Reset and rerun WITH --no-baseline: suppression skipped; exit FINDINGS.
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    rc2 = cli.main(["secrets", "--path", str(project), "--no-baseline"])
    assert rc2 == int(ExitCode.FINDINGS)


# --- baseline subcommands --------------------------------------------------


def test_baseline_list_empty(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(["baseline", "list", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "no baseline" in out


def test_baseline_list_shows_entries(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secscan_dir = project / ".secscan"
    secscan_dir.mkdir()
    save_baseline(
        Baseline(
            entries=(
                BaselineEntry(
                    fingerprint="ffffffffffffabc",
                    scanner="secrets",
                    rule_id="aws-key",
                    reason="legacy",
                    accepted_by="alice",
                    added_at=datetime(2026, 1, 1, tzinfo=UTC),
                    expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                    secscan_version=SECSCAN_VERSION,
                    source_location="src/x.py:10",
                ),
            )
        ),
        secscan_dir / "baseline.json",
    )
    rc = cli.main(["baseline", "list", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "secrets:aws-key" in out
    assert "ffffffffffff" in out
    assert "legacy" in out


def test_baseline_prune_removes_expired(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secscan_dir = project / ".secscan"
    secscan_dir.mkdir()
    expired = BaselineEntry(
        fingerprint="exp",
        scanner="secrets",
        rule_id="r",
        reason="r",
        accepted_by="a",
        added_at=datetime(2025, 1, 1, tzinfo=UTC),
        expires_at=datetime(2025, 6, 1, tzinfo=UTC),
        secscan_version=SECSCAN_VERSION,
    )
    fresh = BaselineEntry(
        fingerprint="fresh",
        scanner="secrets",
        rule_id="r",
        reason="r",
        accepted_by="a",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        secscan_version=SECSCAN_VERSION,
    )
    save_baseline(
        Baseline(entries=(expired, fresh)), secscan_dir / "baseline.json"
    )
    rc = cli.main(["baseline", "prune", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "pruned 1" in out


def test_baseline_accept_refuses_in_ci(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SECSCAN_CI", "1")
    rc = cli.main(
        ["baseline", "accept", "--path", str(project), "--reason", "x", "--all"]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "CI" in captured.err


def test_baseline_accept_requires_fingerprint_or_all(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SECSCAN_CI", raising=False)
    rc = cli.main(
        ["baseline", "accept", "--path", str(project), "--reason", "x"]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "--fingerprint" in captured.err


def test_baseline_accept_all_writes_entries(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SECSCAN_CI", raising=False)
    leak = json.dumps(
        [
            {
                "RuleID": "leaking-rule",
                "Description": "leak",
                "StartLine": 5,
                "StartColumn": 1,
                "File": "src/x.py",
                "Secret": "REDACTED",
                "Match": "REDACTED",
            }
        ]
    ).encode()
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    rc = cli.main(
        [
            "baseline",
            "accept",
            "--path",
            str(project),
            "--all",
            "--reason",
            "intentional test fixture",
        ]
    )
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "accepted 1" in out
    # File created.
    baseline_path = project / ".secscan" / "baseline.json"
    assert baseline_path.exists()
    data = json.loads(baseline_path.read_text())
    assert len(data["entries"]) == 1
    entry = data["entries"][0]
    assert entry["reason"] == "intentional test fixture"
    assert entry["scanner"] == "secrets"
    assert entry["rule_id"] == "leaking-rule"
    assert entry["secscan_version"] == SECSCAN_VERSION


# --- Argparse error paths --------------------------------------------------


def test_unknown_command_exits_via_argparse() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["bogus"])
    # argparse exit code 2 for usage errors.
    assert exc_info.value.code == 2


def test_help_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0


# --- Codex 3rd review regressions -----------------------------------------


def test_deps_subcommand_rejected_when_scanner_not_registered(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Phase 1A registers only the secrets scanner. The deps subcommand must
    # NOT silently exit 0 — that would be a false green in CI.
    rc = cli.main(["deps", "--path", str(project)])
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "not yet implemented" in captured.err


def test_sast_subcommand_rejected_when_scanner_not_registered(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(["sast", "--path", str(project)])
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "not yet implemented" in captured.err


def test_fail_on_none_never_fails(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # --fail-on none used to crash with ValueError. It must accept and mean
    # "never cross threshold", regardless of findings.
    leak = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "x",
                "StartLine": 1,
                "File": "a.py",
                "Secret": "REDACTED",
                "Match": "REDACTED",
            }
        ]
    ).encode()
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    rc = cli.main(["secrets", "--path", str(project), "--fail-on", "none"])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    # The threshold label should reflect the "never" sentinel.
    assert "never" in out


def test_finding_title_is_redacted_not_raw_description(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Even though gitleaks --redact=100 normally redacts the Secret field,
    # the Description field is not guaranteed to be clean. The title shown
    # to the user must be redacted, not pass through unchanged.
    leak = json.dumps(
        [
            {
                "RuleID": "aws-key",
                "Description": "key AKIAIOSFODNN7EXAMPLE found in src",
                "StartLine": 1,
                "File": "a.py",
                "Secret": "REDACTED",
                "Match": "REDACTED",
            }
        ]
    ).encode()
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    cli.main(["secrets", "--path", str(project)])
    out = capsys.readouterr().out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED]" in out


# --- Helpers ---------------------------------------------------------------


def _expected_secrets_fingerprint(rule_id: str, rel_file: str, line: int, col: int) -> str:
    """Recompute the secrets-scanner composite fingerprint for assertions."""
    import hashlib

    return hashlib.sha256(
        "\x00".join((rule_id, rel_file, str(line), str(col))).encode("utf-8")
    ).hexdigest()


def test_helper_matches_scanner_fingerprint() -> None:
    """Guard: if the secrets fingerprint formula changes, this fails too."""
    from secscan.scanners.secrets import _composite_fingerprint  # type: ignore[attr-defined]

    assert _expected_secrets_fingerprint("x", "a.py", 1, 2) == _composite_fingerprint(
        "x", "a.py", 1, 2
    )
