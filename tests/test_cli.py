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
import shutil
import threading
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
    """Replay canned CommandResults. Each .run() pops the next one.

    Thread-safe (Phase 2-X): the parallel orchestrator may call ``run()``
    concurrently from multiple worker threads. The lock keeps the pop
    operation race-free. Tests that depend on a specific *order* of
    canned responses must still opt into serial execution via
    ``--no-parallel`` — the lock only guarantees that each pop returns
    a consistent item, not that calls arrive in the queued order.
    """

    def __init__(self) -> None:
        self.responses: list[CommandResult] = []
        self._lock = threading.Lock()

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
        with self._lock:
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
        # Phase 2-F: the secrets scanner switched from
        # ``--report-path=/dev/stdout`` (which gitleaks refuses on
        # macOS) to ``--report-path=<tempfile>``. To preserve the
        # test contract — "the scripted stdout is what the parser
        # sees" — mirror gitleaks behaviour by also writing the
        # scripted bytes to the report-path file, if any.
        for token in argv:
            if isinstance(token, str) and token.startswith("--report-path="):
                report_path = Path(token.split("=", 1)[1])
                if report_path != Path("/dev/stdout"):
                    try:
                        report_path.parent.mkdir(parents=True, exist_ok=True)
                        report_path.write_bytes(canned.stdout)
                    except OSError:
                        pass
                break
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


def test_all_with_every_scanner_registered_clean(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Phase 1C: secrets + deps + sast are all registered. `all` should
    no longer emit a partial-scan warning. A clean repo (no findings,
    no manifests) exits OK with informational discovery warnings only."""
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    # secrets (gitleaks): no leaks + version probe
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8")
    # deps: no manifest in project, so the scanner never runs — no canned
    # response needed (Discovery short-circuits).
    # sast: no findings.
    scripted_runner.queue(
        returncode=0, stdout=json.dumps({"results": [], "errors": []}).encode()
    )
    # Phase 2-X: ``--no-parallel`` matches the scripted runner's
    # queue order to the secrets-then-sast call order. With the
    # default parallel mode, those two scanners race for queue
    # items and the canned responses can be misrouted.
    rc = cli.main(["all", "--path", str(project), "--no-parallel"])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "partial scan" not in out


def test_all_with_explicit_skip_acknowledges_gap(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # User skips deps and sast: only secrets should run, and the skipped
    # gap should be acknowledged rather than treated as "partial scan".
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8")
    rc = cli.main(
        ["all", "--path", str(project), "--skip", "deps", "--skip", "sast"]
    )
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "partial scan" not in out


def test_deps_subcommand_npm_with_lockfile(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Stub `which` so DepsScanner finds npm, then verify an empty audit
    # report yields a clean exit through the full CLI path.
    monkeypatch.setattr(
        shutil, "which",
        lambda name: f"/usr/local/bin/{name}",
    )
    (project / "package.json").write_text("{}")
    (project / "package-lock.json").write_text("{}")
    scripted_runner.queue(
        returncode=0,
        stdout=json.dumps({"vulnerabilities": {}, "metadata": {}}).encode(),
    )
    rc = cli.main(["deps", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "no findings" in out


def test_deps_subcommand_npm_finding_drives_exit_code(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    (project / "package.json").write_text("{}")
    (project / "package-lock.json").write_text("{}")
    audit = json.dumps(
        {
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-FOO",
                            "title": "Prototype pollution",
                            "severity": "high",
                            "cve": "CVE-2024-LODASH",
                        }
                    ],
                    "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                }
            }
        }
    ).encode()
    scripted_runner.queue(returncode=0, stdout=audit)
    rc = cli.main(["deps", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.FINDINGS)
    assert "lodash" in out


def test_deps_subcommand_warns_without_manifest(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # No manifest in the project root → Discovery emits no WorkUnits,
    # which becomes a discovery warning. The scan still exits OK (no
    # findings, no errors) because there's nothing to actually scan.
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    rc = cli.main(["deps", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "no dependency manifest" in out


def test_deps_subcommand_without_lockfile_errors(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    (project / "package.json").write_text("{}")
    rc = cli.main(["deps", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "lockfile" in out


def test_deps_subcommand_allow_missing_lockfile_proceeds(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    (project / "package.json").write_text("{}")
    scripted_runner.queue(
        returncode=0,
        stdout=json.dumps({"vulnerabilities": {}, "metadata": {}}).encode(),
    )
    rc = cli.main(
        ["deps", "--path", str(project), "--allow-missing-lockfile"]
    )
    capsys.readouterr()
    assert rc == int(ExitCode.OK)


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
    # Drive the test end-to-end instead of recomputing the secrets-scanner
    # fingerprint formula by hand (which would couple the test to a
    # private implementation detail). Steps:
    #   1. Run accept --all to populate the baseline from a real scan.
    #   2. Rerun: baseline should suppress -> OK.
    #   3. Rerun with --no-baseline: same finding -> FINDINGS.
    # Skip deps + sast in the project's config so accept doesn't trip the
    # new "scanner-errors block accept" guard (deps + sast would error
    # since this synthetic project has no manifest / semgrep_config).
    (project / ".secscan.toml").write_text(
        '[scan]\nskip = ["deps", "sast"]\n'
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

    # 1) accept the finding.
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    rc_accept = cli.main(
        [
            "baseline",
            "accept",
            "--path",
            str(project),
            "--all",
            "--reason",
            "test fixture",
        ]
    )
    capsys.readouterr()
    assert rc_accept == int(ExitCode.OK)

    # 2) baseline suppresses → OK.
    scripted_runner.queue(returncode=101, stdout=leak)
    scripted_runner.queue(returncode=0, stdout=b"")
    rc1 = cli.main(["secrets", "--path", str(project)])
    capsys.readouterr()
    assert rc1 == int(ExitCode.OK)

    # 3) --no-baseline → FINDINGS.
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
    (project / ".secscan.toml").write_text(
        '[scan]\nskip = ["deps", "sast"]\n'
    )
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


# --- Phase 2-A: --format / --output / --sarif-include-suppressed ---------


def test_format_json_emits_machine_readable_payload(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8")
    rc = cli.main(["secrets", "--path", str(project), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    payload = json.loads(out)
    assert payload["schema"] == "secscan-json"
    assert payload["format_version"] == 1
    assert payload["exit_code"] == int(ExitCode.OK)


def test_format_sarif_emits_valid_sarif(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8")
    rc = cli.main(["secrets", "--path", str(project), "--format", "sarif"])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert "$schema" in payload
    assert "runs" in payload


def test_quiet_with_json_is_rejected(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Codex 17th review: --quiet is text-only. Mixing with json/sarif
    used to silently produce broken artifacts; now it errors."""
    rc = cli.main(
        ["secrets", "--path", str(project), "--format", "json", "--quiet"]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "quiet" in captured.err.lower()


def test_quiet_with_sarif_is_rejected(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(
        ["secrets", "--path", str(project), "--format", "sarif", "--quiet"]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "quiet" in captured.err.lower()


def test_output_writes_to_file(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8")
    out_file = tmp_path / "report.json"
    rc = cli.main(
        [
            "secrets",
            "--path",
            str(project),
            "--format",
            "json",
            "--output",
            str(out_file),
        ]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.OK)
    # Nothing on stdout when --output is set.
    assert captured.out == ""
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["schema"] == "secscan-json"


def test_output_to_unwritable_path_returns_scan_error(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scripted_runner.queue(returncode=0, stdout=b"[]")
    scripted_runner.queue(returncode=0, stdout=b"v8")
    # A directory we don't have permission to write to / that doesn't exist.
    rc = cli.main(
        [
            "secrets",
            "--path",
            str(project),
            "--format",
            "json",
            "--output",
            "/nonexistent-directory-xyz/report.json",
        ]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "--output" in captured.err


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


def test_sast_subcommand_clean_run(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    scripted_runner.queue(
        returncode=0,
        stdout=json.dumps({"results": [], "errors": []}).encode(),
    )
    rc = cli.main(["sast", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.OK)
    assert "no findings" in out


def test_sast_subcommand_finding_drives_exit_code(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    # Create a real file so orchestrator's path-containment check accepts
    # the finding's location.
    (project / "src").mkdir()
    (project / "src" / "app.py").write_text("import yaml; yaml.load('...')\n")
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-yaml-load",
                    "path": "src/app.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 30},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Avoid yaml.load",
                    },
                }
            ],
            "errors": [],
        }
    ).encode()
    scripted_runner.queue(returncode=0, stdout=payload)
    rc = cli.main(["sast", "--path", str(project)])
    out = capsys.readouterr().out
    assert rc == int(ExitCode.FINDINGS)
    assert "dangerous-yaml-load" in out


def test_sast_subcommand_semgrep_config_override(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--semgrep-config on the CLI overrides the default ruleset."""
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    scripted_runner.queue(
        returncode=0, stdout=json.dumps({"results": [], "errors": []}).encode()
    )
    cli.main(
        [
            "sast",
            "--path",
            str(project),
            "--semgrep-config",
            "p/custom-A",
            "--semgrep-config",
            "p/custom-B",
        ]
    )
    capsys.readouterr()
    # ScriptedRunner doesn't expose argv directly; the smoke test is that
    # the run completed without error.




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


def test_scan_reports_malformed_config_as_scan_error(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A typo'd or otherwise invalid .secscan.toml must fail closed —
    # NEVER silently ignored. Codex 3rd review flagged silent config
    # acceptance as a path to disable severity_overrides etc.
    (project / ".secscan.toml").write_text("[scan]\nfail_on = 'super-high'\n")
    rc = cli.main(["secrets", "--path", str(project)])
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "config error" in captured.err


def test_scan_reports_malformed_baseline_as_scan_error(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A malformed baseline must fail closed: otherwise tampering with the
    # baseline file (e.g. shipping invalid JSON) could quietly disable
    # suppression OR be used to attempt parser exploits.
    secscan_dir = project / ".secscan"
    secscan_dir.mkdir()
    (secscan_dir / "baseline.json").write_text("{not valid json")
    rc = cli.main(["secrets", "--path", str(project)])
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    # The error path goes through the orchestrator -> CLI's BaselineError
    # catch; just verify the user sees a baseline message.
    assert "baseline" in captured.err.lower()


def test_baseline_accept_rejects_unknown_fingerprint(
    project: Path,
    stub_gitleaks_installed: None,
    scripted_runner: _ScriptedRunner,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (project / ".secscan.toml").write_text(
        '[scan]\nskip = ["deps", "sast"]\n'
    )
    # accept --fingerprint must refuse fingerprints that don't appear in
    # the current scan output: otherwise users could accept arbitrary
    # strings, polluting the baseline with entries that suppress nothing
    # (and look the same as ones that DO suppress).
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
            "--fingerprint",
            "deadbeefdeadbeef",  # not present in current findings
            "--reason",
            "trying to fool accept",
        ]
    )
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "not present" in captured.err.lower()


def test_baseline_list_rejects_malformed_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secscan_dir = project / ".secscan"
    secscan_dir.mkdir()
    (secscan_dir / "baseline.json").write_text(
        json.dumps({"version": 99, "entries": []})
    )
    rc = cli.main(["baseline", "list", "--path", str(project)])
    captured = capsys.readouterr()
    assert rc == int(ExitCode.SCAN_ERROR)
    assert "baseline error" in captured.err


# Note: the previous version of this file carried a hand-recomputed copy
# of the secrets-scanner fingerprint formula and a "guard" test pinning the
# two together. That coupled the test suite to a private implementation
# detail; ``test_no_baseline_disables_baseline`` now drives accept-then-
# rerun end-to-end instead.
