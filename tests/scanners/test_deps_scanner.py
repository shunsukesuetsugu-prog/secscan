"""Tests for DepsScanner — the dispatch layer over npm/pnpm/pip-audit.

The adapter functions have their own dedicated tests; here we focus on
dispatch behavior:
- is_applicable filters by ecosystem.
- scan() picks the right tool based on package_manager.
- Lockfile policy (allow_missing_lockfile) is enforced.
- Missing tool raises ToolNotFoundError.
- Tool failure produces a redacted ScannerError, not a crash.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

from secscan.models import ScanConfig, Severity, WorkUnit
from secscan.runner import CommandResult
from secscan.scanners import ToolNotFoundError
from secscan.scanners.deps_scanner import DepsScanner

# --- Fake runner -----------------------------------------------------------


@dataclass
class FakeRunner:
    responses: list[CommandResult] = field(default_factory=list)
    calls: list[tuple[tuple[str, ...], Path, int]] = field(default_factory=list)

    def push(
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
        self.calls.append((tuple(argv), cwd, timeout_seconds))
        if not self.responses:
            raise AssertionError(f"FakeRunner exhausted: argv={list(argv)}")
        canned = self.responses.pop(0)
        return CommandResult(
            argv=tuple(argv),
            returncode=canned.returncode,
            stdout=canned.stdout,
            stderr=canned.stderr,
            duration_seconds=canned.duration_seconds,
            timed_out=canned.timed_out,
        )


@pytest.fixture()
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture()
def scanner() -> DepsScanner:
    return DepsScanner()


@pytest.fixture()
def stub_npm() -> object:
    with patch.object(shutil, "which", side_effect=lambda name: f"/usr/local/bin/{name}"):
        yield


# --- is_applicable --------------------------------------------------------


def test_is_applicable_for_npm_ecosystem(scanner: DepsScanner) -> None:
    assert scanner.is_applicable(
        WorkUnit(root=Path("/x"), ecosystem="npm", package_manager="npm")
    )


def test_is_applicable_for_pypi_ecosystem(scanner: DepsScanner) -> None:
    assert scanner.is_applicable(
        WorkUnit(root=Path("/x"), ecosystem="pypi", package_manager="pip")
    )


def test_is_not_applicable_for_unknown_ecosystem(scanner: DepsScanner) -> None:
    assert not scanner.is_applicable(WorkUnit(root=Path("/x")))
    assert not scanner.is_applicable(
        WorkUnit(root=Path("/x"), ecosystem="ruby", package_manager="bundler")
    )


# --- dispatch by package_manager ------------------------------------------


@pytest.mark.usefixtures("stub_npm")
def test_npm_workunit_invokes_npm_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig(timeout_seconds=60))
    assert outcome.succeeded
    call_argv, _cwd, call_timeout = runner.calls[0]
    assert call_argv[0] == "npm"
    assert "audit" in call_argv
    assert "--audit-level=none" in call_argv
    assert call_timeout == 60


@pytest.mark.usefixtures("stub_npm")
def test_pnpm_workunit_invokes_pnpm_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"advisories": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="pnpm",
        lockfile=tmp_path / "pnpm-lock.yaml",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    argv = runner.calls[0][0]
    assert argv[0] == "pnpm"
    assert "--audit-level=low" in argv


@pytest.mark.usefixtures("stub_npm")
def test_pypi_workunit_invokes_pip_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==1.0")
    payload = json.dumps({"dependencies": []}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip-requirements",
        manifest=req,
        lockfile=req,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    argv = runner.calls[0][0]
    assert argv[0] == "pip-audit"
    assert "--requirement" in argv
    assert str(req) in argv


# --- lockfile policy ------------------------------------------------------


@pytest.mark.usefixtures("stub_npm")
def test_npm_without_lockfile_requires_allow_flag(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=None,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "lockfile" in outcome.error.reason
    # Must never have executed the underlying tool.
    assert runner.calls == []


@pytest.mark.usefixtures("stub_npm")
def test_npm_without_lockfile_runs_when_allowed(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=None,
    )
    cfg = ScanConfig(extra=MappingProxyType({"allow_missing_lockfile": True}))
    outcome = scanner.scan(unit, runner, cfg)
    assert outcome.succeeded
    assert runner.calls != []


@pytest.mark.usefixtures("stub_npm")
def test_pip_audit_can_run_without_lockfile(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """pip-audit has a sensible no-lockfile path via the active env; the
    Scanner should let it run rather than blocking like npm/pnpm."""
    payload = json.dumps({"dependencies": []}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip",  # pyproject only, no lock
        manifest=tmp_path / "pyproject.toml",
        lockfile=None,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    argv = runner.calls[0][0]
    assert "--requirement" not in argv


# --- tool not found -------------------------------------------------------


def test_missing_npm_raises_tool_not_found(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    with (
        patch.object(shutil, "which", return_value=None),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(unit, runner, ScanConfig())
    assert exc_info.value.tool == "npm"


def test_missing_pip_audit_raises_tool_not_found(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip",
        manifest=tmp_path / "pyproject.toml",
    )
    with (
        patch.object(shutil, "which", return_value=None),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(unit, runner, ScanConfig())
    assert exc_info.value.tool == "pip-audit"


# --- error handling -------------------------------------------------------


@pytest.mark.usefixtures("stub_npm")
def test_tool_failure_becomes_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    runner.push(returncode=2, stdout=b"", stderr=b"network error")
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert outcome.error.stderr_excerpt is not None
    assert "network error" in outcome.error.stderr_excerpt


@pytest.mark.usefixtures("stub_npm")
def test_error_stderr_excerpt_is_redacted(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """Defense in depth: even if a dependency manager leaks a credential
    into its stderr (e.g. authenticated registry URL), the excerpt
    surfaced to the user must be redacted."""
    runner.push(
        returncode=2,
        stdout=b"",
        stderr=b"failed: registry token AKIAIOSFODNN7EXAMPLE invalid",
    )
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.error is not None
    assert outcome.error.stderr_excerpt is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in outcome.error.stderr_excerpt


@pytest.mark.usefixtures("stub_npm")
def test_findings_normalized_through_dispatch(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """Smoke test: dispatch through npm yields a properly-normalized
    Finding with severity, package, fix_version, etc."""
    npm_payload = json.dumps(
        {
            "vulnerabilities": {
                "left-pad": {
                    "name": "left-pad",
                    "severity": "critical",
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-PAD",
                            "title": "left-pad RCE",
                            "severity": "critical",
                            "cve": "CVE-2024-PAD",
                        }
                    ],
                    "fixAvailable": {"name": "left-pad", "version": "9.9.9"},
                }
            }
        }
    ).encode()
    runner.push(returncode=0, stdout=npm_payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.succeeded
    (f,) = outcome.findings
    assert f.severity == Severity.CRITICAL
    assert f.location is not None and f.location.package == "left-pad"
    assert f.fix_version == "9.9.9"
    assert f.cve == "CVE-2024-PAD"


def test_unknown_package_manager_is_a_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="yarn",  # Phase 1B doesn't ship a yarn adapter
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "package_manager" in outcome.error.reason


def test_workunit_without_package_manager_is_a_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    unit = WorkUnit(root=tmp_path, ecosystem="npm")  # package_manager omitted
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None


# --- Codex 8th review: pip-audit input-mode dispatch ----------------------


@pytest.mark.usefixtures("stub_npm")
def test_pyproject_only_uses_project_mode(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """Codex 8th review: a pyproject-only project must be audited via
    ``pip-audit <project>``, NOT the interpreter env."""
    payload = json.dumps({"dependencies": []}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip",
        manifest=tmp_path / "pyproject.toml",
        lockfile=None,
    )
    scanner.scan(unit, runner, ScanConfig())
    argv = runner.calls[0][0]
    assert "--requirement" not in argv
    # Positional path = scan root.
    assert str(tmp_path) in argv


@pytest.mark.usefixtures("stub_npm")
def test_pylock_toml_uses_requirement_flag(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    pylock = tmp_path / "pylock.toml"
    pylock.write_text("# pylock")
    payload = json.dumps({"dependencies": []}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pip",
        manifest=tmp_path / "pyproject.toml",
        lockfile=pylock,
    )
    scanner.scan(unit, runner, ScanConfig())
    argv = runner.calls[0][0]
    assert "--requirement" in argv
    assert str(pylock) in argv


@pytest.mark.usefixtures("stub_npm")
def test_uv_lock_is_explicit_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """Codex 8th review: feeding uv.lock to ``pip-audit --requirement`` is
    a misuse — the file is not a requirements-format text. The dispatcher
    must surface a scanner error guiding the user to export instead."""
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text("# uv lock")
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="uv",
        manifest=tmp_path / "pyproject.toml",
        lockfile=uv_lock,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "uv export" in outcome.error.reason
    # Must NOT have executed pip-audit at all.
    assert runner.calls == []


@pytest.mark.usefixtures("stub_npm")
def test_pdm_lock_is_explicit_scanner_error(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    pdm_lock = tmp_path / "pdm.lock"
    pdm_lock.write_text("# pdm lock")
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="pdm",
        manifest=tmp_path / "pyproject.toml",
        lockfile=pdm_lock,
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "pdm export" in outcome.error.reason


# --- Codex 8th review: ignore_dev_dependencies + allow-missing-lockfile --


@pytest.mark.usefixtures("stub_npm")
def test_npm_allow_missing_lockfile_adds_no_package_lock_flag(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """npm needs ``--no-package-lock`` to audit a package.json without a
    lockfile. The previous Phase 1B passed --allow-missing-lockfile via
    config but never translated it to argv."""
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=None,
    )
    cfg = ScanConfig(extra=MappingProxyType({"allow_missing_lockfile": True}))
    scanner.scan(unit, runner, cfg)
    argv = runner.calls[0][0]
    assert "--no-package-lock" in argv


@pytest.mark.usefixtures("stub_npm")
def test_npm_ignore_dev_dependencies_adds_omit_dev(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"vulnerabilities": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="npm",
        lockfile=tmp_path / "package-lock.json",
    )
    cfg = ScanConfig(extra=MappingProxyType({"ignore_dev_dependencies": True}))
    scanner.scan(unit, runner, cfg)
    argv = runner.calls[0][0]
    assert "--omit=dev" in argv


@pytest.mark.usefixtures("stub_npm")
def test_pnpm_ignore_dev_dependencies_adds_prod_flag(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    payload = json.dumps({"advisories": {}, "metadata": {}}).encode()
    runner.push(returncode=0, stdout=payload)
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="npm",
        package_manager="pnpm",
        lockfile=tmp_path / "pnpm-lock.yaml",
    )
    cfg = ScanConfig(extra=MappingProxyType({"ignore_dev_dependencies": True}))
    scanner.scan(unit, runner, cfg)
    argv = runner.calls[0][0]
    assert "--prod" in argv


# --- Phase 2-C-1: uv workspace export pipeline ---------------------------


@pytest.mark.usefixtures("stub_npm")
def test_uv_workspace_runs_export_then_pip_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """A uv workspace WorkUnit triggers a two-step subprocess: uv export
    to a temp requirements.txt, then pip-audit on that file. The audit
    findings inherit the workspace_id so their fingerprint is scoped."""
    # 1) uv export succeeds.
    runner.push(returncode=0, stdout=b"")
    # 2) pip-audit returns one finding.
    runner.push(
        returncode=1,
        stdout=json.dumps(
            {
                "dependencies": [
                    {
                        "name": "requests",
                        "version": "2.0.0",
                        "vulns": [{"id": "PYSEC-2024-1", "fix_versions": ["2.32.0"]}],
                    }
                ]
            }
        ).encode(),
    )
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="uv",
        manifest=tmp_path / "pyproject.toml",
        lockfile=tmp_path / "uv.lock",
        workspace_id="org-api",
    )
    outcome = scanner.scan(unit, runner, ScanConfig(timeout_seconds=120))
    assert outcome.succeeded
    assert len(runner.calls) == 2
    export_argv, _cwd, _timeout = runner.calls[0]
    assert export_argv[0:2] == ("uv", "export")
    # Critical safety flags pinned by Codex 23rd review.
    assert "--locked" in export_argv
    assert "--no-emit-local" in export_argv
    assert "--no-hashes" in export_argv
    # --package selects the workspace member.
    pkg_idx = export_argv.index("--package")
    assert export_argv[pkg_idx + 1] == "org-api"
    # pip-audit was given a --requirement file (the temp export output).
    audit_argv = runner.calls[1][0]
    assert audit_argv[0] == "pip-audit"
    assert "--requirement" in audit_argv
    # workspace_id is carried into the finding's fingerprint.
    (finding,) = outcome.findings
    # Two distinct workspace_ids must produce different fingerprints; we
    # only check the prefix marker here (full test in test_common.py).
    assert finding.fingerprint != ""


@pytest.mark.usefixtures("stub_npm")
def test_uv_export_failure_does_not_invoke_pip_audit(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """If uv export errors out, pip-audit must not be invoked: there's
    nothing valid to audit and running pip-audit anyway would produce
    a confusing secondary error."""
    runner.push(returncode=1, stderr=b"uv: lock is out of date")
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="uv",
        manifest=tmp_path / "pyproject.toml",
        lockfile=tmp_path / "uv.lock",
        workspace_id="org-api",
    )
    outcome = scanner.scan(unit, runner, ScanConfig(timeout_seconds=60))
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "uv export failed" in outcome.error.reason
    assert len(runner.calls) == 1  # pip-audit never ran


def test_uv_workspace_without_uv_binary_raises_tool_not_found(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """uv must be on PATH before we even try to invoke export."""
    # pip-audit is available but uv is not.
    def which(name: str) -> str | None:
        return "/usr/local/bin/pip-audit" if name == "pip-audit" else None

    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="uv",
        manifest=tmp_path / "pyproject.toml",
        lockfile=tmp_path / "uv.lock",
        workspace_id="org-api",
    )
    with (
        patch.object(shutil, "which", side_effect=which),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(unit, runner, ScanConfig())
    assert exc_info.value.tool == "uv"


@pytest.mark.usefixtures("stub_npm")
def test_uv_workspace_export_stderr_is_redacted(
    scanner: DepsScanner, runner: FakeRunner, tmp_path: Path
) -> None:
    """uv stderr can contain index URLs with credentials. Surface
    them only after passing through redact_text."""
    runner.push(
        returncode=1,
        stderr=b"failed to fetch UV_INDEX_URL=https://user:secret@pypi.example.com/simple/",
    )
    unit = WorkUnit(
        root=tmp_path,
        ecosystem="pypi",
        package_manager="uv",
        manifest=tmp_path / "pyproject.toml",
        lockfile=tmp_path / "uv.lock",
        workspace_id="org-api",
    )
    outcome = scanner.scan(unit, runner, ScanConfig())
    assert outcome.error is not None
    excerpt = outcome.error.stderr_excerpt or ""
    assert "user:secret" not in excerpt
    assert "https://user:secret" not in excerpt
