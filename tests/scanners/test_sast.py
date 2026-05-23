"""Tests for SastScanner (semgrep adapter).

Same FakeRunner approach as the deps adapters: drive the scanner with
canned subprocess output and pin both happy and error branches without
spawning semgrep.
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
from secscan.scanners.sast import (
    SastScanner,
    build_findings_from_semgrep,
    classify_semgrep_exit,
    semgrep_argv,
)

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
def fake_runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture()
def scanner() -> SastScanner:
    return SastScanner()


@pytest.fixture()
def stub_semgrep() -> object:
    with patch.object(shutil, "which", return_value="/usr/local/bin/semgrep"):
        yield


@pytest.fixture()
def default_config() -> ScanConfig:
    return ScanConfig(
        timeout_seconds=300,
        extra=MappingProxyType({"semgrep_config": ("p/python", "p/owasp-top-ten")}),
    )


def _result(
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        argv=("semgrep",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.0,
        timed_out=timed_out,
    )


# --- argv -----------------------------------------------------------------


def test_argv_passes_multiple_configs_each_with_its_own_flag(tmp_path: Path) -> None:
    argv = semgrep_argv(unit_root=tmp_path, configs=("p/python", "p/owasp"))
    assert argv[0] == "semgrep"
    assert "scan" in argv
    assert "--json" in argv
    # Each config gets a separate --config flag. Codex 2nd review pinned
    # this: a single space-joined "--config p/a p/b" string would fail.
    cfg_idx = [i for i, x in enumerate(argv) if x == "--config"]
    assert len(cfg_idx) == 2
    assert argv[cfg_idx[0] + 1] == "p/python"
    assert argv[cfg_idx[1] + 1] == "p/owasp"


def test_argv_does_not_pass_error_flag(tmp_path: Path) -> None:
    """--error would make semgrep exit non-zero on findings. secscan's
    policy layer makes the threshold call, so we must NOT add --error."""
    argv = semgrep_argv(unit_root=tmp_path, configs=("p/python",))
    assert "--error" not in argv


def test_argv_includes_scan_path_explicitly(tmp_path: Path) -> None:
    argv = semgrep_argv(unit_root=tmp_path, configs=("p/python",))
    assert str(tmp_path) in argv


# --- classify_semgrep_exit ------------------------------------------------


def test_classify_accepts_well_formed_report() -> None:
    payload = json.dumps({"results": [], "errors": []}).encode()
    ok, err = classify_semgrep_exit(_result(returncode=0, stdout=payload))
    assert ok
    assert err is None


def test_classify_accepts_results_with_findings() -> None:
    payload = json.dumps(
        {"results": [{"check_id": "x", "path": "a.py", "extra": {}}], "errors": []}
    ).encode()
    ok, _err = classify_semgrep_exit(_result(returncode=0, stdout=payload))
    assert ok


def test_classify_rejects_empty_stdout() -> None:
    ok, err = classify_semgrep_exit(_result(returncode=0, stdout=b""))
    assert not ok
    assert err is not None
    assert "no JSON" in err


def test_classify_rejects_malformed_json() -> None:
    ok, err = classify_semgrep_exit(_result(returncode=0, stdout=b"not json"))
    assert not ok
    assert err is not None
    assert "malformed" in err.lower()


def test_classify_rejects_missing_results_key() -> None:
    payload = json.dumps({"errors": []}).encode()  # no results
    ok, err = classify_semgrep_exit(_result(returncode=0, stdout=payload))
    assert not ok
    assert err is not None
    assert "'results'" in err


def test_classify_marks_timeout() -> None:
    ok, err = classify_semgrep_exit(_result(timed_out=True))
    assert not ok
    assert err is not None
    assert "timed out" in err


@pytest.mark.parametrize(
    "code,label",
    [
        (2, "fatal error"),
        (3, "invalid target code"),
        (4, "invalid pattern"),
        (5, "unparseable YAML config"),
        (7, "missing configuration"),
        (8, "invalid language"),
        (13, "invalid API key"),
        (99, "not implemented in osemgrep"),
    ],
)
def test_classify_labels_known_fatal_exits(code: int, label: str) -> None:
    """Each known fatal exit code maps to a specific reason fragment so
    the user sees what went wrong, not just an opaque number."""
    ok, err = classify_semgrep_exit(_result(returncode=code, stderr=b""))
    assert not ok
    assert err is not None
    assert label in err


def test_classify_handles_unknown_nonzero_exit() -> None:
    ok, err = classify_semgrep_exit(_result(returncode=42))
    assert not ok
    assert err is not None
    assert "42" in err


# --- build_findings_from_semgrep ------------------------------------------


_SEMGREP_SAMPLE = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-yaml-load",
                "path": "src/app.py",
                "start": {"line": 10, "col": 5},
                "end": {"line": 10, "col": 25},
                "extra": {
                    "severity": "ERROR",
                    "message": "Avoid yaml.load; use yaml.safe_load.",
                    "fingerprint": "semgrep-appsec-fp-abc",
                    "metadata": {
                        "cwe": ["CWE-94: Code Injection"],
                        "references": ["https://example.com/yaml-load"],
                    },
                },
            },
            {
                "check_id": "javascript.express.security.audit.cors",
                "path": "/abs/elsewhere.js",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 80},
                "extra": {
                    "severity": "WARNING",
                    "message": "Permissive CORS",
                },
            },
        ],
        "errors": [],
    }
).encode()


def test_parses_findings_with_severity_and_metadata(tmp_path: Path) -> None:
    findings = build_findings_from_semgrep(_SEMGREP_SAMPLE, scan_root=tmp_path)
    assert len(findings) == 2
    f1, f2 = findings
    assert f1.scanner == "sast"
    assert f1.severity == Severity.HIGH
    assert f1.location is not None
    assert f1.location.file == "src/app.py"
    assert f1.location.line == 10
    assert f1.location.column == 5
    assert f1.raw_fingerprint == "semgrep-appsec-fp-abc"
    assert f1.cwe == "CWE-94"
    assert f1.references and f1.references[0].startswith("https://")
    # Severity WARNING → MEDIUM.
    assert f2.severity == Severity.MEDIUM


def test_unknown_severity_label_becomes_unknown(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 2},
                    "extra": {"severity": "EXOTIC", "message": "m"},
                }
            ],
            "errors": [],
        }
    ).encode()
    (f,) = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert f.severity == Severity.UNKNOWN


def test_missing_severity_becomes_unknown(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 2},
                    "extra": {"message": "m"},
                }
            ],
            "errors": [],
        }
    ).encode()
    (f,) = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert f.severity == Severity.UNKNOWN


def test_finding_message_is_redacted(tmp_path: Path) -> None:
    """Semgrep messages can echo source code; if a credential-shaped
    token appears it must be redacted before reaching the user."""
    payload = json.dumps(
        [
            {
                "check_id": "x",
                "path": "a.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 2},
                "extra": {
                    "severity": "ERROR",
                    "message": "Found hardcoded key AKIAIOSFODNN7EXAMPLE here",
                },
            }
        ]
    ).encode()
    # The above is a top-level list. build_findings_from_semgrep should
    # treat that as a parse error, but the redaction property we want to
    # test lives in the proper-object path:
    proper = json.dumps(
        {
            "results": [json.loads(payload)[0]],
            "errors": [],
        }
    ).encode()
    (f,) = build_findings_from_semgrep(proper, scan_root=tmp_path)
    assert "AKIAIOSFODNN7EXAMPLE" not in f.message
    assert "AKIAIOSFODNN7EXAMPLE" not in f.title


def test_duplicate_fingerprint_dedupes(tmp_path: Path) -> None:
    """Same rule/file/start/end produces the same composite fingerprint;
    duplicates from the same scan must collapse to one Finding."""
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"severity": "ERROR", "message": "m"},
                },
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"severity": "ERROR", "message": "m"},
                },
            ],
            "errors": [],
        }
    ).encode()
    findings = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert len(findings) == 1


def test_different_column_spans_produce_different_fingerprints(
    tmp_path: Path,
) -> None:
    """Codex 2nd review: include start/end line+col in the composite to
    distinguish two findings on the same rule and line that hit different
    column spans (e.g. distinct expressions in one statement)."""
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"severity": "ERROR", "message": "m"},
                },
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 10},
                    "end": {"line": 1, "col": 20},
                    "extra": {"severity": "ERROR", "message": "m"},
                },
            ],
            "errors": [],
        }
    ).encode()
    findings = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert len(findings) == 2


def test_raw_fingerprint_preserved_when_present(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {
                        "severity": "ERROR",
                        "message": "m",
                        "fingerprint": "semgrep-fp-12345",
                    },
                }
            ],
            "errors": [],
        }
    ).encode()
    (f,) = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert f.raw_fingerprint == "semgrep-fp-12345"


def test_missing_extra_fingerprint_leaves_raw_none(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"severity": "ERROR", "message": "m"},
                }
            ],
            "errors": [],
        }
    ).encode()
    (f,) = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert f.raw_fingerprint is None


def test_results_must_be_a_list(tmp_path: Path) -> None:
    # Importing the private exception class is acceptable here because it
    # IS the public failure mode for the parser — we promise that the
    # scanner catches it and produces a ScannerError.
    from secscan.scanners.sast import _SemgrepParseError

    payload = json.dumps({"results": {"not": "a list"}}).encode()
    with pytest.raises(_SemgrepParseError):
        build_findings_from_semgrep(payload, scan_root=tmp_path)


def test_empty_results_yields_no_findings(tmp_path: Path) -> None:
    payload = json.dumps({"results": [], "errors": []}).encode()
    assert build_findings_from_semgrep(payload, scan_root=tmp_path) == ()


def test_skips_non_dict_result_entries(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "results": [
                "not a dict",
                None,
                {
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 2},
                    "extra": {"severity": "ERROR", "message": "m"},
                },
            ],
            "errors": [],
        }
    ).encode()
    findings = build_findings_from_semgrep(payload, scan_root=tmp_path)
    assert len(findings) == 1


def test_result_without_check_id_or_path_is_skipped(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "results": [
                {"path": "a.py", "extra": {"severity": "ERROR", "message": "m"}},
                {"check_id": "x", "extra": {"severity": "ERROR", "message": "m"}},
            ],
            "errors": [],
        }
    ).encode()
    assert build_findings_from_semgrep(payload, scan_root=tmp_path) == ()


# --- SastScanner.scan dispatch -------------------------------------------


@pytest.mark.usefixtures("stub_semgrep")
def test_scan_returns_findings_on_normal_run(
    scanner: SastScanner,
    fake_runner: FakeRunner,
    default_config: ScanConfig,
    tmp_path: Path,
) -> None:
    fake_runner.push(returncode=0, stdout=_SEMGREP_SAMPLE)
    outcome = scanner.scan(WorkUnit(root=tmp_path), fake_runner, default_config)
    assert outcome.succeeded
    assert len(outcome.findings) == 2


@pytest.mark.usefixtures("stub_semgrep")
def test_scan_passes_timeout_through(
    scanner: SastScanner,
    fake_runner: FakeRunner,
    tmp_path: Path,
) -> None:
    fake_runner.push(returncode=0, stdout=b'{"results": [], "errors": []}')
    cfg = ScanConfig(
        timeout_seconds=42,
        extra=MappingProxyType({"semgrep_config": ("p/python",)}),
    )
    scanner.scan(WorkUnit(root=tmp_path), fake_runner, cfg)
    _argv, _cwd, timeout = fake_runner.calls[0]
    assert timeout == 42


@pytest.mark.usefixtures("stub_semgrep")
def test_scan_without_semgrep_config_is_scan_error(
    scanner: SastScanner,
    fake_runner: FakeRunner,
    tmp_path: Path,
) -> None:
    cfg = ScanConfig()  # no semgrep_config in extra
    outcome = scanner.scan(WorkUnit(root=tmp_path), fake_runner, cfg)
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "semgrep_config" in outcome.error.reason
    # Must not have invoked semgrep at all.
    assert fake_runner.calls == []


@pytest.mark.usefixtures("stub_semgrep")
def test_scan_failure_returns_redacted_scanner_error(
    scanner: SastScanner,
    fake_runner: FakeRunner,
    default_config: ScanConfig,
    tmp_path: Path,
) -> None:
    """semgrep emits a fatal code; the resulting ScannerError must carry
    a redacted stderr excerpt — defense in depth."""
    fake_runner.push(
        returncode=2,
        stderr=b"could not parse rule: token AKIAIOSFODNN7EXAMPLE leaked",
    )
    outcome = scanner.scan(WorkUnit(root=tmp_path), fake_runner, default_config)
    assert not outcome.succeeded
    assert outcome.error is not None
    assert outcome.error.stderr_excerpt is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in outcome.error.stderr_excerpt


def test_scan_raises_tool_not_found_when_missing(
    scanner: SastScanner,
    fake_runner: FakeRunner,
    default_config: ScanConfig,
    tmp_path: Path,
) -> None:
    with (
        patch.object(shutil, "which", return_value=None),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(WorkUnit(root=tmp_path), fake_runner, default_config)
    assert exc_info.value.tool == "semgrep"


@pytest.mark.usefixtures("stub_semgrep")
def test_scan_timeout_returns_scanner_error(
    scanner: SastScanner,
    fake_runner: FakeRunner,
    default_config: ScanConfig,
    tmp_path: Path,
) -> None:
    fake_runner.push(returncode=-1, timed_out=True)
    outcome = scanner.scan(WorkUnit(root=tmp_path), fake_runner, default_config)
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "timed out" in outcome.error.reason
