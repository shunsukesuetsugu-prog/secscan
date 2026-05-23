"""Tests for SecretsScanner (gitleaks adapter).

We use a FakeCommandRunner so the tests don't depend on gitleaks being
installed (gitleaks is a Go binary — install is environment-specific).
We exercise:
- Exit code 0 → no findings
- Exit code 101 + valid JSON → findings normalized
- Exit code 101 + garbage stdout → synthetic parse-error finding
- Other non-zero exit → ScannerError with redacted stderr
- Timeout → ScannerError
- Tool not on PATH → ToolNotFoundError
- Redaction of stderr excerpts
- Fingerprint derived ONLY from rule_id/file/line/col, never from secret
- raw_fingerprint preserved from gitleaks
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest

from secscan.models import ScanConfig, Severity, WorkUnit
from secscan.runner import CommandResult
from secscan.scanners import ToolNotFoundError
from secscan.scanners.secrets import SecretsScanner

# --- Fake runner -----------------------------------------------------------


@dataclass
class FakeRunner:
    """A scripted runner. Returns canned CommandResults by argv match.

    Records ``(argv, cwd, timeout_seconds)`` per call so tests can assert
    that the scanner forwards the expected safety flags and per-call
    timeouts.
    """

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
            raise AssertionError(
                f"FakeRunner ran out of scripted responses for argv={list(argv)}"
            )
        result = self.responses.pop(0)
        return CommandResult(
            argv=tuple(argv),
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=result.duration_seconds,
            timed_out=result.timed_out,
        )


@pytest.fixture()
def fake_runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture()
def work_unit(tmp_path: Path) -> WorkUnit:
    return WorkUnit(root=tmp_path)


@pytest.fixture()
def scanner() -> SecretsScanner:
    return SecretsScanner()


@pytest.fixture()
def stub_which() -> object:
    """Pretend gitleaks is installed."""
    with patch.object(shutil, "which", return_value="/usr/local/bin/gitleaks"):
        yield


# --- Sample gitleaks JSON --------------------------------------------------


_GITLEAKS_LEAK_JSON = json.dumps(
    [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Token",
            "StartLine": 12,
            "EndLine": 12,
            "StartColumn": 5,
            "EndColumn": 25,
            "Match": "REDACTED",
            "Secret": "REDACTED",
            "File": "src/config.py",
            "Fingerprint": "src/config.py:aws-access-token:12",
            "Tags": ["aws"],
        },
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "StartLine": 30,
            "EndLine": 30,
            "StartColumn": 1,
            "EndColumn": 40,
            "Match": "REDACTED",
            "Secret": "REDACTED",
            "File": "src/api.py",
            "Fingerprint": "src/api.py:generic-api-key:30",
        },
    ]
).encode()


# --- Tests: happy paths ----------------------------------------------------


@pytest.mark.usefixtures("stub_which")
def test_no_leaks_returns_empty_findings(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(returncode=0, stdout=b"[]")
    fake_runner.push(returncode=0, stdout=b"v8.18.0")  # version check
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert outcome.succeeded
    assert outcome.findings == ()


@pytest.mark.usefixtures("stub_which")
def test_leaks_are_parsed_into_findings(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(returncode=101, stdout=_GITLEAKS_LEAK_JSON)
    fake_runner.push(returncode=0, stdout=b"v8.18.0")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert outcome.succeeded
    assert len(outcome.findings) == 2
    f1, f2 = outcome.findings
    assert f1.rule_id == "aws-access-token"
    assert f1.severity == Severity.HIGH
    assert f1.location is not None
    assert f1.location.file == "src/config.py"
    assert f1.location.line == 12
    assert f1.location.column == 5
    assert f1.raw_fingerprint == "src/config.py:aws-access-token:12"
    assert f2.rule_id == "generic-api-key"


@pytest.mark.usefixtures("stub_which")
def test_finding_message_is_redacted(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    # Description with an AWS-shaped token in it (should never happen in
    # practice, but defense-in-depth).
    payload = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "Found AKIAIOSFODNN7EXAMPLE here",
                "File": "a.py",
                "StartLine": 1,
                "Match": "REDACTED",
                "Secret": "REDACTED",
            }
        ]
    ).encode()
    fake_runner.push(returncode=101, stdout=payload)
    fake_runner.push(returncode=0, stdout=b"")  # version
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    (f,) = outcome.findings
    assert "AKIAIOSFODNN7EXAMPLE" not in f.message


@pytest.mark.usefixtures("stub_which")
def test_fingerprint_does_not_depend_on_secret_or_match(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    # Codex review: the old version of this test passed identical payloads,
    # so a bug that hashed Secret/Match into the fingerprint would still
    # pass. Use DIFFERENT Secret/Match values to make the test sensitive.
    payload_a = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "d",
                "File": "a.py",
                "StartLine": 1,
                "StartColumn": 1,
                "Match": "value-A",
                "Secret": "secret-A",
            }
        ]
    ).encode()
    payload_b = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "d",
                "File": "a.py",
                "StartLine": 1,
                "StartColumn": 1,
                "Match": "value-B-different",
                "Secret": "secret-B-different",
            }
        ]
    ).encode()
    fake_runner.push(returncode=101, stdout=payload_a)
    fake_runner.push(returncode=0, stdout=b"")
    fake_runner.push(returncode=101, stdout=payload_b)
    fake_runner.push(returncode=0, stdout=b"")
    outcome_a = scanner.scan(work_unit, fake_runner, ScanConfig())
    outcome_b = scanner.scan(work_unit, fake_runner, ScanConfig())
    # Same rule/file/line/column ⇒ same fingerprint regardless of secret.
    assert outcome_a.findings[0].fingerprint == outcome_b.findings[0].fingerprint


@pytest.mark.usefixtures("stub_which")
def test_finding_raw_force_redacts_secret_and_match(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    """``Finding.raw`` must never carry the raw Secret/Match, even if the
    upstream tool somehow forgot to redact them. We pin the force-redact."""
    payload = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "d",
                "File": "a.py",
                "StartLine": 1,
                # Adversarial input: pretend gitleaks failed to redact.
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            }
        ]
    ).encode()
    fake_runner.push(returncode=101, stdout=payload)
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    (f,) = outcome.findings
    assert f.raw is not None
    assert f.raw["Match"] == "[REDACTED]"
    assert f.raw["Secret"] == "[REDACTED]"
    # And neither value appears anywhere else in the raw payload either.
    blob = repr(f.raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "wJalrXUtnFEMI" not in blob


@pytest.mark.usefixtures("stub_which")
def test_finding_raw_drops_unknown_fields(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    """Whitelist approach: any field not on the allowlist (e.g.
    Author/Email/Commit/Message) must not appear in ``Finding.raw``, since
    those can carry user-supplied content that might include secrets."""
    payload = json.dumps(
        [
            {
                "RuleID": "x",
                "Description": "d",
                "File": "a.py",
                "StartLine": 1,
                "Match": "REDACTED",
                "Secret": "REDACTED",
                # Adversarial extra fields:
                "Author": "alice <leak AKIAIOSFODNN7EXAMPLE>",
                "Email": "alice@example.com",
                "Commit": "deadbeef",
                "Message": "leak inside commit message",
                "Unknown": "should be dropped",
            }
        ]
    ).encode()
    fake_runner.push(returncode=101, stdout=payload)
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    (f,) = outcome.findings
    assert f.raw is not None
    assert "Author" not in f.raw
    assert "Email" not in f.raw
    assert "Commit" not in f.raw
    assert "Message" not in f.raw
    assert "Unknown" not in f.raw
    # And no token bled through anywhere.
    assert "AKIAIOSFODNN7EXAMPLE" not in repr(f.raw)


@pytest.mark.usefixtures("stub_which")
def test_long_stderr_is_redacted_before_truncation(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    """Redaction must run before truncation. If we truncate first and the
    cut splits a credential, the surviving prefix would slip past the
    redactor pattern — a quiet leak.

    Codex review: position the AWS key so it STRADDLES the 500-char
    truncate boundary. That way:
    - truncate-first impl: token is cut mid-string → prefix survives →
      "AKIA" leaks past the redactor → assertion FAILS (test catches the
      regression).
    - redact-first impl: full pattern matches → entire key becomes
      [REDACTED] → truncation never sees it → assertion passes.
    """
    aws_key = "AKIAIOSFODNN7EXAMPLE"  # 20 chars; default truncate limit is 500.
    # Position the key so it begins around char 490 and finishes around 510:
    # the default 500-char cut lands inside the token.
    prefix = "x" * 490
    stderr = f"{prefix} {aws_key} trailing-content".encode()
    fake_runner.push(returncode=2, stderr=stderr)
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert outcome.error is not None
    excerpt = outcome.error.stderr_excerpt or ""
    assert aws_key not in excerpt
    # Even a 4-char prefix would be useful to an attacker; ensure none.
    assert aws_key[:4] not in excerpt


# --- Tests: error paths ----------------------------------------------------


@pytest.mark.usefixtures("stub_which")
def test_timeout_produces_scanner_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(returncode=-1, timed_out=True, stderr=b"")
    fake_runner.push(returncode=0, stdout=b"")  # version
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "timed out" in outcome.error.reason


@pytest.mark.usefixtures("stub_which")
def test_unknown_exit_code_produces_scanner_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(returncode=2, stderr=b"some failure")
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert outcome.error is not None
    assert outcome.error.returncode == 2
    assert outcome.error.stderr_excerpt == "some failure"


@pytest.mark.usefixtures("stub_which")
def test_stderr_excerpt_is_redacted(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(
        returncode=2,
        stderr=b"error processing AKIAIOSFODNN7EXAMPLE in repo",
    )
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert outcome.error is not None
    assert outcome.error.stderr_excerpt is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in outcome.error.stderr_excerpt


@pytest.mark.usefixtures("stub_which")
def test_leak_exit_with_garbage_stdout_is_scan_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    # Codex 3rd review: "exit 101 + non-JSON-array stdout" MUST become a
    # ScannerError, never a false-clean and never a synthetic finding.
    fake_runner.push(returncode=101, stdout=b"not json at all")
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "not a JSON array" in outcome.error.reason


@pytest.mark.usefixtures("stub_which")
def test_leak_exit_with_non_array_json_is_scan_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(returncode=101, stdout=b'{"unexpected": "object"}')
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "not a JSON array" in outcome.error.reason


@pytest.mark.usefixtures("stub_which")
def test_leak_exit_with_empty_stdout_is_scan_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    # Empty stdout on exit 101 used to silently mean "no findings" — that's
    # a false-clean. Now it MUST be an error.
    fake_runner.push(returncode=101, stdout=b"")
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "empty" in outcome.error.reason.lower()


@pytest.mark.usefixtures("stub_which")
def test_leak_exit_with_empty_json_array_is_scan_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    # Codex 4th review: `exit 101 + []` is a contradiction — gitleaks emits
    # 101 only when it found leaks. An empty array under that exit code
    # MUST NOT be silently treated as "0 findings".
    fake_runner.push(returncode=101, stdout=b"[]")
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None
    assert "empty" in outcome.error.reason.lower()


@pytest.mark.usefixtures("stub_which")
def test_leak_exit_with_no_parseable_items_is_scan_error(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    # exit 101 + array of non-dicts → no parseable findings. Treat as error.
    fake_runner.push(returncode=101, stdout=b"[1, \"oops\", null]")
    fake_runner.push(returncode=0, stdout=b"")
    outcome = scanner.scan(work_unit, fake_runner, ScanConfig())
    assert not outcome.succeeded
    assert outcome.error is not None


def test_tool_not_installed_raises_tool_not_found(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    with (
        patch.object(shutil, "which", return_value=None),
        pytest.raises(ToolNotFoundError) as exc_info,
    ):
        scanner.scan(work_unit, fake_runner, ScanConfig())
    assert exc_info.value.tool == "gitleaks"
    assert "install" in exc_info.value.install_hint.lower()


# --- Tests: applicability and config --------------------------------------


def test_is_applicable_always_true(scanner: SecretsScanner) -> None:
    assert scanner.is_applicable(WorkUnit(root=Path("/x")))
    assert scanner.is_applicable(WorkUnit(root=Path("/x"), ecosystem="npm"))


@pytest.mark.usefixtures("stub_which")
def test_argv_contains_required_safety_flags(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    fake_runner.push(returncode=0, stdout=b"")
    fake_runner.push(returncode=0, stdout=b"")
    scanner.scan(work_unit, fake_runner, ScanConfig())
    argv = fake_runner.calls[0][0]
    # Critical safety flags: redaction enforced, leak exit code distinct.
    assert "--redact=100" in argv
    assert "--exit-code=101" in argv
    assert "--report-format=json" in argv
    assert "--no-banner" in argv
    assert "dir" in argv  # `gitleaks dir` (not `git`) — MVP scope
    # gitleaks must write JSON to stdout, not a file we'd then have to manage.
    assert "--report-path=/dev/stdout" in argv


@pytest.mark.usefixtures("stub_which")
def test_passes_scan_timeout_to_runner(
    scanner: SecretsScanner, fake_runner: FakeRunner, work_unit: WorkUnit
) -> None:
    """The configured scan timeout must reach the runner verbatim.

    A regression here would let scans hang past their per-scanner budget,
    a real CI problem on large repos. We also verify that the version
    detection call uses a tight, fixed timeout — independent of the user's
    setting — so a misconfigured 10000s scan timeout can't slow down a
    routine version probe.
    """
    fake_runner.push(returncode=0, stdout=b"")  # main scan
    fake_runner.push(returncode=0, stdout=b"")  # version probe
    scanner.scan(work_unit, fake_runner, ScanConfig(timeout_seconds=42))
    assert len(fake_runner.calls) == 2
    scan_call, version_call = fake_runner.calls
    # Main scan: user-provided timeout (42).
    assert scan_call[2] == 42
    # Version probe: fixed short timeout (10s in the implementation).
    assert version_call[2] == 10
