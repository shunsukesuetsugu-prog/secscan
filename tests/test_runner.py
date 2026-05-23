"""Tests for the subprocess runner.

We exercise:
- Normal exit (stdout/stderr captured, returncode preserved).
- Non-zero exit (no exception, returncode visible).
- Missing executable (returncode 127, no exception).
- Timeout (returncode -1, timed_out=True).
- Argv validation (empty / non-str rejected).
- Output decoding via surrogateescape (round-trip safety).
"""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from secscan.runner import (
    CommandResult,
    CommandRunner,
    SubprocessCommandRunner,
    decode_output,
)


@pytest.fixture()
def runner() -> SubprocessCommandRunner:
    return SubprocessCommandRunner()


# --- Normal paths ----------------------------------------------------------


def test_run_returns_stdout_for_successful_command(
    runner: SubprocessCommandRunner, tmp_path: Path
) -> None:
    result = runner.run(
        [sys.executable, "-c", "import sys; sys.stdout.write('hi')"],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout == b"hi"
    assert result.stderr == b""
    assert not result.timed_out


def test_run_captures_stderr(runner: SubprocessCommandRunner, tmp_path: Path) -> None:
    result = runner.run(
        [sys.executable, "-c", "import sys; sys.stderr.write('warn')"],
        cwd=tmp_path,
    )
    assert result.stderr == b"warn"


def test_run_preserves_nonzero_exit(
    runner: SubprocessCommandRunner, tmp_path: Path
) -> None:
    result = runner.run(
        [sys.executable, "-c", "import sys; sys.exit(3)"],
        cwd=tmp_path,
    )
    assert result.returncode == 3
    assert not result.timed_out


def test_run_passes_cwd(runner: SubprocessCommandRunner, tmp_path: Path) -> None:
    result = runner.run(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        cwd=tmp_path,
    )
    # On macOS, /tmp may resolve to /private/tmp; just verify it ends with the tmp_path leaf.
    assert tmp_path.name.encode() in result.stdout


def test_run_passes_env(runner: SubprocessCommandRunner, tmp_path: Path) -> None:
    result = runner.run(
        [sys.executable, "-c", "import os; print(os.environ.get('SECSCAN_TEST', 'unset'))"],
        cwd=tmp_path,
        env={"SECSCAN_TEST": "value", "PATH": ""},
    )
    assert b"value" in result.stdout


# --- Error paths -----------------------------------------------------------


def test_run_missing_executable_returns_127(
    runner: SubprocessCommandRunner, tmp_path: Path
) -> None:
    result = runner.run(
        ["definitely-not-a-real-binary-name-xyz123"],
        cwd=tmp_path,
    )
    assert result.returncode == 127
    assert b"not found" in result.stderr
    assert not result.timed_out


def test_run_timeout_marks_timed_out(
    runner: SubprocessCommandRunner, tmp_path: Path
) -> None:
    result = runner.run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        cwd=tmp_path,
        timeout_seconds=1,
    )
    assert result.timed_out
    assert result.returncode == -1


def test_run_rejects_empty_argv(runner: SubprocessCommandRunner, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="argv must not be empty"):
        runner.run([], cwd=tmp_path)


def test_run_rejects_non_string_argv(
    runner: SubprocessCommandRunner, tmp_path: Path
) -> None:
    with pytest.raises(TypeError):
        runner.run([sys.executable, 42], cwd=tmp_path)  # type: ignore[list-item]


def test_run_records_duration(runner: SubprocessCommandRunner, tmp_path: Path) -> None:
    result = runner.run([sys.executable, "-c", "pass"], cwd=tmp_path)
    assert result.duration_seconds >= 0


# --- decode_output ---------------------------------------------------------


def test_decode_output_handles_valid_utf8() -> None:
    assert decode_output(b"hello") == "hello"


def test_decode_output_handles_invalid_bytes_without_raising() -> None:
    # Non-UTF-8 byte sequence; surrogateescape must keep it round-trippable.
    bad = b"\xff\xfe\xfd"
    s = decode_output(bad)
    assert s.encode("utf-8", errors="surrogateescape") == bad


# --- Protocol conformance --------------------------------------------------


class _FakeRunner:
    """Minimal alternative implementation to verify Protocol satisfaction."""

    def __init__(self, result: CommandResult) -> None:
        self._result = result

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        return self._result


def test_protocol_is_satisfied_by_a_minimal_impl() -> None:
    canned = CommandResult(
        argv=("x",), returncode=0, stdout=b"", stderr=b"", duration_seconds=0.0, timed_out=False
    )
    fake: CommandRunner = _FakeRunner(canned)
    assert fake.run(["x"], cwd=Path(".")) is canned
