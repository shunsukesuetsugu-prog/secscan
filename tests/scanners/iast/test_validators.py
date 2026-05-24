"""Phase 2-P: validators are the security boundary for the IAST
harness. These tests pin:

- ``--command`` does NOT shell-expand its input (shlex + shell=False
  contract).
- ``--probe-url`` MUST resolve exclusively to loopback addresses
  (DNS-rebind defence).
- ``--pyrasp-log`` MUST be scan-root-confined and MUST NOT
  pre-exist (stale-event defence).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secscan.scanners.iast.validators import (
    MAX_PYRASP_LOG_BYTES,
    CommandSpec,
    IastInputError,
    validate_command_argv,
    validate_probe_url,
    validate_pyrasp_log_path,
    validate_run_id,
)

# ---------------------------------------------------------------------------
# validate_command_argv
# ---------------------------------------------------------------------------


class TestValidateCommandArgv:
    def test_simple_python_argv(self) -> None:
        spec = validate_command_argv("python -m flask run")
        assert isinstance(spec, CommandSpec)
        assert spec.argv == ("python", "-m", "flask", "run")

    def test_quoted_argument_preserved(self) -> None:
        spec = validate_command_argv('python -c "print(1)"')
        assert spec.argv == ("python", "-c", "print(1)")

    def test_command_substitution_string_NOT_expanded(self) -> None:
        """Codex Phase 2-P design review FIX_NEEDED #1: a literal
        ``$(...)`` token is harmlessly forwarded as one argv string
        because subprocess uses ``shell=False``. shlex.split alone
        is not enough — the contract is shlex+shell=False together.
        This test pins the shlex behaviour."""
        spec = validate_command_argv('echo "$(cat /etc/passwd)"')
        # The dollar-paren string is preserved as a single argv
        # token; shell would have expanded it but Popen with
        # shell=False does not.
        assert "$(cat /etc/passwd)" in spec.argv

    def test_backtick_command_substitution_also_safe(self) -> None:
        spec = validate_command_argv("echo `whoami`")
        assert "`whoami`" in spec.argv

    def test_unclosed_quote_raises(self) -> None:
        with pytest.raises(IastInputError, match="could not be tokenised"):
            validate_command_argv("python 'unclosed")

    def test_empty_rejected(self) -> None:
        with pytest.raises(IastInputError, match="must not be empty"):
            validate_command_argv("")

    def test_dash_leading_rejected(self) -> None:
        with pytest.raises(IastInputError, match="must not start with '-'"):
            validate_command_argv("-rf /")

    def test_nul_byte_rejected(self) -> None:
        with pytest.raises(IastInputError, match="NUL byte"):
            validate_command_argv("python -c 'x\x00y'")

    def test_control_char_rejected(self) -> None:
        with pytest.raises(IastInputError, match="control character"):
            validate_command_argv("python -c 'x\x01y'")

    def test_non_string_rejected(self) -> None:
        with pytest.raises(IastInputError, match="must be a string"):
            validate_command_argv(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# validate_probe_url (loopback enforcement)
# ---------------------------------------------------------------------------


class TestValidateProbeUrl:
    def test_loopback_ipv4_accepted(self) -> None:
        assert (
            validate_probe_url("http://127.0.0.1:8080")
            == "http://127.0.0.1:8080"
        )

    def test_loopback_ipv4_subnet_accepted(self) -> None:
        # Any 127.0.0.0/8 host is loopback.
        assert (
            validate_probe_url("http://127.0.1.5:5000")
            == "http://127.0.1.5:5000"
        )

    def test_loopback_ipv6_accepted(self) -> None:
        assert (
            validate_probe_url("http://[::1]:8080")
            == "http://[::1]:8080"
        )

    def test_localhost_accepted_and_substituted_to_literal_ip(self) -> None:
        """Codex Phase 2-P diff review MUST-FIX (DNS rebind): the
        validator resolves ``localhost`` once and returns the
        URL with the literal loopback IP. Probes connect to the
        IP, NOT to ``localhost`` again — closing the TOCTOU
        window where a local DNS swap could redirect off-loopback."""
        result = validate_probe_url("http://localhost:8080")
        # Either the IPv4 loopback or the IPv6 loopback got pinned.
        assert (
            result == "http://127.0.0.1:8080"
            or result == "http://[::1]:8080"
        )

    def test_public_ip_rejected(self) -> None:
        with pytest.raises(IastInputError, match="loopback"):
            validate_probe_url("http://8.8.8.8")

    def test_public_dns_rejected(self) -> None:
        with pytest.raises(IastInputError, match="loopback"):
            validate_probe_url("http://example.com")

    def test_https_loopback_accepted(self) -> None:
        assert (
            validate_probe_url("https://127.0.0.1:8443")
            == "https://127.0.0.1:8443"
        )

    def test_ftp_scheme_rejected(self) -> None:
        with pytest.raises(IastInputError, match="scheme must be"):
            validate_probe_url("ftp://127.0.0.1")

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(IastInputError, match="userinfo"):
            validate_probe_url("http://u:p@127.0.0.1")

    def test_query_rejected(self) -> None:
        with pytest.raises(IastInputError, match="query"):
            validate_probe_url("http://127.0.0.1/?x=1")

    def test_fragment_rejected(self) -> None:
        with pytest.raises(IastInputError, match="fragment"):
            validate_probe_url("http://127.0.0.1/#foo")

    def test_empty_rejected(self) -> None:
        with pytest.raises(IastInputError, match="must not be empty"):
            validate_probe_url("")

    def test_arbitrary_hostname_rejected_even_if_in_allowlist_check(
        self,
    ) -> None:
        """A hostname like ``myappserver`` is NOT in the allow-list
        and must be refused even if /etc/hosts happens to map it
        to loopback. This is the DNS-rebind defence."""
        with pytest.raises(IastInputError, match="loopback"):
            validate_probe_url("http://myappserver")


# ---------------------------------------------------------------------------
# validate_pyrasp_log_path
# ---------------------------------------------------------------------------


class TestValidatePyraspLogPath:
    def test_path_inside_scan_root_accepted(self, tmp_path: Path) -> None:
        # File does NOT exist yet — fresh log file the operator
        # tells pyrasp to create.
        candidate = tmp_path / "pyrasp.json"
        resolved = validate_pyrasp_log_path(
            str(candidate), scan_root=tmp_path
        )
        assert resolved == candidate.resolve()

    def test_already_existing_path_rejected(self, tmp_path: Path) -> None:
        """Codex Phase 2-P design review MUST-FIX #5: a pre-
        existing log file would let stale events poison the
        parse. Reject by default."""
        candidate = tmp_path / "pyrasp.json"
        candidate.write_text("{}")
        with pytest.raises(IastInputError, match="already exists"):
            validate_pyrasp_log_path(str(candidate), scan_root=tmp_path)

    def test_existing_path_accepted_when_flag_set(
        self, tmp_path: Path
    ) -> None:
        candidate = tmp_path / "pyrasp.json"
        candidate.write_text("{}")
        # Tests / fixtures may pre-stage the file; flag opts in.
        resolved = validate_pyrasp_log_path(
            str(candidate), scan_root=tmp_path, allow_existing=True
        )
        assert resolved == candidate.resolve()

    def test_symlink_rejected(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.write_text("{}")
        link = tmp_path / "link.json"
        link.symlink_to(target)
        with pytest.raises(IastInputError, match="symlink"):
            validate_pyrasp_log_path(
                str(link), scan_root=tmp_path, allow_existing=True
            )

    def test_outside_scan_root_rejected(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / f"escape-{tmp_path.name}.json"
        try:
            with pytest.raises(IastInputError, match="escapes the scan root"):
                validate_pyrasp_log_path(
                    str(outside), scan_root=tmp_path
                )
        finally:
            if outside.exists():
                outside.unlink()

    def test_forbidden_chars_rejected(self, tmp_path: Path) -> None:
        # The implementation rejects `:` before resolution.
        with pytest.raises(IastInputError, match="forbidden character"):
            validate_pyrasp_log_path(
                str(tmp_path) + "/bad:name.json", scan_root=tmp_path
            )

    def test_empty_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(IastInputError, match="must not be empty"):
            validate_pyrasp_log_path("", scan_root=tmp_path)

    def test_windows_drive_letter_passes_charset_gate(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A2 / Phase 2-W regression: under Windows, the charset
        gate must accept ``C:\\path\\file.json`` (drive colon +
        backslashes). Before the fix, the validator used a private
        POSIX-only forbidden set that rejected every absolute
        Windows path before it could be resolved.

        We simulate Windows by monkey-patching ``IS_WINDOWS`` in
        the shared portability module — the rest of the validator
        (Path resolution, ``relative_to`` containment) is allowed
        to fail with a DIFFERENT error; the assertion is just that
        the charset gate no longer fires.
        """
        from secscan import portability

        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        # Some absolute-looking Windows path. On POSIX it won't
        # resolve to anything meaningful, but the charset gate is
        # the only thing under test here.
        candidate = "C:\\Users\\runner\\AppData\\Temp\\pyrasp.json"
        # Either the call succeeds (path resolved + containment
        # passed in some unusual POSIX env) or it raises an error
        # about scan-root escape / non-existence. What it must
        # NOT raise is "forbidden character".
        try:
            validate_pyrasp_log_path(candidate, scan_root=tmp_path)
        except IastInputError as exc:
            assert "forbidden character" not in str(exc), (
                f"Windows drive-letter path should pass charset gate; "
                f"got {exc!r}"
            )


# ---------------------------------------------------------------------------
# validate_run_id
# ---------------------------------------------------------------------------


class TestValidateRunId:
    def test_valid_32_hex_accepted(self) -> None:
        ok = "a" * 32
        assert validate_run_id(ok) == ok

    def test_short_rejected(self) -> None:
        with pytest.raises(IastInputError, match="32-character hex"):
            validate_run_id("abc")

    def test_uppercase_rejected(self) -> None:
        # secrets.token_hex returns lowercase; regression guard.
        with pytest.raises(IastInputError, match="32-character hex"):
            validate_run_id("A" * 32)

    def test_non_hex_rejected(self) -> None:
        with pytest.raises(IastInputError, match="32-character hex"):
            validate_run_id("z" * 32)


def test_max_pyrasp_log_bytes_is_32_mib() -> None:
    assert MAX_PYRASP_LOG_BYTES == 32 * 1024 * 1024


class TestCodexDiffReviewRegressions:
    """Codex Phase 2-P diff review FIX_NEEDED #5 carry-overs:
    pin the security properties Codex called out as easy to
    regress."""

    def test_ipv4_mapped_ipv6_rejected(self) -> None:
        """``::ffff:8.8.8.8`` is IPv6 syntactically but addresses
        the public IPv4 8.8.8.8. ``ipaddress.is_loopback`` returns
        False for this — must be rejected."""
        with pytest.raises(IastInputError, match="loopback"):
            validate_probe_url("http://[::ffff:8.8.8.8]:8080")

    def test_newline_in_command_rejected_as_control_char(self) -> None:
        """A multi-line ``--command`` token would be a strange
        thing for an operator to type. Reject — control chars
        inside argv tokens are blocked at validation time."""
        with pytest.raises(IastInputError, match="control character"):
            validate_command_argv("python -c 'a\nrm -rf /'")

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"),
        reason="os.mkfifo is POSIX-only — Phase 2-W skip on Windows",
    )
    def test_pyrasp_log_pointing_at_fifo_rejected(
        self, tmp_path: Path
    ) -> None:
        """A FIFO / device file as the pyrasp log path is suspicious
        — pyrasp would block on write and the parser would behave
        unpredictably. The pre-existence check catches this."""
        fifo = tmp_path / "p.json"
        os.mkfifo(fifo)
        try:
            with pytest.raises(IastInputError, match="already exists"):
                validate_pyrasp_log_path(str(fifo), scan_root=tmp_path)
        finally:
            fifo.unlink()


def test_command_argv_rejects_bare_newline_inside_quoted_token() -> None:
    """Defence in depth: even if shlex.split tolerates a newline
    inside a quoted token, the per-token control-char scan
    rejects it. ``"python -c 'x\\ny'"`` (raw newline inside the
    single-quoted block) must fail."""
    with pytest.raises(IastInputError, match="control character"):
        validate_command_argv("python -c 'x\ny'")
