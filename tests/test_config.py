"""Tests for .secscan.toml loading.

Covers:
- Defaults when no file present.
- Ancestor walk in ``find_config_file``.
- Parsing of every section, with type validation.
- Strict rejection of unknown keys (a security property: typo'd
  severity_overrides must NOT silently do nothing).
- Baseline path resolution relative to the config file directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secscan.config import (
    CONFIG_FILENAME,
    DEFAULT_FAIL_ON,
    DEFAULT_SEMGREP_CONFIG,
    ConfigError,
    find_config_file,
    load_config,
    load_config_file,
)
from secscan.models import Severity

# --- Defaults --------------------------------------------------------------


def test_load_config_returns_defaults_when_file_missing(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg.fail_on == DEFAULT_FAIL_ON
    assert cfg.skip == ()
    assert cfg.severity_unknown_policy.deps == "warn"
    assert cfg.severity_unknown_policy.secrets == "fail"
    assert cfg.sast.semgrep_config == DEFAULT_SEMGREP_CONFIG


def test_load_config_resolves_default_baseline_relative_to_scan_root(
    tmp_path: Path,
) -> None:
    cfg = load_config(tmp_path)
    assert cfg.baseline.path == (tmp_path / ".secscan" / "baseline.json").resolve()


# --- find_config_file ------------------------------------------------------


def test_find_config_file_walks_ancestors(tmp_path: Path) -> None:
    config = tmp_path / CONFIG_FILENAME
    config.write_text("[scan]\nfail_on = 'low'\n")
    sub = tmp_path / "a" / "b" / "c"
    sub.mkdir(parents=True)
    assert find_config_file(sub) == config


def test_find_config_file_returns_none_when_absent(tmp_path: Path) -> None:
    assert find_config_file(tmp_path) is None


# --- Successful parsing ----------------------------------------------------


def test_parses_full_config(tmp_path: Path) -> None:
    cfg_text = """
[scan]
fail_on = "critical"
skip = ["sast"]

[scan.severity_unknown_policy]
deps = "fail"
sast = "ignore"
secrets = "warn"

[deps]
allow_missing_lockfile = true
ignore_dev_dependencies = true
timeout_seconds = 30

[sast]
semgrep_config = ["p/python", "custom.yml"]
timeout_seconds = 120

[secrets]
timeout_seconds = 45

[baseline]
path = "baselines/main.json"
default_expiry_days = 30

[severity_overrides.secrets]
"aws-access-token" = "CRITICAL"
"github-pat" = "HIGH"

[severity_overrides.sast]
"taint-sql" = "CRITICAL"
"""
    p = tmp_path / CONFIG_FILENAME
    p.write_text(cfg_text)
    cfg = load_config_file(p)
    assert cfg.fail_on == Severity.CRITICAL
    assert cfg.skip == ("sast",)
    assert cfg.severity_unknown_policy.deps == "fail"
    assert cfg.severity_unknown_policy.sast == "ignore"
    assert cfg.severity_unknown_policy.secrets == "warn"
    assert cfg.deps.allow_missing_lockfile is True
    assert cfg.deps.ignore_dev_dependencies is True
    assert cfg.deps.timeout_seconds == 30
    assert cfg.sast.semgrep_config == ("p/python", "custom.yml")
    assert cfg.sast.timeout_seconds == 120
    assert cfg.secrets.timeout_seconds == 45
    # Baseline path is resolved relative to the config file's dir.
    assert cfg.baseline.path == (tmp_path / "baselines" / "main.json").resolve()
    assert cfg.baseline.default_expiry_days == 30
    assert cfg.severity_overrides["secrets"]["aws-access-token"] == Severity.CRITICAL
    assert cfg.severity_overrides["secrets"]["github-pat"] == Severity.HIGH
    assert cfg.severity_overrides["sast"]["taint-sql"] == Severity.CRITICAL


def test_baseline_absolute_path_is_left_alone(tmp_path: Path) -> None:
    abs_path = (tmp_path / "elsewhere" / "bl.json").resolve()
    cfg_text = f"""
[baseline]
path = "{abs_path}"
"""
    p = tmp_path / CONFIG_FILENAME
    p.write_text(cfg_text)
    cfg = load_config_file(p)
    assert cfg.baseline.path == abs_path


# --- Error paths -----------------------------------------------------------


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / CONFIG_FILENAME
    p.write_text(body)
    return p


def test_invalid_toml_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config_file(_write(tmp_path, "this is = = invalid ["))


def test_unknown_root_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config_file(_write(tmp_path, "[unrecognized]\nx = 1\n"))


def test_unknown_scan_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"\[scan\] unknown keys"):
        load_config_file(_write(tmp_path, "[scan]\nfial_on = 'high'\n"))


def test_unknown_severity_overrides_scanner_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"\[severity_overrides\] unknown keys"):
        load_config_file(
            _write(
                tmp_path,
                "[severity_overrides.bogus]\nx = 'HIGH'\n",
            )
        )


def test_invalid_severity_value_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Unknown severity"):
        load_config_file(_write(tmp_path, "[scan]\nfail_on = 'super-high'\n"))


def test_invalid_unknown_policy_value_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be one of"):
        load_config_file(
            _write(
                tmp_path,
                "[scan.severity_unknown_policy]\ndeps = 'panic'\n",
            )
        )


def test_skip_unknown_scanner_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown scanner"):
        load_config_file(_write(tmp_path, "[scan]\nskip = ['dast']\n"))


def test_scan_timeout_seconds_is_rejected(tmp_path: Path) -> None:
    """Codex 15th review: there is no whole-run timeout; setting
    ``scan.timeout_seconds`` previously stored the value but did nothing.
    We now reject it loudly so users notice the misconfiguration."""
    with pytest.raises(ConfigError, match=r"\[scan\] unknown keys"):
        load_config_file(_write(tmp_path, "[scan]\ntimeout_seconds = 60\n"))


def test_per_scanner_timeout_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be >="):
        load_config_file(_write(tmp_path, "[deps]\ntimeout_seconds = 0\n"))


def test_semgrep_config_must_be_list(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be a list"):
        load_config_file(_write(tmp_path, "[sast]\nsemgrep_config = 'p/python'\n"))


def test_bool_field_rejects_int(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be a boolean"):
        load_config_file(_write(tmp_path, "[deps]\nallow_missing_lockfile = 1\n"))


def test_fail_on_none_is_accepted(tmp_path: Path) -> None:
    cfg = load_config_file(_write(tmp_path, "[scan]\nfail_on = 'none'\n"))
    assert cfg.fail_on == Severity.NEVER


def test_severity_overrides_rejects_none(tmp_path: Path) -> None:
    # `--fail-on none` is OK as a threshold sentinel, but a finding cannot
    # have severity NEVER. severity_overrides must therefore refuse "none".
    with pytest.raises(ConfigError, match="only valid as a fail-on threshold"):
        load_config_file(
            _write(
                tmp_path,
                "[severity_overrides.secrets]\n\"x\" = 'none'\n",
            )
        )
