"""Phase 2-O: unit tests for the apifuzz scanner input validators.

The validators are the security boundary between operator input
and the docker/schemathesis layer — they own the responses to
unsupported URL schemes, bind-mount-unsafe paths, and the
``--mode=active`` second-opt-in gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secscan.scanners.apifuzz.validators import (
    MAX_SCHEMA_BYTES,
    ApifuzzInputError,
    SchemaFile,
    SchemaUrl,
    assert_schema_file_under_scan_root,
    classify_schema,
    validate_api_url,
    validate_auth_header,
    validate_intermediate_volume_name,
    validate_mode,
)


def _write_schema(p: Path, body: str = "openapi: 3.0.0") -> Path:
    p.write_text(body)
    return p


# ---------------------------------------------------------------------------
# classify_schema
# ---------------------------------------------------------------------------


class TestClassifySchemaUrl:
    def test_http_url_accepted(self) -> None:
        s = classify_schema("http://example.com/openapi.json")
        assert isinstance(s, SchemaUrl)

    def test_https_url_accepted(self) -> None:
        s = classify_schema("https://example.com/v3/openapi.json")
        assert isinstance(s, SchemaUrl)

    def test_file_url_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="neither an http"):
            classify_schema("file:///etc/passwd")

    def test_ftp_url_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="neither an http"):
            classify_schema("ftp://example.com/openapi.json")

    def test_url_with_userinfo_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="userinfo"):
            classify_schema("https://user:pass@example.com/openapi.json")


class TestClassifySchemaFile:
    def test_yaml_extension_accepted(self, tmp_path: Path) -> None:
        f = _write_schema(tmp_path / "schema.yaml")
        s = classify_schema(str(f))
        assert isinstance(s, SchemaFile)

    def test_yml_extension_accepted(self, tmp_path: Path) -> None:
        f = _write_schema(tmp_path / "schema.yml")
        s = classify_schema(str(f))
        assert isinstance(s, SchemaFile)

    def test_json_extension_accepted(self, tmp_path: Path) -> None:
        f = _write_schema(tmp_path / "schema.json")
        s = classify_schema(str(f))
        assert isinstance(s, SchemaFile)

    def test_unknown_extension_rejected(self, tmp_path: Path) -> None:
        f = _write_schema(tmp_path / "schema.txt")
        with pytest.raises(ApifuzzInputError, match="OpenAPI schema extension"):
            classify_schema(str(f))

    def test_empty_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "x.yaml"
        f.write_text("")
        with pytest.raises(ApifuzzInputError, match="empty"):
            classify_schema(str(f))

    def test_top_level_symlink_rejected(self, tmp_path: Path) -> None:
        real = _write_schema(tmp_path / "real.yaml")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)
        with pytest.raises(ApifuzzInputError, match="symlink"):
            classify_schema(str(link))

    def test_oversized_file_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f = _write_schema(tmp_path / "x.yaml")
        from secscan.scanners.apifuzz import validators as vmod

        monkeypatch.setattr(vmod, "MAX_SCHEMA_BYTES", 1, raising=True)
        with pytest.raises(ApifuzzInputError, match="exceeds"):
            classify_schema(str(f))


class TestClassifySchemaMisuse:
    def test_non_string(self) -> None:
        with pytest.raises(ApifuzzInputError, match="must be a string"):
            classify_schema(42)  # type: ignore[arg-type]

    def test_empty(self) -> None:
        with pytest.raises(ApifuzzInputError, match="must not be empty"):
            classify_schema("")

    def test_leading_dash(self) -> None:
        with pytest.raises(ApifuzzInputError, match="must not start with '-'"):
            classify_schema("-foo")

    def test_non_existent_path_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="neither an http"):
            classify_schema("/no/such/file.yaml")


# ---------------------------------------------------------------------------
# assert_schema_file_under_scan_root
# ---------------------------------------------------------------------------


class TestSchemaConfinement:
    def test_url_target_always_ok(self, tmp_path: Path) -> None:
        assert_schema_file_under_scan_root(
            SchemaUrl(url="https://example.com/openapi.json"),
            scan_root=tmp_path,
        )

    def test_file_inside_scan_root_ok(self, tmp_path: Path) -> None:
        f = _write_schema(tmp_path / "schema.yaml")
        assert_schema_file_under_scan_root(
            SchemaFile(path=f), scan_root=tmp_path
        )

    def test_file_outside_scan_root_rejected(
        self, tmp_path: Path
    ) -> None:
        """Codex Phase 2-N MUST-FIX carry-over (security): a
        schema FILE supplied via config that escapes the scan
        root must be refused before any docker call."""
        outside = tmp_path.parent / "outside-schema.yaml"
        outside.write_text("openapi")
        try:
            with pytest.raises(ApifuzzInputError, match="escapes"):
                assert_schema_file_under_scan_root(
                    SchemaFile(path=outside), scan_root=tmp_path
                )
        finally:
            outside.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# validate_api_url
# ---------------------------------------------------------------------------


class TestValidateApiUrl:
    def test_http_accepted(self) -> None:
        assert (
            validate_api_url("http://staging.example.com/api/v3")
            == "http://staging.example.com/api/v3"
        )

    def test_https_accepted(self) -> None:
        assert (
            validate_api_url("https://api.example.com")
            == "https://api.example.com"
        )

    def test_ftp_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="scheme"):
            validate_api_url("ftp://example.com")

    def test_missing_host_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="missing the host"):
            validate_api_url("http://")

    def test_query_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="query"):
            validate_api_url("https://example.com/?token=secret")

    def test_fragment_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="fragment"):
            validate_api_url("https://example.com/#part")

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="userinfo"):
            validate_api_url("https://u:p@example.com/")

    def test_leading_dash_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="must not start with"):
            validate_api_url("-x")


# ---------------------------------------------------------------------------
# validate_mode (active-mode second opt-in)
# ---------------------------------------------------------------------------


class TestValidateMode:
    def test_baseline_default(self) -> None:
        assert validate_mode("baseline", allow_active=False) == "baseline"

    def test_baseline_with_allow_active_still_baseline(self) -> None:
        # Passing --allow-active without --mode=active is benign.
        assert validate_mode("baseline", allow_active=True) == "baseline"

    def test_active_requires_allow_flag(self) -> None:
        """Codex Phase 2-O design review MUST-FIX #2: mode=active
        without the CLI-only --allow-active flag must be refused.
        This is the kill-switch that prevents an attacker-
        controlled .secscan.toml from silently enabling destructive
        fuzzing against a target."""
        with pytest.raises(
            ApifuzzInputError, match="requires the second-opt-in"
        ):
            validate_mode("active", allow_active=False)

    def test_active_with_allow_passes(self) -> None:
        assert validate_mode("active", allow_active=True) == "active"

    def test_unknown_mode_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="must be one of"):
            validate_mode("yolo", allow_active=False)


# ---------------------------------------------------------------------------
# Auth-header validator (delegated to Phase 2-K)
# ---------------------------------------------------------------------------


class TestValidateAuthHeader:
    def test_bearer_accepted(self) -> None:
        name, value = validate_auth_header("Authorization: Bearer abc.def.ghi")
        assert name == "Authorization"
        assert value == "Bearer abc.def.ghi"

    def test_missing_colon_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="missing ':'"):
            validate_auth_header("Authorization Bearer x")

    def test_crlf_rejected(self) -> None:
        with pytest.raises(ApifuzzInputError, match="CR/LF"):
            validate_auth_header("X: a\r\nInjected: hostile")


# ---------------------------------------------------------------------------
# Volume name regex
# ---------------------------------------------------------------------------


class TestValidateIntermediateVolumeName:
    def test_accepts_expected_shape(self) -> None:
        n = "secscan-apifuzz-" + "a" * 32
        assert validate_intermediate_volume_name(n) == n

    def test_rejects_unprefixed(self) -> None:
        with pytest.raises(ApifuzzInputError, match="secscan-apifuzz-"):
            validate_intermediate_volume_name("random-12345")

    def test_rejects_short_random(self) -> None:
        with pytest.raises(ApifuzzInputError, match="secscan-apifuzz-"):
            validate_intermediate_volume_name("secscan-apifuzz-aaa")


def test_max_schema_bytes_is_32_mib() -> None:
    assert MAX_SCHEMA_BYTES == 32 * 1024 * 1024


class TestCliOnlyKeysRejectedFromConfig:
    """Codex Phase 2-O diff review MUST-FIX (security
    regression): the config parser must NOT accept any of the
    CLI-only fields. An attacker-controlled .secscan.toml setting
    ``allow_active = true`` would defeat the entire active-mode
    second-opt-in guarantee."""

    def test_config_rejects_allow_active(self) -> None:
        from secscan.config import ConfigError, _parse_apifuzz

        with pytest.raises(ConfigError, match="unknown keys"):
            _parse_apifuzz({"allow_active": True})

    def test_config_rejects_schema_from_cli(self) -> None:
        from secscan.config import ConfigError, _parse_apifuzz

        with pytest.raises(ConfigError, match="unknown keys"):
            _parse_apifuzz({"schema_from_cli": True})

    def test_config_rejects_unconfine_cli_schema(self) -> None:
        from secscan.config import ConfigError, _parse_apifuzz

        with pytest.raises(ConfigError, match="unknown keys"):
            _parse_apifuzz({"unconfine_cli_schema": True})


class TestActiveModeOptInCombinations:
    """Codex Phase 2-O diff review: pin the matrix of (mode,
    allow_active source) combinations explicitly so a future
    refactor of either field cannot silently break the security
    invariant."""

    def test_config_mode_active_plus_cli_allow_active_succeeds(self) -> None:
        """The intended use case: operator decides to allow active
        mode by passing ``--allow-active`` on the CLI even though
        ``[apifuzz].mode = "active"`` is in .secscan.toml."""
        assert validate_mode("active", allow_active=True) == "active"

    def test_config_mode_active_without_cli_allow_active_fails(self) -> None:
        """The threat model: an attacker who edited .secscan.toml
        to set ``mode = "active"`` must NOT cause active fuzzing
        when the operator hasn't passed ``--allow-active`` on the
        CLI. The mode-validator guarantees this regardless of how
        ``allow_active`` got to the scanner."""
        with pytest.raises(ApifuzzInputError, match="second-opt-in"):
            validate_mode("active", allow_active=False)
