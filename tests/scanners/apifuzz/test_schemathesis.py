"""Phase 2-O: argv builder + NDJSON parser unit tests.

Pure tests — no docker invocation. Pins the security-critical
argv shapes (``--max-redirects 0``, ``--report ndjson``, RO/RW
volume distinctions, ``--`` separator) and the Schemathesis
NDJSON parser's mapping from check names to severities.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.models import Severity
from secscan.portability import to_docker_host_path
from secscan.scanners.apifuzz._pinned import (
    DEFAULT_HELPER_IMAGE,
    DEFAULT_SCHEMATHESIS_IMAGE,
)
from secscan.scanners.apifuzz.schemathesis import (
    NDJSON_REPORT_PATH,
    SchemathesisInvocation,
    build_argv,
    build_chown_argv,
    classify_schemathesis_exit,
    parse_ndjson_report,
    severity_for_check,
)
from secscan.scanners.apifuzz.validators import (
    ApifuzzInputError,
    SchemaFile,
    SchemaUrl,
)

_INTER_VOL = "secscan-apifuzz-" + "f" * 32
_API_URL = "https://api.example.com/v3"
_SCHEMA_URL = "https://api.example.com/v3/openapi.json"


# ---------------------------------------------------------------------------
# Chown helper argv
# ---------------------------------------------------------------------------


class TestBuildChownArgv:
    def test_runs_as_root_chowning_volume(self) -> None:
        argv = build_chown_argv(
            helper_image=DEFAULT_HELPER_IMAGE, volume=_INTER_VOL
        )
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=none" in argv
        # The helper needs root to chown the freshly-created volume.
        assert "--user" in argv
        assert argv[argv.index("--user") + 1] == "0:0"
        # Mount is RW (no ``:ro``) — the helper writes uid info.
        v_idx = argv.index("-v")
        assert argv[v_idx + 1] == f"{_INTER_VOL}:/work"
        assert ":ro" not in argv[v_idx + 1]
        # Ends with chown command + uid:gid + path.
        assert argv[-3:] == ["chown", "-R", "1000:1000"] or argv[-4:-1] == [
            "chown",
            "-R",
            "1000:1000",
        ]


# ---------------------------------------------------------------------------
# Schemathesis argv
# ---------------------------------------------------------------------------


class TestBuildArgvSchemaUrl:
    def _invocation(self, **overrides: object) -> SchemathesisInvocation:
        base: dict[str, object] = {
            "schema": SchemaUrl(url=_SCHEMA_URL),
            "api_url": _API_URL,
            "intermediate_volume": _INTER_VOL,
        }
        base.update(overrides)
        return SchemathesisInvocation(**base)  # type: ignore[arg-type]

    def test_basic_shape(self) -> None:
        argv = build_argv(self._invocation())
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=bridge" in argv
        # ``--`` separator before the scanner image.
        sep = argv.index("--")
        assert argv[sep + 1] == DEFAULT_SCHEMATHESIS_IMAGE
        assert argv[sep + 2] == "run"
        # Schema location is the URL.
        assert argv[sep + 3] == _SCHEMA_URL
        # --url comes after schema.
        assert "--url" in argv
        assert argv[argv.index("--url") + 1] == _API_URL

    def test_max_redirects_zero_enforced(self) -> None:
        """Codex Phase 2-O design review MUST-FIX #3: schema-
        declared ``servers:`` URLs must not be followed. The
        --max-redirects 0 flag blocks all 3xx follows."""
        argv = build_argv(self._invocation())
        assert "--max-redirects" in argv
        assert argv[argv.index("--max-redirects") + 1] == "0"

    def test_ndjson_report_explicit(self) -> None:
        """Codex Phase 2-O design review MUST-FIX #1: never rely
        on Schemathesis's default report format."""
        argv = build_argv(self._invocation())
        assert "--report" in argv
        assert argv[argv.index("--report") + 1] == "ndjson"
        assert "--report-ndjson-path" in argv
        assert (
            argv[argv.index("--report-ndjson-path") + 1]
            == NDJSON_REPORT_PATH
        )

    def test_generation_database_memory(self) -> None:
        argv = build_argv(self._invocation())
        assert "--generation-database" in argv
        assert (
            argv[argv.index("--generation-database") + 1] == ":memory:"
        )

    def test_output_sanitize_enabled(self) -> None:
        argv = build_argv(self._invocation())
        assert "--output-sanitize" in argv
        assert argv[argv.index("--output-sanitize") + 1] == "true"

    def test_baseline_mode_includes_safe_methods(self) -> None:
        argv = build_argv(self._invocation(mode="baseline"))
        include_indices = [
            i for i, t in enumerate(argv) if t == "--include-method"
        ]
        included = [argv[i + 1] for i in include_indices]
        assert included == ["GET", "HEAD", "OPTIONS"]

    def test_active_mode_omits_include_filters(self) -> None:
        """Active mode means 'fuzz every method declared in the
        schema'. No --include-method filters."""
        argv = build_argv(self._invocation(mode="active"))
        assert "--include-method" not in argv

    def test_max_examples_flag(self) -> None:
        argv = build_argv(self._invocation(max_examples=7))
        assert "--max-examples" in argv
        assert argv[argv.index("--max-examples") + 1] == "7"

    def test_seed_flag(self) -> None:
        argv = build_argv(self._invocation(seed=42))
        assert "--seed" in argv
        assert argv[argv.index("--seed") + 1] == "42"

    def test_seed_omitted_when_none(self) -> None:
        argv = build_argv(self._invocation(seed=None))
        assert "--seed" not in argv

    def test_deterministic_flag(self) -> None:
        argv = build_argv(self._invocation(deterministic=True))
        assert "--generation-deterministic" in argv

    def test_auth_header_forwarded_with_dash_H(self) -> None:
        argv = build_argv(
            self._invocation(headers=("Authorization: Bearer abc.def.ghi",))
        )
        # -H is Schemathesis's flag for repeatable headers.
        h_indices = [i for i, t in enumerate(argv) if t == "-H"]
        assert len(h_indices) == 1
        assert (
            argv[h_indices[0] + 1] == "Authorization: Bearer abc.def.ghi"
        )

    def test_invalid_header_raises(self) -> None:
        with pytest.raises(ApifuzzInputError):
            build_argv(
                self._invocation(headers=("BrokenHeaderNoColon",))
            )

    def test_invalid_volume_raises(self) -> None:
        with pytest.raises(ApifuzzInputError):
            build_argv(self._invocation(intermediate_volume="bad-name"))


class TestBuildArgvSchemaFile:
    def test_file_mount_and_in_container_path(self, tmp_path: Path) -> None:
        f = tmp_path / "openapi.yaml"
        f.write_text("openapi")
        argv = build_argv(
            SchemathesisInvocation(
                schema=SchemaFile(path=f),
                api_url=_API_URL,
                intermediate_volume=_INTER_VOL,
            )
        )
        # Bind-mounted RO.
        ro_mount = next(
            (t for t in argv if isinstance(t, str) and t.endswith(":ro")),
            None,
        )
        assert ro_mount is not None
        # Use the docker-host form (POSIX: pass-through; Windows:
        # ``C:\\Users\\foo`` → ``/c/Users/foo``) — the raw
        # ``str(f)`` is not what the argv carries on Windows.
        assert to_docker_host_path(f) in ro_mount
        # Schema location is the in-container path with the same suffix.
        sep = argv.index("--")
        assert argv[sep + 3].startswith("/schema/openapi.")


# ---------------------------------------------------------------------------
# Exit classification
# ---------------------------------------------------------------------------


class TestClassifyExit:
    def test_zero_is_success(self) -> None:
        ok, reason = classify_schemathesis_exit(0, timed_out=False)
        assert ok and reason is None

    def test_one_is_success_with_findings(self) -> None:
        """Schemathesis returns 1 when checks fail — that's a
        successful RUN of the scanner; the failures become
        findings, not scanner errors."""
        ok, reason = classify_schemathesis_exit(1, timed_out=False)
        assert ok and reason is None

    def test_other_nonzero_is_failure(self) -> None:
        ok, reason = classify_schemathesis_exit(2, timed_out=False)
        assert not ok and "exited with 2" in (reason or "")

    def test_timeout_is_failure(self) -> None:
        ok, reason = classify_schemathesis_exit(0, timed_out=True)
        assert not ok and "timed out" in (reason or "")


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMap:
    def test_5xx_is_high(self) -> None:
        assert severity_for_check("not_a_server_error") == Severity.HIGH

    def test_ignored_auth_is_high(self) -> None:
        assert severity_for_check("ignored_auth") == Severity.HIGH

    def test_use_after_free_is_high(self) -> None:
        assert severity_for_check("use_after_free") == Severity.HIGH

    def test_status_code_conformance_is_medium(self) -> None:
        assert (
            severity_for_check("status_code_conformance") == Severity.MEDIUM
        )

    def test_negative_data_rejection_is_medium(self) -> None:
        assert (
            severity_for_check("negative_data_rejection") == Severity.MEDIUM
        )

    def test_unknown_check_falls_back_to_low(self) -> None:
        """Schemathesis adds new checks across minor versions; the
        parser must not silently drop them."""
        assert severity_for_check("some_future_check") == Severity.LOW


# ---------------------------------------------------------------------------
# NDJSON parser
# ---------------------------------------------------------------------------


def _ndjson(events: list[dict]) -> bytes:
    return b"\n".join(json.dumps(e).encode() for e in events) + b"\n"


_SAMPLE_FAILURE = {
    "ScenarioFinished": {
        "id": "scen-1",
        "suite_id": "suite-1",
        "phase": "Examples",
        "status": "failure",
        "elapsed_time": 0.5,
        "is_final": False,
        "recorder": {
            "label": "POST /pet",
            "cases": {
                "case-1": {"value": {"method": "POST", "path": "/pet"}}
            },
            "checks": {
                "case-1": [
                    {
                        "name": "not_a_server_error",
                        "status": "failure",
                        "failure_info": {
                            "failure": {
                                "type": "ServerError",
                                "message": "Server error",
                            }
                        },
                    },
                    {
                        "name": "status_code_conformance",
                        "status": "success",
                    },
                ]
            },
            "interactions": {
                "case-1": {
                    "request": {
                        "method": "POST",
                        "uri": "https://api.example.com/v3/pet",
                    },
                    "response": {"status_code": 500},
                }
            },
        },
    }
}


class TestParseNdjsonReport:
    def test_extracts_failure_into_finding(self) -> None:
        parsed = parse_ndjson_report(
            _ndjson([_SAMPLE_FAILURE]), api_url=_API_URL
        )
        assert len(parsed.findings) == 1
        f = parsed.findings[0]
        assert f.scanner == "apifuzz"
        assert f.rule_id == "not_a_server_error"
        assert f.severity == Severity.HIGH
        assert "POST /pet" in f.message
        assert "HTTP 500" in f.message
        assert f.location is not None
        assert f.location.file is not None
        assert "apifuzz/POST/pet" in f.location.file

    def test_skips_passed_scenarios(self) -> None:
        ev = json.loads(json.dumps(_SAMPLE_FAILURE))
        ev["ScenarioFinished"]["status"] = "success"
        parsed = parse_ndjson_report(_ndjson([ev]), api_url=_API_URL)
        assert parsed.findings == ()

    def test_skips_skipped_scenarios(self) -> None:
        ev = json.loads(json.dumps(_SAMPLE_FAILURE))
        ev["ScenarioFinished"]["status"] = "skip"
        parsed = parse_ndjson_report(_ndjson([ev]), api_url=_API_URL)
        assert parsed.findings == ()

    def test_skips_passed_checks_within_failure(self) -> None:
        """A failing scenario may contain a mix of pass/fail
        checks. Only the failures become findings."""
        parsed = parse_ndjson_report(
            _ndjson([_SAMPLE_FAILURE]), api_url=_API_URL
        )
        # Only one failure (not_a_server_error) in the sample;
        # status_code_conformance was 'success' and must not appear.
        rule_ids = {f.rule_id for f in parsed.findings}
        assert rule_ids == {"not_a_server_error"}

    def test_out_of_scope_alert_when_request_uri_escapes_api_url(self) -> None:
        ev = json.loads(json.dumps(_SAMPLE_FAILURE))
        ev["ScenarioFinished"]["recorder"]["interactions"]["case-1"][
            "request"
        ]["uri"] = "https://attacker.example.org/exfil"
        parsed = parse_ndjson_report(_ndjson([ev]), api_url=_API_URL)
        assert any(
            "escaped the --api-url scope" in alert
            for alert in parsed.out_of_scope_alerts
        )

    def test_extracts_tool_version(self) -> None:
        init = {
            "Initialize": {
                "Initialize": {
                    "schemathesis_version": "4.19.0",
                }
            }
        }
        parsed = parse_ndjson_report(
            _ndjson([init, _SAMPLE_FAILURE]), api_url=_API_URL
        )
        assert parsed.tool_version == "4.19.0"

    def test_empty_stdout_warns(self) -> None:
        parsed = parse_ndjson_report(b"", api_url=_API_URL)
        assert parsed.findings == ()
        assert any("empty" in w for w in parsed.warnings)

    def test_oom_cap_refuses_huge_report(self) -> None:
        huge = b"x" * (33 * 1024 * 1024)
        parsed = parse_ndjson_report(huge, api_url=_API_URL)
        assert parsed.findings == ()
        assert any("exceeded" in w for w in parsed.warnings)

    def test_invalid_json_line_warns_but_continues(self) -> None:
        bad = b"{not json\n"
        ok = json.dumps(_SAMPLE_FAILURE).encode() + b"\n"
        parsed = parse_ndjson_report(bad + ok, api_url=_API_URL)
        assert len(parsed.findings) == 1
        assert any("not JSON" in w for w in parsed.warnings)

    def test_dedup_across_repeated_failures(self) -> None:
        """Same (check_name, method, path, status, failure_msg)
        produces one Finding, not multiple."""
        parsed = parse_ndjson_report(
            _ndjson([_SAMPLE_FAILURE, _SAMPLE_FAILURE]),
            api_url=_API_URL,
        )
        assert len(parsed.findings) == 1

    def test_out_of_scope_detected_even_for_successful_scenarios(self) -> None:
        """Codex Phase 2-O diff review MUST-FIX: out-of-scope
        detection must run on ALL scenarios, not just failed ones.
        A successful scenario whose request went to an off-scope
        host is still a security signal worth surfacing."""
        ok_event = json.loads(json.dumps(_SAMPLE_FAILURE))
        ok_event["ScenarioFinished"]["status"] = "success"
        ok_event["ScenarioFinished"]["recorder"]["interactions"][
            "case-1"
        ]["request"]["uri"] = "https://attacker.example.org/exfil"
        # No checks block needed for success scenarios — only the
        # interactions URI matters for the out-of-scope check.
        parsed = parse_ndjson_report(
            _ndjson([ok_event]), api_url=_API_URL
        )
        assert parsed.findings == ()  # status=success → no findings
        # …but the out-of-scope alert MUST fire even though the
        # scenario was "successful".
        assert any(
            "escaped the --api-url scope" in alert
            for alert in parsed.out_of_scope_alerts
        )

    def test_recursion_error_in_loads_does_not_crash_parser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex Phase 2-O diff review MUST-FIX (DoS): a single
        NDJSON line with very deep nesting can hit Python's
        recursion limit in json.loads. The parser must catch
        and continue rather than abort.

        We simulate the failure deterministically via monkeypatch
        (real deeply-nested JSON exceeds the test's default stack
        on some platforms but not others)."""
        from secscan.scanners.apifuzz import schemathesis as sthmod

        # Patch json.loads in the schemathesis module to raise
        # RecursionError on the first call, then delegate to the
        # real loads for subsequent lines.
        real_loads = json.loads
        call_count = {"n": 0}

        def flaky_loads(s: str, *args: object, **kwargs: object) -> object:
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RecursionError("simulated")
            return real_loads(s, *args, **kwargs)

        monkeypatch.setattr(sthmod.json, "loads", flaky_loads)

        bad = b'{"poison": 1}\n'
        good = json.dumps(_SAMPLE_FAILURE).encode() + b"\n"
        parsed = parse_ndjson_report(bad + good, api_url=_API_URL)
        # Parser didn't abort — good line's finding survived.
        assert any(f.rule_id == "not_a_server_error" for f in parsed.findings)
        # Bad line surfaced as a warning, not a crash.
        assert any(
            "RecursionError" in w or "rejected" in w
            for w in parsed.warnings
        )

    def test_value_error_in_loads_does_not_crash_parser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Parallel to the RecursionError test: out-of-range numerics
        can raise ValueError. The parser catches it."""
        from secscan.scanners.apifuzz import schemathesis as sthmod

        real_loads = json.loads
        call_count = {"n": 0}

        def flaky_loads(s: str, *args: object, **kwargs: object) -> object:
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ValueError("simulated")
            return real_loads(s, *args, **kwargs)

        monkeypatch.setattr(sthmod.json, "loads", flaky_loads)

        bad = b'{"poison": 2}\n'
        good = json.dumps(_SAMPLE_FAILURE).encode() + b"\n"
        parsed = parse_ndjson_report(bad + good, api_url=_API_URL)
        assert any(f.rule_id == "not_a_server_error" for f in parsed.findings)
        assert any(
            "ValueError" in w or "rejected" in w
            for w in parsed.warnings
        )
