"""Phase 2-P: pyrasp event log parser tests.

The parser's load-bearing security control is the run_id filter:
events lacking the current run_id are surfaced as warnings, not
Findings (Codex Phase 2-P design review MUST-FIX #5).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.models import Severity
from secscan.scanners.iast.parser import (
    PyraspLogParse,
    parse_pyrasp_log,
)

_RUN_ID = "a" * 32
_OTHER_RUN_ID = "b" * 32


def _ndjson(events: list[dict]) -> str:
    return "\n".join(json.dumps(e) for e in events) + "\n"


def _make_event(
    *,
    rule: str = "rasp_sqli",
    category: str = "sqli",
    method: str = "GET",
    path: str = "/",
    pattern: str = "' OR '1'='1",
    run_id: str | None = _RUN_ID,
    cwe: str | None = None,
) -> dict:
    event: dict = {
        "rule": rule,
        "category": category,
        "matched_pattern": pattern,
        "request": {
            "method": method,
            "path": path,
            "headers": {},
        },
    }
    if run_id is not None:
        event["request"]["headers"]["X-Secscan-Run-Id"] = run_id
    if cwe is not None:
        event["cwe"] = cwe
    return event


class TestParsePyraspLogNdjson:
    def test_single_event_emits_finding(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        log.write_text(_ndjson([_make_event()]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert len(parsed.findings) == 1
        f = parsed.findings[0]
        assert f.scanner == "iast"
        assert f.rule_id == "rasp_sqli"
        assert f.severity == Severity.HIGH
        assert "GET /" in f.message

    def test_event_with_different_run_id_filtered_out(
        self, tmp_path: Path
    ) -> None:
        """Codex Phase 2-P design review MUST-FIX #5: stale events
        from a previous run (or any other writer) must be ignored,
        not turned into Findings for the current run."""
        log = tmp_path / "pyrasp.json"
        log.write_text(_ndjson([_make_event(run_id=_OTHER_RUN_ID)]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings == ()
        assert parsed.out_of_run_events == 1
        assert any("without the current run_id" in w for w in parsed.warnings)

    def test_event_without_run_id_filtered_out(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        log.write_text(_ndjson([_make_event(run_id=None)]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings == ()
        assert parsed.out_of_run_events == 1

    def test_top_level_secscan_run_id_field_also_accepted(
        self, tmp_path: Path
    ) -> None:
        """Some operators may configure pyrasp to emit the run-id
        as a top-level convenience field rather than via headers.
        The parser accepts both."""
        log = tmp_path / "pyrasp.json"
        event = _make_event(run_id=None)
        event["secscan_run_id"] = _RUN_ID
        log.write_text(_ndjson([event]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert len(parsed.findings) == 1

    def test_query_secscan_run_also_accepted(self, tmp_path: Path) -> None:
        """Query-string fallback: pyrasp records ``?secscan_run=X``
        under request.query — parser should pick that up."""
        log = tmp_path / "pyrasp.json"
        event = _make_event(run_id=None)
        event["request"]["query"] = {"secscan_run": _RUN_ID}
        log.write_text(_ndjson([event]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert len(parsed.findings) == 1

    def test_multiple_events_with_dedup(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        ev = _make_event()
        # Two identical events should produce one Finding.
        log.write_text(_ndjson([ev, ev]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert len(parsed.findings) == 1


class TestParsePyraspLogJsonArray:
    def test_array_form_accepted(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        log.write_text(json.dumps([_make_event(), _make_event(rule="rasp_xss", category="xss")]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert len(parsed.findings) == 2

    def test_array_with_garbage_root_warns(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        log.write_text('"not an array but a string"')
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings == ()


class TestParsePyraspLogErrors:
    def test_missing_file_warns(self, tmp_path: Path) -> None:
        parsed = parse_pyrasp_log(
            tmp_path / "nope.json", run_id=_RUN_ID
        )
        assert parsed.findings == ()
        assert any("does not exist" in w for w in parsed.warnings)

    def test_empty_file_warns(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        log.write_text("")
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings == ()
        assert any("is empty" in w for w in parsed.warnings)

    def test_oversized_file_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex Phase 2-P design review MUST-FIX (DoS): a
        gigabyte log must not be read into memory."""
        log = tmp_path / "pyrasp.json"
        log.write_text("{}")
        from secscan.scanners.iast import parser as pmod

        monkeypatch.setattr(pmod, "MAX_PYRASP_LOG_BYTES", 1)
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings == ()
        assert any("exceeds" in w for w in parsed.warnings)

    def test_bad_line_warns_but_continues(self, tmp_path: Path) -> None:
        log = tmp_path / "pyrasp.json"
        log.write_text("not json\n" + json.dumps(_make_event()) + "\n")
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert len(parsed.findings) == 1
        assert any("not JSON" in w for w in parsed.warnings)


class TestPyraspParserSeverityMap:
    def test_sqli_is_high(self, tmp_path: Path) -> None:
        log = tmp_path / "p.json"
        log.write_text(_ndjson([_make_event(category="sqli")]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings[0].severity == Severity.HIGH

    def test_xss_is_medium(self, tmp_path: Path) -> None:
        log = tmp_path / "p.json"
        log.write_text(_ndjson([_make_event(category="xss", rule="rasp_xss")]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings[0].severity == Severity.MEDIUM

    def test_unknown_category_is_low(self, tmp_path: Path) -> None:
        log = tmp_path / "p.json"
        log.write_text(_ndjson([_make_event(category="future_rule_name", rule="rasp_future")]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings[0].severity == Severity.LOW

    def test_cwe_extracted_from_field(self, tmp_path: Path) -> None:
        log = tmp_path / "p.json"
        log.write_text(_ndjson([_make_event(cwe="CWE-89")]))
        parsed = parse_pyrasp_log(log, run_id=_RUN_ID)
        assert parsed.findings[0].cwe == "CWE-89"


def test_pyrasp_log_parse_dataclass_is_frozen() -> None:
    from dataclasses import FrozenInstanceError

    parsed = PyraspLogParse(findings=(), warnings=(), tool_version=None)
    with pytest.raises(FrozenInstanceError):
        parsed.findings = (1,)  # type: ignore[misc]
