"""Tests for the SARIF 2.1.0 formatter.

Two layers of validation:

1. **Schema validation** against the official OASIS SARIF 2.1.0 JSON
   Schema (bundled in ``tests/fixtures/sarif-schema-2.1.0.json``). This
   catches structural drift early.

2. **secscan-specific contracts** that the SARIF spec does NOT enforce but
   Codex 17th review pinned: no source contents/snippets, ruleIndex
   correctness, endColumn conversion, baseline-suppressed default
   exclusion, deps-finding artifact URI fallback, GitHub fingerprint
   field.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from secscan.config import ProjectConfig
from secscan.formatters import format_sarif
from secscan.formatters.base import FormatOptions
from secscan.models import (
    Finding,
    Location,
    RunResult,
    ScannerError,
    Severity,
)
from secscan.policy import evaluate

_SCHEMA_PATH = Path(__file__).parent.parent / "fixtures" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="module")
def sarif_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _validate(payload: dict, schema: dict) -> None:
    """Run jsonschema validation, surfacing a readable error path on failure."""
    jsonschema.validate(instance=payload, schema=schema)


def _finding(
    *,
    scanner: str = "sast",
    severity: Severity = Severity.HIGH,
    rule_id: str = "test-rule",
    fingerprint: str = "fp1",
    file: str | None = "src/a.py",
    line: int | None = 10,
    end_line: int | None = 10,
    column: int | None = 5,
    end_column: int | None = 25,
    package: str | None = None,
    ecosystem: str | None = None,
    raw: dict | None = None,
    raw_fingerprint: str | None = None,
) -> Finding:
    loc: Location | None
    if file or package:
        loc = Location(
            file=file,
            line=line,
            end_line=end_line,
            column=column,
            end_column=end_column,
            package=package,
            ecosystem=ecosystem,
        )
    else:
        loc = None
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        title="t",
        message="m",
        location=loc,
        fingerprint=fingerprint,
        raw=raw,
        raw_fingerprint=raw_fingerprint,
    )


def _emit(result: RunResult, *, include_suppressed: bool = False) -> dict:
    opts = FormatOptions(include_suppressed_in_sarif=include_suppressed)
    decision = evaluate(result, ProjectConfig())
    return json.loads(format_sarif(result, decision, opts))


# --- Schema validation ---------------------------------------------------


def test_empty_run_validates_against_sarif_schema(sarif_schema: dict) -> None:
    payload = _emit(RunResult())
    _validate(payload, sarif_schema)
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-schema-2.1.0.json")


def test_full_payload_validates_against_sarif_schema(sarif_schema: dict) -> None:
    rr = RunResult(
        findings=(
            _finding(scanner="sast", severity=Severity.HIGH, fingerprint="s1"),
            _finding(scanner="secrets", severity=Severity.HIGH, fingerprint="s2"),
            _finding(
                scanner="deps",
                severity=Severity.MEDIUM,
                fingerprint="d1",
                file=None,
                package="lodash",
                ecosystem="npm",
                line=None,
                end_line=None,
                column=None,
                end_column=None,
            ),
        ),
        errors=(
            ScannerError(scanner="sast", reason="parse failure", returncode=2),
        ),
        warnings=("sast: rules.yml failed to parse",),
        skipped=("dast",),
    )
    payload = _emit(rr)
    _validate(payload, sarif_schema)


# --- Run structure --------------------------------------------------------


def test_one_run_per_scanner() -> None:
    rr = RunResult(
        findings=(
            _finding(scanner="sast", fingerprint="s"),
            _finding(scanner="secrets", fingerprint="x"),
        )
    )
    payload = _emit(rr)
    names = [r["tool"]["driver"]["name"] for r in payload["runs"]]
    # Always includes the three MVP scanners so a clean run still uploads
    # a meaningful SARIF.
    assert "secscan-sast" in names
    assert "secscan-secrets" in names
    assert "secscan-deps" in names


def test_clean_run_still_emits_runs_for_each_mvp_scanner() -> None:
    payload = _emit(RunResult())
    names = {r["tool"]["driver"]["name"] for r in payload["runs"]}
    assert names == {"secscan-secrets", "secscan-deps", "secscan-sast"}
    # All runs have empty results.
    for run in payload["runs"]:
        assert run["results"] == []


# --- Rules / ruleIndex ----------------------------------------------------


def test_rules_array_is_built_and_indexed() -> None:
    rr = RunResult(
        findings=(
            _finding(scanner="sast", rule_id="ruleA", fingerprint="a"),
            _finding(scanner="sast", rule_id="ruleB", fingerprint="b"),
            _finding(scanner="sast", rule_id="ruleA", fingerprint="a2"),
        )
    )
    payload = _emit(rr)
    (sast_run,) = [r for r in payload["runs"] if r["tool"]["driver"]["name"] == "secscan-sast"]
    rule_ids = [r["id"] for r in sast_run["tool"]["driver"]["rules"]]
    assert rule_ids == ["ruleA", "ruleB"]  # dedup, insertion order
    for result in sast_run["results"]:
        idx = result["ruleIndex"]
        assert sast_run["tool"]["driver"]["rules"][idx]["id"] == result["ruleId"]


# --- Level mapping --------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected_level",
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
        (Severity.UNKNOWN, "note"),
    ],
)
def test_severity_maps_to_sarif_level(
    severity: Severity, expected_level: str
) -> None:
    """UNKNOWN → 'note', not 'none' — Codex 17th review flagged that
    GitHub Code Scanning drops level=none results."""
    f = _finding(severity=severity, fingerprint=f"f-{severity.name}")
    payload = _emit(RunResult(findings=(f,)))
    (sast_run,) = [r for r in payload["runs"] if r["tool"]["driver"]["name"] == "secscan-sast"]
    assert sast_run["results"][0]["level"] == expected_level


# --- endColumn conversion -------------------------------------------------


def _run(payload: dict, scanner: str) -> dict:
    """Find the run for ``scanner`` regardless of run ordering."""
    return next(
        r for r in payload["runs"] if r["tool"]["driver"]["name"] == f"secscan-{scanner}"
    )


def test_end_column_is_converted_to_exclusive() -> None:
    """secscan's end_column is INCLUSIVE; SARIF's is EXCLUSIVE.
    The formatter must add 1 when emitting."""
    f = _finding(column=5, end_column=25)
    payload = _emit(RunResult(findings=(f,)))
    region = _run(payload, "sast")["results"][0]["locations"][0][
        "physicalLocation"
    ]["region"]
    assert region["startColumn"] == 5
    assert region["endColumn"] == 26  # 25 + 1


# --- Artifact URI fallback for deps --------------------------------------


def test_deps_finding_without_file_uses_synthetic_uri() -> None:
    """Codex 17th review: deps findings without ``file`` would have GitHub
    silently drop the result. Use a synthetic ``deps:<eco>/<pkg>`` URI."""
    f = _finding(
        scanner="deps",
        file=None,
        line=None,
        end_line=None,
        column=None,
        end_column=None,
        package="lodash",
        ecosystem="npm",
    )
    payload = _emit(RunResult(findings=(f,)))
    (deps_run,) = [r for r in payload["runs"] if r["tool"]["driver"]["name"] == "secscan-deps"]
    uri = deps_run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "deps:npm/lodash"


# --- Fingerprints ---------------------------------------------------------


def test_partial_fingerprints_includes_both_secscan_and_github() -> None:
    f = _finding(fingerprint="composite-hash-abc")
    payload = _emit(RunResult(findings=(f,)))
    fps = _run(payload, "sast")["results"][0]["partialFingerprints"]
    assert fps["secscanV1"] == "composite-hash-abc"
    assert "primaryLocationLineHash" in fps
    # primaryLocationLineHash is a stable SHA-256 hex string (64 chars).
    assert len(fps["primaryLocationLineHash"]) == 64


# --- Security invariants --------------------------------------------------


def test_no_snippet_or_contents_anywhere() -> None:
    """SARIF supports source ``snippet`` / artifact ``contents``. We must
    NEVER include them — emitting source into SARIF would echo any
    pre-redaction tokens into the GitHub-uploaded artifact."""
    f = _finding()
    payload = _emit(RunResult(findings=(f,)))
    blob = json.dumps(payload)
    assert '"snippet"' not in blob
    assert '"contents"' not in blob


def test_finding_raw_is_never_serialized_to_sarif() -> None:
    rr = RunResult(
        findings=(_finding(raw={"Secret": "should-not-leak"}),)
    )
    blob = format_sarif(rr, evaluate(rr, ProjectConfig()))
    assert "should-not-leak" not in blob
    assert '"raw"' not in blob


def test_finding_raw_fingerprint_is_never_serialized_to_sarif() -> None:
    rr = RunResult(
        findings=(_finding(raw_fingerprint="/abs/path/from/upstream:rule:1"),)
    )
    blob = format_sarif(rr, evaluate(rr, ProjectConfig()))
    # raw_fingerprint embeds upstream-side paths; we deliberately
    # exclude it. secscanV1 fingerprint is the canonical one.
    assert "raw_fingerprint" not in blob
    assert "/abs/path/from/upstream" not in blob


def test_file_uri_has_no_leading_slash() -> None:
    """SARIF artifact URIs are relative to the project root by convention,
    and GitHub Code Scanning rejects leading-slash URIs."""
    f = _finding(file="/src/a.py")
    payload = _emit(RunResult(findings=(f,)))
    uri = _run(payload, "sast")["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"]
    assert not uri.startswith("/")
    assert uri == "src/a.py"


# --- Suppressed findings --------------------------------------------------


def test_baseline_suppressed_findings_excluded_by_default() -> None:
    suppressed = _finding(rule_id="known", fingerprint="sup")
    rr = RunResult(suppressed_by_baseline=(suppressed,))
    payload = _emit(rr)
    # No results in any run (suppressed are dropped).
    assert all(run["results"] == [] for run in payload["runs"])


def test_baseline_suppressed_findings_included_with_opt_in() -> None:
    suppressed = _finding(rule_id="known", fingerprint="sup")
    rr = RunResult(suppressed_by_baseline=(suppressed,))
    payload = _emit(rr, include_suppressed=True)
    # Now the sast run carries the suppressed result, marked accordingly.
    (sast_run,) = [
        r for r in payload["runs"]
        if r["tool"]["driver"]["name"] == "secscan-sast"
    ]
    assert len(sast_run["results"]) == 1
    result = sast_run["results"][0]
    assert "suppressions" in result
    assert result["suppressions"][0]["kind"] == "external"


# --- Notifications --------------------------------------------------------


def test_scanner_error_appears_as_error_notification() -> None:
    rr = RunResult(
        errors=(
            ScannerError(scanner="deps", reason="npm exited 2", returncode=2),
        )
    )
    payload = _emit(rr)
    deps_run = _run(payload, "deps")
    notifications = deps_run["invocations"][0]["toolExecutionNotifications"]
    assert any(
        n["level"] == "error" and "npm exited 2" in n["message"]["text"]
        for n in notifications
    )


def test_execution_successful_reflects_scanner_errors() -> None:
    rr_clean = RunResult()
    rr_failed = RunResult(
        errors=(ScannerError(scanner="sast", reason="boom"),),
    )
    clean = _emit(rr_clean)
    failed = _emit(rr_failed)
    for run in clean["runs"]:
        assert run["invocations"][0]["executionSuccessful"] is True
    (sast_run,) = [
        r for r in failed["runs"] if r["tool"]["driver"]["name"] == "secscan-sast"
    ]
    assert sast_run["invocations"][0]["executionSuccessful"] is False


# --- Top-level properties ------------------------------------------------


def test_top_level_secscan_properties_attached() -> None:
    rr = RunResult(findings=(_finding(severity=Severity.HIGH),))
    payload = _emit(rr)
    props = payload["properties"]
    assert props["secscan_version"]
    assert props["exit_code"] == 1  # FINDINGS
    assert props["threshold"] == "high"


def test_output_ends_with_newline() -> None:
    rr = RunResult()
    blob = format_sarif(rr, evaluate(rr, ProjectConfig()))
    assert blob.endswith("\n")
