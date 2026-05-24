"""Unit tests for the Trivy adapter.

Mirrors ``tests/scanners/dast/test_zap_validators.py`` and
``test_zap_argv.py`` in shape — security-relevant validators
and argv shape get table-driven coverage. The Trivy JSON parser
gets its own focused tests because secscan-specific fingerprint
and CWE extraction live there.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.models import Severity
from secscan.scanners.config_scanner.trivy import (
    DEFAULT_TRIVY_IMAGE,
    ConfigInputError,
    TrivyInvocation,
    build_argv,
    classify_trivy_exit,
    parse_trivy_report,
    validate_image_ref,
    validate_scan_path,
)

_VALID_DIGEST = "a" * 64
_VALID_IMAGE = f"aquasec/trivy@sha256:{_VALID_DIGEST}"


# --- validators ------------------------------------------------------------


class TestValidateImageRef:
    def test_accepts_valid(self) -> None:
        assert validate_image_ref(_VALID_IMAGE) == _VALID_IMAGE

    def test_rejects_empty(self) -> None:
        with pytest.raises(ConfigInputError, match="must not be empty"):
            validate_image_ref("")

    def test_rejects_leading_dash(self) -> None:
        with pytest.raises(ConfigInputError, match="docker flag"):
            validate_image_ref(f"-{_VALID_IMAGE}")

    def test_rejects_missing_digest(self) -> None:
        with pytest.raises(ConfigInputError, match="digest pinning"):
            validate_image_ref("aquasec/trivy:0.70.0")

    def test_rejects_whitespace(self) -> None:
        with pytest.raises(ConfigInputError, match="whitespace"):
            validate_image_ref(f"aquasec/trivy @sha256:{_VALID_DIGEST}")

    def test_rejects_short_digest(self) -> None:
        with pytest.raises(ConfigInputError, match="digest pinning"):
            validate_image_ref("aquasec/trivy@sha256:" + "a" * 63)

    def test_default_image_is_validatable(self) -> None:
        # The constant we ship as default must pass our own validator.
        assert validate_image_ref(DEFAULT_TRIVY_IMAGE) == DEFAULT_TRIVY_IMAGE


class TestValidateScanPath:
    def test_accepts_existing_dir(self, tmp_path: Path) -> None:
        out = validate_scan_path(tmp_path)
        assert out.is_dir()
        assert out.is_absolute()

    def test_rejects_nonexistent(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigInputError, match="does not exist"):
            validate_scan_path(tmp_path / "nope")

    def test_rejects_file(self, tmp_path: Path) -> None:
        f = tmp_path / "x.txt"
        f.write_text("x")
        with pytest.raises(ConfigInputError, match="not a directory"):
            validate_scan_path(f)


# --- argv shape ------------------------------------------------------------


class TestBuildArgv:
    @pytest.fixture()
    def base(self, tmp_path: Path) -> TrivyInvocation:
        return TrivyInvocation(scan_root=tmp_path, image_ref=_VALID_IMAGE)

    def test_base_shape(self, base: TrivyInvocation) -> None:
        argv = build_argv(base)
        assert argv[0] == "docker"
        assert argv[1] == "run"
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--network=none" in argv
        assert "--rm" in argv

    def test_bind_mount_is_read_only(self, base: TrivyInvocation) -> None:
        argv = build_argv(base)
        v_idx = argv.index("-v")
        mount_arg = argv[v_idx + 1]
        # Must end with ``:/work:ro``.
        assert mount_arg.endswith(":/work:ro")

    def test_separator_precedes_image(self, base: TrivyInvocation) -> None:
        """Phase 2-D pin: ``--`` must sit between docker options
        and the image so a flag-shaped image (which validation
        already forbids) cannot bleed into docker's option
        parser."""
        argv = build_argv(base)
        sep = argv.index("--")
        image_idx = argv.index(_VALID_IMAGE)
        assert sep < image_idx
        assert argv[sep + 1] == _VALID_IMAGE

    def test_trivy_invocation_carries_config_subcommand(
        self, base: TrivyInvocation
    ) -> None:
        argv = build_argv(base)
        image_idx = argv.index(_VALID_IMAGE)
        # Right after the image: ``config``, ``--quiet``, ``--format``, ``json``.
        assert argv[image_idx + 1] == "config"
        assert "--quiet" in argv[image_idx + 1 :]
        assert "--format" in argv[image_idx + 1 :]
        assert "json" in argv[image_idx + 1 :]

    def test_rejects_invalid_image_at_argv_build(self, tmp_path: Path) -> None:
        bad = TrivyInvocation(scan_root=tmp_path, image_ref="aquasec/trivy:latest")
        with pytest.raises(ConfigInputError):
            build_argv(bad)


# --- exit classification ---------------------------------------------------


class TestClassifyTrivyExit:
    def test_zero_is_ok(self) -> None:
        ok, reason = classify_trivy_exit(0, timed_out=False)
        assert ok is True
        assert reason is None

    def test_nonzero_is_error(self) -> None:
        ok, reason = classify_trivy_exit(2, timed_out=False)
        assert ok is False
        assert "exited with 2" in (reason or "")

    def test_timed_out_short_circuits(self) -> None:
        ok, reason = classify_trivy_exit(0, timed_out=True)
        assert ok is False
        assert "timed out" in (reason or "")


# --- JSON parser -----------------------------------------------------------


def _trivy_report(misconfigs: list[dict[str, object]] | None = None) -> bytes:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.0"},
            "Results": [
                {
                    "Target": "deployment.yaml",
                    "Type": "kubernetes",
                    "Misconfigurations": misconfigs or [],
                }
            ],
        }
    ).encode()


class TestParseTrivyReport:
    def test_empty_report_warns(self, tmp_path: Path) -> None:
        parsed = parse_trivy_report(b"", scan_root=tmp_path)
        assert parsed.findings == ()
        assert any("empty" in w for w in parsed.warnings)

    def test_invalid_json_warns(self, tmp_path: Path) -> None:
        parsed = parse_trivy_report(b"not json", scan_root=tmp_path)
        assert parsed.findings == ()
        assert any("not valid JSON" in w for w in parsed.warnings)

    def test_no_results_field_warns(self, tmp_path: Path) -> None:
        parsed = parse_trivy_report(
            json.dumps({"SchemaVersion": 2, "Trivy": {"Version": "0.70.0"}}).encode(),
            scan_root=tmp_path,
        )
        assert parsed.findings == ()
        # Specifically "zero config files" — guides the operator
        # toward "did I point Trivy at the wrong directory?"
        assert any("zero config files" in w for w in parsed.warnings)

    def test_happy_path_emits_findings(self, tmp_path: Path) -> None:
        misc = [
            {
                "ID": "KSV-0017",
                "Severity": "HIGH",
                "Title": "Privileged container",
                "Description": "Privileged containers share namespaces.",
                "References": ["https://avd.aquasec.com/misconfig/ksv0017"],
                "CauseMetadata": {"StartLine": 12, "EndLine": 14},
            }
        ]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        (finding,) = parsed.findings
        assert finding.rule_id == "KSV-0017"
        assert finding.severity == Severity.HIGH
        assert finding.location is not None
        assert finding.location.file == "deployment.yaml"
        assert finding.location.line == 12
        assert finding.location.end_line == 14
        assert finding.references == (
            "https://avd.aquasec.com/misconfig/ksv0017",
        )

    def test_severity_unknown_passes_through(self, tmp_path: Path) -> None:
        misc = [{"ID": "X", "Severity": "WAT", "Title": "weird"}]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        (finding,) = parsed.findings
        assert finding.severity == Severity.UNKNOWN

    def test_missing_id_is_skipped(self, tmp_path: Path) -> None:
        misc = [{"Severity": "HIGH", "Title": "anonymous misc"}]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        assert parsed.findings == ()

    def test_cwe_extracted_from_references(self, tmp_path: Path) -> None:
        misc = [
            {
                "ID": "X",
                "Severity": "HIGH",
                "Title": "y",
                "References": ["https://cwe.mitre.org/data/definitions/798.html"],
            }
        ]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        (f,) = parsed.findings
        assert f.cwe == "CWE-798"

    def test_duplicate_fingerprint_deduped(self, tmp_path: Path) -> None:
        misc = [
            {
                "ID": "KSV-0001",
                "Severity": "MEDIUM",
                "Title": "y",
                "CauseMetadata": {"StartLine": 5},
            },
            {
                "ID": "KSV-0001",
                "Severity": "MEDIUM",
                "Title": "y",
                "CauseMetadata": {"StartLine": 5},
            },
        ]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        assert len(parsed.findings) == 1

    def test_tool_version_extracted(self, tmp_path: Path) -> None:
        parsed = parse_trivy_report(_trivy_report([]), scan_root=tmp_path)
        assert parsed.tool_version == "0.70.0"

    def test_oversized_report_refused(self, tmp_path: Path) -> None:
        """Codex Phase 2-L diff review: a >32 MiB report is refused
        to avoid OOM on hostile / pathological Trivy output."""
        big = b'{"Results": [' + b'{"Target": "x", "Misconfigurations": []},' * 100
        big = big * 200_000  # ~64 MiB
        parsed = parse_trivy_report(big, scan_root=tmp_path)
        assert parsed.findings == ()
        assert any("exceeded" in w for w in parsed.warnings)

    def test_negative_line_number_dropped(self, tmp_path: Path) -> None:
        misc = [
            {
                "ID": "KSV-X",
                "Severity": "HIGH",
                "Title": "y",
                "CauseMetadata": {"StartLine": -5, "EndLine": 0},
            }
        ]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        (f,) = parsed.findings
        # Negative / zero lines must drop to None — SARIF treats
        # those as undefined and would emit invalid output.
        assert f.location is not None
        assert f.location.line is None
        assert f.location.end_line is None

    def test_target_control_chars_strip_path(self, tmp_path: Path) -> None:
        # Trivy report with a NUL in Target. The Finding still emits
        # but its location.file is dropped (we don't propagate
        # attacker-controlled control characters).
        report = json.dumps(
            {
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.70.0"},
                "Results": [
                    {
                        "Target": "evil\x00path.yaml",
                        "Misconfigurations": [
                            {"ID": "KSV-1", "Severity": "HIGH", "Title": "y"}
                        ],
                    }
                ],
            }
        ).encode()
        parsed = parse_trivy_report(report, scan_root=tmp_path)
        (f,) = parsed.findings
        assert f.location is not None
        assert f.location.file is None

    def test_references_redacted_and_limited(self, tmp_path: Path) -> None:
        many = [f"https://refs.example.com/{i}" for i in range(10)]
        misc = [
            {
                "ID": "X",
                "Severity": "LOW",
                "Title": "y",
                "References": ["\n".join(many)],
            }
        ]
        parsed = parse_trivy_report(_trivy_report(misc), scan_root=tmp_path)
        (f,) = parsed.findings
        assert len(f.references) <= 5
