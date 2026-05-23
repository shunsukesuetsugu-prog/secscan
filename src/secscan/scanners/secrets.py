"""Secret detection via gitleaks.

Critical invariant: secscan never holds the raw secret value. We invoke
gitleaks with ``--redact=100`` so the ``Secret`` and ``Match`` fields in the
JSON output are already replaced with ``REDACTED``. We additionally pass
``--exit-code=101`` to make the "leak detected" path distinguishable from
"tool error" — gitleaks v8's default exit code for both is 1 (Codex 2nd
review explicitly required this).

Fingerprint construction uses, in order of preference:
1. gitleaks' own ``Fingerprint`` field (preserved as ``raw_fingerprint``).
2. A composite of ``RuleID + relative file + start_line + start_column``.

We deliberately do NOT hash the secret value as part of the fingerprint:
even with --redact, accidentally hashing user-supplied content would create
a side channel. The composite key is stable enough for baseline matching
and doesn't depend on the secret content at all.

Tested with gitleaks v8.x.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from ..models import (
    Finding,
    Location,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    Severity,
    WorkUnit,
)
from ..redact import REDACTED, redact_text, truncate
from ..runner import CommandRunner, decode_output
from .base import Scanner, ToolNotFoundError

# Distinct exit code requested via --exit-code so we can tell "leaks found"
# apart from gitleaks' own error path (default 1 for both).
_GITLEAKS_LEAK_EXIT_CODE = 101

# Strings gitleaks puts into Secret/Match fields when --redact=100.
_REDACTED_SENTINELS = frozenset({"REDACTED", "[REDACTED]"})


class SecretsScanner(Scanner):
    name = "secrets"
    tool_executable = "gitleaks"
    install_hint = (
        "install gitleaks v8+ (e.g. `brew install gitleaks` on macOS) "
        "and ensure it is on PATH"
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # Secrets are language-agnostic; scan every WorkUnit.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        if shutil.which(self.tool_executable) is None:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)

        argv = [
            "gitleaks",
            "dir",
            str(unit.root),
            "--redact=100",
            "--report-format=json",
            "--report-path=/dev/stdout",
            f"--exit-code={_GITLEAKS_LEAK_EXIT_CODE}",
            "--no-banner",
        ]

        result = runner.run(argv, cwd=unit.root, timeout_seconds=config.timeout_seconds)
        tool_version = _detect_gitleaks_version(runner, unit.root)

        if result.timed_out:
            return _error(
                self.name,
                "gitleaks timed out",
                stderr=result.stderr,
                returncode=result.returncode,
                tool_version=tool_version,
                duration=result.duration_seconds,
            )

        if result.returncode == 0:
            # No leaks detected — gitleaks may still write `[]` or nothing.
            return ScanOutcome(
                scanner=self.name,
                findings=(),
                tool_version=tool_version,
                duration_seconds=result.duration_seconds,
            )

        if result.returncode == _GITLEAKS_LEAK_EXIT_CODE:
            # Expected "leaks present" exit. stdout MUST be parseable JSON.
            findings = _parse_findings(result.stdout, unit.root)
            return ScanOutcome(
                scanner=self.name,
                findings=findings,
                tool_version=tool_version,
                duration_seconds=result.duration_seconds,
            )

        # Any other exit code is an error. Include redacted stderr excerpt.
        return _error(
            self.name,
            f"gitleaks exited with {result.returncode}",
            stderr=result.stderr,
            returncode=result.returncode,
            tool_version=tool_version,
            duration=result.duration_seconds,
        )


def _detect_gitleaks_version(runner: CommandRunner, cwd: Path) -> str | None:
    """Best-effort version detection. Failure is non-fatal."""
    try:
        result = runner.run(["gitleaks", "version"], cwd=cwd, timeout_seconds=10)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    version = decode_output(result.stdout).strip()
    return version or None


def _parse_findings(stdout: bytes, scan_root: Path) -> tuple[Finding, ...]:
    """Parse gitleaks JSON output into normalized Findings.

    gitleaks emits a JSON array of objects. Each object includes RuleID,
    Description, StartLine/EndLine/StartColumn/EndColumn, Match, Secret,
    File, Fingerprint, etc. (See: gitleaks v8 schema.)
    """
    text = decode_output(stdout).strip()
    if not text:
        return ()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Malformed JSON despite leak-exit-code: treat as zero findings but
        # the orchestrator will see the original ScannerError if we raise.
        # Since gitleaks already signaled "leak", we prefer a more honest
        # outcome: return a synthetic Finding describing the parse failure
        # so the user notices something went wrong.
        return (_synthetic_parse_error_finding(text),)

    if not isinstance(data, list):
        return (_synthetic_parse_error_finding(text),)

    findings: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        findings.append(_finding_from_gitleaks(item, scan_root))
    return tuple(findings)


def _finding_from_gitleaks(item: dict[str, object], scan_root: Path) -> Finding:
    rule_id = _str_field(item, "RuleID") or "unknown"
    description = _str_field(item, "Description") or rule_id
    file_path_raw = _str_field(item, "File") or ""
    start_line = _int_field(item, "StartLine")
    end_line = _int_field(item, "EndLine") or start_line
    start_col = _int_field(item, "StartColumn")
    end_col = _int_field(item, "EndColumn")
    raw_fingerprint = _str_field(item, "Fingerprint")

    # File path may be absolute or relative; normalize to forward-slash
    # relative-to-scan-root when possible.
    rel_file = _normalize_path(file_path_raw, scan_root)

    # Ensure no actual secret is in the dict: even with --redact, defense
    # in depth — sweep all string values through redact_text.
    safe_message = redact_text(description)

    # Composite fingerprint: do NOT hash any secret-derived value.
    composite = _composite_fingerprint(rule_id, rel_file, start_line, start_col)

    return Finding(
        scanner="secrets",
        rule_id=rule_id,
        severity=Severity.HIGH,  # gitleaks doesn't grade by severity; default HIGH.
        title=description,
        message=safe_message,
        location=Location(
            file=rel_file,
            line=start_line,
            end_line=end_line,
            column=start_col,
            end_column=end_col,
        ),
        fingerprint=composite,
        raw_fingerprint=raw_fingerprint,
        raw=_safe_raw(item),
    )


def _synthetic_parse_error_finding(text: str) -> Finding:
    excerpt = redact_text(truncate(text, limit=200))
    return Finding(
        scanner="secrets",
        rule_id="secscan.parse-error",
        severity=Severity.HIGH,
        title="gitleaks output parse error",
        message=(
            "gitleaks reported leaks but output was not valid JSON. "
            f"Excerpt (redacted): {excerpt}"
        ),
        location=None,
        fingerprint="secscan-parse-error",
    )


def _composite_fingerprint(
    rule_id: str, rel_file: str | None, line: int | None, col: int | None
) -> str:
    parts = (rule_id, rel_file or "", str(line or 0), str(col or 0))
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _normalize_path(raw: str, scan_root: Path) -> str | None:
    if not raw:
        return None
    p = Path(raw)
    try:
        # gitleaks may emit absolute or relative paths; both should map to
        # the scan-root-relative posix form for display + fingerprinting.
        candidate = p if p.is_absolute() else (scan_root / p)
        rel = candidate.resolve(strict=False).relative_to(scan_root.resolve(strict=False))
        return rel.as_posix()
    except ValueError:
        return p.as_posix()


def _safe_raw(item: dict[str, object]) -> dict[str, object]:
    """Strip any field that might leak the secret value.

    With --redact=100 these fields already contain a placeholder, but we
    over-rotate to be sure: any value matching a known sentinel is left as
    is, others are conservatively redacted.
    """
    out: dict[str, object] = {}
    for key, value in item.items():
        if key in {"Secret", "Match"}:
            if isinstance(value, str) and value in _REDACTED_SENTINELS:
                out[key] = value
            else:
                out[key] = REDACTED
        elif isinstance(value, str):
            out[key] = redact_text(value)
        else:
            out[key] = value
    return out


def _str_field(item: dict[str, object], key: str) -> str | None:
    value = item.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _int_field(item: dict[str, object], key: str) -> int | None:
    value = item.get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _error(
    scanner: str,
    reason: str,
    *,
    stderr: bytes,
    returncode: int,
    tool_version: str | None,
    duration: float,
) -> ScanOutcome:
    excerpt = redact_text(truncate(decode_output(stderr)))
    return ScanOutcome(
        scanner=scanner,
        error=ScannerError(
            scanner=scanner,
            reason=reason,
            stderr_excerpt=excerpt or None,
            returncode=returncode,
        ),
        tool_version=tool_version,
        duration_seconds=duration,
    )
