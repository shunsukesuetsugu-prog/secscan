"""Secret detection via gitleaks.

Critical invariants enforced by this module:

- secscan never holds the raw secret value. We invoke gitleaks with
  ``--redact=100`` so ``Secret`` and ``Match`` are placeholders before we
  ever read them.
- "Leak detected" must be distinguishable from "tool error" — gitleaks v8's
  default exit code for both is 1, so we use ``--exit-code=101`` to make
  leaks land on 101.
- ``101 with empty / malformed stdout`` is an error, not a false-clean.
- All Description / message text is run through ``redact_text`` before it
  becomes ``Finding.title`` or ``Finding.message`` — both render to the user.

Fingerprint construction uses, in order of preference:
1. gitleaks' own ``Fingerprint`` field (preserved as ``raw_fingerprint``).
2. A composite of ``RuleID + relative file + start_line + start_column``.

The fingerprint never incorporates the secret value or its hash.

Tested with gitleaks v8.x.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
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
            # Expected "leaks present" exit. stdout MUST be a non-empty JSON
            # array. Codex 3rd review: "101 + empty stdout" must NOT be
            # silently treated as zero findings — that's a false-clean.
            parsed = _parse_findings(result.stdout, unit.root)
            if isinstance(parsed, _ParseError):
                return _error(
                    self.name,
                    parsed.reason,
                    stderr=result.stderr,
                    returncode=result.returncode,
                    tool_version=tool_version,
                    duration=result.duration_seconds,
                )
            return ScanOutcome(
                scanner=self.name,
                findings=parsed,
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


@dataclass(frozen=True)
class _ParseError:
    """Sentinel returned by ``_parse_findings`` for empty/malformed stdout.

    Carrying the reason inline keeps the scanner branching tight and the
    error message specific. We use a dataclass instead of bare object()
    sentinels so the type narrowing is visible to mypy.
    """

    reason: str


def _parse_findings(
    stdout: bytes, scan_root: Path
) -> tuple[Finding, ...] | _ParseError:
    """Parse gitleaks JSON output into normalized Findings.

    Returns either:
    - A tuple of Findings when stdout is a JSON array.
    - A ``_ParseError`` when stdout is empty or not a JSON array. The caller
      translates these into ScannerError outcomes.

    gitleaks v8 emits a JSON array even when zero findings — see the v8
    README. ``exit 101`` is only emitted when at least one leak is found,
    so an empty stdout in that situation is anomalous.
    """
    text = decode_output(stdout).strip()
    if not text:
        return _ParseError(
            reason="gitleaks reported leaks (exit 101) but stdout was empty"
        )
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _ParseError(
            reason="gitleaks reported leaks (exit 101) but stdout was not a JSON array"
        )

    if not isinstance(data, list):
        return _ParseError(
            reason="gitleaks reported leaks (exit 101) but stdout was not a JSON array"
        )

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
    # in depth — sweep all string values through redact_text. Both ``title``
    # and ``message`` flow into the rendered report, so BOTH must be safe.
    safe_message = redact_text(description)

    # Composite fingerprint: do NOT hash any secret-derived value.
    composite = _composite_fingerprint(rule_id, rel_file, start_line, start_col)

    return Finding(
        scanner="secrets",
        rule_id=rule_id,
        severity=Severity.HIGH,  # gitleaks doesn't grade by severity; default HIGH.
        title=safe_message,
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


_RAW_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "RuleID",
        "Description",
        "StartLine",
        "EndLine",
        "StartColumn",
        "EndColumn",
        "File",
        "SymlinkFile",
        "Fingerprint",
        "Tags",
        "Entropy",
        # Secret/Match intentionally NOT here — see force-redact below.
    }
)


def _safe_raw(item: dict[str, object]) -> dict[str, object]:
    """Return a copy of the gitleaks item safe to retain/display.

    Whitelist approach (Codex 3rd review): unknown fields are dropped rather
    than redacted. ``Secret``/``Match`` are always replaced with
    ``REDACTED``, even when gitleaks claims to have already redacted them —
    we never trust the upstream tool's redaction unconditionally.
    Author/Email/Date/Commit/Message fields are intentionally excluded
    because they can carry user-supplied content that may include secrets.
    """
    out: dict[str, object] = {"Secret": REDACTED, "Match": REDACTED}
    for key, value in item.items():
        if key not in _RAW_ALLOWED_KEYS:
            continue
        if isinstance(value, str):
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
