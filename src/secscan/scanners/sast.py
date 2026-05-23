"""SAST scanner via semgrep.

Implementation notes pinned by past Codex reviews:

- We do NOT pass ``--error``. semgrep's default ``scan`` exits 0 even
  when findings are present; the canonical signal is "did stdout parse to
  a JSON object with a ``results`` array?". The non-error exit codes for
  semgrep are 2 (fatal), 3 (invalid target), 4 (invalid pattern), 5
  (unparseable YAML), 7 (missing configuration), 8 (invalid language),
  13 (invalid API key), 99 (not implemented in osemgrep) — see Kimi's
  tool survey of semgrep CLI exit codes.
- ``semgrep_config`` is a tuple of rulesets. Each entry gets its own
  ``--config`` flag — semgrep stacks multiple configs left-to-right.
- ``results[].extra.fingerprint`` exists in Semgrep AppSec Platform output
  but NOT in CE. When present we record it as ``raw_fingerprint`` purely
  for cross-tool reconciliation; baseline matching is driven by the
  canonical composite fingerprint (``rule_id + relative_file +
  start_line + start_col + end_line + end_col``) so AppSec users and CE
  users get identical baselines for the same finding.
- ``results[].extra.severity`` strings are ERROR / WARNING / INFO. We map
  to HIGH / MEDIUM / LOW respectively. Anything we don't recognize maps
  to UNKNOWN (let policy.severity_unknown_policy decide).
- ``errors`` entries inside the JSON envelope are NOT findings — they are
  parser / config / engine errors. The scanner surfaces them via
  ``ScanOutcome.warnings`` so the user knows the report may be
  incomplete. Codex 12th review flagged that silently dropping these is
  a SAST false-clean path: findings=0 + non-empty errors should never
  read as "clean".
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar

from ..models import (
    Finding,
    Location,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    Severity,
    WorkUnit,
)
from ..redact import redact_text, truncate
from ..runner import CommandResult, CommandRunner, decode_output
from .base import Scanner, ToolNotFoundError

# Severity strings used by semgrep CE.
_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Semgrep exit codes we accept as a successful run (regardless of whether
# findings were produced). Anything else is a tool failure.
# Reference: semgrep CLI exit code documentation. 0 is "success / findings
# allowed"; 1 is reserved for ``--error`` mode which we never request.
_SEMGREP_OK_EXIT_CODES: frozenset[int] = frozenset({0})

# Fatal semgrep exit codes we recognize specifically so the error message
# can be more useful than "exit N".
_SEMGREP_FATAL_LABELS: dict[int, str] = {
    2: "fatal error",
    3: "invalid target code",
    4: "invalid pattern",
    5: "unparseable YAML config",
    7: "missing configuration",
    8: "invalid language",
    13: "invalid API key",
    99: "not implemented in osemgrep",
}


class SastScanner(Scanner):
    name: ClassVar[str] = "sast"
    tool_executable: ClassVar[str] = "semgrep"
    install_hint: ClassVar[str] = (
        "install semgrep (`pip install semgrep` or "
        "`pip install 'secscan[sast]'`) and ensure it is on PATH"
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # semgrep is language-aware via its rulesets; we let it decide and
        # always emit a single root-level WorkUnit (per discovery.py).
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        if shutil.which(self.tool_executable) is None:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)

        configs = _coerce_semgrep_configs(config.extra.get("semgrep_config"))
        if not configs:
            return _error(
                "sast scanner has no semgrep_config: configure "
                "[sast].semgrep_config in .secscan.toml or pass --semgrep-config",
                stderr=b"",
                returncode=None,
                duration=0.0,
            )

        allow_unverified = bool(config.extra.get("allow_unverified_configs", False))
        rejected = _reject_unsafe_configs(
            configs, scan_root=unit.root, allow_unverified=allow_unverified
        )
        if rejected:
            return _error(
                "sast scanner refused unverified semgrep config(s): "
                + ", ".join(rejected)
                + ". Use registry shorthand (e.g. p/python) or a path inside "
                "the scan root, or set [sast].allow_unverified_configs=true "
                "to opt in.",
                stderr=b"",
                returncode=None,
                duration=0.0,
            )

        argv = semgrep_argv(unit_root=unit.root, configs=configs)
        result = runner.run(
            argv, cwd=unit.root, timeout_seconds=config.timeout_seconds
        )
        ok, error_reason = classify_semgrep_exit(result)
        if not ok:
            return _error(
                error_reason or "semgrep failed",
                stderr=result.stderr,
                returncode=result.returncode,
                duration=result.duration_seconds,
            )
        try:
            findings = build_findings_from_semgrep(result.stdout, scan_root=unit.root)
            warnings = extract_semgrep_warnings(result.stdout)
        except _SemgrepParseError as exc:
            return _error(
                str(exc),
                stderr=result.stderr,
                returncode=result.returncode,
                duration=result.duration_seconds,
            )
        return ScanOutcome(
            scanner=self.name,
            findings=findings,
            warnings=warnings,
            tool_version=None,
            duration_seconds=result.duration_seconds,
        )


# --- argv construction ----------------------------------------------------


def semgrep_argv(
    *,
    unit_root: Path,
    configs: Sequence[str],
) -> tuple[str, ...]:
    """Build the semgrep CLI invocation.

    Each config entry gets its own ``--config`` flag so multiple rulesets
    can be stacked. We pass the scan path explicitly (the WorkUnit root)
    rather than relying on the implicit cwd — being explicit helps tests
    assert the exact target.

    We do NOT pass ``--error``. semgrep's default ``scan`` exit code is 0
    even when findings are present; secscan's policy layer makes the
    threshold call, not the tool.
    """
    argv: list[str] = ["semgrep", "scan", "--json", "--quiet"]
    for cfg in configs:
        argv.extend(("--config", cfg))
    argv.append(str(unit_root))
    return tuple(argv)


# --- exit classification --------------------------------------------------


def classify_semgrep_exit(result: CommandResult) -> tuple[bool, str | None]:
    """Decide whether a semgrep run succeeded.

    "Successful" means the JSON report was produced and parsed (the
    classifier itself does not parse — it just verifies the marker keys).
    Findings vs no-findings is a downstream question.
    """
    if result.timed_out:
        return False, "semgrep timed out"
    if result.returncode not in _SEMGREP_OK_EXIT_CODES:
        label = _SEMGREP_FATAL_LABELS.get(result.returncode)
        if label is not None:
            return False, f"semgrep exited {result.returncode} ({label})"
        return False, f"semgrep exited {result.returncode}"
    text = decode_output(result.stdout).strip()
    if not text:
        return False, "semgrep produced no JSON output"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, f"semgrep JSON was malformed: {exc}"
    if not isinstance(data, dict):
        return False, "semgrep JSON top-level was not an object"
    if "results" not in data:
        # The "results" key is always present in a well-formed semgrep
        # report, even when empty. Its absence means something else got
        # printed to stdout — most likely a non-semgrep program (PATH
        # collision) or a partial / cancelled run.
        return False, "semgrep JSON did not contain a 'results' array"
    return True, None


# --- finding construction -------------------------------------------------


class _SemgrepParseError(ValueError):
    """Raised when ``build_findings_from_semgrep`` is given invalid input.

    Internal to this module — the Scanner catches it and converts to a
    ScannerError outcome.
    """


def extract_semgrep_warnings(stdout: bytes) -> tuple[str, ...]:
    """Pull semgrep's top-level ``errors`` array out and format as warnings.

    Semgrep emits parser/config/engine errors here even when the scan
    itself completed. Treating these as "no findings, all good" is the
    SAST false-clean path Codex 12th review flagged. We hand the strings
    back as warnings so the reporter surfaces them; we do NOT escalate
    them to ScannerError because the rest of the scan IS valid.

    Each warning is redacted (defense in depth) and truncated to 200
    chars so a chatty engine error can't flood the report.
    """
    text = decode_output(stdout).strip()
    if not text:
        return ()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(data, dict):
        return ()
    errs = data.get("errors")
    if not isinstance(errs, list) or not errs:
        return ()
    notes: list[str] = []
    for err in errs:
        if isinstance(err, dict):
            level = _first_str(err.get("level")) or "error"
            msg = (
                _first_str(err.get("message"))
                or _first_str(err.get("short_msg"))
                or _first_str(err.get("type"))
                or "(no message)"
            )
            notes.append(
                truncate(redact_text(f"semgrep {level}: {msg}"), limit=200)
            )
        elif isinstance(err, str):
            notes.append(truncate(redact_text(f"semgrep error: {err}"), limit=200))
    # Cap to avoid drowning the user. If there are more, summarize.
    MAX = 5
    if len(notes) > MAX:
        omitted = len(notes) - MAX
        return (*notes[:MAX], f"(+{omitted} more semgrep errors omitted)")
    return tuple(notes)


def build_findings_from_semgrep(
    stdout: bytes, *, scan_root: Path
) -> tuple[Finding, ...]:
    """Parse a semgrep JSON report into normalized Findings.

    Caller must have already validated the JSON shape via
    ``classify_semgrep_exit``. This function focuses on per-result
    extraction and is strict about its inputs — a malformed report
    (e.g. ``results`` not a list) raises ``_SemgrepParseError`` so the
    scanner can surface it explicitly.
    """
    text = decode_output(stdout).strip()
    if not text:
        return ()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise _SemgrepParseError("semgrep JSON top-level was not an object")
    results = data.get("results")
    if not isinstance(results, list):
        raise _SemgrepParseError("semgrep JSON 'results' was not a list")

    findings: list[Finding] = []
    seen_fingerprints: set[str] = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        finding = _finding_from_semgrep(entry, scan_root=scan_root)
        if finding is None:
            continue
        if finding.fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(finding.fingerprint)
        findings.append(finding)
    return tuple(findings)


def _finding_from_semgrep(
    entry: dict[str, Any], *, scan_root: Path
) -> Finding | None:
    rule_id = _first_str(entry.get("check_id"))
    path_raw = _first_str(entry.get("path"))
    if not rule_id or not path_raw:
        return None
    start: dict[str, Any] = entry["start"] if isinstance(entry.get("start"), dict) else {}
    end: dict[str, Any] = entry["end"] if isinstance(entry.get("end"), dict) else {}
    extra: dict[str, Any] = entry["extra"] if isinstance(entry.get("extra"), dict) else {}

    start_line = _int_field(start, "line")
    start_col = _int_field(start, "col")
    end_line = _int_field(end, "line") or start_line
    end_col = _int_field(end, "col")

    severity = _severity_from_extra(extra)
    message = _first_str(extra.get("message")) or rule_id
    rel_file = _normalize_path(path_raw, scan_root)

    # Defense in depth: redact any credential-shaped strings before they
    # land in the user-visible title/message.
    safe_message = redact_text(message)

    # AppSec Platform supplies its own fingerprint; we keep it verbatim
    # as ``raw_fingerprint`` and ALSO build our own composite so cross-
    # platform installs (CE vs AppSec) stay comparable in baseline.
    raw_fp = _first_str(extra.get("fingerprint"))
    composite = _composite_fingerprint(
        rule_id=rule_id,
        rel_file=rel_file,
        start_line=start_line,
        start_col=start_col,
        end_line=end_line,
        end_col=end_col,
    )

    references = _collect_references(extra)
    cwe = _first_cwe(extra)

    return Finding(
        scanner="sast",
        rule_id=rule_id,
        severity=severity,
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
        raw_fingerprint=raw_fp,
        cwe=cwe,
        references=references,
    )


def _severity_from_extra(extra: dict[str, Any]) -> Severity:
    label = extra.get("severity")
    if isinstance(label, str):
        normalized = label.strip().upper()
        if normalized in _SEMGREP_SEVERITY_MAP:
            return _SEMGREP_SEVERITY_MAP[normalized]
    return Severity.UNKNOWN


_REFERENCE_MAX_LEN = 200
_REFERENCE_ALLOWED_SCHEME = ("https://", "http://")


def _sanitize_reference(ref: str) -> str | None:
    """Apply defense-in-depth to a single reference string.

    Semgrep ruleset metadata is effectively user-controlled (anyone can
    publish or PR a rule). Codex 12th review flagged that letting the
    string flow into the reporter verbatim opens up control-character
    injection, ANSI escapes, credential leaks, and unbounded length.
    Caller already type-checked; we just sanitize.
    """
    # Strip surrounding whitespace and control chars (including ANSI ESC).
    cleaned = "".join(ch for ch in ref if ch.isprintable() and ch not in ("\x1b",))
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    if not cleaned.startswith(_REFERENCE_ALLOWED_SCHEME):
        return None
    if len(cleaned) > _REFERENCE_MAX_LEN:
        cleaned = cleaned[: _REFERENCE_MAX_LEN - 3] + "..."
    cleaned = redact_text(cleaned)
    return cleaned


def _collect_references(extra: dict[str, Any]) -> tuple[str, ...]:
    metadata: dict[str, Any] = (
        extra["metadata"] if isinstance(extra.get("metadata"), dict) else {}
    )
    candidates: list[str] = []
    references = metadata.get("references")
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, str) and ref:
                candidates.append(ref)
    elif isinstance(references, str) and references:
        candidates.append(references)
    source = metadata.get("source")
    if isinstance(source, str) and source:
        candidates.append(source)

    refs: list[str] = []
    for cand in candidates:
        cleaned = _sanitize_reference(cand)
        if cleaned and cleaned not in refs:
            refs.append(cleaned)
    return tuple(refs[:5])  # cap


def _first_cwe(extra: dict[str, Any]) -> str | None:
    metadata: dict[str, Any] = (
        extra["metadata"] if isinstance(extra.get("metadata"), dict) else {}
    )
    cwe_raw = metadata.get("cwe")
    if isinstance(cwe_raw, list):
        for c in cwe_raw:
            if isinstance(c, str) and c:
                # Semgrep metadata often holds "CWE-79: ...". Keep just the
                # leading "CWE-NN" identifier for consistency with deps.
                head = c.split(":", 1)[0].strip()
                if head.startswith("CWE"):
                    return head
    elif isinstance(cwe_raw, str) and cwe_raw:
        head = cwe_raw.split(":", 1)[0].strip()
        if head.startswith("CWE"):
            return head
    return None


def _coerce_semgrep_configs(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(v).strip() for v in value if isinstance(v, str) and v.strip())
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    return ()


def _reject_unsafe_configs(
    configs: Sequence[str], *, scan_root: Path, allow_unverified: bool
) -> tuple[str, ...]:
    """Return the configs that are NOT in the default-safe set.

    Default-safe means:
    - Semgrep registry shorthand starting with ``p/`` or ``r/`` (Semgrep's
      public ruleset namespaces), OR
    - A local filesystem path under the scan root.

    Anything else (arbitrary URL, absolute path outside the scan root, etc.)
    requires the user to opt in via ``[sast].allow_unverified_configs=true``.

    Codex 12th review: an untrusted PR that modifies ``.secscan.toml`` could
    otherwise tell semgrep to fetch a malicious ruleset (which can include
    rule actions that exfiltrate code via patterns / metavariables) or to
    read out-of-tree files. This gate is a reasonable middle ground for
    MVP — strict by default, opt-in if needed.
    """
    if allow_unverified:
        return ()
    bad: list[str] = []
    for cfg in configs:
        if cfg.startswith(("p/", "r/")):
            continue
        # Codex 13th review: URL-like strings (anything with a scheme
        # separator) must NEVER fall into the path-resolution branch.
        # ``Path("https://evil/rules.yml").resolve()`` happily produces
        # ``<cwd>/https:/evil/rules.yml`` which then passes the
        # ``relative_to(scan_root)`` check when ``cwd == scan_root``.
        if "://" in cfg:
            bad.append(cfg)
            continue
        # Treat as a path; accept if it resolves under the scan root.
        try:
            candidate = Path(cfg).resolve(strict=False)
            scan_root_resolved = scan_root.resolve(strict=False)
            candidate.relative_to(scan_root_resolved)
            # Inside the scan root → safe.
            continue
        except (ValueError, OSError):
            pass
        bad.append(cfg)
    return tuple(bad)


def _composite_fingerprint(
    *,
    rule_id: str,
    rel_file: str | None,
    start_line: int | None,
    start_col: int | None,
    end_line: int | None,
    end_col: int | None,
) -> str:
    parts = (
        "sast",
        rule_id,
        rel_file or "",
        str(start_line or 0),
        str(start_col or 0),
        str(end_line or 0),
        str(end_col or 0),
    )
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _normalize_path(raw: str, scan_root: Path) -> str | None:
    if not raw:
        return None
    p = Path(raw)
    try:
        candidate = p if p.is_absolute() else (scan_root / p)
        rel = candidate.resolve(strict=False).relative_to(scan_root.resolve(strict=False))
        return rel.as_posix()
    except ValueError:
        return p.as_posix()


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int_field(d: object, key: str) -> int | None:
    if isinstance(d, dict):
        value = d.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _error(
    reason: str,
    *,
    stderr: bytes,
    returncode: int | None,
    duration: float,
) -> ScanOutcome:
    excerpt: str | None = None
    if stderr:
        excerpt = truncate(redact_text(decode_output(stderr)))
        if not excerpt:
            excerpt = None
    safe_reason = truncate(redact_text(reason), limit=300)
    return ScanOutcome(
        scanner="sast",
        error=ScannerError(
            scanner="sast",
            reason=safe_reason,
            stderr_excerpt=excerpt,
            returncode=returncode,
        ),
        duration_seconds=duration,
    )
