"""pyrasp event log parser.

Phase 2-P: pyrasp writes one JSON object per detection to its
event log file. We read the file after the harness terminates
the app, filter for events tagged with the current run_id, and
emit one ``Finding`` per matched event.

Event filtering by run_id (Codex Phase 2-P design review
MUST-FIX #5) is the load-bearing security control here: an
event with a missing or mismatched run_id is treated as
"belongs to a previous run, ignore". Without this gate a stale
log file from a previous secscan run could pollute the current
output.

The file format we accept is **either**:

- One JSON object per line (NDJSON), or
- A JSON array of objects (`[{...}, {...}, ...]`).

pyrasp's official format is NDJSON; we accept the array form
to remain compatible with operator scripts that aggregate
multiple pyrasp logs into one file before handing it to
secscan.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ...models import Finding, Location
from ...redact import redact_text, truncate
from .probes import severity_for_category
from .validators import (
    MAX_PYRASP_LOG_BYTES,
    IastInputError,
)

_SCANNER_NAME = "iast"

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


@dataclass(frozen=True)
class PyraspLogParse:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    tool_version: str | None
    events_total: int = 0
    events_matched_run_id: int = 0
    out_of_run_events: int = 0
    """Codex Phase 2-P design review FIX_NEEDED: surface the
    count of events that DON'T carry our run_id. A non-zero
    value here means either (a) operator gave us a log file
    that pyrasp shared with another writer (which is
    indistinguishable from log pollution) or (b) pyrasp's
    library wrote events without honouring our run-id tag.
    Either way the operator should know."""

    extra: dict[str, object] = field(default_factory=dict)


def parse_pyrasp_log(
    log_path: Path, *, run_id: str
) -> PyraspLogParse:
    """Read ``log_path`` and yield a normalized parse result.

    The full file is loaded into memory and capped at 32 MiB
    (Codex MUST-FIX #5 carry-over). Lines that fail
    ``json.loads`` become warnings; the parser continues so
    one malformed line does not abort the rest.
    """
    if not isinstance(log_path, Path):
        raise IastInputError("log_path must be a pathlib.Path")
    try:
        size = log_path.stat().st_size
    except FileNotFoundError:
        return PyraspLogParse(
            findings=(),
            warnings=(
                f"iast: pyrasp log {log_path} does not exist — "
                "the operator's app may not have written any events "
                "(no probes triggered pyrasp's rules)",
            ),
            tool_version=None,
        )
    if size == 0:
        return PyraspLogParse(
            findings=(),
            warnings=(
                f"iast: pyrasp log {log_path} is empty — "
                "no events were written during this run",
            ),
            tool_version=None,
        )
    if size > MAX_PYRASP_LOG_BYTES:
        return PyraspLogParse(
            findings=(),
            warnings=(
                f"iast: pyrasp log {log_path} is {size} bytes, exceeds the "
                f"{MAX_PYRASP_LOG_BYTES}-byte cap (refusing to parse — "
                "possible OOM avoidance)",
            ),
            tool_version=None,
        )
    text = log_path.read_text(encoding="utf-8", errors="replace")
    return _parse_text(text, run_id=run_id)


def _parse_text(text: str, *, run_id: str) -> PyraspLogParse:
    if not text.strip():
        return PyraspLogParse(
            findings=(),
            warnings=("iast: pyrasp log was empty",),
            tool_version=None,
        )

    events: list[object] = []
    warnings: list[str] = []
    stripped = text.lstrip()
    # JSON array form: a single top-level ``[...]``.
    if stripped.startswith("["):
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            warnings.append(
                f"iast: pyrasp log array parse failed ({type(exc).__name__})"
            )
            return PyraspLogParse(
                findings=(),
                warnings=tuple(warnings),
                tool_version=None,
            )
        if not isinstance(parsed, list):
            warnings.append(
                "iast: pyrasp log root was not a JSON array"
            )
            return PyraspLogParse(
                findings=(),
                warnings=tuple(warnings),
                tool_version=None,
            )
        events.extend(parsed)
    else:
        # NDJSON: one object per line.
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped_line = line.strip()
            if not stripped_line:
                continue
            try:
                events.append(json.loads(stripped_line))
            except json.JSONDecodeError as exc:
                warnings.append(
                    f"iast: pyrasp log line {line_number} not JSON ({exc.msg})"
                )
                continue
            except (RecursionError, ValueError) as exc:
                warnings.append(
                    f"iast: pyrasp log line {line_number} rejected "
                    f"({type(exc).__name__})"
                )
                continue

    return _events_to_parse(events, run_id=run_id, warnings=warnings)


def _events_to_parse(
    events: list[object],
    *,
    run_id: str,
    warnings: list[str],
) -> PyraspLogParse:
    findings: list[Finding] = []
    seen: set[str] = set()
    tool_version: str | None = None
    matched_count = 0
    out_of_run = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        # pyrasp version field appears either as ``pyrasp_version`` at
        # the top level or under ``meta.version``. Either is fine.
        if tool_version is None:
            v = event.get("pyrasp_version")
            if isinstance(v, str) and v.strip():
                tool_version = v.strip()
            else:
                meta = event.get("meta")
                if isinstance(meta, dict):
                    mv = meta.get("version")
                    if isinstance(mv, str) and mv.strip():
                        tool_version = mv.strip()

        # Run-id gate (Codex MUST-FIX #5).
        observed_run_id = _extract_run_id(event)
        if observed_run_id is None:
            # Event lacks any run-id hint — could be a pyrasp event
            # from a different writer. We don't drop those silently;
            # they're counted as out-of-run.
            out_of_run += 1
            continue
        if observed_run_id != run_id:
            out_of_run += 1
            continue
        matched_count += 1

        finding = _finding_from_event(event, seen=seen)
        if finding is not None:
            findings.append(finding)

    if out_of_run > 0:
        warnings.append(
            f"iast: ignored {out_of_run} pyrasp event(s) without "
            "the current run_id (stale log entries or events from a "
            "different writer)"
        )

    return PyraspLogParse(
        findings=tuple(findings),
        warnings=tuple(warnings),
        tool_version=tool_version,
        events_total=len(events),
        events_matched_run_id=matched_count,
        out_of_run_events=out_of_run,
    )


def _extract_run_id(event: dict[str, object]) -> str | None:
    """Look up the secscan run_id inside a pyrasp event.

    pyrasp lets the operator configure custom header names to
    capture. Our convention is that the operator configures
    pyrasp to record the ``X-Secscan-Run-Id`` header. The event
    structure varies by pyrasp version, so we look in several
    well-known nesting positions.
    """
    # Direct top-level convenience field — most parser-friendly
    # shape and what our docs recommend for operator pyrasp
    # configuration.
    rid = event.get("secscan_run_id")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    # Inside ``request.headers``: pyrasp's standard event shape.
    req = event.get("request")
    if isinstance(req, dict):
        headers = req.get("headers")
        if isinstance(headers, dict):
            for header_key, header_value in headers.items():
                if not isinstance(header_key, str):
                    continue
                if header_key.lower() != "x-secscan-run-id":
                    continue
                if isinstance(header_value, str) and header_value.strip():
                    return header_value.strip()
                if isinstance(header_value, list) and header_value:
                    first = header_value[0]
                    if isinstance(first, str) and first.strip():
                        return first.strip()
        # Some pyrasp versions stash query parameters under
        # ``request.query`` as a flat dict.
        query = req.get("query")
        if isinstance(query, dict):
            qv = query.get("secscan_run")
            if isinstance(qv, str) and qv.strip():
                return qv.strip()
    return None


def _finding_from_event(
    event: dict[str, object], *, seen: set[str]
) -> Finding | None:
    rule_id = _first_str(event.get("rule")) or _first_str(
        event.get("event")
    )
    if not rule_id:
        return None
    category = _first_str(event.get("category")) or _first_str(
        event.get("event")
    ) or "unknown"
    severity = severity_for_category(category)

    matched_pattern = _first_str(event.get("matched_pattern")) or ""
    request = event.get("request") if isinstance(
        event.get("request"), dict
    ) else {}
    method = ""
    path = ""
    if isinstance(request, dict):
        method = _first_str(request.get("method")) or ""
        path = (
            _first_str(request.get("path"))
            or _first_str(request.get("uri"))
            or ""
        )

    title = f"{rule_id}: {method} {path}".strip(": ").strip()
    body_parts = []
    if method or path:
        body_parts.append(f"{method} {path}".strip())
    if matched_pattern:
        body_parts.append(f"matched: {matched_pattern}")
    description = _first_str(event.get("description")) or ""
    if description:
        body_parts.append(description)
    message = truncate(
        redact_text(" — ".join(p for p in body_parts if p) or rule_id)
    )

    cwe = _extract_cwe(event)
    fingerprint = _fingerprint(rule_id, category, method, path, matched_pattern)
    if fingerprint in seen:
        return None
    seen.add(fingerprint)

    method_slug = "".join(
        ch for ch in method.upper() if ch.isalpha()
    ) or "ANY"
    path_slug = path or "/"
    location_label = f"iast/{method_slug}{path_slug}"

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=rule_id,
        severity=severity,
        title=truncate(redact_text(title)),
        message=message,
        location=Location(file=location_label),
        fingerprint=fingerprint,
        cwe=cwe,
    )


def _extract_cwe(event: dict[str, object]) -> str | None:
    """pyrasp sometimes includes a ``cwe`` field on events; fall
    back to scanning a free-text ``description`` for the literal
    ``CWE-N`` pattern. Same shape as Phase 2-N's grype CWE
    extractor."""
    v = event.get("cwe")
    if isinstance(v, str) and v.strip():
        m = _CWE_RE.search(v)
        if m:
            return m.group(0).upper()
    desc = event.get("description")
    if isinstance(desc, str):
        m = _CWE_RE.search(desc)
        if m:
            return m.group(0).upper()
    return None


def _fingerprint(
    rule_id: str,
    category: str,
    method: str,
    path: str,
    matched_pattern: str,
) -> str:
    pattern_digest = hashlib.sha256(
        (matched_pattern or "").encode("utf-8")
    ).hexdigest()[:16]
    parts = ("iast", rule_id, category, method, path, pattern_digest)
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__: Sequence[str] = (
    "PyraspLogParse",
    "parse_pyrasp_log",
)
