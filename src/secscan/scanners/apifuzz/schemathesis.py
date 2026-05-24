"""``docker run`` argv builder + NDJSON parser for Schemathesis.

Phase 2-O: Schemathesis runs property-based fuzz tests against an
OpenAPI schema + base API URL. The output we consume is the
NDJSON event stream written to a named volume — each line is one
JSON event with a single top-level discriminator key (e.g.
``"ScenarioFinished": {...}``).

The parser walks the NDJSON, finds ``ScenarioFinished`` events
with ``status == "failure"``, and emits one secscan ``Finding``
per failing ``check`` block (a single scenario can fail multiple
checks against the same response — e.g. ``not_a_server_error`` +
``response_schema_conformance`` on a 500 reply with a bogus
body).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ...models import Finding, Location, Severity
from ...redact import redact_text, truncate
from ...runner import decode_output
from ..image.trivy import validate_image_ref as _validate_image_ref_strict
from ._pinned import (
    DEFAULT_HELPER_IMAGE,
    DEFAULT_SCHEMATHESIS_IMAGE,
    SCHEMATHESIS_GID,
    SCHEMATHESIS_UID,
)
from .validators import (
    MAX_REPORT_BYTES,
    ApifuzzInputError,
    Schema,
    SchemaFile,
    SchemaUrl,
    validate_api_url,
    validate_auth_header,
    validate_intermediate_volume_name,
)

_SCANNER_NAME = "apifuzz"
_WORK_DIR = "/work"
_SCHEMA_MOUNT_DIR = "/schema"
NDJSON_REPORT_PATH = f"{_WORK_DIR}/report.ndjson"

# HTTP methods Schemathesis can test. Baseline mode includes only
# the "safe" (RFC 9110 §9.2.1) methods. Active mode adds the
# mutating ones — operator must pass ``--allow-active`` to use it.
_BASELINE_METHODS = ("GET", "HEAD", "OPTIONS")

# Generation budget defaults. The bench/CI path overrides these
# with fixed values for reproducibility (Codex MUST-FIX #5).
DEFAULT_MAX_EXAMPLES = 25


# ---------------------------------------------------------------------------
# Helper-image argv (volume chown)
# ---------------------------------------------------------------------------


def build_chown_argv(*, helper_image: str, volume: str) -> list[str]:
    """Build the argv for the Alpine helper that chowns the
    intermediate volume to the Schemathesis uid/gid.

    Mirrors Phase 2-D (DAST) report-volume bootstrapping: the
    helper runs as root, chowns ``/work`` to ``1000:1000``, and
    exits. The Schemathesis container that follows runs as uid
    1000 and so can write into the volume.
    """
    helper = _validate_image_ref_strict(helper_image, label="helper_image")
    vol = validate_intermediate_volume_name(volume)
    return [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=none",
        # ``--user 0:0`` is needed for chown; the helper image is a
        # plain alpine that runs as root by default, but Docker
        # Desktop's default user namespace mapping makes this
        # explicit and defends against future image rotation.
        "--user",
        "0:0",
        "-v",
        f"{vol}:{_WORK_DIR}",
        "--",
        helper,
        "chown",
        "-R",
        f"{SCHEMATHESIS_UID}:{SCHEMATHESIS_GID}",
        _WORK_DIR,
    ]


# ---------------------------------------------------------------------------
# Schemathesis argv
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemathesisInvocation:
    """Resolved inputs for one Schemathesis ``run`` invocation."""

    schema: Schema
    api_url: str
    intermediate_volume: str
    scanner_image: str = DEFAULT_SCHEMATHESIS_IMAGE
    mode: str = "baseline"
    """``baseline`` (GET/HEAD/OPTIONS only) or ``active`` (all
    methods). Activation requires the operator to pass the
    CLI-only ``--allow-active`` flag — see ``validators.validate_mode``."""

    headers: tuple[str, ...] = ()
    """Raw ``"Name: Value"`` HTTP header strings. Each is
    re-validated via ``validators.validate_auth_header`` before
    reaching argv."""

    max_examples: int = DEFAULT_MAX_EXAMPLES
    seed: int | None = None
    """``None`` (default) → Schemathesis picks a random seed.
    Bench mode passes a fixed integer for reproducibility."""

    deterministic: bool = False
    """Bench/CI flag. Enables Schemathesis's deterministic test-
    generation mode."""

    request_timeout: float = 5.0


def build_argv(invocation: SchemathesisInvocation) -> list[str]:
    """Build the ``docker run`` argv for one Schemathesis ``run``.

    Layout::

        docker run --rm \
          --cap-drop=ALL --security-opt=no-new-privileges \
          --network=bridge \
          -v <volume>:/work \
          [-v <schema-file>:/schema/openapi.<ext>:ro]   (only for SchemaFile)
          -- <scanner-image> run <SCHEMA_LOCATION> \
          --url <API_URL> \
          --max-redirects 0 \
          --report ndjson --report-ndjson-path /work/report.ndjson \
          --generation-database :memory: \
          --output-sanitize true \
          --no-color --tls-verify true \
          [--include-method GET --include-method HEAD --include-method OPTIONS]  (baseline only)
          [--max-examples N]
          [--seed N]
          [--generation-deterministic]
          [--request-timeout F]
          [-H "Name: Value" ...]

    Design pins (Codex Phase 2-O design review):

    - ``--max-redirects 0`` is mandatory — schema-declared
      ``servers:`` URLs (which Schemathesis would otherwise follow)
      cannot redirect outside the operator-supplied ``--url``.
    - ``--report ndjson --report-ndjson-path`` is explicit; we
      never rely on Schemathesis's default report format.
    - ``--generation-database :memory:`` prevents Schemathesis
      from persisting Hypothesis examples to disk across runs,
      keeping the bench deterministic given a fixed seed.
    - ``--output-sanitize true`` redacts sensitive token-shaped
      values in Schemathesis's own logs.
    - Methods are filtered via ``--include-method`` (not
      ``--method``) per Schemathesis 4.x docs.
    """
    scanner_image = _validate_image_ref_strict(
        invocation.scanner_image, label="scanner_image"
    )
    volume = validate_intermediate_volume_name(invocation.intermediate_volume)
    api_url = validate_api_url(invocation.api_url)

    docker_args: list[str] = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
        "-v",
        f"{volume}:{_WORK_DIR}",
    ]

    schema = invocation.schema
    if isinstance(schema, SchemaFile):
        # Bind-mount the file at a fixed in-container path so the
        # schema LOCATION argument is a stable literal we control.
        from ...portability import to_docker_host_path

        suffix = schema.path.suffix.lower() or ".json"
        in_container = f"{_SCHEMA_MOUNT_DIR}/openapi{suffix}"
        docker_args.extend(
            [
                "-v",
                f"{to_docker_host_path(schema.path)}:{in_container}:ro",
            ]
        )
        schema_location = in_container
    elif isinstance(schema, SchemaUrl):
        schema_location = schema.url
    else:  # pragma: no cover — Schema is a closed union
        raise ApifuzzInputError(
            f"unexpected schema type {type(schema).__name__}"
        )

    docker_args.extend(
        [
            "--",
            scanner_image,
            "run",
            schema_location,
            "--url",
            api_url,
            "--max-redirects",
            "0",
            "--report",
            "ndjson",
            "--report-ndjson-path",
            NDJSON_REPORT_PATH,
            "--generation-database",
            ":memory:",
            "--output-sanitize",
            "true",
            "--no-color",
            "--tls-verify",
            "true",
        ]
    )

    # Method filter: baseline = read-only methods; active = no
    # filter (Schemathesis picks every method declared in the
    # schema). The validator caller has already enforced that
    # ``mode=active`` carries the second-opt-in flag.
    if invocation.mode == "baseline":
        for m in _BASELINE_METHODS:
            docker_args.extend(["--include-method", m])

    if invocation.max_examples > 0:
        docker_args.extend(["--max-examples", str(invocation.max_examples)])
    if invocation.seed is not None:
        docker_args.extend(["--seed", str(invocation.seed)])
    if invocation.deterministic:
        docker_args.append("--generation-deterministic")
    if invocation.request_timeout > 0:
        docker_args.extend(
            ["--request-timeout", f"{invocation.request_timeout:g}"]
        )

    # Auth headers — each is re-validated before going to argv so
    # a tampered ``SchemathesisInvocation.headers`` cannot escape
    # the original CLI validator.
    for raw in invocation.headers:
        name, value = validate_auth_header(raw)
        docker_args.extend(["-H", f"{name}: {value}"])

    return docker_args


def classify_schemathesis_exit(
    returncode: int, *, timed_out: bool
) -> tuple[bool, str | None]:
    """Schemathesis returns 0 when all tests pass and 1 when any
    check fails. Either is a successful RUN of the scanner — the
    failures are the findings. A non-0/1 exit is a tool error.
    """
    if timed_out:
        return False, "schemathesis scan timed out"
    if returncode in (0, 1):
        return True, None
    return False, f"schemathesis exited with {returncode}"


# ---------------------------------------------------------------------------
# Severity mapping per check name
# ---------------------------------------------------------------------------

# Map each Schemathesis built-in check to a secscan Severity. Each
# check is documented in Schemathesis CLI ``--checks`` reference.
# Unknown check names default to LOW so a future Schemathesis check
# release doesn't silently drop new findings.
_CHECK_SEVERITY: dict[str, Severity] = {
    # 5xx response from the API — almost certainly a real bug.
    "not_a_server_error": Severity.HIGH,
    # API returned a status code not declared in the OpenAPI spec.
    "status_code_conformance": Severity.MEDIUM,
    # Response body didn't match the declared schema.
    "response_schema_conformance": Severity.MEDIUM,
    # Response Content-Type didn't match the spec.
    "content_type_conformance": Severity.LOW,
    # Response headers didn't match the spec.
    "response_headers_conformance": Severity.LOW,
    # Bad input that the spec marks invalid was accepted (200/201).
    "negative_data_rejection": Severity.MEDIUM,
    # Valid input was rejected (4xx).
    "positive_data_acceptance": Severity.LOW,
    # Required header was missing yet the endpoint responded.
    "missing_required_header": Severity.LOW,
    # Spec marks a method unsupported but the endpoint accepted it.
    "unsupported_method": Severity.MEDIUM,
    # Resource id reused after delete — auth/leakage smell.
    "use_after_free": Severity.HIGH,
    # Resource that should exist but doesn't (lifecycle bug).
    "ensure_resource_availability": Severity.MEDIUM,
    # Auth was missing but the endpoint responded without 401/403.
    "ignored_auth": Severity.HIGH,
}


def severity_for_check(check_name: str) -> Severity:
    """Map a Schemathesis check name to a secscan ``Severity``.

    Unknown check names default to ``LOW`` rather than raising:
    Schemathesis adds new checks across minor versions, and we'd
    rather surface them quietly than drop them.
    """
    return _CHECK_SEVERITY.get(check_name, Severity.LOW)


# ---------------------------------------------------------------------------
# NDJSON parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemathesisReportParse:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    tool_version: str | None
    scenarios_total: int = 0
    scenarios_failed: int = 0
    out_of_scope_alerts: tuple[str, ...] = field(default_factory=tuple)


_OPERATION_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>/\S*)$")


def parse_ndjson_report(
    stdout_or_file_bytes: bytes,
    *,
    api_url: str,
) -> SchemathesisReportParse:
    """Parse a Schemathesis NDJSON report into ``Finding`` objects.

    ``stdout_or_file_bytes`` is the contents of
    ``/work/report.ndjson`` (extracted from the intermediate
    volume by the scanner adapter).

    Codex Phase 2-O design review MUST-FIX #3: each
    ``interactions.request.uri`` is checked against the
    operator-supplied ``api_url`` host/scheme. URLs that fall
    outside the trust boundary are surfaced via
    ``out_of_scope_alerts`` (the scanner adapter promotes them to
    warnings on the ScanOutcome).
    """
    if len(stdout_or_file_bytes) > MAX_REPORT_BYTES:
        return SchemathesisReportParse(
            findings=(),
            warnings=(
                f"apifuzz: ndjson report exceeded {MAX_REPORT_BYTES} bytes "
                "(refusing to parse — possible OOM avoidance)",
            ),
            tool_version=None,
        )
    text = decode_output(stdout_or_file_bytes)
    if not text.strip():
        return SchemathesisReportParse(
            findings=(),
            warnings=("apifuzz: ndjson report was empty",),
            tool_version=None,
        )

    tool_version: str | None = None
    findings: list[Finding] = []
    warnings: list[str] = []
    out_of_scope: list[str] = []
    seen_fingerprints: set[str] = set()
    scenarios_total = 0
    scenarios_failed = 0

    try:
        api_host = (urlparse(api_url).netloc or "").lower()
        api_scheme = (urlparse(api_url).scheme or "").lower()
    except ValueError:
        api_host = ""
        api_scheme = ""

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            warnings.append(
                f"apifuzz: report line {line_number} not JSON ({exc.msg})"
            )
            continue
        except (RecursionError, ValueError) as exc:
            # Codex Phase 2-O diff review MUST-FIX (DoS): a NDJSON
            # line that's structurally within the 32 MiB cap can
            # still trigger Python's recursion limit on deeply-
            # nested JSON, or raise ValueError on out-of-range
            # numerics. Catch and skip the line so one hostile
            # event doesn't abort parsing of the rest.
            warnings.append(
                f"apifuzz: report line {line_number} rejected "
                f"({type(exc).__name__})"
            )
            continue
        if not isinstance(event, dict) or not event:
            continue
        kind, body = next(iter(event.items()))

        if kind == "Initialize" and isinstance(body, dict):
            inner = body.get("Initialize", body)
            if isinstance(inner, dict):
                v = inner.get("schemathesis_version")
                if isinstance(v, str) and v.strip():
                    tool_version = v.strip()

        if kind != "ScenarioFinished" or not isinstance(body, dict):
            continue
        scenarios_total += 1

        recorder = body.get("recorder")
        if not isinstance(recorder, dict):
            continue

        # Codex Phase 2-O diff review MUST-FIX: scope detection
        # runs on ALL scenarios (including successful ones). A
        # successful scenario whose request was sent to an
        # off-scope host is still a security concern — the operator
        # needs to know Schemathesis touched something outside
        # ``--api-url`` regardless of whether the request happened
        # to "pass" the API's checks.
        interactions = recorder.get("interactions")
        if isinstance(interactions, dict) and api_host:
            for _case_id, entry in interactions.items():
                if not isinstance(entry, dict):
                    continue
                request = entry.get("request")
                if not isinstance(request, dict):
                    continue
                uri = request.get("uri")
                if not isinstance(uri, str) or not uri.strip():
                    continue
                req_parsed = urlparse(uri.strip())
                if (
                    req_parsed.netloc.lower() != api_host
                    or (
                        req_parsed.scheme.lower() != api_scheme
                        and req_parsed.scheme
                    )
                ):
                    alert = (
                        f"apifuzz: request URI {uri.strip()!r} escaped "
                        f"the --api-url scope ({api_scheme}://{api_host})"
                    )
                    if alert not in out_of_scope:
                        out_of_scope.append(alert)

        # The remainder of this block only applies to failed
        # scenarios — that's where findings come from.
        status = body.get("status")
        if status != "failure":
            continue
        scenarios_failed += 1

        op_label = _first_str(recorder.get("label")) or ""
        method, op_path = _split_operation_label(op_label)

        cases = recorder.get("cases")
        checks_block = recorder.get("checks")
        if (
            not isinstance(cases, dict)
            or not isinstance(checks_block, dict)
        ):
            continue

        for case_id, case_checks in checks_block.items():
            if not isinstance(case_checks, list):
                continue
            response_status = _extract_response_status(
                interactions, case_id
            )
            for check in case_checks:
                if not isinstance(check, dict):
                    continue
                if check.get("status") != "failure":
                    continue
                check_name = _first_str(check.get("name")) or "unknown"
                failure_msg = _extract_failure_message(check)
                fp = _fingerprint(
                    check_name=check_name,
                    method=method,
                    op_path=op_path,
                    response_status=response_status,
                    failure_msg=failure_msg,
                )
                if fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)
                findings.append(
                    _build_finding(
                        check_name=check_name,
                        op_label=op_label,
                        method=method,
                        op_path=op_path,
                        response_status=response_status,
                        failure_msg=failure_msg,
                        fingerprint=fp,
                    )
                )

    return SchemathesisReportParse(
        findings=tuple(findings),
        warnings=tuple(warnings),
        tool_version=tool_version,
        scenarios_total=scenarios_total,
        scenarios_failed=scenarios_failed,
        out_of_scope_alerts=tuple(out_of_scope),
    )


def _split_operation_label(label: str) -> tuple[str, str]:
    m = _OPERATION_RE.match(label)
    if m:
        return m.group("method"), m.group("path")
    return "", label


def _extract_response_status(
    interactions: object, case_id: str
) -> int | None:
    if not isinstance(interactions, dict):
        return None
    entry = interactions.get(case_id)
    if not isinstance(entry, dict):
        return None
    response = entry.get("response")
    if not isinstance(response, dict):
        return None
    sc = response.get("status_code")
    if isinstance(sc, int) and not isinstance(sc, bool):
        return sc
    return None


def _extract_failure_message(check: dict[str, object]) -> str:
    info = check.get("failure_info")
    if isinstance(info, dict):
        nested = info.get("failure")
        if isinstance(nested, dict):
            msg = _first_str(nested.get("message"))
            if msg:
                return msg
            t = _first_str(nested.get("type"))
            if t:
                return t
    return ""


def _build_finding(
    *,
    check_name: str,
    op_label: str,
    method: str,
    op_path: str,
    response_status: int | None,
    failure_msg: str,
    fingerprint: str,
) -> Finding:
    severity = severity_for_check(check_name)
    title_raw = f"{check_name}: {op_label}".strip(": ")
    body_parts: list[str] = []
    if op_label:
        body_parts.append(op_label)
    if response_status is not None:
        body_parts.append(f"HTTP {response_status}")
    if failure_msg:
        body_parts.append(failure_msg)
    message_raw = " — ".join(body_parts) if body_parts else check_name
    message = truncate(redact_text(message_raw))
    title = truncate(redact_text(title_raw))

    # Synthetic location label — Schemathesis findings have no file
    # but DO have a stable operation handle.
    method_slug = "".join(
        ch for ch in (method or "ANY").upper() if ch.isalpha()
    )
    op_slug = (op_path or "/").replace(" ", "_")
    location_label = f"apifuzz/{method_slug}{op_slug}"

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=check_name,
        severity=severity,
        title=title,
        message=message,
        location=Location(file=location_label),
        fingerprint=fingerprint,
    )


def _fingerprint(
    *,
    check_name: str,
    method: str,
    op_path: str,
    response_status: int | None,
    failure_msg: str,
) -> str:
    msg_digest = hashlib.sha256(
        (failure_msg or "").encode("utf-8")
    ).hexdigest()[:16]
    parts = (
        "apifuzz",
        check_name,
        method or "",
        op_path or "",
        str(response_status if response_status is not None else ""),
        msg_digest,
    )
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__: Sequence[str] = (
    "DEFAULT_HELPER_IMAGE",
    "DEFAULT_MAX_EXAMPLES",
    "DEFAULT_SCHEMATHESIS_IMAGE",
    "NDJSON_REPORT_PATH",
    "SchemathesisInvocation",
    "SchemathesisReportParse",
    "build_argv",
    "build_chown_argv",
    "classify_schemathesis_exit",
    "parse_ndjson_report",
    "severity_for_check",
)
