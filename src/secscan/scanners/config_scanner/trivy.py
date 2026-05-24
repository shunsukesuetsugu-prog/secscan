"""Pure helpers for the Trivy / docker config-scan adapter.

Mirrors ``scanners.dast.zap`` for the configuration-scanning case
(IaC: Kubernetes manifests, Terraform, Dockerfile, Helm, etc.).
Everything in this module is side-effect-free and unit-tested
without docker.

Security boundary (inherits from DAST Phase 2-D/H decisions):

- Image refs MUST be ``<repo>[:tag]@sha256:<64 hex>``. Leading ``-``
  is rejected. ``--`` separator between docker options and the
  image is mandatory.
- Bind-mounted scan path is read-only (``:ro``) — Trivy never
  needs to write to the scan tree.
- ``--cap-drop=ALL --security-opt=no-new-privileges --network=none``.
  Trivy config scanning is purely local (reads the bundled check
  policies from the image), so blocking outbound network is safe.
- Container runs as the image's default user (root inside Trivy),
  but with ``--cap-drop=ALL`` it has no Linux caps and the host
  bind mount is read-only — defence in depth.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ...models import Finding, Location, Severity
from ...redact import redact_text, truncate
from ...runner import decode_output
from ._pinned import DEFAULT_TRIVY_IMAGE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCANNER_NAME = "config"

# Trivy uses its own 5-level severity ladder. Map directly to ours.
# UNKNOWN stays UNKNOWN (Policy decides what to do with it).
_TRIVY_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.UNKNOWN,
}

# In-container mount point for the scan target. Read-only by design.
_TRIVY_WORK_DIR = "/work"

# Image ref validator — same shape as ``dast.zap.validate_image_ref``.
_IMAGE_REF_RE = re.compile(
    r"^"
    r"(?P<repo>[a-z0-9][a-z0-9._\-]*"
    r"(?:/[a-z0-9][a-z0-9._\-]*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}))?"
    r"@sha256:(?P<digest>[0-9a-f]{64})"
    r"$"
)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


class ConfigInputError(ValueError):
    """Caller-supplied input we refuse for the config scanner."""


def validate_image_ref(image: str) -> str:
    """Reject anything that is not a digest-pinned OCI image ref.

    Same posture as ``dast.zap.validate_image_ref`` — see that
    function's docstring for the full security rationale.
    """
    if not isinstance(image, str):
        raise ConfigInputError("--trivy-image must be a string")
    candidate = image.strip()
    if not candidate:
        raise ConfigInputError("--trivy-image must not be empty")
    if candidate.startswith("-"):
        raise ConfigInputError(
            "--trivy-image must not start with '-' (would be interpreted "
            "as a docker flag)"
        )
    if any(ch.isspace() or not ch.isprintable() for ch in candidate):
        raise ConfigInputError(
            "--trivy-image must not contain whitespace or control characters"
        )
    if not _IMAGE_REF_RE.match(candidate):
        raise ConfigInputError(
            "--trivy-image must be of the form "
            "'<repo>[:tag]@sha256:<64 hex>' (digest pinning is required)"
        )
    return candidate


def validate_scan_path(scan_root: Path) -> Path:
    """Resolve and sanity-check the bind-mount source path.

    ``scan_root`` is what we'll mount into the Trivy container as
    ``/work:ro``. The path MUST be:

    - absolute (so docker's bind-mount parser has no ambiguity);
    - existing (``.is_dir()``);
    - free of ``:`` in its string form (otherwise docker would
      treat the second colon as a mount-option separator);
    - not starting with ``-`` (defence in depth — caller cannot
      smuggle a docker flag);
    - free of control / non-printable characters (Codex Phase 2-L
      diff review: an attacker-controlled scan_root with embedded
      newlines or NULs could confuse docker's argv parser on
      certain platforms — reject outright).
    """
    if not isinstance(scan_root, Path):
        raise ConfigInputError("scan_root must be a Path")
    resolved = scan_root.resolve()
    if not resolved.is_dir():
        raise ConfigInputError(f"scan_root does not exist or is not a directory: {resolved}")
    s = str(resolved)
    if ":" in s:
        raise ConfigInputError(
            "scan_root must not contain ':' (docker would interpret "
            "it as a bind-mount option separator)"
        )
    if s.startswith("-"):
        raise ConfigInputError("scan_root must not start with '-'")
    if any(not ch.isprintable() for ch in s):
        raise ConfigInputError(
            "scan_root must not contain control or non-printable characters"
        )
    return resolved


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrivyInvocation:
    """Resolved inputs for a single Trivy config-scan invocation."""

    scan_root: Path
    image_ref: str
    severity_floor: str = "UNKNOWN"
    """Minimum Trivy severity to include. ``"UNKNOWN"`` (default) means
    all findings flow through; the secscan Policy layer makes the
    threshold call. We could pass ``--severity HIGH,CRITICAL`` to
    Trivy itself but doing so loses LOW/MEDIUM findings we'd want
    to display even if they're below the fail-on threshold."""


def build_argv(invocation: TrivyInvocation) -> list[str]:
    """Build the ``docker run`` argv for Trivy config scan.

    Layout (positional ordering matters):

      docker run \
        --rm \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --network=none \
        -v <abs>:/work:ro \
        -- <image> \
        config --quiet --format json /work

    The ``--`` separator before the image is mandatory (Codex
    Phase 2-D pin — see ``zap.build_argv`` for the rationale).
    ``--network=none`` is safe for Trivy config scans: the policy
    bundles ship inside the image, no outbound calls needed.
    """
    image_ref = validate_image_ref(invocation.image_ref)
    scan_root = validate_scan_path(invocation.scan_root)
    return [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=none",
        "-v",
        f"{scan_root}:{_TRIVY_WORK_DIR}:ro",
        "--",
        image_ref,
        "config",
        "--quiet",
        "--format",
        "json",
        _TRIVY_WORK_DIR,
    ]


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrivyReportParse:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    tool_version: str | None


# Maximum stdout size we accept from Trivy. A well-formed
# config-scan report on a typical repo is ~10-200 KiB; even a
# heavily-misconfigured monorepo rarely exceeds 5 MiB. We cap at
# 32 MiB to bound memory while leaving plenty of headroom for
# pathological IaC trees.
#
# Codex Phase 2-L diff review: an attacker who controls the
# scanned tree (untrusted PR adding malformed YAML that makes
# Trivy emit gigabytes of nonsense) should not be able to OOM
# secscan. The cap is enforced in ``parse_trivy_report``.
_MAX_REPORT_BYTES = 32 * 1024 * 1024


def parse_trivy_report(
    stdout: bytes,
    *,
    scan_root: Path,
) -> TrivyReportParse:
    """Parse Trivy JSON output into normalized Findings.

    Trivy emits one JSON object with::

        {
          "SchemaVersion": 2,
          "Trivy": {"Version": "X.Y.Z"},
          "Results": [
            {
              "Target": "deployment.yaml",
              "Type": "kubernetes",
              "Misconfigurations": [
                {
                  "ID": "KSV-0017",
                  "Severity": "HIGH",
                  "Title": "...",
                  "Description": "...",
                  "References": ["https://avd.aquasec.com/..."],
                  "CauseMetadata": {"StartLine": 12, ...}
                }, ...
              ]
            }, ...
          ]
        }

    We extract each Misconfiguration into a Finding. ``Results``
    entries without ``Misconfigurations`` are skipped silently
    (Trivy reports them for traceability — e.g. "this file was
    scanned and found clean").
    """
    if len(stdout) > _MAX_REPORT_BYTES:
        return TrivyReportParse(
            findings=(),
            warnings=(
                f"config: trivy report exceeded {_MAX_REPORT_BYTES} bytes "
                "(refusing to parse — possible OOM avoidance)",
            ),
            tool_version=None,
        )
    text = decode_output(stdout)
    if not text.strip():
        return TrivyReportParse(
            findings=(),
            warnings=("config: trivy report was empty",),
            tool_version=None,
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return TrivyReportParse(
            findings=(),
            warnings=(f"config: trivy report not valid JSON ({exc.msg})",),
            tool_version=None,
        )
    if not isinstance(payload, dict):
        return TrivyReportParse(
            findings=(),
            warnings=("config: trivy report root was not a JSON object",),
            tool_version=None,
        )

    tool_version = None
    trivy_meta = payload.get("Trivy")
    if isinstance(trivy_meta, dict):
        v = trivy_meta.get("Version")
        if isinstance(v, str) and v.strip():
            tool_version = v.strip()

    results = payload.get("Results")
    if results is None:
        # Trivy emits no Results when no files were detected as
        # IaC. Surface a warning so the operator notices ("are
        # there actually any k8s manifests / TF / Dockerfile in
        # this tree?") but don't error.
        return TrivyReportParse(
            findings=(),
            warnings=(
                "config: trivy detected zero config files in the scan tree",
            ),
            tool_version=tool_version,
        )
    if not isinstance(results, list):
        return TrivyReportParse(
            findings=(),
            warnings=("config: trivy 'Results' was not a list",),
            tool_version=tool_version,
        )

    findings: list[Finding] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        target = _first_str(entry.get("Target")) or ""
        miscs = entry.get("Misconfigurations")
        if not isinstance(miscs, list):
            continue
        for m in miscs:
            finding = _finding_from_misc(m, target=target, scan_root=scan_root, seen=seen)
            if finding is not None:
                findings.append(finding)
    return TrivyReportParse(
        findings=tuple(findings),
        warnings=tuple(warnings),
        tool_version=tool_version,
    )


def _finding_from_misc(
    misc: object,
    *,
    target: str,
    scan_root: Path,
    seen: set[str],
) -> Finding | None:
    if not isinstance(misc, dict):
        return None
    check_id = _first_str(misc.get("ID"))
    if not check_id:
        return None
    severity_raw = _first_str(misc.get("Severity")) or "UNKNOWN"
    severity = _TRIVY_SEVERITY_MAP.get(severity_raw.upper(), Severity.UNKNOWN)
    title = _first_str(misc.get("Title")) or check_id
    description = _first_str(misc.get("Description")) or ""
    message = truncate(redact_text(description or title))

    cause_raw = misc.get("CauseMetadata")
    cause: dict[str, object] = cause_raw if isinstance(cause_raw, dict) else {}
    # Codex Phase 2-L diff review: clamp line numbers to ``>= 1``.
    # A negative ``StartLine`` from a tampered Trivy report could
    # confuse downstream consumers (SARIF formatters in particular
    # treat negative coordinates as undefined).
    start_line = _positive_line(cause.get("StartLine"))
    end_line = _positive_line(cause.get("EndLine"))

    # CWE / references: Trivy emits References as a list of URLs.
    refs = _references_from_misc(misc)
    cwe = _cwe_from_misc(misc)

    # File path: ``Target`` is relative to the bind-mount root
    # (e.g. ``deployment.yaml`` or ``app/Dockerfile``). Surface
    # it relative to ``scan_root`` for consistency with the other
    # scanners.
    rel_file = _normalize_target_path(target, scan_root)

    fingerprint = _fingerprint(check_id, rel_file, start_line)
    if fingerprint in seen:
        return None
    seen.add(fingerprint)

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=check_id,
        severity=severity,
        title=truncate(redact_text(title)),
        message=message,
        location=Location(
            file=rel_file,
            line=start_line,
            end_line=end_line,
        ),
        fingerprint=fingerprint,
        cwe=cwe,
        references=refs,
    )


def _fingerprint(check_id: str, rel_file: str | None, start_line: int | None) -> str:
    parts = ("config", check_id, rel_file or "", str(start_line or 0))
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


_REFERENCE_LIMIT = 5
_REFERENCE_URL_RE = re.compile(r"https?://[^\s\"<>]+")


def _references_from_misc(misc: dict[str, object]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    raw_refs = misc.get("References")
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if not isinstance(ref, str):
                continue
            for url in _REFERENCE_URL_RE.findall(ref):
                clean = url.rstrip(".,;:)")
                clean = redact_text(clean)
                if clean in seen:
                    continue
                seen.add(clean)
                out.append(clean)
                if len(out) >= _REFERENCE_LIMIT:
                    return tuple(out)
    return tuple(out)


_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_CWE_MITRE_URL_RE = re.compile(
    r"cwe\.mitre\.org/data/definitions/(\d+)\.html",
    re.IGNORECASE,
)


def _extract_cwe_from_text(text: str) -> str | None:
    """Return the first ``CWE-N`` reference found in ``text``.

    Recognises two shapes:
    - Literal ``CWE-798`` anywhere in the text (case-insensitive).
    - The ``cwe.mitre.org/data/definitions/NNN.html`` URL pattern,
      which Trivy frequently emits in ``References`` for k8s and
      Dockerfile checks. We rebuild the canonical ``CWE-NNN`` form
      from the URL's numeric segment.
    """
    m = _CWE_RE.search(text)
    if m:
        return m.group(0).upper()
    m2 = _CWE_MITRE_URL_RE.search(text)
    if m2:
        return f"CWE-{m2.group(1)}"
    return None


def _cwe_from_misc(misc: dict[str, object]) -> str | None:
    """Best-effort CWE extraction.

    Trivy doesn't ship a stable CWE field on every check (the
    schema varies by check family). We look in:

    1. ``CauseMetadata.CWE`` if present (rare but exists).
    2. ``References`` URLs (literal ``CWE-N`` or cwe.mitre.org form).
    3. ``Description`` text containing ``CWE-N``.
    """
    # 1. structured field
    cause = misc.get("CauseMetadata")
    if isinstance(cause, dict):
        v = cause.get("CWE")
        if isinstance(v, str):
            found = _extract_cwe_from_text(v)
            if found:
                return found
    # 2. references
    refs = misc.get("References")
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, str):
                found = _extract_cwe_from_text(r)
                if found:
                    return found
    # 3. description text
    desc = misc.get("Description")
    if isinstance(desc, str):
        found = _extract_cwe_from_text(desc)
        if found:
            return found
    return None


def _normalize_target_path(target: str, scan_root: Path) -> str | None:
    if not target:
        return None
    # Codex Phase 2-L diff review: reject control / non-printable
    # characters in Target. A tampered Trivy report with NUL /
    # newline in the path would propagate to Finding.location.file
    # and downstream consumers (SARIF, text renderer) — strip the
    # path entirely in that case rather than emit hostile output.
    if any(not ch.isprintable() for ch in target):
        return None
    # Trivy reports targets either as just the filename (when run
    # against a single file) or as a path relative to the scanned
    # root. Either way, the path is already relative-ish; we
    # forward-slash normalise it for display.
    p = Path(target)
    if p.is_absolute():
        # If Trivy somehow emits an absolute path (rare), strip
        # the bind-mount prefix so the operator sees a relative
        # path. The container's mount is at /work — strip that.
        try:
            rel = p.relative_to("/work")
            return rel.as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix()


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _first_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _positive_line(value: object) -> int | None:
    """Codex Phase 2-L diff review: clamp line numbers to ``>= 1``.

    A negative or zero value from a tampered Trivy report is
    silently dropped to ``None`` rather than propagated to
    Finding.location — downstream formatters (SARIF in particular)
    treat 0/negative coordinates as undefined behaviour.
    """
    n = _first_int(value)
    if n is None or n < 1:
        return None
    return n


# ---------------------------------------------------------------------------
# Exit code classification
# ---------------------------------------------------------------------------


_TRIVY_SUCCESS_EXIT_CODES = frozenset({0})


def classify_trivy_exit(returncode: int, *, timed_out: bool) -> tuple[bool, str | None]:
    """Trivy returns 0 when the scan completes (regardless of
    findings). Any other exit is a tool failure — typically a
    config-file parse error, registry / network problem, or a
    crashed Trivy process. Pass-through to ``_error`` so the
    operator sees the actual reason.
    """
    if timed_out:
        return False, "trivy config scan timed out"
    if returncode in _TRIVY_SUCCESS_EXIT_CODES:
        return True, None
    return False, f"trivy config exited with {returncode}"


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


__all__: Sequence[str] = (
    "DEFAULT_TRIVY_IMAGE",
    "ConfigInputError",
    "TrivyInvocation",
    "TrivyReportParse",
    "build_argv",
    "classify_trivy_exit",
    "parse_trivy_report",
    "validate_image_ref",
    "validate_scan_path",
)
