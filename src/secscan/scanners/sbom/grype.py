"""``docker run`` argv builder + JSON parser for the Grype step.

Phase 2-N: Grype reads an SBOM (CycloneDX or SPDX JSON) and matches
each package against its vulnerability database. The output is one
JSON object with a ``matches`` array; each match has
``vulnerability`` + ``artifact`` + ``matchDetails`` blocks.

The parser normalises each match into a :class:`Finding`. Severity
maps directly from Grype's 6-level ladder (Critical / High /
Medium / Low / Negligible / Unknown). CWE comes from the
``vulnerability.cwes`` array (already structured ``CWE-N`` strings;
no regex extraction needed).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from ...models import Finding, Location, Severity
from ...redact import redact_text, truncate
from ...runner import decode_output
from ..image.trivy import validate_image_ref as _validate_image_ref_strict
from ._pinned import DEFAULT_GRYPE_IMAGE
from .syft import SBOM_OUT_PATH
from .validators import (
    MAX_SBOM_BYTES,
    SbomInputError,
    validate_cache_volume_name,
    validate_intermediate_volume_name,
)

_SCANNER_NAME = "sbom"

# Mirror Phase 2-M: a Grype report on a heavily-vulnerable image can
# reach a few MiB; 32 MiB caps OOM avoidance.
_MAX_REPORT_BYTES = MAX_SBOM_BYTES

# Grype's 6-level severity ladder → secscan Severity enum. Grype
# capitalises severity names (``"Critical"``); we lowercase before
# lookup so we don't depend on Grype's case staying stable.
_GRYPE_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}

_GRYPE_DB_DIR = "/.cache/grype/db"
_WORK_DIR = "/work"


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GrypeInvocation:
    """Resolved inputs for one Grype CVE-match invocation.

    Two source modes:

    - ``intermediate_volume`` set + ``sbom_file_path`` None:
      Grype reads the SBOM at ``/work/sbom.cdx.json`` from a
      named volume Syft populated in the previous step.
    - ``intermediate_volume`` None + ``sbom_file_path`` set:
      Grype reads an operator-supplied SBOM file mounted
      read-only at ``/sbom/sbom.json``.
    """

    scanner_image: str = DEFAULT_GRYPE_IMAGE
    intermediate_volume: str | None = None
    sbom_file_path: str | None = None
    cache_volume: str = ""
    """Optional Grype DB cache volume (mounted RO when set,
    combined with ``GRYPE_DB_AUTO_UPDATE=false`` env). Bench mode
    only — production runs let Grype update its DB on demand."""

    extra_argv: tuple[str, ...] = field(default_factory=tuple)


# In-container path for SBOM file targets (read-only mount).
SBOM_FILE_MOUNT = "/sbom/sbom.json"


def build_argv(invocation: GrypeInvocation) -> list[str]:
    """Build the ``docker run`` argv for one Grype invocation.

    Two layouts, depending on the SBOM source::

        # Via intermediate volume (post-Syft step)
        docker run --rm --cap-drop=ALL --security-opt=no-new-privileges
          --network=bridge
          -v <intermediate-volume>:/work:ro
          [-v <cache-volume>:/.cache/grype/db:ro -e GRYPE_DB_AUTO_UPDATE=false]
          -e HOME=/work -e TMPDIR=/work
          -- <grype-image> sbom:/work/sbom.cdx.json -o json

        # Direct SBOM file (operator supplied)
        docker run --rm ... --network=bridge
          -v <sbom-file>:/sbom/sbom.json:ro
          [...cache volume...]
          -- <grype-image> sbom:/sbom/sbom.json -o json
    """
    scanner_image = _validate_image_ref_strict(
        invocation.scanner_image, label="grype scanner_image"
    )
    has_volume = invocation.intermediate_volume is not None
    has_file = invocation.sbom_file_path is not None
    if has_volume == has_file:
        # Either both or neither — both cases are an internal bug.
        raise SbomInputError(
            "GrypeInvocation must have exactly one of "
            "intermediate_volume or sbom_file_path"
        )

    docker_args: list[str] = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
    ]

    if has_volume:
        volume = validate_intermediate_volume_name(
            invocation.intermediate_volume or ""
        )
        docker_args.extend(["-v", f"{volume}:{_WORK_DIR}:ro"])
        sbom_arg = f"sbom:{SBOM_OUT_PATH}"
    else:
        # SBOM file mount. The path here flows from the validator
        # chain in ``validators.py`` so it's already charset-clean.
        # We still strip a defensive last check: leading dash, no
        # spaces, no colons.
        host_path = invocation.sbom_file_path or ""
        if (
            not host_path
            or host_path.startswith("-")
            or " " in host_path
            or ":" in host_path
            or "\n" in host_path
        ):
            raise SbomInputError(
                f"sbom_file_path {host_path!r} is not safe for a docker "
                "bind mount"
            )
        docker_args.extend(["-v", f"{host_path}:{SBOM_FILE_MOUNT}:ro"])
        sbom_arg = f"sbom:{SBOM_FILE_MOUNT}"

    if invocation.cache_volume:
        cache = validate_cache_volume_name(invocation.cache_volume)
        docker_args.extend(["-v", f"{cache}:{_GRYPE_DB_DIR}:ro"])
        docker_args.extend(["-e", "GRYPE_DB_AUTO_UPDATE=false"])

    # IMPORTANT: do NOT redirect HOME/TMPDIR into the RO /work
    # mount. Grype needs a writable tmpdir for its DB listing file
    # even when ``--skip-db-update`` is set; redirecting it at /work
    # would force Grype to attempt a write to the RO volume and
    # crash. The in-container writable layer (default ``/tmp``) is
    # safe — ``--rm`` discards it at exit.
    docker_args.extend(
        [
            "--",
            scanner_image,
            sbom_arg,
            "-o",
            "json",
        ]
    )
    for token in invocation.extra_argv:
        if not isinstance(token, str):
            raise SbomInputError("Grype extra_argv entries must be strings")
        if token.startswith("-") and any(
            ch.isspace() or not ch.isprintable() for ch in token
        ):
            raise SbomInputError(
                f"Grype extra_argv entry {token!r} contains whitespace or "
                "control characters"
            )
        docker_args.append(token)
    return docker_args


def build_db_seed_argv(
    *,
    scanner_image: str = DEFAULT_GRYPE_IMAGE,
    cache_volume: str,
) -> list[str]:
    """Build a one-shot argv to pre-populate the Grype DB cache.

    Bench/CI uses this once at the start of an sbom-bench run so
    subsequent scans share the same DB snapshot and don't repull
    from the registry. Mounts the volume RW (the ONLY place that
    writes to it); ``build_argv`` mounts the same volume RO.
    """
    scanner_image = _validate_image_ref_strict(
        scanner_image, label="grype scanner_image"
    )
    volume = validate_cache_volume_name(cache_volume)
    return [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
        "-v",
        f"{volume}:{_GRYPE_DB_DIR}",
        "--",
        scanner_image,
        "db",
        "update",
    ]


def classify_grype_exit(returncode: int, *, timed_out: bool) -> tuple[bool, str | None]:
    if timed_out:
        return False, "grype scan timed out"
    # Grype returns 0 for "scan completed", regardless of findings.
    # A non-zero exit is a tool failure (DB missing, SBOM parse
    # error, registry timeout, etc.).
    if returncode == 0:
        return True, None
    return False, f"grype exited with {returncode}"


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GrypeReportParse:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    tool_version: str | None
    artifact_count: int = 0


_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_REFERENCE_URL_RE = re.compile(r"https?://[^\s\"<>]+")
_REFERENCE_LIMIT = 5


def parse_grype_report(
    stdout: bytes,
    *,
    target_label: str,
) -> GrypeReportParse:
    """Parse a Grype JSON report into normalized Findings.

    Schema (Grype 0.x)::

        {
          "matches": [
            {
              "vulnerability": {
                "id": "CVE-2022-37434",
                "severity": "Critical",
                "description": "...",
                "urls": ["https://nvd..."],
                "cwes": ["CWE-787"],
                "fix": {"versions": ["..."], "state": "fixed"},
                "dataSource": "https://nvd.nist.gov/..."
              },
              "artifact": {
                "name": "zlib",
                "version": "1.2.11-r3",
                "type": "apk",
                "purl": "pkg:apk/alpine/zlib@1.2.11-r3"
              },
              "matchDetails": [...]
            },
            ...
          ],
          "descriptor": {
            "name": "grype",
            "version": "0.X.Y"
          }
        }

    ``target_label`` is the operator-facing identifier of what
    Grype scanned (image ref / directory / SBOM filename) — used
    as the synthetic Finding location so reports show *which*
    target each match came from.
    """
    if len(stdout) > _MAX_REPORT_BYTES:
        return GrypeReportParse(
            findings=(),
            warnings=(
                f"sbom: grype report exceeded {_MAX_REPORT_BYTES} bytes "
                "(refusing to parse — possible OOM avoidance)",
            ),
            tool_version=None,
        )
    text = decode_output(stdout)
    if not text.strip():
        return GrypeReportParse(
            findings=(),
            warnings=("sbom: grype report was empty",),
            tool_version=None,
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return GrypeReportParse(
            findings=(),
            warnings=(f"sbom: grype report not valid JSON ({exc.msg})",),
            tool_version=None,
        )
    if not isinstance(payload, dict):
        return GrypeReportParse(
            findings=(),
            warnings=("sbom: grype report root was not a JSON object",),
            tool_version=None,
        )

    tool_version: str | None = None
    descriptor = payload.get("descriptor")
    if isinstance(descriptor, dict):
        v = descriptor.get("version")
        if isinstance(v, str) and v.strip():
            tool_version = v.strip()

    matches = payload.get("matches")
    if matches is None:
        return GrypeReportParse(
            findings=(),
            warnings=("sbom: grype reported zero matches block",),
            tool_version=tool_version,
        )
    if not isinstance(matches, list):
        return GrypeReportParse(
            findings=(),
            warnings=("sbom: grype 'matches' was not a list",),
            tool_version=tool_version,
        )

    # ArtifactCount: useful for sanity-checking SBOM completeness
    # (a "zero CVEs" report is much more meaningful when we know
    # Grype actually saw N packages).
    artifacts_seen: set[tuple[str, str]] = set()

    findings: list[Finding] = []
    seen: set[str] = set()
    for entry in matches:
        finding = _finding_from_match(
            entry, target_label=target_label, seen=seen
        )
        if finding is not None:
            findings.append(finding)
            if finding.location and finding.location.package:
                artifacts_seen.add(
                    (finding.location.package, finding.rule_id)
                )

    return GrypeReportParse(
        findings=tuple(findings),
        warnings=(),
        tool_version=tool_version,
        artifact_count=len(artifacts_seen),
    )


def _finding_from_match(
    match: object,
    *,
    target_label: str,
    seen: set[str],
) -> Finding | None:
    if not isinstance(match, dict):
        return None
    vuln = match.get("vulnerability")
    if not isinstance(vuln, dict):
        return None
    vuln_id = _first_str(vuln.get("id"))
    if not vuln_id:
        return None
    severity_raw = _first_str(vuln.get("severity")) or "Unknown"
    severity = _GRYPE_SEVERITY_MAP.get(
        severity_raw.lower(), Severity.UNKNOWN
    )

    artifact = match.get("artifact")
    pkg_name = ""
    pkg_version = ""
    pkg_type = ""
    if isinstance(artifact, dict):
        pkg_name = _first_str(artifact.get("name")) or ""
        pkg_version = _first_str(artifact.get("version")) or ""
        pkg_type = _first_str(artifact.get("type")) or ""

    title_raw = _first_str(vuln.get("description")) or vuln_id
    fix_hint = _fix_hint(vuln.get("fix"))
    pkg_label = (
        f"{pkg_name} {pkg_version}"
        if pkg_name and pkg_version
        else (pkg_name or "")
    )
    body_parts: list[str] = []
    if pkg_label:
        body_parts.append(pkg_label)
    if fix_hint:
        body_parts.append(fix_hint)
    body_prefix = "; ".join(body_parts)
    message_raw = (
        f"{body_prefix}: {title_raw}" if body_prefix else title_raw
    )
    message = truncate(redact_text(message_raw))
    title = truncate(redact_text(vuln_id))

    cwe = _cwe_from_vuln(vuln)
    refs = _references_from_vuln(vuln)

    location_label = _location_label(target_label, pkg_type)
    fingerprint = _fingerprint(
        vuln_id, pkg_name, pkg_version, location_label
    )
    if fingerprint in seen:
        return None
    seen.add(fingerprint)

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=vuln_id,
        severity=severity,
        title=title,
        message=message,
        location=Location(
            file=location_label,
            package=pkg_name or None,
            ecosystem=pkg_type or None,
        ),
        fingerprint=fingerprint,
        cwe=cwe,
        references=refs,
    )


def _fix_hint(fix: object) -> str:
    if not isinstance(fix, dict):
        return ""
    state = _first_str(fix.get("state"))
    versions = fix.get("versions")
    if isinstance(versions, list) and versions:
        first_fix = next(
            (v for v in versions if isinstance(v, str) and v.strip()),
            None,
        )
        if first_fix:
            return f"fixed in {first_fix}"
    if state == "not-fixed":
        return "no fix available"
    if state == "wont-fix":
        return "will not be fixed"
    return ""


def _cwe_from_vuln(vuln: dict[str, object]) -> str | None:
    cwes = vuln.get("cwes")
    if isinstance(cwes, list):
        for c in cwes:
            if not isinstance(c, str):
                continue
            stripped = c.strip().upper()
            if _CWE_RE.fullmatch(stripped):
                return stripped
    # Fallback: scan description text for a literal ``CWE-N``.
    desc = vuln.get("description")
    if isinstance(desc, str):
        m = _CWE_RE.search(desc)
        if m:
            return m.group(0).upper()
    return None


def _references_from_vuln(vuln: dict[str, object]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    # Prefer dataSource (single canonical URL) before urls list.
    ds = vuln.get("dataSource")
    if isinstance(ds, str):
        for url in _REFERENCE_URL_RE.findall(ds):
            clean = redact_text(url.rstrip(".,;:)"))
            if clean and clean not in seen:
                seen.add(clean)
                out.append(clean)
    urls = vuln.get("urls")
    if isinstance(urls, list):
        for u in urls:
            if not isinstance(u, str):
                continue
            for url in _REFERENCE_URL_RE.findall(u):
                clean = redact_text(url.rstrip(".,;:)"))
                if not clean or clean in seen:
                    continue
                seen.add(clean)
                out.append(clean)
                if len(out) >= _REFERENCE_LIMIT:
                    return tuple(out)
    return tuple(out)


def _location_label(target_label: str, pkg_type: str) -> str:
    label = "".join(ch for ch in (target_label or "") if ch.isprintable())
    cls = "".join(
        ch for ch in (pkg_type or "pkgs") if ch.isalnum() or ch in "-_"
    )
    return f"sbom/{cls}/{label}".rstrip("/")


def _fingerprint(
    vuln_id: str, pkg_name: str, pkg_version: str, location: str
) -> str:
    parts = ("sbom", vuln_id, pkg_name, pkg_version, location)
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__: Sequence[str] = (
    "SBOM_FILE_MOUNT",
    "GrypeInvocation",
    "GrypeReportParse",
    "build_argv",
    "build_db_seed_argv",
    "classify_grype_exit",
    "parse_grype_report",
)
