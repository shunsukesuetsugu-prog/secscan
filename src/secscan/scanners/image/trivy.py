"""Pure helpers for the Trivy / docker image-vulnerability adapter.

Mirrors ``scanners.config_scanner.trivy`` (Phase 2-L), but for the
``trivy image`` subcommand: scan a built OCI image for CVEs in OS
packages and language packages (npm/pip/maven/etc.). Everything
in this module is side-effect-free and unit-tested without docker.

Security boundary (inherits the same posture as Phase 2-D / 2-L):

- All image refs (the Trivy scanner image AND the *target* image
  we're scanning) MUST be ``<repo>[:tag]@sha256:<64 hex>``. Leading
  ``-`` is rejected. ``--`` separator between docker options and
  the scanner image is mandatory.
- ``--cap-drop=ALL --security-opt=no-new-privileges``.
- ``--network=bridge`` is *necessary* (Trivy must pull the target
  image from the registry, and absent a pre-seeded cache it also
  pulls its vulnerability DB from ghcr.io). The DAST module made
  the same trade-off; ``--network=none`` is impossible here.
- Trivy cache volume (when provided) is bind-mounted **read-only**
  so a scan invocation can't corrupt the seeded DB.
- ``--platform`` is always set so multi-arch index digests resolve
  deterministically across hosts.
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
from ._pinned import DEFAULT_TARGET_PLATFORM, DEFAULT_TRIVY_IMAGE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCANNER_NAME = "image"

_TRIVY_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.UNKNOWN,
}

# Identical regex to Phase 2-D / 2-L. Duplicated rather than imported
# to keep this module a leaf with no cross-scanner coupling.
_IMAGE_REF_RE = re.compile(
    r"^"
    r"(?P<repo>[a-z0-9][a-z0-9._\-]*"
    r"(?:/[a-z0-9][a-z0-9._\-]*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}))?"
    r"@sha256:(?P<digest>[0-9a-f]{64})"
    r"$"
)

# Docker --platform syntax: "<os>/<arch>[/<variant>]" — restrict to
# the small alphabet docker itself accepts. Reject anything with
# whitespace, control chars, or a leading '-'.
_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]*(?:/[a-z0-9][a-z0-9._\-]*){1,2}$")

# Docker named-volume reference: must look like a docker volume name
# (no slashes, no leading dash, no special chars). The bench passes
# its own seeded volume; CLI users normally leave this empty so
# Trivy uses its in-container default cache dir.
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")

# In-container Trivy cache dir — matches Trivy's default.
_TRIVY_CACHE_DIR = "/root/.cache/trivy"


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


class ImageInputError(ValueError):
    """Caller-supplied input we refuse for the image scanner."""


def validate_image_ref(image: str, *, label: str = "--image") -> str:
    """Reject anything that is not a digest-pinned OCI image ref.

    Used for BOTH the Trivy scanner image and each target image.
    ``label`` lets the error message disambiguate the two.
    """
    if not isinstance(image, str):
        raise ImageInputError(f"{label} must be a string")
    candidate = image.strip()
    if not candidate:
        raise ImageInputError(f"{label} must not be empty")
    if candidate.startswith("-"):
        raise ImageInputError(
            f"{label} must not start with '-' (would be interpreted "
            "as a docker flag)"
        )
    if any(ch.isspace() or not ch.isprintable() for ch in candidate):
        raise ImageInputError(
            f"{label} must not contain whitespace or control characters"
        )
    if not _IMAGE_REF_RE.match(candidate):
        raise ImageInputError(
            f"{label} must be of the form "
            "'<repo>[:tag]@sha256:<64 hex>' (digest pinning is required)"
        )
    return candidate


def validate_platform(platform: str) -> str:
    """Reject anything that isn't a docker --platform value.

    Codex Phase 2-M design pin (item C): an unvalidated platform
    string lands inside ``docker run --platform <p>``. A value like
    ``--privileged`` would be flag-interpreted; whitespace would
    split the argv element. The regex is strict on purpose: every
    real platform docker accepts (``linux/amd64``, ``linux/arm64``,
    ``linux/arm/v7``, …) fits within ``[a-z0-9._-]`` separated by
    forward slashes.
    """
    if not isinstance(platform, str):
        raise ImageInputError("--platform must be a string")
    candidate = platform.strip()
    if not candidate:
        raise ImageInputError("--platform must not be empty")
    if candidate.startswith("-"):
        raise ImageInputError(
            "--platform must not start with '-' (would be interpreted "
            "as a docker flag)"
        )
    if not _PLATFORM_RE.match(candidate):
        raise ImageInputError(
            f"--platform value {candidate!r} is not a valid docker "
            "platform string (expected '<os>/<arch>[/<variant>]')"
        )
    return candidate


def validate_cache_volume(volume: str) -> str:
    """Reject anything that isn't a plausible docker volume name.

    Bench's pre-seeded ``secscan-trivy-image-cache`` volume flows
    through here. Refuse a path-like value (would otherwise be
    interpreted as a bind-mount source) and anything starting with
    ``-`` (would be flag-interpreted at argv position).
    """
    if not isinstance(volume, str):
        raise ImageInputError("cache_volume must be a string")
    candidate = volume.strip()
    if not candidate:
        raise ImageInputError("cache_volume must not be empty")
    if "/" in candidate or candidate.startswith("-"):
        raise ImageInputError(
            f"cache_volume {candidate!r} must be a docker volume name, "
            "not a path (no '/'), and must not start with '-'"
        )
    if not _VOLUME_NAME_RE.match(candidate):
        raise ImageInputError(
            f"cache_volume {candidate!r} contains characters outside "
            "the docker volume-name charset [A-Za-z0-9_.-]"
        )
    return candidate


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrivyImageInvocation:
    """Resolved inputs for a single ``trivy image`` invocation.

    One invocation scans one target image. Multiple targets are
    handled by the scanner adapter looping over invocations and
    accumulating the findings.
    """

    target_image: str
    scanner_image: str = DEFAULT_TRIVY_IMAGE
    platform: str = DEFAULT_TARGET_PLATFORM
    cache_volume: str = ""
    """Empty: Trivy downloads its DB on every invocation (default
    operator behaviour). Non-empty: a named docker volume holding
    a pre-seeded ``trivy-db``; mounted read-only and combined with
    ``--skip-db-update`` for deterministic / offline scans (bench
    workflow)."""

    extra_argv: tuple[str, ...] = field(default_factory=tuple)
    """Reserved for future per-image options (e.g. ``--ignore-unfixed``).
    Each element is appended verbatim *after* the validated argv
    backbone; callers MUST validate every element themselves."""


def build_argv(invocation: TrivyImageInvocation) -> list[str]:
    """Build the ``docker run`` argv for one ``trivy image`` scan.

    Layout::

        docker run \
          --rm \
          --cap-drop=ALL \
          --security-opt=no-new-privileges \
          --network=bridge \
          --platform <platform> \
          [-v <volume>:/root/.cache/trivy:ro] \
          -- <scanner-image> \
          image --quiet --format json --platform <platform> \
          [--skip-db-update] \
          <target-image>

    Notes on the design:

    - ``--`` separates docker options from the scanner image (the
      Codex Phase 2-D / 2-L pin — without it, an image starting with
      ``-`` could be argv-interpreted as a flag if the regex ever
      regressed).
    - ``--platform`` appears on BOTH the docker layer (so the
      *scanner* container runs on the host's matching arch) and
      the Trivy CLI layer (so the *target* image's per-arch
      manifest is selected reproducibly).
    - When a cache volume is given, ``--skip-db-update`` is added
      to the Trivy CLI so the seeded DB is used as-is. Without a
      cache volume, Trivy pulls its DB on every invocation (slow
      but always current).
    - ``--network=none`` is impossible here — Trivy must reach the
      registry to pull the target image. See module docstring.
    """
    scanner_image = validate_image_ref(invocation.scanner_image, label="scanner_image")
    target_image = validate_image_ref(invocation.target_image, label="--image")
    platform = validate_platform(invocation.platform)

    argv: list[str] = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
        "--platform",
        platform,
    ]

    if invocation.cache_volume:
        volume = validate_cache_volume(invocation.cache_volume)
        argv.extend(["-v", f"{volume}:{_TRIVY_CACHE_DIR}:ro"])

    argv.extend(
        [
            "--",
            scanner_image,
            "image",
            "--quiet",
            "--format",
            "json",
            "--platform",
            platform,
        ]
    )
    if invocation.cache_volume:
        argv.append("--skip-db-update")
    # Codex Phase 2-M design pin: extra_argv is appended LAST so it
    # cannot reorder the validated backbone, and BEFORE the target
    # image so target stays at the final positional slot.
    for token in invocation.extra_argv:
        if not isinstance(token, str):
            raise ImageInputError("extra_argv entries must be strings")
        if token.startswith("-") and any(
            ch.isspace() or not ch.isprintable() for ch in token
        ):
            raise ImageInputError(
                f"extra_argv entry {token!r} contains whitespace or "
                "control characters"
            )
        argv.append(token)
    argv.append(target_image)
    return argv


def build_db_seed_argv(
    *,
    scanner_image: str = DEFAULT_TRIVY_IMAGE,
    platform: str = DEFAULT_TARGET_PLATFORM,
    cache_volume: str,
) -> list[str]:
    """Build a one-shot argv to pre-populate the Trivy cache volume.

    Run by the bench harness once at the start of an image-bench run::

        docker run \
          --rm --cap-drop=ALL --security-opt=no-new-privileges \
          --network=bridge --platform linux/amd64 \
          -v secscan-trivy-image-cache:/root/.cache/trivy \
          -- <scanner-image> image --download-db-only

    The volume is mounted **read-write** here (the only place we
    grant write access). Subsequent ``build_argv`` calls mount the
    same volume read-only and pass ``--skip-db-update`` so the DB
    is taken as-is. This is the deterministic-bench mode Codex
    flagged as MUST-FIX during the Phase 2-M design review.
    """
    scanner_image = validate_image_ref(scanner_image, label="scanner_image")
    platform = validate_platform(platform)
    volume = validate_cache_volume(cache_volume)
    return [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
        "--platform",
        platform,
        "-v",
        f"{volume}:{_TRIVY_CACHE_DIR}",
        "--",
        scanner_image,
        "image",
        "--download-db-only",
    ]


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrivyImageReportParse:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    tool_version: str | None
    target_image: str | None


# Same 32 MiB cap as Phase 2-L. A Trivy report on a multi-layer
# image with many CVEs can reach several MiB; 32 MiB leaves plenty
# of headroom while bounding memory if something goes wrong.
_MAX_REPORT_BYTES = 32 * 1024 * 1024


def parse_trivy_image_report(
    stdout: bytes,
    *,
    target_image: str,
) -> TrivyImageReportParse:
    """Parse Trivy image JSON output into normalized Findings.

    Trivy emits one JSON object with::

        {
          "SchemaVersion": 2,
          "Trivy": {"Version": "X.Y.Z"},
          "ArtifactName": "alpine:3.10",
          "Results": [
            {
              "Target": "alpine:3.10 (alpine 3.10.9)",
              "Type": "alpine",
              "Class": "os-pkgs",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2021-3711",
                  "PkgName": "openssl",
                  "InstalledVersion": "1.1.1k-r0",
                  "FixedVersion": "1.1.1l-r0",
                  "Severity": "CRITICAL",
                  "Title": "...",
                  "Description": "...",
                  "PrimaryURL": "https://avd.aquasec.com/...",
                  "References": [...],
                  "CweIDs": ["CWE-787"]
                }, ...
              ]
            }, ...
          ]
        }

    We extract each Vulnerability into a Finding. ``Results``
    entries without ``Vulnerabilities`` are skipped silently.
    """
    if len(stdout) > _MAX_REPORT_BYTES:
        return TrivyImageReportParse(
            findings=(),
            warnings=(
                f"image: trivy report exceeded {_MAX_REPORT_BYTES} bytes "
                "(refusing to parse — possible OOM avoidance)",
            ),
            tool_version=None,
            target_image=target_image,
        )
    text = decode_output(stdout)
    if not text.strip():
        return TrivyImageReportParse(
            findings=(),
            warnings=("image: trivy report was empty",),
            tool_version=None,
            target_image=target_image,
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return TrivyImageReportParse(
            findings=(),
            warnings=(f"image: trivy report not valid JSON ({exc.msg})",),
            tool_version=None,
            target_image=target_image,
        )
    if not isinstance(payload, dict):
        return TrivyImageReportParse(
            findings=(),
            warnings=("image: trivy report root was not a JSON object",),
            tool_version=None,
            target_image=target_image,
        )

    tool_version: str | None = None
    trivy_meta = payload.get("Trivy")
    if isinstance(trivy_meta, dict):
        v = trivy_meta.get("Version")
        if isinstance(v, str) and v.strip():
            tool_version = v.strip()

    # Trivy emits the actual artifact name it scanned. If it doesn't,
    # we keep the caller's target_image — they're usually identical
    # but the report value (with its OS tag suffix) is more useful
    # for the display location.
    artifact_name = _first_str(payload.get("ArtifactName")) or target_image

    results = payload.get("Results")
    if results is None:
        # Trivy returns no Results when an image is fully clean
        # (or when Trivy didn't understand the image format).
        # Either way: zero findings + a soft warning so the
        # operator notices "no CVEs reported" wasn't because the
        # scan failed.
        return TrivyImageReportParse(
            findings=(),
            warnings=(
                "image: trivy returned zero scannable layers for "
                f"{artifact_name!r}",
            ),
            tool_version=tool_version,
            target_image=artifact_name,
        )
    if not isinstance(results, list):
        return TrivyImageReportParse(
            findings=(),
            warnings=("image: trivy 'Results' was not a list",),
            tool_version=tool_version,
            target_image=artifact_name,
        )

    findings: list[Finding] = []
    seen: set[str] = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        result_target = _first_str(entry.get("Target")) or artifact_name
        result_class = _first_str(entry.get("Class")) or ""
        vulns = entry.get("Vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            finding = _finding_from_vuln(
                v,
                result_target=result_target,
                result_class=result_class,
                artifact_name=artifact_name,
                seen=seen,
            )
            if finding is not None:
                findings.append(finding)
    return TrivyImageReportParse(
        findings=tuple(findings),
        warnings=(),
        tool_version=tool_version,
        target_image=artifact_name,
    )


def _finding_from_vuln(
    vuln: object,
    *,
    result_target: str,
    result_class: str,
    artifact_name: str,
    seen: set[str],
) -> Finding | None:
    if not isinstance(vuln, dict):
        return None
    vuln_id = _first_str(vuln.get("VulnerabilityID"))
    if not vuln_id:
        return None
    severity_raw = _first_str(vuln.get("Severity")) or "UNKNOWN"
    severity = _TRIVY_SEVERITY_MAP.get(severity_raw.upper(), Severity.UNKNOWN)

    pkg_name = _first_str(vuln.get("PkgName")) or ""
    installed = _first_str(vuln.get("InstalledVersion")) or ""
    fixed = _first_str(vuln.get("FixedVersion")) or ""

    title = _first_str(vuln.get("Title")) or vuln_id
    description = _first_str(vuln.get("Description")) or ""

    # Compose a human-readable message that surfaces the affected
    # package and an upgrade hint. The package + installed-version
    # pair is what the operator needs to act, and they're often
    # missing from a bare "Description" field.
    msg_parts: list[str] = []
    if pkg_name:
        if installed:
            msg_parts.append(f"{pkg_name} {installed}")
        else:
            msg_parts.append(pkg_name)
    if fixed:
        msg_parts.append(f"fixed in {fixed}")
    pkg_hint = "; ".join(msg_parts)
    body = description or title
    message_raw = f"{pkg_hint}: {body}" if pkg_hint else body
    message = truncate(redact_text(message_raw))

    cwe = _cwe_from_vuln(vuln)
    refs = _references_from_vuln(vuln)

    # Image findings have no source file/line — they're attached
    # to an *image layer* + package. We synthesise a "location"
    # that points at the artifact path (e.g. ``alpine:3.10
    # (alpine 3.10.9)``) so reports show *which* image emitted
    # the finding without leaking host filesystem paths.
    rel_location = _location_label(result_target, result_class, artifact_name)

    fingerprint = _fingerprint(vuln_id, pkg_name, installed, rel_location)
    if fingerprint in seen:
        return None
    seen.add(fingerprint)

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=vuln_id,
        severity=severity,
        title=truncate(redact_text(title)),
        message=message,
        location=Location(
            file=rel_location,
            package=pkg_name or None,
        ),
        fingerprint=fingerprint,
        cwe=cwe,
        references=refs,
    )


def _location_label(
    result_target: str, result_class: str, artifact_name: str
) -> str:
    """Synthesize a stable, non-sensitive location label.

    Trivy's ``Target`` for OS packages looks like
    ``alpine:3.10 (alpine 3.10.9)``; for language packages it's
    ``app/node_modules/...``. We forward-slash normalise and clamp
    to printable ASCII so a tampered report can't smuggle control
    chars into ``Finding.location.file``.
    """
    label = result_target or artifact_name
    label = "".join(ch for ch in label if ch.isprintable())
    # Prefix with the scanner namespace + class so a SARIF/text
    # consumer can tell `image/os-pkgs/...` from a real file path.
    klass = result_class or "pkgs"
    klass = "".join(ch for ch in klass if ch.isalnum() or ch in "-_")
    return f"image/{klass}/{label}".rstrip("/")


def _fingerprint(
    vuln_id: str, pkg_name: str, installed: str, location: str
) -> str:
    parts = ("image", vuln_id, pkg_name, installed, location)
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


_REFERENCE_LIMIT = 5
_REFERENCE_URL_RE = re.compile(r"https?://[^\s\"<>]+")


def _references_from_vuln(vuln: dict[str, object]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    # Prefer PrimaryURL first, then References.
    primary = vuln.get("PrimaryURL")
    if isinstance(primary, str):
        for url in _REFERENCE_URL_RE.findall(primary):
            clean = redact_text(url.rstrip(".,;:)"))
            if clean not in seen:
                seen.add(clean)
                out.append(clean)
    raw_refs = vuln.get("References")
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if not isinstance(ref, str):
                continue
            for url in _REFERENCE_URL_RE.findall(ref):
                clean = redact_text(url.rstrip(".,;:)"))
                if clean in seen:
                    continue
                seen.add(clean)
                out.append(clean)
                if len(out) >= _REFERENCE_LIMIT:
                    return tuple(out)
    return tuple(out)


_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _cwe_from_vuln(vuln: dict[str, object]) -> str | None:
    """Best-effort CWE extraction.

    Image-mode Trivy emits a structured ``CweIDs`` array on most
    vulnerabilities. If present, use the first entry. Otherwise
    fall back to scanning Description and References for the
    literal ``CWE-N`` pattern.
    """
    cwes = vuln.get("CweIDs")
    if isinstance(cwes, list):
        for c in cwes:
            if isinstance(c, str) and _CWE_RE.fullmatch(c.strip().upper()):
                return c.strip().upper()
    desc = vuln.get("Description")
    if isinstance(desc, str):
        m = _CWE_RE.search(desc)
        if m:
            return m.group(0).upper()
    refs = vuln.get("References")
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, str):
                m = _CWE_RE.search(r)
                if m:
                    return m.group(0).upper()
    return None


def _first_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


# ---------------------------------------------------------------------------
# Exit code classification
# ---------------------------------------------------------------------------


_TRIVY_SUCCESS_EXIT_CODES = frozenset({0})


def classify_trivy_image_exit(
    returncode: int, *, timed_out: bool
) -> tuple[bool, str | None]:
    if timed_out:
        return False, "trivy image scan timed out"
    if returncode in _TRIVY_SUCCESS_EXIT_CODES:
        return True, None
    return False, f"trivy image exited with {returncode}"


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


__all__: Sequence[str] = (
    "DEFAULT_TARGET_PLATFORM",
    "DEFAULT_TRIVY_IMAGE",
    "ImageInputError",
    "TrivyImageInvocation",
    "TrivyImageReportParse",
    "build_argv",
    "build_db_seed_argv",
    "classify_trivy_image_exit",
    "parse_trivy_image_report",
    "validate_cache_volume",
    "validate_image_ref",
    "validate_platform",
)
