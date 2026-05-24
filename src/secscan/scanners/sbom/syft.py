"""``docker run`` argv builder for the Syft step.

Phase 2-N: Syft generates a CycloneDX JSON SBOM from a directory
target or an OCI image target. The SBOM is written to the
intermediate volume; Grype reads it in the next step.

Syft is NOT invoked when the operator's target is already an SBOM
file — in that case the pipeline skips straight to Grype.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..image.trivy import validate_image_ref as _validate_image_ref_strict
from ._pinned import DEFAULT_SYFT_IMAGE, DEFAULT_TARGET_PLATFORM
from .validators import (
    DirectoryTarget,
    ImageTarget,
    SbomInputError,
    Target,
    validate_intermediate_volume_name,
    validate_platform,
)

# In-container layout: Syft writes the SBOM to ``/work/sbom.cdx.json``
# and uses ``/work`` for its own cache + tmpdir (HOME / TMPDIR
# overrides). Grype later mounts the same path read-only.
_WORK_DIR = "/work"
_SBOM_FILENAME = "sbom.cdx.json"
SBOM_OUT_PATH = f"{_WORK_DIR}/{_SBOM_FILENAME}"


@dataclass(frozen=True)
class SyftInvocation:
    """Resolved inputs for one Syft step."""

    target: Target
    """``DirectoryTarget`` or ``ImageTarget`` only. A ``SbomFileTarget``
    skips Syft entirely — the pipeline never builds this dataclass
    for that branch."""

    intermediate_volume: str
    scanner_image: str = DEFAULT_SYFT_IMAGE
    platform: str = DEFAULT_TARGET_PLATFORM


def build_argv(invocation: SyftInvocation) -> list[str]:
    """Build the ``docker run`` argv for one Syft invocation.

    Layout (positional order matters)::

        docker run --rm \
          --cap-drop=ALL --security-opt=no-new-privileges \
          --network=bridge \
          -v <intermediate-volume>:/work \
          [-v <source-path>:/scan:ro]   (only for DirectoryTarget)
          -e HOME=/work -e TMPDIR=/work \
          -- <syft-image> <syft-target> \
          --platform <platform>   (only for ImageTarget)
          -o cyclonedx-json=/work/sbom.cdx.json

    Design pins (Codex MUST-FIX #1/#3):

    - Output is **always** ``-o cyclonedx-json=<path>``; we never
      rely on Syft's default (table) output.
    - ``--platform`` is forwarded to Syft's *CLI* for image targets
      so multi-arch index digests resolve deterministically. It is
      NOT placed on the ``docker run`` invocation (Apple Silicon
      Rosetta crashes Syft 1.x under linux/amd64 emulation; we
      keep the scanner container on the host's native arch).
    - The intermediate volume is mounted ``rw`` here — this is the
      only point in the pipeline that writes to it. Grype's step
      mounts the same volume ``ro`` so a buggy Syft can't smuggle
      data Grype then sees as "current".
    - ``HOME``/``TMPDIR`` env vars point at the writable
      intermediate volume so Syft 1.x's filesystem cache (a hard
      requirement; without a writable cache dir Syft fails to
      resolve registry images) doesn't try to mkdir ``/.cache``
      with no privileges.
    """
    scanner_image = _validate_image_ref_strict(
        invocation.scanner_image, label="syft scanner_image"
    )
    volume = validate_intermediate_volume_name(invocation.intermediate_volume)
    target = invocation.target

    docker_args: list[str] = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
        "-v",
        f"{volume}:{_WORK_DIR}",
        "-e",
        f"HOME={_WORK_DIR}",
        "-e",
        f"TMPDIR={_WORK_DIR}",
    ]

    if isinstance(target, DirectoryTarget):
        docker_args.extend(["-v", f"{target.path}:/scan:ro"])
        syft_target = "dir:/scan"
    elif isinstance(target, ImageTarget):
        syft_target = f"registry:{target.ref}"
    else:
        raise SbomInputError(
            "SyftInvocation.target must be DirectoryTarget or ImageTarget; "
            f"got {type(target).__name__}"
        )

    docker_args.extend(["--", scanner_image, syft_target])

    if isinstance(target, ImageTarget):
        platform = validate_platform(invocation.platform)
        docker_args.extend(["--platform", platform])

    docker_args.extend(["-o", f"cyclonedx-json={SBOM_OUT_PATH}"])
    return docker_args


def classify_syft_exit(returncode: int, *, timed_out: bool) -> tuple[bool, str | None]:
    if timed_out:
        return False, "syft sbom generation timed out"
    if returncode == 0:
        return True, None
    return False, f"syft exited with {returncode}"


__all__: Sequence[str] = (
    "SBOM_OUT_PATH",
    "SyftInvocation",
    "build_argv",
    "classify_syft_exit",
)
