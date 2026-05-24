"""Pinned default Trivy image digest.

Phase 2-L: ``secscan config`` invokes Aqua Security's Trivy via
Docker. The image is addressed by ``repository@sha256:<digest>``
the same way the ZAP image is pinned for DAST (Phase 2-D).

Rotate this constant when upgrading Trivy:

1. ``docker pull aquasec/trivy:<version>``
2. ``docker inspect --format='{{index .RepoDigests 0}}' aquasec/trivy:<version>``
3. Update ``DEFAULT_TRIVY_IMAGE`` + ``DEFAULT_TRIVY_IMAGE_PINNED_AT``
4. Re-run the config bench to refresh the expected check-ID sets.
"""

from __future__ import annotations

DEFAULT_TRIVY_IMAGE_REPOSITORY = "aquasec/trivy"

# Trivy 0.70.0 (May 2026). Pulled fresh during Phase 2-L
# implementation; verified via ``docker pull`` then ``docker inspect``.
DEFAULT_TRIVY_IMAGE_DIGEST = (
    "be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
)

DEFAULT_TRIVY_IMAGE = (
    f"{DEFAULT_TRIVY_IMAGE_REPOSITORY}@sha256:{DEFAULT_TRIVY_IMAGE_DIGEST}"
)

DEFAULT_TRIVY_IMAGE_PINNED_AT = "2026-05-24"
"""ISO date when the default digest was last rotated."""
