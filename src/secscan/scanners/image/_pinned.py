"""Pinned default Trivy image for the image-vulnerability scanner.

Phase 2-M: ``secscan image`` reuses the *same* pinned Trivy image
that Phase 2-L (``secscan config``) ships with — only the Trivy
subcommand differs (``trivy image`` vs ``trivy config``). The
value is duplicated here on purpose rather than re-imported from
``scanners.config_scanner._pinned``: each scanner module owns its
own pin so a future Trivy rotation in one place doesn't silently
drag the other along, and so an accidental ``import`` cycle stays
impossible. The ``test_pinned_images_agree`` regression test
guards against the two values drifting.

Rotate this constant when upgrading Trivy:

1. ``docker pull aquasec/trivy:<version>``
2. ``docker inspect --format='{{index .RepoDigests 0}}' aquasec/trivy:<version>``
3. Update ``DEFAULT_TRIVY_IMAGE`` + ``DEFAULT_TRIVY_IMAGE_PINNED_AT``
   here AND in ``scanners/config_scanner/_pinned.py``.
4. Re-run the image bench to refresh the expected CVE-ID sets.
"""

from __future__ import annotations

DEFAULT_TRIVY_IMAGE_REPOSITORY = "aquasec/trivy"

# Trivy 0.70.0 (May 2026). Identical to the digest pinned in
# ``scanners/config_scanner/_pinned.py``; the
# ``test_pinned_images_agree`` regression catches drift.
DEFAULT_TRIVY_IMAGE_DIGEST = (
    "be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
)

DEFAULT_TRIVY_IMAGE = (
    f"{DEFAULT_TRIVY_IMAGE_REPOSITORY}@sha256:{DEFAULT_TRIVY_IMAGE_DIGEST}"
)

DEFAULT_TRIVY_IMAGE_PINNED_AT = "2026-05-24"
"""ISO date when the default digest was last rotated."""

DEFAULT_TARGET_PLATFORM = "linux/amd64"
"""Codex Phase 2-M design pin: multi-arch image digests (the OCI
index manifest) resolve to different per-platform manifests, so
the digest alone is not a reproducibility guarantee. We force
``--platform linux/amd64`` by default and let the operator
override via ``[image].platform`` or ``--platform``."""

# Named docker volume that holds the Trivy vulnerability DB cache.
# Used by bench/run.py to seed the DB once (with
# ``trivy image --download-db-only``) and then mount the volume
# read-only for every scan, so subsequent runs are deterministic
# and don't repull the DB from ghcr.io.
TRIVY_CACHE_VOLUME = "secscan-trivy-image-cache"
