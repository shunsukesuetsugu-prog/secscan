"""Pinned default OWASP ZAP image digest.

We require the image to be addressed by ``repository@sha256:<digest>``
(see ``zap.validate_image_ref``). This module supplies the default
digest used when the operator does NOT pass ``--zap-image``.

The digest is intentionally kept in a dedicated module so security
review can audit changes to the trusted image without scanning the
whole DAST package.

To rotate:

1. Pull the desired upstream tag:
   ``docker pull zaproxy/zap-stable:2.15.0``
2. Resolve its digest:
   ``docker inspect --format='{{index .RepoDigests 0}}' zaproxy/zap-stable:2.15.0``
3. Replace ``DEFAULT_ZAP_IMAGE`` below and bump ``DEFAULT_ZAP_IMAGE_PINNED_AT``.
4. Re-run the DAST regression tests AND have an additional reviewer
   confirm the digest matches what they independently see on Docker Hub.

The placeholder digest below is structurally valid but is the
all-zero sentinel so any accidental shipped build will be rejected by
Docker Hub at pull time rather than silently running an unverified
image.
"""

from __future__ import annotations

# Repository portion only — the validator (``validate_image_ref``)
# accepts any OCI-style ``<repo>[:tag]@sha256:<hex>`` string, but the
# default we ship is locked to the upstream ZAP image so operators
# don't accidentally point ``--zap-image`` at an unrelated registry
# by mis-typing a value.
DEFAULT_ZAP_IMAGE_REPOSITORY = "zaproxy/zap-stable"

# 64 hex zeros — a structurally valid SHA-256 digest that does NOT
# correspond to any real image. Operators MUST override this with
# ``--zap-image`` until we ship a verified default. The scanner's
# ``is_applicable`` deliberately allows the default to be referenced
# (so the CLI exposes a working argv) but the all-zero sentinel will
# fail at ``docker pull`` time, surfacing a clear "image not found"
# error rather than silently running an untrusted image.
DEFAULT_ZAP_IMAGE_DIGEST = "0" * 64

DEFAULT_ZAP_IMAGE = (
    f"{DEFAULT_ZAP_IMAGE_REPOSITORY}@sha256:{DEFAULT_ZAP_IMAGE_DIGEST}"
)

DEFAULT_ZAP_IMAGE_PINNED_AT = "2026-05-24"
"""ISO date when the default digest was last rotated."""
