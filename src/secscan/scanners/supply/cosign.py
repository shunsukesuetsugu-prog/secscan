"""Cosign keyless verification — argv builder + result classifier.

Phase 2-Q: secscan invokes cosign via Docker to verify that an
operator-supplied OCI image was signed by an expected identity at
an expected issuer. The Sigstore project ships cosign as a
container at ``gcr.io/projectsigstore/cosign:vX.Y.Z`` with
embedded TUF trust material; we pin a specific digest in
``_pinned.py``.

Verification outcomes (Codex Phase 2-Q design review MUST-FIX #3):

- **Signature missing** (``MEDIUM`` ``cosign-signature-missing``):
  cosign exits non-zero with stderr like "no matching signatures"
  but the image itself exists and was reachable.
- **Identity mismatch** (``HIGH`` ``cosign-identity-mismatch``):
  signatures exist but none match the requested
  ``--certificate-identity`` / issuer pair. Signed by someone
  other than the expected publisher.
- **Invalid signature** (``HIGH`` ``cosign-signature-invalid``):
  signatures cryptographically don't verify — the image bytes
  were tampered with after signing, or the certificate chain is
  broken.
- **Network / TUF failure** (``LOW``
  ``cosign-verification-network-failure``): transparency log
  unreachable, TUF trust material refresh failed. The
  signature *may* be fine; we just couldn't confirm. Operator
  re-runs once the network heals.

The 4-way split is documented in
``classify_cosign_failure``; the scanner adapter emits one
``Finding`` per failure with the appropriate severity.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from ...models import Finding, Location, Severity
from ...redact import redact_text, truncate
from ...runner import decode_output
from ._pinned import (
    DEFAULT_COSIGN_IMAGE,
    DEFAULT_COSIGN_TIMEOUT_SECONDS,
    MAX_COSIGN_STDOUT_BYTES,
)
from .validators import (
    SupplyInputError,
    validate_image_ref,
    validate_signer_identity,
    validate_signer_identity_regexp,
    validate_signer_issuer,
)

_SCANNER_NAME = "supply"


# ---------------------------------------------------------------------------
# Invocation + argv
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CosignVerification:
    """One ``cosign verify`` invocation."""

    target_image: str
    signer_identity: str | None = None
    """Exact-match identity. Mutually exclusive with
    ``signer_identity_regexp`` — exactly one MUST be set."""

    signer_identity_regexp: str | None = None
    signer_issuer: str = ""
    """OIDC issuer URL (e.g. ``https://token.actions.githubusercontent.com``).
    Mandatory for keyless verification."""

    cosign_image: str = DEFAULT_COSIGN_IMAGE
    timeout_seconds: int = DEFAULT_COSIGN_TIMEOUT_SECONDS


def build_argv(invocation: CosignVerification) -> list[str]:
    """Build the ``docker run`` argv for one cosign verification.

    Layout::

        docker run --rm \
          --cap-drop=ALL --security-opt=no-new-privileges \
          --network=bridge \
          -- <cosign-image> verify \
          --certificate-identity <id>   (OR --certificate-identity-regexp)
          --certificate-oidc-issuer <url> \
          --output json \
          <target-image>

    Codex Phase 2-Q design review MUST-FIX #2: exact-match
    ``--certificate-identity`` is the default. The regex form is
    only used when the caller explicitly passes
    ``signer_identity_regexp``.

    Codex MUST-FIX (env strip): the scanner adapter strips
    SIGSTORE_* / COSIGN_* env vars before invoking subprocess.
    This function only builds argv; the env-strip happens in
    ``scanner.py``.
    """
    cosign_image = validate_image_ref(invocation.cosign_image, label="--cosign-image")
    target_image = validate_image_ref(invocation.target_image)

    if not invocation.signer_issuer:
        raise SupplyInputError(
            "cosign verification requires --signer-issuer (the OIDC "
            "issuer URL — keyless flow has no alternative)"
        )
    issuer = validate_signer_issuer(invocation.signer_issuer)

    has_literal = invocation.signer_identity is not None
    has_regex = invocation.signer_identity_regexp is not None
    if has_literal == has_regex:
        # Either both set or neither — both cases are an internal
        # bug (validator caller is responsible).
        raise SupplyInputError(
            "cosign verification requires EXACTLY one of "
            "--signer-identity (literal) or --signer-identity-regexp"
        )

    argv: list[str] = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=bridge",
        "--",
        cosign_image,
        "verify",
    ]

    if has_literal:
        argv.extend(
            ["--certificate-identity", validate_signer_identity(
                invocation.signer_identity or ""
            )]
        )
    else:
        argv.extend(
            ["--certificate-identity-regexp", validate_signer_identity_regexp(
                invocation.signer_identity_regexp or ""
            )]
        )
    argv.extend(["--certificate-oidc-issuer", issuer])
    argv.extend(["--output", "json"])
    argv.append(target_image)
    return argv


# ---------------------------------------------------------------------------
# Failure classification (Codex Phase 2-Q design review MUST-FIX #3)
# ---------------------------------------------------------------------------


_RULE_SIGNATURE_MISSING = "cosign-signature-missing"
_RULE_IDENTITY_MISMATCH = "cosign-identity-mismatch"
_RULE_SIGNATURE_INVALID = "cosign-signature-invalid"
_RULE_NETWORK_FAILURE = "cosign-verification-network-failure"

_RULE_SEVERITY: dict[str, Severity] = {
    _RULE_SIGNATURE_MISSING: Severity.MEDIUM,
    _RULE_IDENTITY_MISMATCH: Severity.HIGH,
    _RULE_SIGNATURE_INVALID: Severity.HIGH,
    _RULE_NETWORK_FAILURE: Severity.LOW,
}


# cosign error-message fingerprints. cosign's error strings have
# been stable across v2.x; if they change in a future release, the
# classifier degrades to ``signature_invalid`` (HIGH) — the safer
# default than ``network_failure`` (LOW).
_NETWORK_FAILURE_PATTERNS = (
    re.compile(r"failed to get the TUF targets", re.IGNORECASE),
    re.compile(r"unable to obtain Sigstore trust material", re.IGNORECASE),
    re.compile(r"failed to fetch.*Rekor", re.IGNORECASE),
    re.compile(r"context deadline exceeded", re.IGNORECASE),
    re.compile(r"connection refused", re.IGNORECASE),
    re.compile(r"i/o timeout", re.IGNORECASE),
    re.compile(r"no such host", re.IGNORECASE),
)
_SIGNATURE_MISSING_PATTERNS = (
    re.compile(r"no signatures found", re.IGNORECASE),
    re.compile(r"no matching signatures", re.IGNORECASE),
    re.compile(r"no signature found", re.IGNORECASE),
)
_IDENTITY_MISMATCH_PATTERNS = (
    re.compile(
        r"none of the expected (identities|signatures) matched",
        re.IGNORECASE,
    ),
    re.compile(r"identity does not match", re.IGNORECASE),
    re.compile(r"the OIDC issuer.*did not match", re.IGNORECASE),
    re.compile(r"certificate identity.*does not match", re.IGNORECASE),
)


def classify_cosign_failure(
    *, returncode: int, stderr: bytes, timed_out: bool
) -> str:
    """Return the rule_id for a cosign non-zero exit.

    Order matters: network/TUF failures look like generic
    transport errors and should be classified before pattern-
    matching the signature-domain failure messages, otherwise a
    transient DNS failure could be reported as a signature
    problem.
    """
    if timed_out:
        return _RULE_NETWORK_FAILURE
    text = decode_output(stderr[:MAX_COSIGN_STDOUT_BYTES]).lower()
    for pat in _NETWORK_FAILURE_PATTERNS:
        if pat.search(text):
            return _RULE_NETWORK_FAILURE
    for pat in _SIGNATURE_MISSING_PATTERNS:
        if pat.search(text):
            return _RULE_SIGNATURE_MISSING
    for pat in _IDENTITY_MISMATCH_PATTERNS:
        if pat.search(text):
            return _RULE_IDENTITY_MISMATCH
    # Unrecognised non-zero exit: assume signature invalid (safer
    # default than network failure). Operators with a novel
    # failure pattern can re-classify by adding to the regex
    # tables above.
    _ = returncode  # currently unused; reserved for future cosign exit-code splits
    return _RULE_SIGNATURE_INVALID


def severity_for_rule(rule_id: str) -> Severity:
    """Map a cosign rule_id to its severity. Unknown rule_ids
    default to LOW so a future addition doesn't silently drop
    the finding."""
    return _RULE_SEVERITY.get(rule_id, Severity.LOW)


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CosignParse:
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    tool_version: str | None = None
    extra: dict[str, object] = field(default_factory=dict)


def finding_for_cosign_failure(
    *,
    target_image: str,
    rule_id: str,
    stderr: bytes,
    expected_identity: str,
    issuer: str,
) -> Finding:
    """Build the ``Finding`` for a cosign non-zero result.

    The message includes a short summary of what the operator
    expected and what cosign reported, so the SARIF / text
    renderer can surface the failure without the operator
    digging into stderr.
    """
    stderr_text = decode_output(stderr[:4096]).strip()
    excerpt = truncate(redact_text(stderr_text), limit=400)
    severity = severity_for_rule(rule_id)
    title = f"{rule_id}: {target_image}"
    message_parts = [
        f"expected identity {expected_identity!r} from issuer {issuer!r}"
    ]
    if excerpt:
        message_parts.append(f"cosign stderr: {excerpt}")
    message = truncate(redact_text(" — ".join(message_parts)))

    # Synthetic location label: ``supply/cosign/<image>``. Avoids
    # leaking host filesystem paths and follows the same shape as
    # other dynamic scanners (apifuzz/iast/dast use synthetic
    # location strings too).
    safe_image = "".join(
        ch for ch in target_image if ch.isprintable() and ch not in (" ",)
    )
    location_label = f"supply/cosign/{safe_image}"

    fingerprint_parts = (
        "supply",
        "cosign",
        rule_id,
        target_image,
        expected_identity,
        issuer,
    )
    import hashlib

    fingerprint = hashlib.sha256(
        "\x00".join(fingerprint_parts).encode("utf-8")
    ).hexdigest()

    return Finding(
        scanner=_SCANNER_NAME,
        rule_id=rule_id,
        severity=severity,
        title=truncate(redact_text(title)),
        message=message,
        location=Location(file=location_label),
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------------
# Success-case parser (cosign JSON output)
# ---------------------------------------------------------------------------


def parse_cosign_success(stdout: bytes) -> dict[str, object]:
    """Parse the JSON cosign emits on a successful verification.

    Returned dict has keys like ``critical`` / ``optional`` /
    ``signatures``. We don't currently surface anything from a
    successful verification (the absence of a finding IS the
    signal), but we capture the parse for future use (e.g.
    SBOM-style attestations) and to validate that cosign's
    output is well-formed.
    """
    if len(stdout) > MAX_COSIGN_STDOUT_BYTES:
        return {
            "_error": f"cosign stdout exceeded {MAX_COSIGN_STDOUT_BYTES} bytes",
        }
    text = decode_output(stdout[:MAX_COSIGN_STDOUT_BYTES]).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"_error": f"cosign stdout not JSON: {exc.msg}"}
    except (ValueError, RecursionError) as exc:
        return {"_error": f"cosign stdout parse error: {type(exc).__name__}"}
    if isinstance(parsed, list):
        return {"signatures": parsed}
    if isinstance(parsed, dict):
        return parsed
    return {"_error": "cosign stdout was not a JSON object or array"}


__all__: Sequence[str] = (
    "CosignParse",
    "CosignVerification",
    "build_argv",
    "classify_cosign_failure",
    "finding_for_cosign_failure",
    "parse_cosign_success",
    "severity_for_rule",
)
