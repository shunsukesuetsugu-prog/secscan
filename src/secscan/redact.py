"""Secret redaction.

secscan must never persist or display raw secrets. Even when an upstream tool
(gitleaks) reports a ``Secret`` field verbatim, we replace it before anything
else inspects, hashes, logs, or stores it. This module provides:

- ``redact_secret(value)``    : replace a single secret with a token that
                                preserves length category but no content.
- ``hash_secret(value)``      : SHA-256 of the original bytes, used ONCE for
                                fingerprint construction; the caller must
                                discard the original immediately afterwards.
- ``redact_text(text, secrets)``: redact a multi-line blob given known secrets.

We deliberately do NOT try to "detect" secrets in arbitrary text — that's
gitleaks' job. This module only redacts values we have already been told are
secrets, plus a small set of well-known credential patterns when masking
stderr/message fields where a scanner might have leaked one.

Defense in depth: we also apply ``redact_text`` to scanner stderr excerpts
before they reach the reporter or logs.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

# Well-known credential-shaped strings we proactively scrub from stderr,
# message fields, and other "should not contain secrets but might" inputs.
# Each entry is ``(pattern, replacement)``. The replacement supports
# backreferences so we can preserve a non-sensitive prefix (e.g. the
# ``Authorization: Bearer `` part of a header) and only redact the value.
# These patterns are conservative — false negatives are fine here (gitleaks
# is the real detector); we only want to avoid the obvious leak path.
_CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    # AWS Secret Access Key (40-char base64-ish)
    (re.compile(r"\b[A-Za-z0-9/+=]{40}\b"), REDACTED),
    # GitHub fine-grained / classic / OAuth tokens
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), REDACTED),
    # Slack bot/user/app tokens
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    # Generic Bearer header values: preserve the header name, redact the value.
    (
        re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+"),
        r"\1" + REDACTED,
    ),
    # JWT (three base64url segments joined by dots).
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        REDACTED,
    ),
)


def hash_secret(value: str) -> str:
    """One-shot SHA-256 of a secret value, returned as hex.

    Callers MUST discard ``value`` immediately after this call. This function
    exists specifically so the only code path that touches a raw secret is
    this tiny, auditable surface — fingerprints flow downstream, the secret
    does not.
    """
    return hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()


def redact_secret(value: str) -> str:
    """Replace a secret with a fixed token.

    We do not return any portion of the original — partial redaction (e.g.
    last 4 chars) is a known foot-gun in security tooling because adversaries
    can use the prefix/suffix as an oracle. If a partial display is needed
    for human disambiguation later, we will add an explicit, opt-in helper.
    """
    if not value:
        return value
    return REDACTED


def redact_text(text: str, known_secrets: Iterable[str] = ()) -> str:
    """Redact all known secrets plus credential-shaped substrings from text.

    Order matters: we redact known secrets first (exact match), then sweep
    for credential patterns. We don't bother coalescing — multiple passes
    over short strings are cheap.
    """
    out = text
    for secret in known_secrets:
        if secret:
            out = out.replace(secret, REDACTED)
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def truncate(text: str, limit: int = 500) -> str:
    """Truncate long text for display.

    Stderr excerpts are passed through ``redact_text`` first, then this. The
    limit is intentionally short — users rarely need more than a few lines to
    diagnose, and longer stderr increases the chance of leaking environment.
    """
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
