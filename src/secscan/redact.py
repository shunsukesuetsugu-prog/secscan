"""Secret redaction.

secscan must never persist or display raw secrets. Even when an upstream tool
(gitleaks) reports a ``Secret`` field verbatim, we replace it before anything
else inspects, logs, or stores it. This module provides:

- ``redact_secret(value)``    : replace a single secret with a fixed token.
- ``redact_text(text, secrets)``: redact a multi-line blob given known secrets
                                  plus well-known credential-shape patterns.
- ``truncate(text, limit)``   : bound stderr excerpts before display.

We deliberately do NOT try to "detect" secrets in arbitrary text — that's
gitleaks' job. This module only redacts values we have already been told are
secrets, plus a small set of well-known credential patterns when masking
stderr/message fields where a scanner might have leaked one.

We deliberately do NOT provide a ``hash_secret`` helper. Hashing a secret
creates a useful oracle for offline brute-force attacks against weak/short
secrets (api keys, sessions), so the only safe path is "never let the secret
into secscan in the first place" — the gitleaks adapter enforces this via
``--redact=100``.

Defense in depth: we also apply ``redact_text`` to scanner stderr excerpts
before they reach the reporter or logs.
"""

from __future__ import annotations

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
    # npm registry tokens (uuid-shaped and "npm_..." prefixed)
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), REDACTED),
    # PyPI tokens
    (re.compile(r"\bpypi-[A-Za-z0-9_\-]{30,}\b"), REDACTED),
    # .npmrc / pip.conf style "key=token" lines: preserve the key, redact value.
    # We only target known-name keys to avoid stripping benign config.
    (
        re.compile(
            r"(?i)(_authToken\s*=\s*|"
            r"_password\s*=\s*|"
            r"_auth\s*=\s*|"
            r"NPM_TOKEN\s*=\s*|"
            r"PIP_INDEX_URL\s*=\s*|"
            r"index-url\s*=\s*)"
            r"\S+"
        ),
        r"\1" + REDACTED,
    ),
    # Generic Bearer header values: preserve the header name, redact the value.
    (
        re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+"),
        r"\1" + REDACTED,
    ),
    # URL with basic-auth user:pass — keep the scheme + host, drop creds.
    # Example:  https://user:pass@host/path  →  https://[REDACTED]@host/path
    (
        re.compile(r"\b(https?://)[^/\s:@]+:[^/\s@]+@"),
        r"\1" + REDACTED + "@",
    ),
    # JWT (three base64url segments joined by dots).
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        REDACTED,
    ),
)


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
