"""Bundled HTTP probe payloads for the IAST harness.

Phase 2-P design pin (Codex MUST-FIX #3): these are NOT
fuzzing payloads. They are a small set of **non-destructive
canaries** chosen to *trigger pyrasp's detection rules without
mutating target state*. The goal is "did pyrasp fire on
something we sent?", not "did we find every vulnerability".

Two payload tiers:

- ``SAFE_PROBES`` — default. Every payload is read-only, uses
  fake/closed-port targets for SSRF, and avoids ``DROP`` /
  ``sleep()`` / ``cat /etc/passwd`` / IMDS endpoints. This
  set runs by default.
- ``RISKY_PROBES`` — gated behind ``--allow-risky-probes``.
  Adds IMDS (169.254.169.254), time-based blind SQLi,
  blind RCE (``sleep``), and other payloads that some
  operators consider noisy or potentially impactful.

Each probe carries a stable ``probe_id`` so secscan output
and pyrasp events can be cross-referenced after the run.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ...models import Severity


@dataclass(frozen=True)
class Probe:
    """One HTTP request the harness will send during a scan.

    ``method`` + ``path`` + ``query`` + ``body`` are forwarded
    literally to ``urllib.request.Request``. The harness adds
    the run-id header / query to every probe; that field is NOT
    part of this dataclass.
    """

    probe_id: str
    """Stable identifier used for Finding fingerprints and pyrasp
    event correlation. Two probes with the same id MUST send the
    same shape — when you add a new probe, give it a fresh id."""

    category: str
    """Free-text bucket name: ``sqli``, ``xss``, ``rce``, ``ssrf``,
    ``traversal``, ``nosqli``. Used for severity inference and
    report grouping."""

    method: str
    """HTTP method. Default probes use only safe (RFC 9110 §9.2.1)
    methods to keep the canary set non-destructive even when the
    operator's app exposes mutating endpoints at the probed path."""

    path_template: str
    """Path the probe targets — relative to ``--probe-url``.
    ``{payload}`` placeholder is replaced with the payload literal
    in either path or query, depending on ``injection_site``."""

    payload: str
    """The literal injection string."""

    injection_site: str
    """``path`` (substituted into ``path_template``), ``query``
    (appended as a ``q=<payload>`` query parameter), or ``header``
    (a custom probe header — used for SSRF via Host: header)."""

    expected_categories: tuple[str, ...]
    """The pyrasp rule categories we EXPECT to fire for this
    payload. Used by the bench to compute a recall score.
    Empty tuple ``()`` means "any rule firing is informative
    enough — don't assert a specific category"."""


# ---------------------------------------------------------------------------
# Default safe probes (Codex MUST-FIX #3: non-destructive canaries)
# ---------------------------------------------------------------------------

SAFE_PROBES: tuple[Probe, ...] = (
    # SQL injection — classic read-only OR 1=1.
    Probe(
        probe_id="sqli-001",
        category="sqli",
        method="GET",
        path_template="/",
        payload="' OR '1'='1",
        injection_site="query",
        expected_categories=("sqli", "injection"),
    ),
    Probe(
        probe_id="sqli-002",
        category="sqli",
        method="GET",
        path_template="/",
        payload="1 UNION SELECT NULL--",
        injection_site="query",
        expected_categories=("sqli", "injection"),
    ),
    # XSS — reflected, single-line script.
    Probe(
        probe_id="xss-001",
        category="xss",
        method="GET",
        path_template="/",
        payload="<script>alert(1)</script>",
        injection_site="query",
        expected_categories=("xss",),
    ),
    Probe(
        probe_id="xss-002",
        category="xss",
        method="GET",
        path_template="/",
        payload='"><img src=x onerror=alert(1)>',
        injection_site="query",
        expected_categories=("xss",),
    ),
    # Command injection — read-only ``id`` / ``whoami``.
    Probe(
        probe_id="rce-001",
        category="rce",
        method="GET",
        path_template="/",
        payload=";id",
        injection_site="query",
        expected_categories=("rce", "command_injection"),
    ),
    Probe(
        probe_id="rce-002",
        category="rce",
        method="GET",
        path_template="/",
        payload="|whoami",
        injection_site="query",
        expected_categories=("rce", "command_injection"),
    ),
    # SSRF — closed loopback ports (port 1 is reserved; nothing
    # should be listening). This still fires the SSRF rule in
    # pyrasp but cannot reach real internal services.
    Probe(
        probe_id="ssrf-001",
        category="ssrf",
        method="GET",
        path_template="/",
        payload="http://127.0.0.1:1/",
        injection_site="query",
        expected_categories=("ssrf",),
    ),
    Probe(
        probe_id="ssrf-002",
        category="ssrf",
        method="GET",
        path_template="/",
        payload="file:///dev/null",
        injection_site="query",
        expected_categories=("ssrf",),
    ),
    # Path traversal — relative-path probe (does not reference a
    # real sensitive file; pyrasp's traversal rule fires on the
    # ``../`` sequence itself).
    Probe(
        probe_id="trav-001",
        category="traversal",
        method="GET",
        path_template="/",
        payload="../../etc/.fake-secscan-canary",
        injection_site="query",
        expected_categories=("traversal", "path_traversal"),
    ),
    # NoSQL injection — Mongo-style operator object.
    Probe(
        probe_id="nosqli-001",
        category="nosqli",
        method="GET",
        path_template="/",
        payload='{"$ne": ""}',
        injection_site="query",
        expected_categories=("nosqli", "injection"),
    ),
)


# ---------------------------------------------------------------------------
# Risky probes (require --allow-risky-probes)
# ---------------------------------------------------------------------------

RISKY_PROBES: tuple[Probe, ...] = (
    # IMDSv1 — AWS instance metadata service. Real exfiltration
    # vector if the app SSRFs to this address.
    Probe(
        probe_id="ssrf-imds-001",
        category="ssrf",
        method="GET",
        path_template="/",
        payload="http://169.254.169.254/latest/meta-data/",
        injection_site="query",
        expected_categories=("ssrf",),
    ),
    # Time-based blind SQLi — operators uncomfortable with `sleep`
    # syntax in logs want this gated.
    Probe(
        probe_id="sqli-blind-001",
        category="sqli",
        method="GET",
        path_template="/",
        payload="1' AND SLEEP(0)--",
        injection_site="query",
        expected_categories=("sqli",),
    ),
    # Time-based blind RCE — sleep 0 so even if the rule fires
    # and the WAF lets it through there is no actual delay.
    Probe(
        probe_id="rce-blind-001",
        category="rce",
        method="GET",
        path_template="/",
        payload="$(sleep 0)",
        injection_site="query",
        expected_categories=("rce",),
    ),
)


# ---------------------------------------------------------------------------
# Severity inference
# ---------------------------------------------------------------------------

_CATEGORY_SEVERITY: dict[str, Severity] = {
    "sqli": Severity.HIGH,
    "rce": Severity.HIGH,
    "command_injection": Severity.HIGH,
    "ssrf": Severity.HIGH,
    "deserialization": Severity.HIGH,
    "xss": Severity.MEDIUM,
    "nosqli": Severity.MEDIUM,
    "injection": Severity.MEDIUM,
    "traversal": Severity.MEDIUM,
    "path_traversal": Severity.MEDIUM,
}


def severity_for_category(category: str) -> Severity:
    """Best-effort severity mapping for a pyrasp event ``category``.

    Unknown categories default to ``LOW`` rather than raising:
    pyrasp adds new rules across minor versions, and a parser
    that drops unknown rules would silently let new findings
    escape.
    """
    return _CATEGORY_SEVERITY.get(category.lower(), Severity.LOW)


def select_probes(*, allow_risky: bool) -> Sequence[Probe]:
    """Return the probe set for one scan.

    Default = ``SAFE_PROBES`` only. Operators who explicitly opt
    in to ``--allow-risky-probes`` also get the destructive /
    IMDS-touching set.
    """
    if allow_risky:
        return SAFE_PROBES + RISKY_PROBES
    return SAFE_PROBES


__all__: tuple[str, ...] = (
    "RISKY_PROBES",
    "SAFE_PROBES",
    "Probe",
    "select_probes",
    "severity_for_category",
)
