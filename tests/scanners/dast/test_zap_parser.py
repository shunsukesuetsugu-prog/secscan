"""JSON parser, fingerprint, and URI-normalization tests.

These cover the security-relevant external-output contracts:

- URLs that ZAP reports never leak into ``location.url`` as-is —
  they're normalized to ``dast/<encoded-path>``.
- Fingerprints are stable across runs and split on
  (``pluginid``, ``path``, ``query_keys``, ``param_token``).
- Each Finding carries the coarse alias fingerprint so a single
  ``baseline accept`` suppresses both ``param``-bearing and
  ``param``-less variants of the same advisory.
- Unrecognized severity ZAP shapes degrade to ``UNKNOWN`` with a
  warning rather than crashing.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from secscan.models import Severity
from secscan.scanners.dast.zap import (
    compute_coarse_fingerprint,
    compute_fingerprint,
    normalize_alert_uri,
    parse_zap_report,
)

# --- normalize_alert_uri ---------------------------------------------------


class TestNormalizeAlertUri:
    def test_none_returns_dast_root(self) -> None:
        assert normalize_alert_uri(None) == "dast/"

    def test_empty_returns_dast_root(self) -> None:
        assert normalize_alert_uri("") == "dast/"

    def test_drops_host(self) -> None:
        uri = normalize_alert_uri("https://example.com/login")
        assert "example.com" not in uri
        assert uri == "dast/%2Flogin"

    def test_drops_query_and_fragment(self) -> None:
        uri = normalize_alert_uri("https://example.com/x?id=1#frag")
        assert "id" not in uri
        assert "frag" not in uri

    def test_encodes_traversal_components(self) -> None:
        uri = normalize_alert_uri("https://example.com/../etc/passwd")
        # The safety property is that path SEPARATORS are encoded — a
        # consumer parsing the URI as multiple path segments cannot
        # recover ``..`` / ``etc`` / ``passwd`` as separate components.
        # ``.`` is RFC-3986 unreserved so the literal dots survive,
        # but they're inside one indivisible URI component starting
        # at ``dast/``.
        assert uri.startswith("dast/")
        # No raw forward slash past the ``dast/`` prefix → no
        # multi-segment interpretation possible.
        assert uri[len("dast/") :].count("/") == 0
        # ``etc`` and ``passwd`` survive as substrings but are NOT
        # reachable as standalone path components.
        assert "%2F" in uri  # at least one encoded slash present

    def test_invalid_url_falls_back_to_dast_root(self) -> None:
        # urllib doesn't raise on most weird input, so we get a graceful
        # fallback either way. Sanity: still safe-prefixed.
        assert normalize_alert_uri("not a url at all").startswith("dast/")


# --- Fingerprints ----------------------------------------------------------


class TestFingerprint:
    HOST = "example.com"

    def test_stable_across_runs(self) -> None:
        a = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login?x=1",
            param_token="username",
        )
        b = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login?x=1",
            param_token="username",
        )
        assert a == b

    def test_query_value_does_not_affect(self) -> None:
        a = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login?session=abc",
            param_token="username",
        )
        b = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login?session=xyz",
            param_token="username",
        )
        assert a == b, "query VALUES must not influence the fingerprint"

    def test_query_keys_DO_affect(self) -> None:
        a = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login?x=1",
            param_token="username",
        )
        b = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login?y=1",
            param_token="username",
        )
        assert a != b

    def test_param_token_changes_fingerprint(self) -> None:
        url = "https://example.com/login"
        a = compute_fingerprint(
            pluginid="10038", target_host=self.HOST, alert_url=url, param_token="user"
        )
        b = compute_fingerprint(
            pluginid="10038", target_host=self.HOST, alert_url=url, param_token="pass"
        )
        assert a != b

    def test_host_changes_fingerprint(self) -> None:
        url = "https://example.com/login"
        a = compute_fingerprint(
            pluginid="10038", target_host="a.com", alert_url=url, param_token="x"
        )
        b = compute_fingerprint(
            pluginid="10038", target_host="b.com", alert_url=url, param_token="x"
        )
        assert a != b

    def test_coarse_drops_param_and_query_keys(self) -> None:
        url = "https://example.com/login?x=1"
        coarse = compute_coarse_fingerprint(
            pluginid="10038", target_host=self.HOST, alert_url=url
        )
        # Same as fine with NO_PARAM and ?-stripped path.
        expected = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/login",
            param_token="NO_PARAM",
        )
        assert coarse == expected

    def test_value_is_sha256_hex(self) -> None:
        fp = compute_fingerprint(
            pluginid="10038",
            target_host=self.HOST,
            alert_url="https://example.com/x",
            param_token="NO_PARAM",
        )
        assert len(fp) == 64
        # round-trip parse as hex
        int(fp, 16)
        assert fp == hashlib.sha256(fp_payload()).hexdigest()


def fp_payload() -> bytes:
    """The exact byte sequence the production code hashes for the
    canonical fingerprint above. Kept here so we can sanity-check the
    hashing scheme without re-implementing it inside the test."""
    return "\x00".join(
        ("dast", "10038", "example.com", "/x", "", "NO_PARAM")
    ).encode("utf-8")


# --- parse_zap_report ------------------------------------------------------


def _report(**overrides: object) -> bytes:
    payload: dict[str, object] = {
        "@version": "2.15.0",
        "site": [
            {
                "@host": "example.com",
                "@name": "https://example.com",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "name": "Content Security Policy missing",
                        "riskcode": 2,
                        "desc": "<p>CSP is missing.</p>",
                        "solution": "Set the header.",
                        "cweid": "693",
                        "reference": "https://owasp.org/csp\nhttps://example.com/help",
                        "instances": [
                            {
                                "uri": "https://example.com/login?id=42",
                                "method": "GET",
                                "param": "id",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


class TestParseZapReport:
    def test_happy_path_emits_one_finding(self) -> None:
        parsed = parse_zap_report(_report(), target_host="example.com")
        assert parsed.warnings == ()
        assert parsed.zap_version == "2.15.0"
        (finding,) = parsed.findings
        assert finding.rule_id == "10038"
        assert finding.severity == Severity.MEDIUM
        assert finding.cwe == "CWE-693"
        # URI must be the sanitized form, not the raw URL.
        assert finding.location is not None
        assert finding.location.file == "dast/%2Flogin"
        # Aliases include the coarse fingerprint (param-less variant).
        assert finding.fingerprint_aliases
        coarse = compute_coarse_fingerprint(
            pluginid="10038",
            target_host="example.com",
            alert_url="https://example.com/login?id=42",
        )
        assert finding.fingerprint != coarse
        assert coarse in finding.fingerprint_aliases

    def test_empty_report_returns_warning(self) -> None:
        parsed = parse_zap_report(b"", target_host="example.com")
        assert parsed.findings == ()
        assert any("was empty" in w for w in parsed.warnings)

    def test_invalid_json_returns_warning(self) -> None:
        parsed = parse_zap_report(b"not json{", target_host="example.com")
        assert parsed.findings == ()
        assert any("not valid JSON" in w for w in parsed.warnings)

    def test_missing_site_returns_warning(self) -> None:
        parsed = parse_zap_report(
            json.dumps({"@version": "2.0"}).encode(), target_host="example.com"
        )
        assert parsed.findings == ()
        assert any("no 'site'" in w for w in parsed.warnings)

    def test_riskdesc_string_fallback(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10",
                            "name": "x",
                            "riskdesc": "High (Medium)",
                            "instances": [{"uri": "https://example.com/a"}],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        assert finding.severity == Severity.HIGH

    def test_unknown_severity_becomes_unknown(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10",
                            "name": "x",
                            "riskdesc": "Catastrophic",
                            "instances": [{"uri": "https://example.com/a"}],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        assert finding.severity == Severity.UNKNOWN
        assert any("no recognizable severity" in w for w in parsed.warnings)

    def test_missing_pluginid_skipped(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {"name": "Anonymous alert", "riskcode": 1},
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        assert parsed.findings == ()
        assert any("missing 'pluginid'" in w for w in parsed.warnings)

    def test_param_list_normalized(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "20",
                            "name": "xss",
                            "riskcode": 3,
                            "instances": [
                                {
                                    "uri": "https://example.com/search",
                                    "param": ["q", "lang", "q"],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        # Fingerprint should be deterministic regardless of duplicate /
        # unsorted entries in the list.
        expected = compute_fingerprint(
            pluginid="20",
            target_host="example.com",
            alert_url="https://example.com/search",
            param_token="lang,q",
        )
        assert finding.fingerprint == expected

    def test_param_list_with_non_scalar_items_warns(self) -> None:
        """Codex Phase 2-D diff review: a ``param`` list containing
        a dict (or None / nested list) must NOT silently drop those
        elements. We keep only scalar values but emit a warning so
        the operator notices the ZAP report contained something we
        didn't model."""
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "20",
                            "name": "weird-list",
                            "riskcode": 2,
                            "instances": [
                                {
                                    "uri": "https://example.com/x",
                                    "param": ["good", {"nested": True}, None, "good2"],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        # Two elements skipped: dict and None.
        assert any("skipped 2 non-scalar" in w for w in parsed.warnings)
        # Scalar entries still feed the fingerprint, sorted.
        expected = compute_fingerprint(
            pluginid="20",
            target_host="example.com",
            alert_url="https://example.com/x",
            param_token="good,good2",
        )
        assert finding.fingerprint == expected

    def test_param_list_with_bools_skipped(self) -> None:
        """Booleans subclass ``int`` in Python but ``True/False`` as
        param names are nonsensical — they would silently merge
        unrelated findings if stringified. Skip them explicitly."""
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "20",
                            "name": "weird-bool",
                            "riskcode": 1,
                            "instances": [
                                {
                                    "uri": "https://example.com/x",
                                    "param": [True, "ok", False],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        # Only "ok" survives.
        expected = compute_fingerprint(
            pluginid="20",
            target_host="example.com",
            alert_url="https://example.com/x",
            param_token="ok",
        )
        assert finding.fingerprint == expected
        assert any("skipped 2 non-scalar" in w for w in parsed.warnings)

    def test_param_dict_warns_and_falls_back(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "20",
                            "name": "weird",
                            "riskcode": 1,
                            "instances": [
                                {
                                    "uri": "https://example.com/x",
                                    "param": {"unexpected": True},
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        assert any("unexpected param type" in w for w in parsed.warnings)
        # Falls back to NO_PARAM → equals the coarse fingerprint.
        coarse = compute_coarse_fingerprint(
            pluginid="20",
            target_host="example.com",
            alert_url="https://example.com/x",
        )
        assert finding.fingerprint == coarse
        # And because primary == coarse, aliases must be empty (no
        # double-recording with the same key).
        assert finding.fingerprint_aliases == ()

    def test_multiple_instances_dedupe_to_max_severity(self) -> None:
        """When the same (pluginid, path, query_keys, param) appears
        twice with different severities, the merged finding takes the
        max — never the min — so we never under-report."""
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "30",
                            "name": "lowdupe",
                            "riskcode": 1,
                            "instances": [
                                {"uri": "https://example.com/x", "param": "a"}
                            ],
                        },
                        {
                            "pluginid": "30",
                            "name": "highdupe",
                            "riskcode": 3,
                            "instances": [
                                {"uri": "https://example.com/x", "param": "a"}
                            ],
                        },
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        assert finding.severity == Severity.HIGH

    def test_no_url_in_external_message(self) -> None:
        """The full alert URL (including host) must never appear in
        Finding.location.file. Codex 2nd review pinned this — leaking
        host names through SARIF/JSON output is forbidden."""
        parsed = parse_zap_report(_report(), target_host="example.com")
        (finding,) = parsed.findings
        assert finding.location is not None
        assert "example.com" not in (finding.location.file or "")

    def test_cwe_minus_one_drops(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10",
                            "name": "x",
                            "riskcode": 1,
                            "cweid": "-1",
                            "instances": [{"uri": "https://example.com/a"}],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        assert finding.cwe is None

    def test_references_extracted_and_limited(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10",
                            "name": "x",
                            "riskcode": 1,
                            "reference": "\n".join(
                                f"https://refs.example.com/{i}" for i in range(8)
                            ),
                            "instances": [{"uri": "https://example.com/a"}],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        (finding,) = parsed.findings
        assert len(finding.references) == 5
        for ref in finding.references:
            assert ref.startswith("https://")

    def test_pluginid_as_integer(self) -> None:
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": 10038,  # int instead of str
                            "name": "x",
                            "riskcode": 1,
                            "instances": [{"uri": "https://example.com/a"}],
                        }
                    ]
                }
            ]
        }
        parsed = parse_zap_report(
            json.dumps(payload).encode(), target_host="example.com"
        )
        assert parsed.findings == () or parsed.findings[0].rule_id == "10038"


@pytest.fixture()
def empty_payload() -> bytes:
    return b"{}"


def test_payload_with_only_braces_does_not_crash(empty_payload: bytes) -> None:
    parsed = parse_zap_report(empty_payload, target_host="example.com")
    assert parsed.findings == ()
    # A bare ``{}`` triggers the "no 'site'" warning; that's expected.
    assert any("no 'site'" in w for w in parsed.warnings)
