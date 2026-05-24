"""Phase 2-Q: lockfile self-consistency parsers (npm / pip / uv)."""

from __future__ import annotations

import json

from secscan.scanners.supply.parsers import (
    check_npm_lockfile,
    check_pipfile_lock,
    check_uv_lock,
)

# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def _npm_lockfile(packages: dict[str, dict]) -> str:
    return json.dumps(
        {"name": "x", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    )


class TestNpmLockfile:
    def test_well_formed_lockfile_no_issues(self) -> None:
        text = _npm_lockfile(
            {
                "": {"name": "x", "version": "1.0.0"},
                "node_modules/lodash": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "resolved": (
                        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                    ),
                },
            }
        )
        issues, meta = check_npm_lockfile(text)
        assert issues == []
        assert meta.get("lockfileVersion") == 3

    def test_malformed_integrity_flagged(self) -> None:
        text = _npm_lockfile(
            {
                "node_modules/foo": {
                    "name": "foo",
                    "version": "1.0.0",
                    # Wrong shape — missing algorithm prefix.
                    "integrity": "this-is-not-an-sri-hash",
                }
            }
        )
        issues, _ = check_npm_lockfile(text)
        rule_ids = {i.rule_id for i in issues}
        assert "npm-integrity-malformed" in rule_ids

    def test_integrity_mismatch_flagged(self) -> None:
        """Same (name, version) with different integrity values across
        entries is the strongest 'lockfile tampered' signal."""
        text = _npm_lockfile(
            {
                "node_modules/foo": {
                    "name": "foo",
                    "version": "1.0.0",
                    "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaa",
                },
                "node_modules/bar/node_modules/foo": {
                    "name": "foo",
                    "version": "1.0.0",
                    "integrity": "sha512-bbbbbbbbbbbbbbbbbbbbbb",
                },
            }
        )
        issues, _ = check_npm_lockfile(text)
        assert any(
            i.rule_id == "npm-integrity-mismatch" for i in issues
        )

    def test_non_canonical_registry_flagged(self) -> None:
        text = _npm_lockfile(
            {
                "node_modules/foo": {
                    "name": "foo",
                    "version": "1.0.0",
                    "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaa",
                    "resolved": "https://my-private-registry.example.com/foo/-/foo-1.0.0.tgz",
                }
            }
        )
        issues, _ = check_npm_lockfile(text)
        assert any(
            i.rule_id == "npm-non-canonical-registry" for i in issues
        )

    def test_invalid_json_flagged(self) -> None:
        issues, _ = check_npm_lockfile("not json at all")
        assert any(
            i.rule_id == "lockfile-not-json" for i in issues
        )


# ---------------------------------------------------------------------------
# pip (Pipfile.lock)
# ---------------------------------------------------------------------------


class TestPipfileLock:
    def test_well_formed_no_issues(self) -> None:
        text = json.dumps(
            {
                "_meta": {
                    "hash": {"sha256": "a" * 64},
                    "sources": [
                        {
                            "name": "pypi",
                            "url": "https://pypi.org/simple",
                            "verify_ssl": True,
                        }
                    ],
                },
                "default": {
                    "django": {
                        "version": "==4.2.0",
                        "hashes": [
                            "sha256:" + "a" * 64,
                            "sha256:" + "b" * 64,
                        ],
                    }
                },
                "develop": {},
            }
        )
        issues, _ = check_pipfile_lock(text)
        assert issues == []

    def test_malformed_meta_hash_flagged(self) -> None:
        text = json.dumps(
            {
                "_meta": {
                    "hash": {"sha256": "not-a-hex"},
                    "sources": [],
                },
                "default": {},
                "develop": {},
            }
        )
        issues, _ = check_pipfile_lock(text)
        assert any(
            i.rule_id == "pip-meta-hash-malformed" for i in issues
        )

    def test_malformed_package_hash_flagged(self) -> None:
        text = json.dumps(
            {
                "_meta": {"hash": {"sha256": "a" * 64}, "sources": []},
                "default": {
                    "django": {
                        "version": "==4.2.0",
                        "hashes": ["md5:bad"],
                    }
                },
                "develop": {},
            }
        )
        issues, _ = check_pipfile_lock(text)
        assert any(i.rule_id == "pip-hash-malformed" for i in issues)


# ---------------------------------------------------------------------------
# uv (uv.lock — TOML)
# ---------------------------------------------------------------------------


class TestUvLock:
    def test_well_formed_no_issues(self) -> None:
        text = """\
version = 1
[[package]]
name = "django"
version = "4.2.0"

[package.sdist]
url = "https://files.pythonhosted.org/packages/.../django-4.2.0.tar.gz"
hash = "sha256:%s"
""" % ("a" * 64)
        issues, meta = check_uv_lock(text)
        assert issues == []
        assert meta.get("uv_lock_version") == 1

    def test_malformed_sdist_hash_flagged(self) -> None:
        text = """\
version = 1
[[package]]
name = "django"
version = "4.2.0"

[package.sdist]
url = "https://files.pythonhosted.org/packages/.../django-4.2.0.tar.gz"
hash = "md5:not-correct"
"""
        issues, _ = check_uv_lock(text)
        assert any(i.rule_id == "uv-hash-malformed" for i in issues)

    def test_non_canonical_index_flagged(self) -> None:
        text = """\
version = 1
[[package]]
name = "django"
version = "4.2.0"

[package.sdist]
url = "https://private-mirror.example.com/django-4.2.0.tar.gz"
hash = "sha256:%s"
""" % ("a" * 64)
        issues, _ = check_uv_lock(text)
        assert any(
            i.rule_id == "uv-non-canonical-index" for i in issues
        )

    def test_invalid_toml_flagged(self) -> None:
        issues, _ = check_uv_lock("not = valid = toml = at all")
        assert any(
            i.rule_id == "lockfile-not-toml" for i in issues
        )
