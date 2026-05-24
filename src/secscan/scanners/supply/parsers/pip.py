"""``Pipfile.lock`` self-consistency checks.

Pipenv's lockfile stores per-package hashes under
``default.<name>.hashes`` and ``develop.<name>.hashes`` as an
array of ``sha256:<64 hex>`` strings (often multiple — one per
wheel + sdist).

Checks (offline):

1. Each hash string has the expected ``sha256:<64 hex>`` shape.
2. The lockfile's ``_meta.hash.sha256`` (top-level metadata
   hash) is a valid sha256 hex.
3. Resolved index URLs (``_meta.sources``) point at pypi.org /
   files.pythonhosted.org (LOW finding when they don't — could
   be a benign private index or a malicious mirror).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

from ._common import (
    LockfileIssue,
    is_canonical_registry_url,
    looks_like_sha256_hex,
)

_PIPENV_HASH_RE = re.compile(r"^sha256:[a-fA-F0-9]{64}$")


def check_pipfile_lock(
    text: str,
) -> tuple[Sequence[LockfileIssue], dict[str, object]]:
    issues: list[LockfileIssue] = []
    metadata: dict[str, object] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return (
            [
                LockfileIssue(
                    rule_id="lockfile-not-json",
                    severity="low",
                    title="Pipfile.lock is not valid JSON",
                    message=f"JSON parse error: {exc.msg}",
                )
            ],
            metadata,
        )
    except (ValueError, RecursionError) as exc:
        return (
            [
                LockfileIssue(
                    rule_id="lockfile-parse-error",
                    severity="low",
                    title="Pipfile.lock could not be parsed",
                    message=f"{type(exc).__name__}: {exc}",
                )
            ],
            metadata,
        )

    if not isinstance(data, dict):
        return (
            [
                LockfileIssue(
                    rule_id="lockfile-shape",
                    severity="low",
                    title="Pipfile.lock root is not an object",
                    message=f"got {type(data).__name__}",
                )
            ],
            metadata,
        )

    meta = data.get("_meta")
    if isinstance(meta, dict):
        # _meta.hash.sha256 — top-level lockfile content hash.
        hash_block = meta.get("hash")
        if isinstance(hash_block, dict):
            top_sha = hash_block.get("sha256")
            if top_sha is not None and not looks_like_sha256_hex(top_sha):
                issues.append(
                    LockfileIssue(
                        rule_id="pip-meta-hash-malformed",
                        severity="medium",
                        title="Pipfile.lock _meta.hash.sha256 is not a 64-hex string",
                        message=(
                            f"top-level hash {str(top_sha)[:16]!r} is not "
                            "the expected sha256 hex shape"
                        ),
                        location_hint="_meta.hash.sha256",
                    )
                )
        sources = meta.get("sources")
        if isinstance(sources, list):
            for i, src in enumerate(sources):
                if not isinstance(src, dict):
                    continue
                url = src.get("url")
                if (
                    isinstance(url, str)
                    and url
                    and not is_canonical_registry_url(url, "pip")
                ):
                    issues.append(
                        LockfileIssue(
                            rule_id="pip-non-canonical-index",
                            severity="low",
                            title="Pipfile.lock _meta.sources points outside pypi.org",
                            message=(
                                f"source[{i}] url is {url!r} — expected "
                                "pypi.org / files.pythonhosted.org. Benign "
                                "for private indexes; review for "
                                "unexpected mirrors."
                            ),
                            location_hint=f"_meta.sources[{i}]",
                        )
                    )

    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, entry in block.items():
            if not isinstance(entry, dict):
                continue
            hashes = entry.get("hashes")
            if not isinstance(hashes, list):
                continue
            for j, h in enumerate(hashes):
                if not isinstance(h, str) or not _PIPENV_HASH_RE.match(h):
                    issues.append(
                        LockfileIssue(
                            rule_id="pip-hash-malformed",
                            severity="medium",
                            title=(
                                "Pipfile.lock hash entry is not the expected "
                                "``sha256:<64 hex>`` shape"
                            ),
                            message=(
                                f"package {name!r}.hashes[{j}] = "
                                f"{str(h)[:32]!r}"
                            ),
                            location_hint=f"{section}.{name}.hashes[{j}]",
                        )
                    )

    return issues, metadata
