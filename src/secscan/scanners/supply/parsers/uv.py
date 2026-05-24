"""``uv.lock`` self-consistency checks.

uv writes a TOML lockfile with ``[[package]]`` entries that
contain ``sdist.hash`` / ``wheels[*].hash`` fields. Hashes use
the ``sha256:<64 hex>`` prefix form (matching pip / PyPI's
canonical hash representation).

We parse via the stdlib ``tomllib`` (Python 3.11+).
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Sequence

from ._common import (
    LockfileIssue,
    is_canonical_registry_url,
)

_UV_HASH_RE = re.compile(r"^sha256:[a-fA-F0-9]{64}$")


def check_uv_lock(
    text: str,
) -> tuple[Sequence[LockfileIssue], dict[str, object]]:
    issues: list[LockfileIssue] = []
    metadata: dict[str, object] = {}

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return (
            [
                LockfileIssue(
                    rule_id="lockfile-not-toml",
                    severity="low",
                    title="uv.lock is not valid TOML",
                    message=f"TOML parse error: {exc}",
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
                    title="uv.lock could not be parsed",
                    message=f"{type(exc).__name__}: {exc}",
                )
            ],
            metadata,
        )

    # ``tomllib.loads`` always returns dict for valid TOML; if a
    # future API change returns something else we'd want to fail
    # gracefully, but mypy correctly sees that branch as
    # unreachable today, so we omit the explicit isinstance.

    version = data.get("version")
    if isinstance(version, int):
        metadata["uv_lock_version"] = version

    packages = data.get("package")
    if not isinstance(packages, list):
        return issues, metadata

    for i, entry in enumerate(packages):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", f"<#{i}>")
        # sdist.hash and url
        sdist = entry.get("sdist")
        if isinstance(sdist, dict):
            h = sdist.get("hash")
            if h is not None and not (
                isinstance(h, str) and _UV_HASH_RE.match(h)
            ):
                issues.append(
                    LockfileIssue(
                        rule_id="uv-hash-malformed",
                        severity="medium",
                        title="uv.lock sdist.hash is not a sha256:<hex> string",
                        message=(
                            f"package {name!r} sdist.hash = {str(h)[:32]!r}"
                        ),
                        location_hint=f"package[{i}].sdist.hash",
                    )
                )
            url = sdist.get("url")
            if (
                isinstance(url, str)
                and url
                and not is_canonical_registry_url(url, "uv")
            ):
                issues.append(
                    LockfileIssue(
                        rule_id="uv-non-canonical-index",
                        severity="low",
                        title="uv.lock sdist.url points outside pypi.org",
                        message=(
                            f"package {name!r} sdist.url = {url!r} — "
                            "expected pypi.org / files.pythonhosted.org"
                        ),
                        location_hint=f"package[{i}].sdist.url",
                    )
                )
        wheels = entry.get("wheels")
        if isinstance(wheels, list):
            for j, w in enumerate(wheels):
                if not isinstance(w, dict):
                    continue
                h = w.get("hash")
                if h is not None and not (
                    isinstance(h, str) and _UV_HASH_RE.match(h)
                ):
                    issues.append(
                        LockfileIssue(
                            rule_id="uv-hash-malformed",
                            severity="medium",
                            title="uv.lock wheel.hash is not a sha256:<hex> string",
                            message=(
                                f"package {name!r} wheels[{j}].hash = "
                                f"{str(h)[:32]!r}"
                            ),
                            location_hint=(
                                f"package[{i}].wheels[{j}].hash"
                            ),
                        )
                    )
                url = w.get("url")
                if (
                    isinstance(url, str)
                    and url
                    and not is_canonical_registry_url(url, "uv")
                ):
                    issues.append(
                        LockfileIssue(
                            rule_id="uv-non-canonical-index",
                            severity="low",
                            title="uv.lock wheel.url points outside pypi.org",
                            message=(
                                f"package {name!r} wheels[{j}].url = "
                                f"{url!r} — expected pypi.org / "
                                "files.pythonhosted.org"
                            ),
                            location_hint=(
                                f"package[{i}].wheels[{j}].url"
                            ),
                        )
                    )

    return issues, metadata
