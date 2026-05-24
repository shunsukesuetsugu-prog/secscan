"""npm ``package-lock.json`` self-consistency checks.

Checks (offline only — no node_modules tarball comparison):

1. Each ``packages.<path>.integrity`` is a valid SRI string.
2. The same ``(name, version)`` pair appears with a consistent
   ``integrity`` across every place it's listed in the
   lockfile. A mismatch is the strongest "lockfile tampered"
   signal we can produce without the actual tarball.
3. Each ``packages.<path>.resolved`` URL points at
   ``registry.npmjs.org`` (LOW severity if it doesn't — could be
   a private mirror, which is benign, or a malicious mirror,
   which is the supply-chain concern).
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from ._common import (
    LockfileIssue,
    is_canonical_registry_url,
    looks_like_sri,
)


def check_npm_lockfile(
    text: str,
) -> tuple[Sequence[LockfileIssue], dict[str, object]]:
    """Walk ``package-lock.json`` content, return anomalies + metadata."""
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
                    title="package-lock.json is not valid JSON",
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
                    title="package-lock.json could not be parsed",
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
                    title="package-lock.json root is not an object",
                    message=f"got {type(data).__name__}",
                )
            ],
            metadata,
        )

    lockfile_version = data.get("lockfileVersion")
    if isinstance(lockfile_version, int):
        metadata["lockfileVersion"] = lockfile_version

    # npm v7+ format: ``packages`` is a flat dict from path to
    # metadata. Older v1/v2 used a recursive ``dependencies``
    # tree; both can coexist in a v7-compatible file. We walk
    # both.
    packages = data.get("packages")
    if isinstance(packages, dict):
        issues.extend(_walk_packages_block(packages))

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        issues.extend(_walk_dependencies_block(dependencies, prefix=""))

    return issues, metadata


def _walk_packages_block(
    packages: dict[str, object],
) -> list[LockfileIssue]:
    """Iterate the v7+ ``packages`` table."""
    issues: list[LockfileIssue] = []
    # ``(name, version) → integrity`` aggregate to detect
    # cross-location mismatches.
    integrity_by_pkg: dict[tuple[str, str], list[tuple[str, str]]] = {}

    for path, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        # The root entry has key "" and no integrity — skip.
        if path == "":
            continue

        integrity = entry.get("integrity")
        if integrity is not None:
            if not looks_like_sri(integrity):
                issues.append(
                    LockfileIssue(
                        rule_id="npm-integrity-malformed",
                        severity="medium",
                        title="package-lock.json integrity is not a valid SRI",
                        message=(
                            f"package {path!r} has integrity "
                            f"{str(integrity)[:64]!r} which is not the "
                            "expected ``<sha256|sha384|sha512>-<base64>`` "
                            "shape"
                        ),
                        location_hint=path,
                    )
                )
            else:
                name = entry.get("name") or _path_to_name(path)
                version = entry.get("version") or ""
                if isinstance(name, str) and isinstance(version, str):
                    integrity_by_pkg.setdefault(
                        (name, version), []
                    ).append((path, str(integrity)))

        resolved = entry.get("resolved")
        if isinstance(resolved, str) and resolved and not is_canonical_registry_url(
            resolved, "npm"
        ):
            issues.append(
                LockfileIssue(
                    rule_id="npm-non-canonical-registry",
                    severity="low",
                    title="package-lock.json resolved URL is not registry.npmjs.org",
                    message=(
                        f"package {path!r} resolves from {resolved!r} — "
                        "expected ``https://registry.npmjs.org/...``. "
                        "Benign for private registries; review for "
                        "unexpected mirrors."
                    ),
                    location_hint=path,
                )
            )

    # Cross-location integrity mismatch
    for (name, version), entries in integrity_by_pkg.items():
        if len({integ for _path, integ in entries}) > 1:
            mismatches = ", ".join(
                f"{p}={i[:16]}…" for p, i in entries
            )
            issues.append(
                LockfileIssue(
                    rule_id="npm-integrity-mismatch",
                    severity="medium",
                    title=(
                        f"npm lockfile: {name}@{version} has divergent "
                        "integrity values across entries"
                    ),
                    message=(
                        f"package {name}@{version} appears with different "
                        f"integrity values: {mismatches}. This is a "
                        "metadata anomaly — the same exact package can "
                        "only have one canonical tarball hash."
                    ),
                    location_hint=f"{name}@{version}",
                )
            )

    return issues


def _walk_dependencies_block(
    dependencies: dict[str, object], *, prefix: str
) -> list[LockfileIssue]:
    """Iterate the legacy ``dependencies`` tree (v1/v2 npm)."""
    issues: list[LockfileIssue] = []
    for name, entry in dependencies.items():
        if not isinstance(entry, dict):
            continue
        loc = f"{prefix}/{name}" if prefix else name
        integrity = entry.get("integrity")
        if integrity is not None and not looks_like_sri(integrity):
            issues.append(
                LockfileIssue(
                    rule_id="npm-integrity-malformed",
                    severity="medium",
                    title="package-lock.json integrity is not a valid SRI",
                    message=(
                        f"package {loc!r} has integrity "
                        f"{str(integrity)[:64]!r} which is not the "
                        "expected ``<sha256|sha384|sha512>-<base64>`` shape"
                    ),
                    location_hint=loc,
                )
            )
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            issues.extend(_walk_dependencies_block(nested, prefix=loc))
    return issues


def _path_to_name(path: str) -> str:
    """``node_modules/foo`` → ``foo``; ``node_modules/@scope/bar`` → ``@scope/bar``."""
    parts = path.split("node_modules/")
    return parts[-1] if parts else path
