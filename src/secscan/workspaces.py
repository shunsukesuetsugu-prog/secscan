"""Workspace topology discovery.

Discovery reads three workspace formats — pnpm, npm, and (stub) uv — and
returns the list of WorkUnits the deps scanner should process.

Responsibility note (Codex 20th review):
  Discovery is allowed to read manifest files just enough to extract
  *workspace topology*. It does NOT parse dependencies, lockfiles, or
  package versions — that's the scanner's job. Keeping this line crisp
  prevents the module from growing into a parallel package-resolver.

Security properties pinned by the same review:
  - All workspace config / manifest / lockfile reads go through
    ``path_safety._is_real_file`` so symlinked configs are rejected.
  - Glob patterns containing ``..``, absolute paths, or drive letters
    are rejected before expansion.
  - YAML files larger than ``_MAX_CONFIG_SIZE_BYTES`` are rejected to
    bound parser memory.
  - Workspace member counts above ``_WORKSPACE_HARD_CAP`` are truncated.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

import yaml

from .discovery import _is_real_file
from .models import WorkUnit
from .path_safety import ResolvedRoot

# Hard limit on workspace config file size. pnpm-workspace.yaml's biggest
# real-world examples are well under 100KB; 1MB is a generous ceiling that
# still bounds yaml.safe_load memory.
_MAX_CONFIG_SIZE_BYTES = 1 * 1024 * 1024

# Cap the number of workspace members. Beyond this we keep the first N and
# emit a warning so the user knows their topology is being truncated.
_WORKSPACE_HARD_CAP = 100
_WORKSPACE_WARN_THRESHOLD = 50

# Characters that pnpm's ``--filter`` (and npm's ``--workspace`` to a
# lesser extent) interpret as selector grammar. A package name that
# contains any of these would expand to a different scope than the
# author intended when passed verbatim as a selector — Codex 21st
# review flagged this as a selector-injection class issue. Real npm
# package names per the registry spec do not include these characters,
# so refusing them is safe.
_UNSAFE_SELECTOR_CHARS = re.compile(r"[!*^~()<>\[\]{}\s]|\.\.\.")


@dataclass(frozen=True)
class WorkspaceExpansion:
    """Result of expanding a workspace configuration.

    ``provider`` identifies which workspace format produced the units; the
    scanner adapter consults this to add ``--workspace`` (npm) /
    ``--filter`` (pnpm) selectors. ``warnings`` are surfaced through the
    Discovery result so the user sees what was truncated / skipped.
    """

    provider: str
    """One of ``"npm"``, ``"pnpm"``, ``"uv"``."""

    units: tuple[WorkUnit, ...]
    """The WorkUnits to scan. May be empty if no valid members remain."""

    warnings: tuple[str, ...] = ()


# --- Public detection entry points ---------------------------------------


def detect_pnpm_workspace(root: ResolvedRoot) -> WorkspaceExpansion | None:
    """Detect pnpm workspaces by ``pnpm-workspace.yaml``.

    Returns None if the file is absent. Returns an Expansion (possibly with
    warnings + zero units) when present but malformed; the caller surfaces
    that as a Discovery warning rather than crashing.
    """
    config_path = root.resolved / "pnpm-workspace.yaml"
    if not _is_real_file(config_path):
        return None
    raw = _read_yaml(config_path)
    # ``None`` happens when the file is empty / comments-only / oversize /
    # malformed. pnpm treats an empty workspace config as "root package
    # only" — emit no warnings, let the regular npm detection handle the
    # root. A non-dict, non-None value is a real schema error.
    if raw is None:
        return WorkspaceExpansion(provider="pnpm", units=(), warnings=())
    if not isinstance(raw, dict):
        return WorkspaceExpansion(
            provider="pnpm",
            units=(),
            warnings=(f"pnpm-workspace.yaml is not a YAML object: {config_path}",),
        )
    raw_packages = raw.get("packages")
    if raw_packages is None:
        # Per pnpm docs, omitted "packages:" means "only the root package".
        # Treat as "no member expansion; deps will still scan the root via
        # the existing _detect_npm path".
        return WorkspaceExpansion(
            provider="pnpm",
            units=(),
            warnings=(),
        )
    if not isinstance(raw_packages, list):
        return WorkspaceExpansion(
            provider="pnpm",
            units=(),
            warnings=(
                f"pnpm-workspace.yaml 'packages' is not a list: {config_path}",
            ),
        )

    includes, excludes, glob_warnings = _split_globs(raw_packages, source="pnpm")
    matches = _expand_globs(root, includes, excludes)
    units, count_warnings = _build_npm_units(root, matches, package_manager="pnpm")
    return WorkspaceExpansion(
        provider="pnpm",
        units=units,
        warnings=tuple(glob_warnings) + tuple(count_warnings),
    )


def detect_npm_workspace(root: ResolvedRoot) -> WorkspaceExpansion | None:
    """Detect npm workspaces by the ``workspaces`` key in package.json.

    Accepts both the canonical ``["packages/*"]`` array form and the
    Yarn-Classic-derived ``{"packages": [...], "nohoist": [...]}`` shape.
    ``nohoist`` is silently ignored — secscan only needs the package list.
    """
    pkg_json = root.resolved / "package.json"
    if not _is_real_file(pkg_json):
        return None
    raw = _read_json(pkg_json)
    if not isinstance(raw, dict):
        return None
    raw_workspaces = raw.get("workspaces")
    if raw_workspaces is None:
        return None

    if isinstance(raw_workspaces, list):
        patterns = raw_workspaces
    elif isinstance(raw_workspaces, dict):
        nested = raw_workspaces.get("packages")
        if not isinstance(nested, list):
            return WorkspaceExpansion(
                provider="npm",
                units=(),
                warnings=(
                    "package.json workspaces.packages is not a list",
                ),
            )
        patterns = nested
    else:
        return WorkspaceExpansion(
            provider="npm",
            units=(),
            warnings=(
                "package.json workspaces must be a list or object",
            ),
        )

    includes, excludes, glob_warnings = _split_globs(patterns, source="npm")
    matches = _expand_globs(root, includes, excludes)
    units, count_warnings = _build_npm_units(root, matches, package_manager="npm")
    return WorkspaceExpansion(
        provider="npm",
        units=units,
        warnings=tuple(glob_warnings) + tuple(count_warnings),
    )


def detect_uv_workspace(root: ResolvedRoot) -> WorkspaceExpansion | None:
    """Detect uv workspaces by ``[tool.uv.workspace]`` in pyproject.toml.

    Phase 2-B status: pip-audit cannot consume ``uv.lock`` directly, so
    secscan does NOT split a uv workspace into per-member WorkUnits yet.
    We still detect the configuration so the Discovery layer can emit a
    clear warning and fall back to scanning the root as a single unit.
    Phase 2-C will fix the export path.
    """
    pyproject = root.resolved / "pyproject.toml"
    if not _is_real_file(pyproject):
        return None
    raw = _read_toml(pyproject)
    tool = raw.get("tool")
    if not isinstance(tool, dict):
        return None
    uv = tool.get("uv")
    if not isinstance(uv, dict):
        return None
    workspace = uv.get("workspace")
    if not isinstance(workspace, dict):
        return None
    # Workspace stanza exists. Phase 2-B doesn't split members here yet.
    return WorkspaceExpansion(
        provider="uv",
        units=(),  # caller falls back to root scanning
        warnings=(
            "uv workspace detected; per-member scanning is not yet supported "
            "(planned for a future release). Scanning the root project as a "
            "single unit. To audit each member explicitly, run "
            "`uv export -o requirements.txt --package <name>` per member.",
        ),
    )


def detect_yarn_unsupported(root: ResolvedRoot) -> tuple[str, ...]:
    """If yarn.lock + package.json workspaces co-exist, emit a warning.

    Yarn workspaces are NOT supported in Phase 2-B. Without this guard,
    the npm-workspaces detection above would happily walk the patterns
    and the npm adapter would then try ``npm audit`` against a yarn-only
    project, producing a confusing error.
    """
    yarn_lock = root.resolved / "yarn.lock"
    pkg_json = root.resolved / "package.json"
    if not _is_real_file(yarn_lock) or not _is_real_file(pkg_json):
        return ()
    npm_lock = root.resolved / "package-lock.json"
    pnpm_lock = root.resolved / "pnpm-lock.yaml"
    if _is_real_file(npm_lock) or _is_real_file(pnpm_lock):
        # Mixed setup: npm/pnpm lockfile is present alongside yarn.lock.
        # The npm/pnpm adapter will pick the right lockfile, but the user
        # likely has stale yarn.lock — warn but don't block.
        return (
            "yarn.lock coexists with another lockfile; secscan will use the "
            "non-yarn lockfile. Remove yarn.lock to avoid drift.",
        )
    raw = _read_json(pkg_json)
    if isinstance(raw, dict) and "workspaces" in raw:
        return (
            "yarn workspaces detected but not supported in this release; "
            "secscan supports npm and pnpm workspaces.",
        )
    return ()


# --- Internals -----------------------------------------------------------


def _read_yaml(path: Path) -> object:
    """Safely load a YAML file with a size cap.

    Returns ``None`` on any read / parse failure so callers can produce a
    targeted warning. We use ``yaml.safe_load`` which restricts the parser
    to Python primitives (no arbitrary object construction). Size cap
    bounds parser memory against pathological inputs.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _MAX_CONFIG_SIZE_BYTES:
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _read_json(path: Path) -> object:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _MAX_CONFIG_SIZE_BYTES:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_toml(path: Path) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError:
        return {}
    if size > _MAX_CONFIG_SIZE_BYTES:
        return {}
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return data


def _split_globs(
    patterns: list[object], *, source: str
) -> tuple[list[str], list[str], list[str]]:
    """Split a list of glob entries into (includes, excludes, warnings).

    pnpm and Yarn use ``!`` prefix for excludes. npm canonical doesn't,
    but we accept and warn for forward-compat. Unsafe patterns (absolute,
    drive prefix, ``..``) are dropped with a warning.
    """
    includes: list[str] = []
    excludes: list[str] = []
    warnings: list[str] = []
    for entry in patterns:
        if not isinstance(entry, str) or not entry.strip():
            warnings.append(
                f"{source}: skipped non-string workspace pattern: {entry!r}"
            )
            continue
        pattern = entry.strip()
        is_exclude = pattern.startswith("!")
        if is_exclude:
            pattern = pattern[1:]
        if not _is_safe_pattern(pattern):
            warnings.append(
                f"{source}: skipped unsafe workspace pattern: {entry!r}"
            )
            continue
        (excludes if is_exclude else includes).append(pattern)
    return includes, excludes, warnings


def _is_safe_pattern(pattern: str) -> bool:
    """Reject patterns that could escape the scan root or denote URIs."""
    if not pattern:
        return False
    # Absolute paths (POSIX or Windows-drive-style).
    if pattern.startswith("/") or pattern.startswith("\\"):
        return False
    if len(pattern) >= 2 and pattern[1] == ":":  # e.g. "C:..."
        return False
    # Embedded URI scheme.
    if "://" in pattern:
        return False
    # Path components equal to "..".
    for separator in ("/", "\\"):
        if any(seg == ".." for seg in pattern.split(separator)):
            return False
    return True


def _expand_globs(
    root: ResolvedRoot, includes: list[str], excludes: list[str]
) -> list[Path]:
    """Expand include/exclude patterns into a list of validated directories.

    Each result is a real directory under ``root.resolved`` whose
    ``package.json`` (or, for uv, ``pyproject.toml``) is a regular file
    (not a symlink). Order is deterministic (sorted by relative path) so
    fingerprints are stable.
    """
    matched: set[Path] = set()
    for pat in includes:
        for candidate in root.resolved.glob(pat):
            if not _accept_member_dir(candidate, root):
                continue
            matched.add(candidate.resolve(strict=False))

    excluded: set[Path] = set()
    for pat in excludes:
        for candidate in root.resolved.glob(pat):
            try:
                excluded.add(candidate.resolve(strict=False))
            except OSError:
                continue
    return sorted(matched - excluded)


def _accept_member_dir(candidate: Path, root: ResolvedRoot) -> bool:
    """Whether ``candidate`` is a directory we may treat as a workspace member."""
    try:
        if candidate.is_symlink():
            return False
        if not candidate.is_dir():
            return False
    except OSError:
        return False
    resolved = candidate.resolve(strict=False)
    if not root.contains(resolved):
        return False
    return not root.is_ignored(resolved)


def _build_npm_units(
    root: ResolvedRoot,
    member_dirs: list[Path],
    *,
    package_manager: str,
) -> tuple[tuple[WorkUnit, ...], list[str]]:
    """Build WorkUnits for an npm-family workspace expansion.

    The audit runs from ``scan_root`` (so the root lockfile is the
    authoritative source); each unit carries the workspace selector
    (``workspace_id``) that the npm/pnpm adapter passes via ``--workspace``
    / ``--filter``.
    """
    warnings: list[str] = []
    truncated = False
    if len(member_dirs) > _WORKSPACE_HARD_CAP:
        warnings.append(
            f"workspace has {len(member_dirs)} members; truncating to "
            f"{_WORKSPACE_HARD_CAP}. Use --skip-workspaces or split your "
            f"repo if this is intentional."
        )
        member_dirs = member_dirs[:_WORKSPACE_HARD_CAP]
        truncated = True
    elif len(member_dirs) > _WORKSPACE_WARN_THRESHOLD:
        warnings.append(
            f"workspace has {len(member_dirs)} members; secscan will scan "
            f"each individually which may take a while."
        )

    units: list[WorkUnit] = []
    for member in member_dirs:
        manifest = member / "package.json"
        if not _is_real_file(manifest):
            continue
        raw = _read_json(manifest)
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            # Without a package name, npm/pnpm's --workspace / --filter
            # selectors have nothing to bind to. Skip rather than emit a
            # selector that would silently match nothing.
            try:
                rel = member.relative_to(root.resolved)
                warnings.append(
                    f"workspace member at '{rel.as_posix()}' has no 'name' "
                    f"in package.json; skipped."
                )
            except ValueError:
                warnings.append(
                    "workspace member outside scan root; skipped."
                )
            continue
        stripped_name = name.strip()
        if _UNSAFE_SELECTOR_CHARS.search(stripped_name):
            # Codex 21st review: a name containing pnpm filter grammar
            # would expand to a scope different from this one member. We
            # cannot safely pass it to --filter / --workspace; skip with
            # a warning so the user sees that the member was excluded.
            try:
                rel = member.relative_to(root.resolved)
                warnings.append(
                    f"workspace member '{stripped_name}' at "
                    f"'{rel.as_posix()}' has a name containing selector "
                    f"grammar characters; skipped."
                )
            except ValueError:
                warnings.append(
                    f"workspace member '{stripped_name}' has a name "
                    f"containing selector grammar characters; skipped."
                )
            continue
        try:
            member_path = member.relative_to(root.resolved)
        except ValueError:
            continue
        units.append(
            WorkUnit(
                # The audit runs from the repo root so the root lockfile
                # is the authoritative dependency graph.
                root=root.resolved,
                ecosystem="npm",
                manifest=manifest,
                lockfile=_root_npm_lockfile(root, package_manager),
                package_manager=package_manager,
                workspace_id=stripped_name,
                workspace_member_path=member_path,
            )
        )
    if not units and not truncated and not warnings:
        warnings.append("workspace patterns matched no members.")
    return tuple(units), warnings


def _root_npm_lockfile(root: ResolvedRoot, package_manager: str) -> Path | None:
    """Return the authoritative root lockfile for an npm-family workspace."""
    candidates = {
        "pnpm": ("pnpm-lock.yaml",),
        "npm": ("package-lock.json", "npm-shrinkwrap.json"),
    }.get(package_manager, ())
    for name in candidates:
        candidate = root.resolved / name
        if _is_real_file(candidate):
            return candidate
    return None
