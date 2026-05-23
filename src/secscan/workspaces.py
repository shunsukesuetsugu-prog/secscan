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

    Phase 2-C-1: full per-member support. We parse ``members`` (+ optional
    ``exclude``) globs, look at each member's ``pyproject.toml`` for the
    PEP 503 project name, and emit one WorkUnit per member. The
    ``DepsScanner`` then drives ``uv export --package <name>`` for each
    unit to produce a per-member requirements.txt that pip-audit can
    consume (uv.lock is not directly readable by pip-audit).

    Returns ``None`` when there is no uv workspace stanza, so the
    discovery layer falls through to single-project pypi detection.
    A *malformed* stanza returns a non-None WorkspaceExpansion whose
    ``units`` is empty and ``warnings`` explains why — discovery uses
    that to suppress the single-project fallback and avoid silently
    scanning the root with the wrong assumptions.
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

    # uv requires the root lockfile to be present for any reproducible
    # export. Without one, ``uv export --locked`` (which we run later)
    # will fail; surface that early instead of crashing per-member.
    uv_lock = root.resolved / "uv.lock"
    if not _is_real_file(uv_lock):
        return WorkspaceExpansion(
            provider="uv",
            units=(),
            warnings=(
                "uv workspace detected but uv.lock is missing or a symlink; "
                "run `uv lock` at the repo root to enable per-member audit.",
            ),
        )

    raw_members = workspace.get("members")
    if raw_members is None:
        # Per uv docs, omitting ``members`` means the workspace is the
        # root project only. We still emit a single WorkUnit for the
        # root so the export-based audit pipeline kicks in.
        raw_members = []
    elif not isinstance(raw_members, list):
        return WorkspaceExpansion(
            provider="uv",
            units=(),
            warnings=(
                "uv workspace 'members' must be a list of glob patterns.",
            ),
        )

    raw_exclude = workspace.get("exclude", [])
    if not isinstance(raw_exclude, list):
        raw_exclude = []

    includes, excl_inline, glob_warnings = _split_globs(raw_members, source="uv")
    excludes_clean, _excl_dummy, exclude_warnings = _split_globs(
        raw_exclude, source="uv-exclude"
    )
    # uv uses a separate ``exclude`` key (vs pnpm's ``!`` prefix); merge.
    excludes = excl_inline + excludes_clean
    member_dirs = _expand_globs(root, includes, excludes)

    # uv root is always a workspace member; add it explicitly so that an
    # ``--package <root-name>`` export covers root-level deps.
    if root.resolved not in member_dirs:
        member_dirs = [root.resolved, *member_dirs]

    units, count_warnings = _build_uv_units(root, member_dirs, root_lock=uv_lock)
    warnings = list(glob_warnings) + list(exclude_warnings) + list(count_warnings)
    return WorkspaceExpansion(
        provider="uv",
        units=units,
        warnings=tuple(warnings),
    )


# PEP 503 normalization: package distribution names are case-insensitive
# and treat any run of ``-_.`` as equivalent to a single ``-``.
_PEP503_SEPARATOR = re.compile(r"[-_.]+")
# A valid PEP 508/503 distribution name is a letter/digit start, then
# letters/digits/_/-/. characters. We are more permissive than strict
# PEP 508 to accept names that uv itself accepts, but we DO refuse
# anything that could be interpreted as a CLI flag (``-`` prefix) or
# contain shell-grammar.
_VALID_DIST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _canonicalize_pep503(name: str) -> str:
    return _PEP503_SEPARATOR.sub("-", name).lower()


def _build_uv_units(
    root: ResolvedRoot,
    member_dirs: list[Path],
    *,
    root_lock: Path,
) -> tuple[tuple[WorkUnit, ...], list[str]]:
    """Build WorkUnits for a uv workspace expansion.

    Each unit carries the (validated, canonicalized) ``[project].name``
    of the member as its ``workspace_id``; the DepsScanner drives
    ``uv export --package <name>`` against this id. Duplicate
    canonicalized names are skipped with a warning so the same package
    never produces conflated findings.
    """
    warnings: list[str] = []
    truncated = False
    if len(member_dirs) > _WORKSPACE_HARD_CAP:
        warnings.append(
            f"uv workspace has {len(member_dirs)} members; truncating to "
            f"{_WORKSPACE_HARD_CAP}."
        )
        member_dirs = member_dirs[:_WORKSPACE_HARD_CAP]
        truncated = True
    elif len(member_dirs) > _WORKSPACE_WARN_THRESHOLD:
        warnings.append(
            f"uv workspace has {len(member_dirs)} members; secscan will "
            f"export and audit each individually which may take a while."
        )

    units: list[WorkUnit] = []
    seen_canonical: set[str] = set()
    for member in member_dirs:
        manifest = member / "pyproject.toml"
        if not _is_real_file(manifest):
            try:
                rel = member.relative_to(root.resolved)
                warnings.append(
                    f"uv workspace member at '{rel.as_posix()}' has no "
                    f"pyproject.toml; skipped."
                )
            except ValueError:
                warnings.append("uv workspace member outside scan root; skipped.")
            continue
        data = _read_toml(manifest)
        project = data.get("project") if isinstance(data, dict) else None
        if not isinstance(project, dict):
            continue
        name = project.get("name")
        if not isinstance(name, str) or not name.strip():
            try:
                rel = member.relative_to(root.resolved)
                warnings.append(
                    f"uv workspace member at '{rel.as_posix()}' has no "
                    f"[project].name; skipped."
                )
            except ValueError:
                warnings.append("uv workspace member outside scan root; skipped.")
            continue
        stripped = name.strip()
        if not _VALID_DIST_NAME.match(stripped) or _UNSAFE_SELECTOR_CHARS.search(stripped):
            warnings.append(
                f"uv workspace member name '{stripped}' is not a valid PEP "
                f"508/503 distribution name or contains unsafe characters; "
                f"skipped."
            )
            continue
        canonical = _canonicalize_pep503(stripped)
        if canonical in seen_canonical:
            warnings.append(
                f"uv workspace has duplicate canonicalized name "
                f"'{canonical}'; the second occurrence was skipped."
            )
            continue
        seen_canonical.add(canonical)
        try:
            member_path = member.relative_to(root.resolved)
        except ValueError:
            continue
        units.append(
            WorkUnit(
                root=root.resolved,
                ecosystem="pypi",
                manifest=manifest,
                lockfile=root_lock,
                package_manager="uv",
                workspace_id=canonical,
                workspace_member_path=member_path,
            )
        )
    if not units and not truncated and not warnings:
        warnings.append("uv workspace patterns matched no members.")
    return tuple(units), warnings


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
