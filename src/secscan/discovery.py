"""Project discovery.

MVP scope (deliberately small — Codex pushed back on a full monorepo design
and we chose to defer workspaces to Phase 1.5):

- For ``secrets`` and ``sast``, the WorkUnit is the scan root itself.
  These scanners operate on raw file content, not on package manifests.
- For ``deps``, we look at the top level of the scan root for known manifest
  files and emit one WorkUnit per detected ecosystem. The MVP recognizes:
    - npm/pnpm (``package.json`` + lockfile selection)
    - PyPI (``pyproject.toml`` / ``requirements*.txt`` / ``setup.py``)
- Nested manifests (e.g. ``packages/foo/package.json``) are NOT walked. We
  emit a warning so the user knows their workspace setup isn't fully covered.

The discovery layer never reads file content beyond what's needed to pick a
lockfile — it only enumerates work units. Parsing manifests is a scanner
concern.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import WorkUnit
from .path_safety import ResolvedRoot


@dataclass(frozen=True)
class Discovery:
    work_units: tuple[WorkUnit, ...]
    warnings: tuple[str, ...]


def discover_for_scanner(scanner: str, root: ResolvedRoot) -> Discovery:
    """Return the work units a given scanner should process.

    For non-deps scanners we return a single root-level WorkUnit. For deps,
    we look at top-level manifests and emit one WorkUnit per detected
    ecosystem. Each scanner remains free to skip WorkUnits via
    ``Scanner.is_applicable``.
    """
    if scanner != "deps":
        return Discovery(
            work_units=(WorkUnit(root=root.resolved),),
            warnings=(),
        )
    return _discover_deps(root)


def _discover_deps(root: ResolvedRoot) -> Discovery:
    units: list[WorkUnit] = []
    warnings: list[str] = []

    npm = _detect_npm(root.resolved)
    if npm is not None:
        units.append(npm)

    pypi = _detect_pypi(root.resolved)
    if pypi is not None:
        units.append(pypi)

    if not units:
        warnings.append(
            "no dependency manifest detected at the scan root "
            "(looked for package.json, pyproject.toml, requirements*.txt, setup.py)"
        )

    nested = _detect_nested_manifests(root)
    if nested:
        # Truncate to keep warnings actionable.
        sample = ", ".join(sorted(nested)[:5])
        more = "" if len(nested) <= 5 else f" (+{len(nested) - 5} more)"
        warnings.append(
            f"nested package manifests found but not scanned in MVP: {sample}{more}"
        )

    return Discovery(work_units=tuple(units), warnings=tuple(warnings))


# --- Per-ecosystem detection ----------------------------------------------


def _detect_npm(root: Path) -> WorkUnit | None:
    manifest = root / "package.json"
    if not manifest.is_file():
        return None
    # Lockfile preference order matches what npm/pnpm themselves prefer:
    # pnpm > npm package-lock > shrinkwrap. We don't currently scan yarn.lock
    # in MVP — yarn audit semantics differ enough that Phase 1B will decide.
    for lockname in ("pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json"):
        candidate = root / lockname
        if candidate.is_file():
            return WorkUnit(
                root=root,
                ecosystem="npm",
                manifest=manifest,
                lockfile=candidate,
            )
    return WorkUnit(root=root, ecosystem="npm", manifest=manifest, lockfile=None)


def _detect_pypi(root: Path) -> WorkUnit | None:
    pyproject = root / "pyproject.toml"
    setup_py = root / "setup.py"
    # Multiple requirements*.txt is normal (e.g. requirements.txt,
    # requirements-dev.txt). We pick the canonical one for the manifest hint
    # and let the scanner enumerate the rest.
    req_main = root / "requirements.txt"
    has_any = pyproject.is_file() or setup_py.is_file() or req_main.is_file()
    # Even with a non-canonical requirements file (e.g. requirements-dev.txt),
    # the top-level check should still surface it.
    if not has_any and any(p.is_file() for p in root.glob("requirements*.txt")):
        has_any = True
    if not has_any:
        return None

    manifest: Path | None
    lockfile: Path | None
    if pyproject.is_file():
        manifest = pyproject
        # uv/pdm style locks
        for lockname in ("uv.lock", "pdm.lock", "pylock.toml"):
            candidate = root / lockname
            if candidate.is_file():
                lockfile = candidate
                break
        else:
            lockfile = None
    elif req_main.is_file():
        manifest = req_main
        lockfile = req_main  # requirements.txt itself doubles as a lock-ish file
    elif setup_py.is_file():
        manifest = setup_py
        lockfile = None
    else:
        # requirements*.txt only (no requirements.txt by canonical name)
        manifest = next(iter(sorted(root.glob("requirements*.txt"))), None)
        lockfile = manifest

    return WorkUnit(
        root=root,
        ecosystem="pypi",
        manifest=manifest,
        lockfile=lockfile,
    )


def _detect_nested_manifests(root: ResolvedRoot) -> set[str]:
    """Find package.json / pyproject.toml below the top level.

    We use this only to emit a warning. To keep discovery O(reasonable), we
    cap the walk depth and skip ignored directories early.
    """
    nested: set[str] = set()
    interesting = {"package.json", "pyproject.toml", "setup.py", "requirements.txt"}
    max_depth = 4

    def _walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue  # Don't follow symlinks
                if entry.is_dir():
                    if entry.name in root.ignore_dirs:
                        continue
                    _walk(entry, depth + 1)
                elif entry.is_file() and entry.name in interesting:
                    nested.add(root.relativize(entry))
            except OSError:
                continue

    # Walk only direct children's subdirectories (top level already handled).
    try:
        children = [p for p in root.resolved.iterdir() if p.is_dir()]
    except OSError:
        return nested
    for child in children:
        if child.name in root.ignore_dirs:
            continue
        if child.is_symlink():
            continue
        _walk(child, depth=1)
    return nested
