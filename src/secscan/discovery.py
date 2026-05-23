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

    # Phase 2-B: check for workspace topology BEFORE falling back to the
    # single-project discovery path. ``_check_workspaces`` returns the
    # workspace units (possibly empty if the workspace expansion produced
    # nothing) AND any associated warnings.
    (
        workspace_units,
        workspace_warnings,
        workspace_npm_handled,
        workspace_uv_handled,
    ) = _check_workspaces(root)
    units.extend(workspace_units)
    warnings.extend(workspace_warnings)

    # Fall back to single-project npm detection ONLY when no npm-family
    # workspace was processed. Otherwise we'd emit a redundant "root"
    # WorkUnit alongside the per-member ones and audit dependencies twice.
    if not workspace_npm_handled:
        npm = _detect_npm(root.resolved)
        if npm is not None:
            units.append(npm)

    # Same logic for pypi: uv workspace expansion (Phase 2-C-1) already
    # emits one WorkUnit per member; without this guard we'd add a
    # redundant single-project pypi unit and pip-audit twice.
    if not workspace_uv_handled:
        pypi = _detect_pypi(root.resolved)
        if pypi is not None:
            units.append(pypi)

    if not units:
        warnings.append(
            "no dependency manifest detected at the scan root "
            "(looked for package.json, pyproject.toml, requirements*.txt, setup.py)"
        )

    nested = _detect_nested_manifests(root)
    # Codex 24th review: a workspace member's manifest IS being scanned
    # via the corresponding WorkUnit; the "nested not scanned" warning
    # would be misleading. Drop manifests that any unit already covers.
    if nested:
        covered = _covered_manifest_paths(units, root)
        nested = nested - covered
    if nested:
        # Truncate to keep warnings actionable.
        sample = ", ".join(sorted(nested)[:5])
        more = "" if len(nested) <= 5 else f" (+{len(nested) - 5} more)"
        warnings.append(
            f"nested package manifests found but not scanned in MVP: {sample}{more}"
        )

    return Discovery(work_units=tuple(units), warnings=tuple(warnings))


def _covered_manifest_paths(
    units: list[WorkUnit], root: ResolvedRoot
) -> set[str]:
    """Return the set of nested-manifest display strings already covered
    by an emitted WorkUnit. Used to suppress the "nested but not scanned"
    warning for workspace members we DID scan."""
    covered: set[str] = set()
    for unit in units:
        if unit.manifest is None:
            continue
        try:
            rel = unit.manifest.resolve(strict=False).relative_to(root.resolved)
        except (ValueError, OSError):
            continue
        covered.add(rel.as_posix())
    return covered


def _check_workspaces(
    root: ResolvedRoot,
) -> tuple[list[WorkUnit], list[str], bool, bool]:
    """Inspect the scan root for workspace configurations.

    Returns ``(units, warnings, npm_handled, uv_handled)`` where:

    - ``units``: WorkUnits produced by workspace expansion.
    - ``warnings``: messages to surface in the report.
    - ``npm_handled``: True when an npm-family workspace expansion
      produced at least one unit; single-project npm fallback should be
      skipped in that case.
    - ``uv_handled``: same idea for uv workspace expansion (Phase 2-C-1).
      A non-empty uv workspace suppresses the single-project pypi
      fallback to avoid auditing the root twice. A *malformed* uv
      workspace stanza (returned as ``units=()`` with warnings) also
      suppresses the fallback so we don't silently audit with the wrong
      assumptions.

    Workspace detection consults the workspace config files only — the
    heavy lifting lives in ``workspaces.py``.
    """
    # Avoid a circular import by deferring it to call time.
    from .workspaces import (
        detect_npm_workspace,
        detect_pnpm_workspace,
        detect_uv_workspace,
        detect_yarn_unsupported,
    )

    units: list[WorkUnit] = []
    warnings: list[str] = []
    npm_handled = False

    yarn_warnings = detect_yarn_unsupported(root)
    warnings.extend(yarn_warnings)
    # Codex 21st review: a yarn-only repo whose package.json carries a
    # ``workspaces`` field must NOT then be processed as an npm workspace
    # — that would run ``npm audit --workspace <id>`` against a project
    # that lacks the npm lockfile entirely. The yarn detector flags the
    # "unsupported" condition specifically; the drift-warning case (yarn
    # lockfile coexists with an npm/pnpm lockfile) is benign because
    # those scanners handle it correctly.
    yarn_blocks_npm = any("yarn workspaces" in w for w in yarn_warnings)

    pnpm = detect_pnpm_workspace(root)
    if pnpm is not None:
        units.extend(pnpm.units)
        warnings.extend(pnpm.warnings)
        # Only suppress the single-project npm fallback when pnpm
        # actually produced members. An empty/malformed
        # pnpm-workspace.yaml that yielded zero units MUST still let
        # the root project be scanned (Codex 21st BLOCKER: otherwise
        # presence of an empty workspace config silently disables deps
        # scanning entirely).
        if pnpm.units:
            npm_handled = True

    # Only fall through to npm-workspaces when pnpm didn't already claim
    # the project: a repo with both pnpm-workspace.yaml AND
    # package.json#workspaces is pnpm-managed in practice. Skip
    # entirely when yarn unsupported was detected.
    if not npm_handled and not yarn_blocks_npm:
        npm_ws = detect_npm_workspace(root)
        if npm_ws is not None:
            units.extend(npm_ws.units)
            warnings.extend(npm_ws.warnings)
            # Same logic as pnpm: only suppress single-project fallback
            # when workspace expansion produced real units.
            if npm_ws.units:
                npm_handled = True

    uv_handled = False
    uv = detect_uv_workspace(root)
    if uv is not None:
        units.extend(uv.units)
        warnings.extend(uv.warnings)
        # Phase 2-C-1: when uv detection returns ANY response (units OR
        # warnings) we suppress the single-project pypi fallback. A
        # malformed/missing-lock uv workspace must not silently fall
        # back to scanning the root as if no workspace existed — that
        # would be a different audit than the user expected.
        uv_handled = True

    return units, warnings, npm_handled, uv_handled


# --- Per-ecosystem detection ----------------------------------------------


def _is_real_file(path: Path) -> bool:
    """``True`` only if ``path`` is a regular file that is NOT a symlink.

    Codex 8th review flagged that ``Path.is_file()`` silently follows
    symlinks, so a manifest/lockfile under the scan root could point to a
    file outside the root. We refuse symlinked manifests outright: a
    package manager reading them would read out-of-tree content, and a
    legitimate project rarely needs its lockfile to be a symlink.
    """
    try:
        if path.is_symlink():
            return False
        return path.is_file()
    except OSError:
        return False


def _detect_npm(root: Path) -> WorkUnit | None:
    manifest = root / "package.json"
    if not _is_real_file(manifest):
        return None
    # Lockfile preference order matches what npm/pnpm themselves prefer:
    # pnpm > npm package-lock > shrinkwrap. We don't currently scan yarn.lock
    # in MVP — yarn audit semantics differ enough that Phase 1C will decide.
    # ``package_manager`` is set from the lockfile choice so the deps
    # adapter can pick the right CLI (npm/pnpm have different audit flags).
    lockfile_to_pm: dict[str, str] = {
        "pnpm-lock.yaml": "pnpm",
        "package-lock.json": "npm",
        "npm-shrinkwrap.json": "npm",
    }
    for lockname, pm in lockfile_to_pm.items():
        candidate = root / lockname
        if _is_real_file(candidate):
            return WorkUnit(
                root=root,
                ecosystem="npm",
                manifest=manifest,
                lockfile=candidate,
                package_manager=pm,
            )
    # No lockfile: default to npm (more widely deployed). The adapter still
    # respects ``allow_missing_lockfile`` before deciding to run.
    return WorkUnit(
        root=root,
        ecosystem="npm",
        manifest=manifest,
        lockfile=None,
        package_manager="npm",
    )


def _detect_pypi(root: Path) -> WorkUnit | None:
    pyproject = root / "pyproject.toml"
    setup_py = root / "setup.py"
    # Multiple requirements*.txt is normal (e.g. requirements.txt,
    # requirements-dev.txt). We pick the canonical one for the manifest hint
    # and let the scanner enumerate the rest.
    req_main = root / "requirements.txt"
    has_any = _is_real_file(pyproject) or _is_real_file(setup_py) or _is_real_file(req_main)
    # Even with a non-canonical requirements file (e.g. requirements-dev.txt),
    # the top-level check should still surface it.
    if not has_any and any(_is_real_file(p) for p in root.glob("requirements*.txt")):
        has_any = True
    if not has_any:
        return None

    manifest: Path | None
    lockfile: Path | None
    package_manager: str
    if _is_real_file(pyproject):
        manifest = pyproject
        # uv/pdm style locks. The package_manager hint matches the lockfile
        # producer so the adapter can decide whether `pip-audit --project`
        # is meaningful (it understands pylock.toml natively from 2.10+).
        pm_by_lock = {"uv.lock": "uv", "pdm.lock": "pdm", "pylock.toml": "pip"}
        lockfile = None
        package_manager = "pip"  # pyproject without lock → fall back to pip
        for lockname, pm in pm_by_lock.items():
            candidate = root / lockname
            if _is_real_file(candidate):
                lockfile = candidate
                package_manager = pm
                break
    elif _is_real_file(req_main):
        manifest = req_main
        lockfile = req_main  # requirements.txt itself doubles as a lock-ish file
        package_manager = "pip-requirements"
    elif _is_real_file(setup_py):
        manifest = setup_py
        lockfile = None
        package_manager = "pip"
    else:
        # requirements*.txt only (no requirements.txt by canonical name)
        manifest = next(
            iter(sorted(p for p in root.glob("requirements*.txt") if _is_real_file(p))),
            None,
        )
        lockfile = manifest
        package_manager = "pip-requirements"

    return WorkUnit(
        root=root,
        ecosystem="pypi",
        manifest=manifest,
        lockfile=lockfile,
        package_manager=package_manager,
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
