"""Tests for workspace discovery (Phase 2-B).

We drive the public detection functions directly with a freshly-built
``ResolvedRoot`` over a ``tmp_path``. These tests cover:

- pnpm: packages glob, exclude with ``!``, root-level member, unsafe
  glob rejection, symlinked member rejection.
- npm: array form, ``{packages: [...]}`` Yarn-Classic shape, malformed
  shapes, ``name``-less member rejection.
- uv: workspace stanza detected → warning only, no per-member units
  (Phase 2-B doesn't split uv).
- yarn: ``yarn.lock`` + workspaces → unsupported warning.
- limits: > _WORKSPACE_HARD_CAP truncation, > _WORKSPACE_WARN_THRESHOLD
  warning.
- safety: yaml size limit, ``..`` / absolute / URI-scheme patterns
  rejected before glob expansion.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from secscan.path_safety import resolve_scan_root
from secscan.workspaces import (
    detect_npm_workspace,
    detect_pnpm_workspace,
    detect_uv_workspace,
    detect_yarn_unsupported,
)

# --- pnpm-workspace.yaml -------------------------------------------------


def _write_pnpm_workspace(root: Path, body: str) -> None:
    (root / "pnpm-workspace.yaml").write_text(body, encoding="utf-8")


def _write_package(root: Path, rel: str, name: str) -> Path:
    pkg_dir = root / rel
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8"
    )
    return pkg_dir


def test_pnpm_workspace_returns_none_when_file_absent(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    assert detect_pnpm_workspace(root) is None


def test_pnpm_workspace_expands_packages_glob(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    _write_package(tmp_path, "packages/api", "@org/api")
    _write_package(tmp_path, "packages/web", "@org/web")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.provider == "pnpm"
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert workspace_ids == {"@org/api", "@org/web"}
    # Every unit's root is the repo root (audit runs from there).
    assert all(u.root == tmp_path.resolve() for u in expansion.units)
    # ecosystem + package_manager populated.
    assert all(u.ecosystem == "npm" for u in expansion.units)
    assert all(u.package_manager == "pnpm" for u in expansion.units)


def test_pnpm_workspace_exclude_patterns(tmp_path: Path) -> None:
    """``!`` prefix marks an exclude pattern."""
    _write_pnpm_workspace(
        tmp_path,
        "packages:\n  - 'packages/*'\n  - '!packages/internal'\n",
    )
    _write_package(tmp_path, "packages/api", "@org/api")
    _write_package(tmp_path, "packages/internal", "@org/internal")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert workspace_ids == {"@org/api"}


def test_pnpm_workspace_lockfile_attached(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    _write_package(tmp_path, "packages/api", "@org/api")
    (tmp_path / "pnpm-lock.yaml").write_text("# pnpm lock\n", encoding="utf-8")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    (unit,) = expansion.units
    assert unit.lockfile is not None
    assert unit.lockfile.name == "pnpm-lock.yaml"


def test_pnpm_workspace_member_without_name_is_skipped(tmp_path: Path) -> None:
    """Members lacking a ``name`` can't be targeted by ``--filter`` and
    are skipped with a warning rather than emitted with no selector."""
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    pkg = tmp_path / "packages" / "unnamed"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"version": "1.0.0"}))
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("no 'name'" in w for w in expansion.warnings)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics")
def test_pnpm_workspace_symlinked_member_is_excluded(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    real_dir = tmp_path / "real_package"
    real_dir.mkdir()
    (real_dir / "package.json").write_text(
        json.dumps({"name": "@org/real"}), encoding="utf-8"
    )
    link = tmp_path / "packages" / "linked"
    link.parent.mkdir()
    link.symlink_to(real_dir, target_is_directory=True)
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert all(u.workspace_id != "@org/real" for u in expansion.units)


@pytest.mark.parametrize(
    "unsafe_pattern",
    [
        "/abs/path",
        "../escape",
        "packages/..",
        "C:\\windows\\path",
        "http://example.com/pkg",
    ],
)
def test_pnpm_workspace_rejects_unsafe_glob_patterns(
    tmp_path: Path, unsafe_pattern: str
) -> None:
    """Unsafe glob patterns are dropped before expansion (Codex 20th)."""
    _write_pnpm_workspace(tmp_path, f"packages:\n  - '{unsafe_pattern}'\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("unsafe" in w for w in expansion.warnings)


def test_pnpm_workspace_oversize_file_is_rejected(tmp_path: Path) -> None:
    """A pathologically large pnpm-workspace.yaml is refused before parsing."""
    big = tmp_path / "pnpm-workspace.yaml"
    # 2 MB > 1 MB cap.
    big.write_text("packages:\n  - 'x'\n" + ("# pad\n" * (2 * 1024 * 1024 // 6)))
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    # Returned expansion has no units since _read_yaml refused to parse.
    assert expansion.units == ()


def test_pnpm_workspace_packages_omitted_is_acceptable(tmp_path: Path) -> None:
    """pnpm docs: omitted 'packages:' means root package only."""
    _write_pnpm_workspace(tmp_path, "# nothing here\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert expansion.warnings == ()


def test_pnpm_workspace_malformed_yaml_warns(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, ": : : not valid")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()


@pytest.mark.parametrize(
    "evil_name",
    [
        "!internal",
        "pkg*",
        "pkg^1.0.0",
        "pkg~1.0.0",
        "pkg<{config}>",
        "pkg(filter)",
        "pkg space",
        "pkg...",
    ],
)
def test_workspace_member_with_selector_grammar_is_skipped(
    tmp_path: Path, evil_name: str
) -> None:
    """Codex 21st review: a workspace member whose ``name`` contains
    pnpm filter grammar (``!``, ``*``, ``^``, ``~``, ``...``, etc.)
    must NOT be forwarded as a ``--filter`` selector — that would
    expand to a different scope than the user expects."""
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    pkg = tmp_path / "packages" / "evil"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(
        json.dumps({"name": evil_name, "version": "1.0.0"})
    )
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert all(u.workspace_id != evil_name for u in expansion.units)
    assert any("selector grammar" in w for w in expansion.warnings)


# --- npm workspaces (array + object forms) -------------------------------


def _write_root_package(root: Path, *, workspaces: object) -> None:
    payload = {"name": "monorepo-root", "private": True, "workspaces": workspaces}
    (root / "package.json").write_text(json.dumps(payload), encoding="utf-8")


def test_npm_workspace_returns_none_when_no_workspaces_key(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    root = resolve_scan_root(tmp_path)
    assert detect_npm_workspace(root) is None


def test_npm_workspace_array_form(tmp_path: Path) -> None:
    _write_root_package(tmp_path, workspaces=["packages/*"])
    _write_package(tmp_path, "packages/api", "@org/api")
    _write_package(tmp_path, "packages/web", "@org/web")
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert workspace_ids == {"@org/api", "@org/web"}
    assert all(u.package_manager == "npm" for u in expansion.units)


def test_npm_workspace_yarn_classic_object_form(tmp_path: Path) -> None:
    """``{"packages": [...], "nohoist": [...]}`` is accepted; nohoist is ignored."""
    _write_root_package(
        tmp_path,
        workspaces={"packages": ["apps/*"], "nohoist": ["**/foo"]},
    )
    _write_package(tmp_path, "apps/web", "@org/web")
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    (unit,) = expansion.units
    assert unit.workspace_id == "@org/web"


def test_npm_workspace_invalid_shape_warns(tmp_path: Path) -> None:
    _write_root_package(tmp_path, workspaces=42)  # neither array nor object
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert expansion.warnings  # some explanatory warning


def test_npm_workspace_lockfile_attached(tmp_path: Path) -> None:
    _write_root_package(tmp_path, workspaces=["packages/*"])
    _write_package(tmp_path, "packages/api", "@org/api")
    (tmp_path / "package-lock.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    (unit,) = expansion.units
    assert unit.lockfile is not None
    assert unit.lockfile.name == "package-lock.json"


# --- uv workspaces (Phase 2-C-1) -----------------------------------------


def _write_uv_pyproject(
    root: Path, *, name: str = "root-app", members: list[str] | None = None
) -> None:
    body = f"[project]\nname='{name}'\n"
    if members is not None:
        joined = ", ".join(f"'{m}'" for m in members)
        body += f"\n[tool.uv.workspace]\nmembers = [{joined}]\n"
    (root / "pyproject.toml").write_text(body, encoding="utf-8")


def _write_uv_member(root: Path, rel: str, name: str) -> Path:
    member = root / rel
    member.mkdir(parents=True, exist_ok=True)
    (member / "pyproject.toml").write_text(
        f"[project]\nname='{name}'\n", encoding="utf-8"
    )
    return member


def test_uv_workspace_returns_none_when_no_stanza(tmp_path: Path) -> None:
    _write_uv_pyproject(tmp_path)
    root = resolve_scan_root(tmp_path)
    assert detect_uv_workspace(root) is None


def test_uv_workspace_without_uv_lock_warns(tmp_path: Path) -> None:
    """uv workspace audit requires a root uv.lock; missing it must
    surface a clear warning rather than letting the audit silently
    re-lock the project mid-scan."""
    _write_uv_pyproject(tmp_path, members=["packages/*"])
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("uv.lock is missing" in w for w in expansion.warnings)


def test_uv_workspace_expands_members(tmp_path: Path) -> None:
    _write_uv_pyproject(tmp_path, name="root-app", members=["packages/*"])
    _write_uv_member(tmp_path, "packages/api", "org-api")
    _write_uv_member(tmp_path, "packages/web", "org-web")
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    # Root + 2 members. All names canonicalized lowercase / hyphenated.
    assert workspace_ids == {"root-app", "org-api", "org-web"}
    assert all(u.ecosystem == "pypi" for u in expansion.units)
    assert all(u.package_manager == "uv" for u in expansion.units)
    # The root lockfile is attached to every unit (uv audits run from the
    # repo root, so every export pulls from the same lock).
    assert all(u.lockfile is not None for u in expansion.units)
    assert all(u.lockfile.name == "uv.lock" for u in expansion.units)


def test_uv_workspace_canonicalizes_member_names(tmp_path: Path) -> None:
    """Two members differing only in case / separator (PEP 503 quirks)
    must be detected as duplicates so they don't conflate fingerprints."""
    _write_uv_pyproject(tmp_path, members=["packages/*"])
    _write_uv_member(tmp_path, "packages/api", "Org_API")
    _write_uv_member(tmp_path, "packages/api2", "org-api")
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    canonical_ids = [u.workspace_id for u in expansion.units]
    # Root + first canonical occurrence only — duplicate is skipped.
    assert canonical_ids.count("org-api") == 1
    assert any("duplicate canonicalized name" in w for w in expansion.warnings)


def test_uv_workspace_rejects_invalid_member_name(tmp_path: Path) -> None:
    _write_uv_pyproject(tmp_path, members=["packages/*"])
    _write_uv_member(tmp_path, "packages/bad", "-bad-leading-hyphen")
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    assert all(
        u.workspace_id != "-bad-leading-hyphen" for u in expansion.units
    )


@pytest.mark.parametrize("bad_name", ["foo-", "foo.", "foo_", "@foo", "foo!"])
def test_uv_workspace_rejects_trailing_separator_or_invalid_chars(
    tmp_path: Path, bad_name: str
) -> None:
    """Codex 24th review: trailing separators (``foo-`` / ``foo.``) are
    not valid PEP 508 names — uv/pip reject them and we should too."""
    _write_uv_pyproject(tmp_path, members=["packages/*"])
    _write_uv_member(tmp_path, "packages/bad", bad_name)
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert bad_name not in workspace_ids
    # And a canonicalized form of the bad name also shouldn't be emitted.
    assert not any(bad_name.lower().startswith(wid) for wid in workspace_ids if wid)


@pytest.mark.parametrize(
    "valid_name",
    [
        "x",                # single character (legal per PEP 508).
        "foo",
        "Foo",              # mixed case canonicalizes to "foo".
        "foo-bar",
        "foo.bar",
        "foo_bar",
        "foo--bar",         # adjacent hyphens are LEGAL (Codex 25th).
        "foo..bar",         # adjacent dots also legal.
        "foo...bar",        # 3 adjacent dots: legal per PEP 508 / Codex 26th.
        "foo.bar-baz_qux",  # mixed separators.
        "1foo",             # digit-leading is fine.
    ],
)
def test_uv_workspace_accepts_valid_pep508_names(
    tmp_path: Path, valid_name: str
) -> None:
    """Codex 25th review: the validation must accept every name that
    pip/uv would. Adjacent separators were over-rejected by the
    previous regex; pin them as valid here so we don't regress."""
    _write_uv_pyproject(tmp_path, members=["packages/*"])
    _write_uv_member(tmp_path, "packages/m", valid_name)
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    # The canonical form (PEP 503) should appear in the unit list.
    from secscan.workspaces import _canonicalize_pep503

    assert _canonicalize_pep503(valid_name) in workspace_ids


def test_uv_workspace_includes_root_as_member(tmp_path: Path) -> None:
    """uv workspaces always include the root project as a member."""
    _write_uv_pyproject(tmp_path, name="root-app", members=[])
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    assert {u.workspace_id for u in expansion.units} == {"root-app"}


def test_uv_workspace_exclude_glob(tmp_path: Path) -> None:
    _write_uv_pyproject(tmp_path, name="root", members=["packages/*"])
    # Add an exclude entry by rewriting the workspace stanza directly.
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='root'\n"
        "[tool.uv.workspace]\n"
        "members = ['packages/*']\n"
        "exclude = ['packages/internal']\n"
    )
    _write_uv_member(tmp_path, "packages/api", "org-api")
    _write_uv_member(tmp_path, "packages/internal", "org-internal")
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert "org-internal" not in workspace_ids
    assert "org-api" in workspace_ids


def test_uv_workspace_malformed_members_warns(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='root'\n"
        "[tool.uv.workspace]\nmembers = 42\n"
    )
    (tmp_path / "uv.lock").write_text("version = 1\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("members" in w for w in expansion.warnings)


# --- yarn unsupported warning -------------------------------------------


def test_yarn_lock_with_workspaces_warns(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    _write_root_package(tmp_path, workspaces=["packages/*"])
    root = resolve_scan_root(tmp_path)
    warnings = detect_yarn_unsupported(root)
    assert warnings
    assert any("yarn workspaces" in w for w in warnings)


def test_yarn_lock_with_other_lockfile_emits_drift_warning(
    tmp_path: Path,
) -> None:
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    root = resolve_scan_root(tmp_path)
    warnings = detect_yarn_unsupported(root)
    assert any("drift" in w for w in warnings)


def test_yarn_lock_alone_no_workspaces_no_warning(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    root = resolve_scan_root(tmp_path)
    assert detect_yarn_unsupported(root) == ()


# --- workspace count limits ---------------------------------------------


def test_workspace_warn_threshold(tmp_path: Path) -> None:
    """Exceeding the warn threshold triggers a non-fatal advisory."""
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'pkg/*'\n")
    # 55 members > the 50 warn threshold.
    for i in range(55):
        _write_package(tmp_path, f"pkg/p{i:03d}", f"@org/p{i:03d}")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert len(expansion.units) == 55
    assert any("may take a while" in w for w in expansion.warnings)


def test_workspace_hard_cap_truncates(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'pkg/*'\n")
    # 120 members > the 100 hard cap.
    for i in range(120):
        _write_package(tmp_path, f"pkg/p{i:03d}", f"@org/p{i:03d}")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert len(expansion.units) == 100
    assert any("truncating" in w for w in expansion.warnings)
