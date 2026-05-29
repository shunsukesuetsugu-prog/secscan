"""Phase 2-Y: diff-baseline resolution + precondition tests.

These pin the security-critical contract of ``diffscan.resolve_diff_baseline``:

- malformed / option-injection-shaped refs are rejected BEFORE any git call
- the scan root must be the git repository top level
- the working tree must be clean
- the ref must resolve to a commit
- the baseline is the merge-base of the ref and HEAD (one consistent OID)
- the resolved OID charset is always validated (SHA-1 40-hex or SHA-256 64-hex)

A scripted fake git runner returns canned (rc, stdout, stderr) per git
subcommand so we never touch a real repo.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from secscan.diffscan import (
    DiffScanError,
    resolve_diff_baseline,
)
from secscan.runner import CommandResult

_OID_A = "a" * 40  # a valid-looking SHA-1 OID
_MERGE_BASE = "b" * 40
_OID_SHA256 = "c" * 64


class _FakeGitRunner:
    """CommandRunner that dispatches on the git subcommand.

    ``script`` maps a git subcommand (the token after ``-C <root>``) to a
    ``(returncode, stdout, stderr)`` triple. The toplevel path defaults to
    whatever ``cwd`` was passed so the repo-root check passes unless a test
    overrides it.
    """

    def __init__(
        self,
        *,
        toplevel: str | None = None,
        status_porcelain: str = "",
        rev_parse: tuple[int, str] = (0, _OID_A),
        merge_base: tuple[int, str] = (0, _MERGE_BASE),
        ls_files: str = "",
    ) -> None:
        self.toplevel = toplevel
        self.status_porcelain = status_porcelain
        self.rev_parse = rev_parse
        self.merge_base = merge_base
        # ``git ls-files -s -z`` output (NUL-delimited). Default empty =
        # no tracked files / no gitlinks = not a submodule repo.
        self.ls_files = ls_files
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        args = tuple(argv)
        self.calls.append(args)
        # argv is ["git", "-C", <root>, <subcommand>, ...]
        sub = args[3] if len(args) > 3 else ""

        def _result(rc: int, out: str) -> CommandResult:
            return CommandResult(
                argv=args,
                returncode=rc,
                stdout=out.encode(),
                stderr=b"" if rc == 0 else b"git error",
                duration_seconds=0.0,
                timed_out=False,
            )

        if sub == "rev-parse" and "--show-toplevel" in args:
            top = self.toplevel if self.toplevel is not None else str(cwd)
            return _result(0 if top else 1, top)
        if sub == "ls-files":
            return _result(0, self.ls_files)
        if sub == "status":
            return _result(0, self.status_porcelain)
        if sub == "rev-parse":  # rev-parse --verify --quiet <ref>^{commit}
            rc, out = self.rev_parse
            return _result(rc, out)
        if sub == "merge-base":
            rc, out = self.merge_base
            return _result(rc, out)
        raise AssertionError(f"unexpected git subcommand: {args}")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return tmp_path


# --- happy path -------------------------------------------------------------


def test_resolves_to_merge_base(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo))
    baseline = resolve_diff_baseline("HEAD~3", scan_root=repo, runner=runner)
    assert baseline.user_ref == "HEAD~3"
    # The baseline OID is the MERGE-BASE, not the raw rev-parse OID.
    assert baseline.baseline_oid == _MERGE_BASE


def test_accepts_sha256_oid(repo: Path) -> None:
    runner = _FakeGitRunner(
        toplevel=str(repo),
        rev_parse=(0, _OID_SHA256),
        merge_base=(0, _OID_SHA256),
    )
    baseline = resolve_diff_baseline("main", scan_root=repo, runner=runner)
    assert baseline.baseline_oid == _OID_SHA256


# --- ref validation (pre-git) ----------------------------------------------


def test_leading_dash_ref_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo))
    with pytest.raises(DiffScanError, match="must not start with '-'"):
        resolve_diff_baseline("--upload-pack=evil", scan_root=repo, runner=runner)
    # Rejected BEFORE any git subprocess.
    assert runner.calls == []


def test_empty_ref_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo))
    with pytest.raises(DiffScanError, match="must not be empty"):
        resolve_diff_baseline("   ", scan_root=repo, runner=runner)
    assert runner.calls == []


def test_whitespace_in_ref_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo))
    with pytest.raises(DiffScanError, match="whitespace"):
        resolve_diff_baseline("HEAD --output=x", scan_root=repo, runner=runner)
    assert runner.calls == []


def test_control_char_in_ref_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo))
    with pytest.raises(DiffScanError, match="control character"):
        resolve_diff_baseline("HEAD\x00evil", scan_root=repo, runner=runner)
    assert runner.calls == []


# --- repo-root precondition -------------------------------------------------


def test_subdir_rejected(repo: Path) -> None:
    # Toplevel is the PARENT of the scan root → scan root is a subdir.
    runner = _FakeGitRunner(toplevel=str(repo.parent))
    with pytest.raises(DiffScanError, match="must be run from the repository root"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


def test_not_a_git_repo_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel="")  # rev-parse --show-toplevel fails
    with pytest.raises(DiffScanError, match=r"not.*git repository|requires a git"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


# --- clean-worktree precondition -------------------------------------------


def test_dirty_worktree_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(
        toplevel=str(repo),
        status_porcelain=" M src/foo.py\n?? newfile.txt\n",
    )
    with pytest.raises(DiffScanError, match="clean working tree"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


def test_untracked_file_counts_as_dirty(repo: Path) -> None:
    runner = _FakeGitRunner(
        toplevel=str(repo),
        status_porcelain="?? untracked.py\n",
    )
    with pytest.raises(DiffScanError, match="clean working tree"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


def test_status_uses_strict_flags(repo: Path) -> None:
    """Codex diff review #1: status must force --untracked-files=all and
    --ignore-submodules=none so user config can't hide dirtiness."""
    runner = _FakeGitRunner(toplevel=str(repo))
    resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)
    status_calls = [c for c in runner.calls if len(c) > 3 and c[3] == "status"]
    assert status_calls, "expected a git status call"
    flat = status_calls[0]
    assert "--untracked-files=all" in flat
    assert "--ignore-submodules=none" in flat


# --- submodule rejection (Codex diff review #2) ----------------------------


def test_submodules_rejected_via_gitlink(repo: Path) -> None:
    """A repo with a gitlink entry (mode 160000) in the index is rejected
    in diff mode — gitleaks' commit-range scan does not descend into
    submodule contents, so diff mode would be a false-negative trap. We
    detect via ``git ls-files -s`` (the index), NOT just ``.gitmodules``
    (which can be absent while a gitlink exists)."""
    runner = _FakeGitRunner(
        toplevel=str(repo),
        # gitlink entry: mode 160000, no .gitmodules file at all.
        ls_files="160000 " + "d" * 40 + " 0\tvendor/lib\x00",
    )
    with pytest.raises(DiffScanError, match="submodule"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


def test_normal_files_not_flagged_as_submodule(repo: Path) -> None:
    """Regular tracked files (mode 100644) must NOT trip the gitlink check."""
    runner = _FakeGitRunner(
        toplevel=str(repo),
        ls_files=(
            "100644 " + "e" * 40 + " 0\tsrc/app.py\x00"
            "100755 " + "f" * 40 + " 0\tscripts/run.sh\x00"
        ),
    )
    # No gitlink → resolves normally.
    baseline = resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)
    assert baseline.baseline_oid == _MERGE_BASE


# --- ref resolution failures -----------------------------------------------


def test_unknown_ref_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo), rev_parse=(1, ""))
    with pytest.raises(DiffScanError, match="not a known git commit"):
        resolve_diff_baseline("nonexistent", scan_root=repo, runner=runner)


def test_no_common_ancestor_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(toplevel=str(repo), merge_base=(1, ""))
    with pytest.raises(DiffScanError, match="no common ancestor"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


def test_garbage_oid_from_git_rejected(repo: Path) -> None:
    # rev-parse "succeeds" but returns a non-OID string (defensive).
    runner = _FakeGitRunner(toplevel=str(repo), rev_parse=(0, "not-an-oid"))
    with pytest.raises(DiffScanError, match="unexpected object id"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


def test_garbage_merge_base_rejected(repo: Path) -> None:
    runner = _FakeGitRunner(
        toplevel=str(repo), merge_base=(0, "deadbeef-not-hex-enough")
    )
    with pytest.raises(DiffScanError, match="unexpected object id"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)


# --- ordering: preconditions run before ref resolution ----------------------


def test_dirty_tree_checked_before_ref_resolution(repo: Path) -> None:
    """A dirty tree must fail even if the ref would resolve — we don't want
    to leak 'ref ok but tree dirty' ordering that runs extra git work."""
    runner = _FakeGitRunner(
        toplevel=str(repo),
        status_porcelain=" M x\n",
        rev_parse=(0, _OID_A),
    )
    with pytest.raises(DiffScanError, match="clean working tree"):
        resolve_diff_baseline("HEAD~1", scan_root=repo, runner=runner)
    # rev-parse for the ref (not --show-toplevel) must NOT have run.
    ref_resolutions = [
        c for c in runner.calls
        if len(c) > 3 and c[3] == "rev-parse" and "--show-toplevel" not in c
    ]
    assert ref_resolutions == []
