"""Phase 2-Y: differential scanning support.

``secscan all --since <ref>`` scans only what changed since a git ref,
for fast PR / CI delta checks. This module owns the security-critical
plumbing: validating the operator-supplied ref, enforcing the
preconditions that make diff semantics *consistent across scanners*,
and normalising the ref to a single canonical baseline commit OID.

Why a canonical merge-base OID (Codex Phase 2-Y design review NEW
MUST-FIX #8): the NATIVE diff scanners use different upstream
machinery — gitleaks reads ``git log -p`` over a commit *range*,
semgrep's ``--baseline-commit`` diffs *findings* against a baseline.
If we handed each the raw ``<ref>``, a ref that is not a direct
ancestor of HEAD (e.g. a sibling branch tip) would make gitleaks scan
a range that semgrep interprets via merge-base — two different notions
of "since". We compute ``git merge-base <ref> HEAD`` ONCE and feed
that OID to both, so "since" means the same thing everywhere.

Why clean-worktree + repo-root + committed-range only (Codex Phase
2-Y design review #1/#2/#7): ``--since`` is defined as the COMMITTED
range ``<baseline>..HEAD``. gitleaks (commits only) and semgrep
(baseline mode rejects a dirty tree) both look at committed state,
while the ALWAYS scanners (deps/supply) read the working tree. If the
tree were dirty those two views would diverge. We therefore require a
clean index+worktree and that the scan root IS the repository root, so
every scanner observes one coherent snapshot. Pre-commit / staged
scanning (a deliberately *dirty* tree) is a separate mode deferred to
Phase 2-Y.1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .runner import CommandRunner

# SHA-1 (40 hex) or SHA-256 (64 hex) object IDs. Git is migrating to
# SHA-256 repositories; rejecting 64-hex OIDs would break those (Codex
# Phase 2-Y design review #2).
_OID_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

# Cap on git helper output we will read. ``rev-parse`` / ``merge-base``
# emit a single OID line; ``--show-toplevel`` one path. ``status
# --porcelain`` can be large in a dirty tree but we only test emptiness.
_GIT_TIMEOUT_SECONDS = 30


class DiffScanError(ValueError):
    """A diff-mode precondition was not met.

    The CLI converts this to a usage error (exit SCAN_ERROR) with the
    message shown to the operator. The messages are intentionally
    actionable ("commit or stash", "run from the repository root").
    """


@dataclass(frozen=True)
class DiffBaseline:
    """A validated, normalised diff baseline.

    ``baseline_oid`` is ``git merge-base <user_ref> HEAD`` — the single
    consistent starting point handed to every NATIVE scanner. It is a
    plain hex OID (40 or 64 chars), safe to place verbatim in an argv
    element such as ``f"{baseline_oid}..HEAD"`` (no shell, no option
    prefix, charset already validated).

    ``user_ref`` is the original operator input, retained for display
    in the report banner only — it is NEVER passed to a subprocess.
    """

    user_ref: str
    baseline_oid: str


def _run_git(
    runner: CommandRunner,
    repo_root: Path,
    args: list[str],
) -> tuple[int, str, str]:
    """Run ``git -C <repo_root> <args>`` and return (rc, stdout, stderr).

    shell=False is enforced by CommandRunner. ``-C <repo_root>`` pins
    the repository; we also set cwd for good measure. Output is decoded
    leniently (surrogateescape) — git refs/paths are normally ASCII but
    exotic filenames must not crash the decode.
    """
    argv = ["git", "-C", str(repo_root), *args]
    result = runner.run(argv, cwd=repo_root, timeout_seconds=_GIT_TIMEOUT_SECONDS)
    stdout = result.stdout.decode("utf-8", errors="surrogateescape")
    stderr = result.stderr.decode("utf-8", errors="surrogateescape")
    return result.returncode, stdout, stderr


def _validate_raw_ref(raw_ref: str) -> str:
    """Reject obviously dangerous / malformed ref strings BEFORE they
    reach any git subprocess.

    Codex Phase 2-Y design review #3: even with shell=False, a ref
    beginning with ``-`` would be parsed by git as an option
    (``--upload-pack=...``, ``--output=...``). We reject leading dash,
    empty, whitespace, and control characters up front; the
    ``rev-parse`` step then confirms the ref actually resolves.
    """
    if not isinstance(raw_ref, str):
        raise DiffScanError("--since ref must be a string")
    ref = raw_ref.strip()
    if not ref:
        raise DiffScanError("--since ref must not be empty")
    if ref.startswith("-"):
        raise DiffScanError(
            f"--since ref must not start with '-' (got {raw_ref!r}); "
            "this prevents git option injection"
        )
    for ch in ref:
        if ord(ch) < 0x20 or ch == "\x7f":
            raise DiffScanError(
                "--since ref contains a control character; refusing"
            )
        if ch.isspace():
            raise DiffScanError(
                f"--since ref must not contain whitespace (got {raw_ref!r})"
            )
    return ref


def _assert_repo_root(runner: CommandRunner, scan_root: Path) -> None:
    """Require that ``scan_root`` is the git repository top level.

    Codex Phase 2-Y design review #1: gitleaks' native git mode scans
    the WHOLE repository (it has no clean per-path confinement in
    ``--log-opts``). If the scan root were a subdirectory, gitleaks
    would scan secrets outside ``--path``. Requiring scan_root ==
    toplevel makes "whole repo" and "scan root" identical, so the
    confinement guarantee holds without pathspec gymnastics.
    """
    rc, stdout, stderr = _run_git(
        runner, scan_root, ["rev-parse", "--show-toplevel"]
    )
    if rc != 0:
        raise DiffScanError(
            "--since requires a git repository, but "
            f"{scan_root} is not inside one ({stderr.strip() or 'git failed'})"
        )
    toplevel = stdout.strip()
    if not toplevel:
        raise DiffScanError("could not determine git repository root")
    try:
        same = Path(toplevel).resolve() == scan_root.resolve()
    except OSError as exc:
        raise DiffScanError(f"failed to resolve repository root: {exc}") from exc
    if not same:
        raise DiffScanError(
            "diff mode (--since) must be run from the repository root. "
            f"Repository root is {toplevel}, but --path resolved to "
            f"{scan_root}. Re-run with --path pointing at the repo root."
        )


def _assert_clean_worktree(runner: CommandRunner, repo_root: Path) -> None:
    """Require a clean index AND working tree (incl. untracked files).

    Codex Phase 2-Y design review #7: ``--since`` is committed-range
    semantics. gitleaks sees only commits; semgrep's baseline mode
    refuses a dirty tree; deps/supply read the working tree. A dirty
    tree makes those views diverge (deps would scan uncommitted
    manifests that gitleaks never sees). We require ``git status
    --porcelain`` to be empty so every scanner observes the same
    committed snapshot. ``--porcelain`` lists untracked files (??)
    too; we treat any output as dirty.
    """
    # Codex Phase 2-Y diff review #1: ``--porcelain`` alone honours user
    # config that can HIDE dirtiness — ``status.showUntrackedFiles=no``
    # suppresses untracked files, and the default ``--ignore-submodules``
    # can hide dirty submodules. Force the strict flags so neither a
    # suppressed untracked file nor a dirty submodule slips past.
    rc, stdout, stderr = _run_git(
        runner,
        repo_root,
        [
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    if rc != 0:
        raise DiffScanError(
            f"git status failed: {stderr.strip() or 'unknown error'}"
        )
    if stdout.strip():
        raise DiffScanError(
            "diff mode (--since) requires a clean working tree so every "
            "scanner sees the same committed snapshot. Commit or stash "
            "your changes first (uncommitted/untracked files are present). "
            "For scanning uncommitted changes, a --staged mode is planned "
            "(Phase 2-Y.1)."
        )


def _assert_no_submodules(runner: CommandRunner, repo_root: Path) -> None:
    """Refuse diff mode for repositories that contain git submodules.

    Codex Phase 2-Y diff review #2: ``gitleaks git <root>
    --log-opts=<base>..HEAD`` scans the PARENT repository's commit
    patches. A parent commit that merely advances a submodule pointer
    does not expose the submodule's file contents to that scan — so a
    secret introduced inside a bumped submodule would be MISSED in diff
    mode even though a full ``gitleaks dir`` would catch it. Rather than
    silently under-scan, we reject submodule repos in diff mode.

    Codex Phase 2-Y diff review (follow-up): detecting by ``.gitmodules``
    alone is insufficient — git's real source of truth is the
    **gitlink** entry in the index (file mode ``160000``). ``.gitmodules``
    can be absent, sparse-checked-out, or malformed while a gitlink
    still exists. We enumerate the index with ``git ls-files -s -z`` and
    reject if ANY entry has the gitlink mode. (``-z`` NUL-delimits so
    exotic paths can't break parsing.)
    """
    rc, stdout, stderr = _run_git(runner, repo_root, ["ls-files", "-s", "-z"])
    if rc != 0:
        raise DiffScanError(
            f"git ls-files failed while checking for submodules: "
            f"{stderr.strip() or 'unknown error'}"
        )
    for entry in stdout.split("\x00"):
        # Each entry: "<mode> <object> <stage>\t<path>". The gitlink
        # (submodule) mode is 160000; a leading "160000 " is unambiguous.
        if entry.startswith("160000 "):
            raise DiffScanError(
                "diff mode (--since) does not support repositories with git "
                "submodules (a gitlink entry exists in the index). gitleaks' "
                "commit-range scan does not descend into submodule contents, "
                "so a parent commit that advances a submodule could introduce "
                "secrets that diff mode would miss. Run a full scan (omit "
                "--since) instead."
            )


def _resolve_oid(runner: CommandRunner, repo_root: Path, ref: str) -> str:
    """Resolve ``ref`` to a commit OID via ``rev-parse --verify``.

    The ``^{commit}`` peel ensures we get a commit (not a tree/tag
    object). ``--verify --quiet`` exits non-zero on an unknown ref
    instead of echoing the input back. The result is asserted to match
    the OID charset so nothing but a clean hex OID flows downstream.
    """
    rc, stdout, stderr = _run_git(
        runner,
        repo_root,
        ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
    )
    if rc != 0:
        raise DiffScanError(
            f"--since ref {ref!r} is not a known git commit "
            f"({stderr.strip() or 'rev-parse failed'})"
        )
    oid = stdout.strip()
    if not _OID_RE.match(oid):
        # Defensive: rev-parse should only ever emit a clean OID here.
        raise DiffScanError(
            f"git returned an unexpected object id for {ref!r}; refusing"
        )
    return oid


def _merge_base(
    runner: CommandRunner, repo_root: Path, oid: str
) -> str:
    """Compute ``git merge-base <oid> HEAD`` — the canonical baseline.

    Codex Phase 2-Y design review #8: using the merge-base (rather than
    the raw ``<oid>``) gives every NATIVE scanner the same starting
    point even when ``<oid>`` is on a sibling branch. semgrep CI docs
    recommend exactly this for diff scans.
    """
    rc, stdout, stderr = _run_git(
        runner, repo_root, ["merge-base", oid, "HEAD"]
    )
    if rc != 0:
        raise DiffScanError(
            f"--since ref {oid[:12]} has no common ancestor with HEAD "
            f"({stderr.strip() or 'merge-base failed'}); cannot compute a "
            "diff baseline"
        )
    base = stdout.strip()
    if not _OID_RE.match(base):
        raise DiffScanError(
            "git merge-base returned an unexpected object id; refusing"
        )
    return base


def resolve_diff_baseline(
    raw_ref: str,
    *,
    scan_root: Path,
    runner: CommandRunner,
) -> DiffBaseline:
    """Validate diff-mode preconditions and return the canonical baseline.

    Raises :class:`DiffScanError` (→ CLI usage error) when:
    - the ref is malformed / option-injection-shaped,
    - the scan root is not the git repository root,
    - the working tree is not clean,
    - the ref does not resolve to a commit,
    - the ref shares no history with HEAD.

    On success returns a :class:`DiffBaseline` whose ``baseline_oid`` is
    the merge-base of the ref and HEAD — safe to embed verbatim in argv.
    """
    ref = _validate_raw_ref(raw_ref)
    _assert_repo_root(runner, scan_root)
    _assert_no_submodules(runner, scan_root)
    _assert_clean_worktree(runner, scan_root)
    oid = _resolve_oid(runner, scan_root, ref)
    baseline_oid = _merge_base(runner, scan_root, oid)
    return DiffBaseline(user_ref=ref, baseline_oid=baseline_oid)
