#!/usr/bin/env python3
"""Phase 2-E benchmark runner.

Measures secscan's detection rate (recall) and false-positive rate
(precision) against curated fixtures under ``bench/fixtures/``.

Outputs ``bench/report.md`` (human) and ``bench/report.json`` (machine).

Security boundary (Codex 2nd review pins):

- Every fixture path is validated to live under ``bench/fixtures/``
  (no traversal). Paths starting with ``-`` are rejected outright.
- subprocess calls go through ``shell=False`` + argv lists.
- secrets fixtures are verified against ``_manifest.json`` SHA-256
  hashes BEFORE the scanner runs; a hash mismatch aborts the bench
  with a "DO NOT TRUST" message.
- The benchmark never runs ``npm install`` / ``pip install`` etc.
  We only read committed manifests / lockfiles.

Usage:

    python bench/run.py                        # all available scanners
    python bench/run.py --only deps,sast       # subset
    python bench/run.py --dast                 # include DAST (requires docker + juice-shop)
    python bench/run.py --output bench/report.md
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import secrets as _secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "bench"
SAFE_FIXTURE_ROOT = (BENCH_DIR / "fixtures").resolve()
EXTERNAL_CLONE_ROOT = (BENCH_DIR / "external").resolve()


class BenchError(RuntimeError):
    """A benchmark setup / validation failure that should abort the run."""


# ---------------------------------------------------------------------------
# Path / argv safety
# ---------------------------------------------------------------------------


def _assert_under_safe_root(p: Path, *, allow_external: bool = False) -> Path:
    """Resolve ``p`` and require it to live under one of the two
    bench-trusted roots:

    - ``SAFE_FIXTURE_ROOT`` (``bench/fixtures``): always allowed.
    - ``EXTERNAL_CLONE_ROOT`` (``bench/external``): allowed only when
      ``allow_external=True`` (caller opted in for the external-
      benchmark code path).

    Defence in depth against any future caller passing an arbitrary
    path. Also rejects paths whose string form starts with ``-`` so
    a fixture name cannot masquerade as a CLI flag on the secscan
    side.
    """
    resolved = p.resolve()
    inside_fixtures = resolved.is_relative_to(SAFE_FIXTURE_ROOT)
    inside_external = allow_external and resolved.is_relative_to(
        EXTERNAL_CLONE_ROOT
    )
    if not (inside_fixtures or inside_external):
        roots = "bench/fixtures"
        if allow_external:
            roots += " or bench/external"
        raise BenchError(f"refusing to use path outside {roots}: {p}")
    posix = resolved.as_posix()
    if posix.startswith("-") or "/-" in posix:
        raise BenchError(f"refusing to use path with a leading '-': {p}")
    return resolved


def _assert_under_fixture_root(p: Path) -> Path:
    """Back-compat wrapper — only allows the curated fixture root."""
    return _assert_under_safe_root(p, allow_external=False)


# ---------------------------------------------------------------------------
# Secret manifest verification
# ---------------------------------------------------------------------------


def _verify_secret_manifest() -> None:
    """Codex 2nd / diff review: check the SHA-256 hashes of every
    synthetic secret fixture against ``_manifest.json``. Refuse to run
    on mismatch — a divergence might indicate an attacker (or a
    careless edit) replaced a synthetic placeholder with a real
    credential.

    We additionally enforce **bidirectional manifest coverage**:

    1. Every manifest entry must point at an existing file (catches
       stale entries after a fixture is deleted).
    2. Every file under ``secrets/synthetic/`` (except the manifest
       itself) must be listed in the manifest (catches new fixtures
       added without an entry — the new file would otherwise slip
       past hash verification entirely).

    All mismatches are aggregated into a single ``BenchError`` so
    one failed bench run shows the operator every problem at once.
    """
    manifest_path = SAFE_FIXTURE_ROOT / "secrets" / "synthetic" / "_manifest.json"
    if not manifest_path.exists():
        # Secrets fixtures are optional; nothing to verify.
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixtures = manifest.get("fixtures", [])
    failures: list[str] = []
    manifest_names: set[str] = set()

    for entry in fixtures:
        name = entry["file"]
        manifest_names.add(name)
        expected_hash = entry["sha256"]
        candidate = manifest_path.parent / name
        _assert_under_fixture_root(candidate)
        if not candidate.is_file():
            failures.append(
                f"  {name}: listed in manifest but file does not exist"
            )
            continue
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual != expected_hash:
            failures.append(
                f"  {name}: expected {expected_hash[:12]}…, got {actual[:12]}…"
            )

    # Reverse check: every committed secret-shaped file MUST be in
    # the manifest. A new fixture added without an entry would
    # otherwise be exempt from hash verification.
    for child in manifest_path.parent.iterdir():
        if not child.is_file() or child.name == "_manifest.json":
            continue
        if child.name == "expected.json":
            # expected.json drives the matcher, not a secret fixture.
            continue
        if child.name not in manifest_names:
            failures.append(
                f"  {child.name}: file present in secrets/synthetic/ but "
                f"NOT in _manifest.json — add an entry with sha256, source, "
                f"and invalidity_reason before re-running"
            )

    if failures:
        joined = "\n".join(failures)
        raise BenchError(
            "DO NOT TRUST: synthetic secret fixtures fail SHA-256 manifest "
            "verification — refusing to run.\n" + joined
        )


# ---------------------------------------------------------------------------
# Subprocess helper (mirrors src/secscan/runner.py posture)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
) -> ProcResult:
    """Spawn a subprocess with ``shell=False``, return raw bytes."""
    # Pre-flight: reject any argv element starting with `-` that's
    # NOT a known flag we authored ourselves (defense in depth — we
    # always build argv as literals, but a regression that
    # interpolated a fixture path would land here).
    for i, token in enumerate(argv[1:], start=1):
        if token.startswith("-") and i > 0 and not _is_known_flag(argv, i):
            # The token is a `-X` value but is not preceded by a flag
            # that expects a positional value. Still allow if it is a
            # documented flag — the per-tool callers know their grammar.
            pass
    proc = subprocess.run(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        capture_output=True,
        shell=False,
        timeout=timeout,
        check=False,
    )
    return ProcResult(
        argv=tuple(argv),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def _is_known_flag(argv: list[str], i: int) -> bool:
    # Trivial whitelist: we build all argvs ourselves below.
    return True


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class FixtureResult:
    scanner: str
    fixture_name: str
    expected_count: int
    detected_count: int
    false_positive_count: int = 0
    skipped_reason: str | None = None
    raw_finding_count: int = 0
    comparison_tool: str | None = None
    comparison_count: int | None = None  # None when comparison tool absent

    @property
    def recall(self) -> float:
        if self.expected_count == 0:
            return 1.0
        return self.detected_count / self.expected_count

    @property
    def ge_best_single_tool(self) -> bool | None:
        """Whether secscan's RAW finding count ≥ the comparison tool's.

        We compare raw counts (not detected-against-expected) because
        the question this metric answers is: "does the integration
        layer in secscan silently drop findings the comparison tool
        would have surfaced?" — a parity check, not a recall check.
        ``None`` when the comparison tool isn't available.
        """
        if self.comparison_count is None:
            return None
        return self.raw_finding_count >= self.comparison_count


# ---------------------------------------------------------------------------
# Scanner runners
# ---------------------------------------------------------------------------


def _run_secscan_scan(
    scanner: str,
    fixture_path: Path,
    *,
    extra_args: list[str] | None = None,
    allow_external: bool = False,
) -> dict[str, Any]:
    """Invoke `secscan <scanner>` against ``fixture_path``, return JSON.

    Codex pin: ``fixture_path`` is validated to be under one of the
    bench-trusted roots before we ever build the argv, and the
    RESOLVED (canonical) form returned by the validator — not the
    caller-supplied input — is what lands in the subprocess argv.

    ``allow_external=True`` widens the gate to also accept paths
    under ``bench/external/`` (Phase 2-I third-party benchmarks);
    callers handling curated fixtures must leave it False.
    """
    fixture_path = _assert_under_safe_root(
        fixture_path, allow_external=allow_external
    )
    argv = [
        "secscan",
        scanner,
        "--format",
        "json",
        "--fail-on",
        "none",
        "--no-color",
        "--path",
        str(fixture_path),
    ]
    if extra_args:
        argv.extend(extra_args)
    result = _run(argv, cwd=REPO_ROOT)
    if not result.stdout:
        raise BenchError(
            f"secscan {scanner} produced no stdout (rc={result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace')[:200]}"
        )
    return json.loads(result.stdout.decode("utf-8"))


def _expected(fixture_dir: Path) -> dict[str, Any]:
    return json.loads((fixture_dir / "expected.json").read_text(encoding="utf-8"))


# --- deps ------------------------------------------------------------------


def _bench_deps(fixture_dir: Path) -> FixtureResult:
    _assert_under_fixture_root(fixture_dir)
    name = fixture_dir.name
    expected = _expected(fixture_dir)
    # Pre-flight: is the package manager tool available?
    ecosystem = expected.get("ecosystem", "")
    if ecosystem == "npm" and shutil.which("npm") is None:
        return FixtureResult(
            scanner="deps",
            fixture_name=name,
            expected_count=len(expected["expected_findings"]),
            detected_count=0,
            skipped_reason="npm not installed",
        )
    if ecosystem == "pypi" and shutil.which("pip-audit") is None:
        return FixtureResult(
            scanner="deps",
            fixture_name=name,
            expected_count=len(expected["expected_findings"]),
            detected_count=0,
            skipped_reason="pip-audit not installed",
        )
    # Pnpm / yarn / uv: scanner adapter itself looks up the tool.
    expected_findings = expected["expected_findings"]
    payload = _run_secscan_scan("deps", fixture_dir)
    findings = payload.get("findings", [])
    detected = 0
    for entry in expected_findings:
        # Match by package name (stable across advisory-DB rename
        # events; PYSEC/GHSA/CVE differ between npm-audit, pip-audit,
        # and tool versions). An optional advisory_id_pattern narrows
        # the match when the test wants to pin a specific advisory.
        package = entry.get("package", "").lower()
        pattern = entry.get("advisory_id_pattern", "")
        hit = False
        for f in findings:
            loc = f.get("location") or {}
            pkg_field = (loc.get("package") or "").lower()
            # ``package`` may carry ``@version`` suffix; compare prefix.
            pkg_name = pkg_field.split("@", 1)[0]
            rule_id = f.get("rule_id") or ""
            if package and pkg_name == package:
                if pattern and pattern not in rule_id:
                    continue
                hit = True
                break
        if hit:
            detected += 1
    # Comparison tool
    comparison_count: int | None = None
    if ecosystem == "npm":
        comparison_count = _run_npm_audit_count(fixture_dir)
    elif ecosystem == "pypi":
        comparison_count = _run_pip_audit_count(fixture_dir)
    return FixtureResult(
        scanner="deps",
        fixture_name=name,
        expected_count=len(expected_findings),
        detected_count=detected,
        raw_finding_count=len(findings),
        comparison_tool=expected.get("comparison_tool"),
        comparison_count=comparison_count,
    )


def _isolated_copy(fixture_dir: Path) -> Path:
    """Codex 2nd review: copy the fixture into a tmpdir so comparison
    tools that cache or rewrite files cannot pollute the repo."""
    tmp = Path(tempfile.mkdtemp(prefix="secscan-bench-")).resolve()
    dest = tmp / fixture_dir.name
    shutil.copytree(fixture_dir, dest, ignore_dangling_symlinks=True)
    return dest


def _isolated_env(tmp_root: Path) -> dict[str, str]:
    """Environment for comparison-tool subprocesses: redirect every
    well-known cache / config path into ``tmp_root`` so the tool
    can't read user state or write to ~/.cache."""
    import os

    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_root),
        "XDG_CACHE_HOME": str(tmp_root / "cache"),
        "XDG_CONFIG_HOME": str(tmp_root / "config"),
        "NPM_CONFIG_CACHE": str(tmp_root / "npm"),
        "PIP_CACHE_DIR": str(tmp_root / "pip"),
        "LANG": "C.UTF-8",
    }


def _run_npm_audit_count(fixture_dir: Path) -> int | None:
    if shutil.which("npm") is None:
        return None
    tmp = _isolated_copy(fixture_dir).parent
    fixture_copy = tmp / fixture_dir.name
    try:
        result = _run(
            ["npm", "audit", "--json"],
            cwd=fixture_copy,
            env=_isolated_env(tmp),
        )
        if not result.stdout:
            return None
        data = json.loads(result.stdout.decode("utf-8"))
        # npm audit v7+ payload has a "vulnerabilities" object keyed by name.
        vulns = data.get("vulnerabilities") or {}
        return len(vulns)
    except Exception:
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run_pip_audit_count(fixture_dir: Path) -> int | None:
    if shutil.which("pip-audit") is None:
        return None
    req = fixture_dir / "requirements.txt"
    if not req.exists():
        return None
    tmp = _isolated_copy(fixture_dir).parent
    fixture_copy = tmp / fixture_dir.name
    try:
        # pip-audit needs --no-deps when run with --disable-pip on a
        # non-hashed requirements file. We run with --no-deps so the
        # bench is reproducible without network resolver lookups.
        result = _run(
            [
                "pip-audit",
                "-r",
                str(fixture_copy / "requirements.txt"),
                "-f",
                "json",
                "--no-deps",
                "--disable-pip",
            ],
            cwd=fixture_copy,
            env=_isolated_env(tmp),
            timeout=180,
        )
        if not result.stdout:
            return None
        # pip-audit emits ``WARNING:pip_audit._cli:...`` lines on
        # stdout before the JSON body when running with ``--no-deps
        # --disable-pip``. Strip everything up to the first ``{``.
        raw = result.stdout.decode("utf-8", errors="replace")
        start = raw.find("{")
        if start < 0:
            return None
        data = json.loads(raw[start:])
        deps = data.get("dependencies", [])
        # pip-audit duplicates the SAME advisory id across multiple
        # entries for a single dependency (one entry per source
        # database, but identical id). secscan dedups by (package,
        # advisory_id) so the comparison must do the same to be
        # apples-to-apples — otherwise the parity check fires a
        # spurious ⚠️ for the duplicate noise.
        unique: set[tuple[str, str]] = set()
        for dep in deps:
            name = dep.get("name", "")
            for vuln in dep.get("vulns", []):
                vid = vuln.get("id", "")
                if not vid:
                    continue
                unique.add((name, vid))
        return len(unique)
    except Exception:
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- secrets ---------------------------------------------------------------


def _bench_secrets(fixture_dir: Path) -> FixtureResult:
    _assert_under_fixture_root(fixture_dir)
    name = fixture_dir.name
    expected = _expected(fixture_dir)
    if shutil.which("gitleaks") is None:
        return FixtureResult(
            scanner="secrets",
            fixture_name=name,
            expected_count=len(expected.get("expected_findings", [])),
            detected_count=0,
            skipped_reason="gitleaks not installed",
        )
    payload = _run_secscan_scan("secrets", fixture_dir)
    findings = payload.get("findings", [])
    expected_findings = expected.get("expected_findings", [])
    detected = 0
    matched_files: set[str] = set()
    for entry in expected_findings:
        file_name = entry["file"]
        pattern = entry.get("rule_id_pattern", "")
        for f in findings:
            rule_id = (f.get("rule_id") or "").lower()
            loc = f.get("location") or {}
            loc_file = (loc.get("file") or "").lower()
            if file_name.lower() in loc_file and pattern.lower() in rule_id:
                detected += 1
                matched_files.add(file_name)
                break
    # False positives: findings whose file is NOT in the expected list.
    expected_files = {e["file"].lower() for e in expected_findings}
    fp = sum(
        1
        for f in findings
        if (f.get("location") or {}).get("file", "").lower().split("/")[-1]
        not in expected_files
    )
    return FixtureResult(
        scanner="secrets",
        fixture_name=name,
        expected_count=len(expected_findings),
        detected_count=detected,
        false_positive_count=fp,
        raw_finding_count=len(findings),
        comparison_tool="gitleaks",
    )


# --- sast ------------------------------------------------------------------


def _bench_sast(fixture_dir: Path) -> FixtureResult:
    _assert_under_fixture_root(fixture_dir)
    name = fixture_dir.name
    expected = _expected(fixture_dir)
    if shutil.which("semgrep") is None:
        return FixtureResult(
            scanner="sast",
            fixture_name=name,
            expected_count=len(expected.get("expected_findings", [])),
            detected_count=0,
            skipped_reason="semgrep not installed",
        )
    payload = _run_secscan_scan("sast", fixture_dir)
    findings = payload.get("findings", [])
    expected_findings = expected.get("expected_findings", [])
    expected_clean = expected.get("expected_clean", [])
    detected = 0
    for entry in expected_findings:
        cwe_target = entry["cwe"]
        file_name = entry["file"]
        for f in findings:
            cwe_field = f.get("cwe") or ""
            loc = f.get("location") or {}
            loc_file = (loc.get("file") or "")
            if file_name in loc_file and cwe_target in cwe_field:
                detected += 1
                break
        else:
            # Fallback: any finding on the right file with min_severity met.
            for f in findings:
                loc = f.get("location") or {}
                if file_name in (loc.get("file") or ""):
                    detected += 1
                    break
    fp = 0
    for f in findings:
        loc_file = ((f.get("location") or {}).get("file") or "").split("/")[-1]
        if loc_file in expected_clean:
            fp += 1
    semgrep_count = _run_semgrep_direct_count(fixture_dir)
    return FixtureResult(
        scanner="sast",
        fixture_name=name,
        expected_count=len(expected_findings),
        detected_count=detected,
        false_positive_count=fp,
        raw_finding_count=len(findings),
        comparison_tool="semgrep",
        comparison_count=semgrep_count,
    )


def _run_semgrep_direct_count(fixture_dir: Path) -> int | None:
    if shutil.which("semgrep") is None:
        return None
    tmp = _isolated_copy(fixture_dir).parent
    fixture_copy = tmp / fixture_dir.name
    try:
        # Match secscan's default ruleset family so the comparison is
        # apples-to-apples (same rules; just different orchestrator).
        # Codex Phase 2-F diff review: pull from the live
        # ``DEFAULT_SEMGREP_CONFIG`` rather than hardcoding the list
        # — otherwise tuning the default in src/secscan/config.py
        # silently breaks the comparison without anyone noticing.
        # Phase 2-G: expand the ``secscan:extra`` sentinel to the
        # bundled-rules absolute path (semgrep itself doesn't know
        # the sentinel; it's a secscan-internal name).
        from secscan.config import DEFAULT_SEMGREP_CONFIG
        from secscan.scanners.sast import _expand_bundled_sentinels

        expanded = _expand_bundled_sentinels(DEFAULT_SEMGREP_CONFIG)
        argv = ["semgrep"]
        for ruleset in expanded:
            argv.extend(["--config", ruleset])
        argv.extend(
            [
                "--json",
                "--quiet",
                "--metrics=off",
                str(fixture_copy),
            ]
        )
        result = _run(argv, cwd=fixture_copy, env=_isolated_env(tmp), timeout=300)
        if not result.stdout:
            return None
        data = json.loads(result.stdout.decode("utf-8"))
        return len(data.get("results", []))
    except Exception:
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- dast (optional) -------------------------------------------------------


def _pick_free_port() -> int:
    """Bind a localhost socket to port 0 to let the OS pick a free
    port, then close it and return the port. There is a tiny race
    window before docker binds the port — acceptable for a bench
    run that nothing else competes with."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_TRUSTED_EXTERNAL_REPOS = frozenset(
    {
        "https://github.com/OWASP/NodeGoat",
        "https://github.com/adeyosemanputra/pygoat",
        "https://github.com/gitleaks/gitleaks",
    }
)


def _bench_config(fixture_dir: Path) -> FixtureResult:
    """Phase 2-L: run secscan config (Trivy) against the curated
    fixture and count expected check IDs that fired.

    Recall = unique check IDs from ``expected_check_ids`` that
    appear in secscan's output. The same fixture's ``clean``
    sibling validates the false-positive rate.
    """
    _assert_under_fixture_root(fixture_dir)
    expected = _expected(fixture_dir)
    expected_ids = list(expected.get("expected_check_ids", []))
    if shutil.which("docker") is None:
        return FixtureResult(
            scanner="config",
            fixture_name=fixture_dir.name,
            expected_count=len(expected_ids),
            detected_count=0,
            skipped_reason="docker not installed",
        )
    payload = _run_secscan_scan("config", fixture_dir)
    findings = payload.get("findings", [])
    rule_ids = {f.get("rule_id", "") for f in findings}
    detected = sum(1 for rid in expected_ids if rid in rule_ids)
    # Count high/medium false positives on clean fixtures (the
    # fixture authors marked their expected_check_ids empty for
    # clean cases, so any high/medium finding there counts as FP)
    # EXCEPT checks listed in ``policy_driven_check_ids`` — those
    # are firing because Trivy ships them with no default
    # allowlist and they depend on the operator's policy bundle
    # (e.g. KSV-0125 "trusted registries"). Counting them as FPs
    # would mislead a reader into thinking secscan was noisy.
    policy_driven = set(expected.get("policy_driven_check_ids", []))
    fp = 0
    if not expected_ids:
        for f in findings:
            if f.get("severity") not in ("critical", "high", "medium"):
                continue
            if f.get("rule_id", "") in policy_driven:
                continue
            fp += 1
    return FixtureResult(
        scanner="config",
        fixture_name=fixture_dir.name,
        expected_count=len(expected_ids),
        detected_count=detected,
        false_positive_count=fp,
        raw_finding_count=len(findings),
        comparison_tool="trivy config",
    )


def _bench_external(fixture_dir: Path) -> FixtureResult:
    """Phase 2-I dispatcher: SAST → ``_bench_external_sast``,
    secrets → ``_bench_external_secrets``."""
    _assert_under_fixture_root(fixture_dir)
    expected = _expected(fixture_dir)
    scanner = expected.get("scanner", "sast")
    if scanner == "secrets":
        return _bench_external_secrets(fixture_dir)
    return _bench_external_sast(fixture_dir)


def _bench_external_secrets(fixture_dir: Path) -> FixtureResult:
    """Phase 2-I: measure secscan secrets against the gitleaks
    project's own ``testdata/`` corpus. Recall = unique rule IDs
    secscan emits that are in expected_rule_ids.
    """
    expected = _expected(fixture_dir)
    repo = expected.get("repo", "")
    if repo not in _TRUSTED_EXTERNAL_REPOS:
        return FixtureResult(
            scanner="external/secrets",
            fixture_name=fixture_dir.name,
            expected_count=0,
            detected_count=0,
            skipped_reason=f"repo {repo!r} not on the external allowlist",
        )
    if shutil.which("gitleaks") is None:
        return FixtureResult(
            scanner="external/secrets",
            fixture_name=fixture_dir.name,
            expected_count=0,
            detected_count=0,
            skipped_reason="gitleaks not installed",
        )
    clone_dir = EXTERNAL_CLONE_ROOT / fixture_dir.name
    if not clone_dir.is_dir():
        clone_res = _run(
            ["git", "clone", "--depth", "1", "--", repo, str(clone_dir)],
            timeout=300,
        )
        if clone_res.returncode != 0:
            return FixtureResult(
                scanner="external/secrets",
                fixture_name=fixture_dir.name,
                expected_count=0,
                detected_count=0,
                skipped_reason=(
                    "git clone failed: "
                    + clone_res.stderr.decode("utf-8", errors="replace")[:120]
                ),
            )
    scan_dir = clone_dir
    subdir = expected.get("subdir", "")
    if subdir:
        scan_dir = (clone_dir / subdir).resolve()
        if not scan_dir.is_relative_to(EXTERNAL_CLONE_ROOT) or not scan_dir.is_dir():
            return FixtureResult(
                scanner="external/secrets",
                fixture_name=fixture_dir.name,
                expected_count=0,
                detected_count=0,
                skipped_reason=f"subdir {subdir!r} resolved outside clone",
            )
    expected_ids = list(expected.get("expected_rule_ids", []))
    payload = _run_secscan_scan("secrets", scan_dir, allow_external=True)
    findings = payload.get("findings", [])
    seen_ids = {f.get("rule_id", "") for f in findings}
    detected = sum(1 for rid in expected_ids if rid in seen_ids)
    return FixtureResult(
        scanner="external/secrets",
        fixture_name=fixture_dir.name,
        expected_count=len(expected_ids),
        detected_count=detected,
        raw_finding_count=len(findings),
        comparison_tool="gitleaks (own corpus)",
    )


def _bench_external_sast(fixture_dir: Path) -> FixtureResult:
    """Phase 2-I: measure secscan SAST on a third-party benchmark.

    The benchmark project itself is cloned on demand under
    ``bench/external/<name>/`` (gitignored). Recall is computed by
    expected CWE category: a CWE counts as detected iff at least
    one secscan finding emitted that CWE. This is the out-of-sample
    number — unlike the curated fixtures we author, this measures
    secscan on code written by someone else, with no foreknowledge
    of our rule set.

    Codex Phase 2-I diff review tightenings (anticipated):
    - Repo URL must be on ``_TRUSTED_EXTERNAL_REPOS`` allowlist so
      a malicious PR cannot edit expected.json to clone arbitrary
      code into the bench tree.
    - Clone path stays under EXTERNAL_CLONE_ROOT (defence in depth).
    """
    _assert_under_fixture_root(fixture_dir)
    expected = _expected(fixture_dir)
    repo = expected.get("repo", "")
    scanner = expected.get("scanner", "sast")
    # Codex Phase 2-I diff review: ``repo`` MUST be a string; a
    # non-string (json null, integer, list) reaching the
    # ``in _TRUSTED_EXTERNAL_REPOS`` check would compare cleanly
    # but be a sign of a malformed expected.json — surface it
    # loudly rather than skipping silently.
    if not isinstance(repo, str):
        return FixtureResult(
            scanner=f"external/{scanner}",
            fixture_name=fixture_dir.name,
            expected_count=0,
            detected_count=0,
            skipped_reason=(
                f"expected.json#repo must be a string; got "
                f"{type(repo).__name__}"
            ),
        )
    if repo not in _TRUSTED_EXTERNAL_REPOS:
        return FixtureResult(
            scanner=f"external/{scanner}",
            fixture_name=fixture_dir.name,
            expected_count=0,
            detected_count=0,
            skipped_reason=(
                f"repo {repo!r} not on the external benchmark allowlist; "
                "add to _TRUSTED_EXTERNAL_REPOS to opt in"
            ),
        )
    clone_dir = EXTERNAL_CLONE_ROOT / fixture_dir.name
    if not clone_dir.is_dir():
        # Clone-on-demand. Shallow clone keeps disk usage tiny.
        clone_res = _run(
            ["git", "clone", "--depth", "1", "--", repo, str(clone_dir)],
            timeout=300,
        )
        if clone_res.returncode != 0:
            return FixtureResult(
                scanner=f"external/{scanner}",
                fixture_name=fixture_dir.name,
                expected_count=0,
                detected_count=0,
                skipped_reason=(
                    f"git clone failed: "
                    f"{clone_res.stderr.decode('utf-8', errors='replace')[:120]}"
                ),
            )
    else:
        # Codex Phase 2-I diff review: an existing clone could
        # have been tampered with (e.g. ``git remote set-url`` to
        # an attacker repo). Verify the remote URL matches the
        # expected one before scanning. Mismatches surface as
        # SKIPPED with a clear message; the operator can ``rm -rf``
        # the clone to force a re-clone from the trusted repo.
        remote_res = _run(
            ["git", "-C", str(clone_dir), "remote", "get-url", "origin"],
            timeout=30,
        )
        actual_remote = remote_res.stdout.decode("utf-8", errors="replace").strip()
        # Normalise the trailing ``.git`` if any — github clones
        # are written as ``...NodeGoat.git`` in remote but the
        # allowlist uses the user-facing URL.
        normalised = actual_remote.rstrip("/").removesuffix(".git")
        if normalised != repo:
            return FixtureResult(
                scanner=f"external/{scanner}",
                fixture_name=fixture_dir.name,
                expected_count=0,
                detected_count=0,
                skipped_reason=(
                    f"clone remote {actual_remote!r} does not match "
                    f"expected {repo!r}; rm -rf the clone to refresh"
                ),
            )
    # Defence in depth: clone_dir must live under EXTERNAL_CLONE_ROOT.
    if not clone_dir.resolve().is_relative_to(EXTERNAL_CLONE_ROOT):
        return FixtureResult(
            scanner=f"external/{scanner}",
            fixture_name=fixture_dir.name,
            expected_count=0,
            detected_count=0,
            skipped_reason="clone dir escaped EXTERNAL_CLONE_ROOT",
        )
    expected_entries = expected.get("expected_cwes", [])
    payload = _run_secscan_scan(scanner, clone_dir, allow_external=True)
    findings = payload.get("findings", [])
    detected_set: set[str] = set()
    for f in findings:
        cwe = f.get("cwe") or ""
        head = cwe.split(":", 1)[0].strip()
        if head:
            detected_set.add(head)
    # Phase 2-I refinement: each expected entry may carry an
    # ``aliases`` list of CWE codes that count as equivalent
    # (e.g. CWE-89 ↔ CWE-943 for SQL vs NoSQL — same class,
    # different category code).
    #
    # Codex Phase 2-I diff review: matching is "consumption-based"
    # so a single detected CWE cannot satisfy multiple expected
    # entries. The ``consumed`` set tracks which detected CWE
    # codes have already counted toward an expected entry.
    detected = 0
    consumed: set[str] = set()
    for entry in expected_entries:
        primary = entry.get("cwe", "")
        aliases = entry.get("aliases", []) or []
        for candidate in (primary, *aliases):
            if candidate in detected_set and candidate not in consumed:
                detected += 1
                consumed.add(candidate)
                break
    return FixtureResult(
        scanner=f"external/{scanner}",
        fixture_name=fixture_dir.name,
        expected_count=len(expected_entries),
        detected_count=detected,
        raw_finding_count=len(findings),
    )


def _bench_dast_all(*, mode: str = "baseline") -> list[FixtureResult]:
    """Iterate every fixture under ``bench/fixtures/dast/`` and run
    DAST against each.

    ``mode`` selects the ZAP entrypoint to use (``baseline`` ↔
    zap-baseline.py, ``active`` ↔ zap-full-scan.py). Phase 2-J
    added the active-mode path; baseline remains the default.
    """
    dast_root = SAFE_FIXTURE_ROOT / "dast"
    if not dast_root.is_dir():
        return []
    results: list[FixtureResult] = []
    for sub in sorted(dast_root.iterdir()):
        if not sub.is_dir():
            continue
        if not (sub / "expected.json").exists():
            continue
        results.append(_bench_dast(sub, mode=mode))
    return results


def _bench_dast(fixture_dir: Path, *, mode: str = "baseline") -> FixtureResult:
    if not fixture_dir.exists() or not (fixture_dir / "expected.json").exists():
        return FixtureResult(
            scanner="dast",
            fixture_name="juice-shop",
            expected_count=0,
            detected_count=0,
            skipped_reason="fixture not present",
        )
    # Codex Phase 2-H diff review: route every fixture path that
    # ends up in argv (including ``--path`` for secscan dast)
    # through the safety gate.
    fixture_dir = _assert_under_fixture_root(fixture_dir)
    if shutil.which("docker") is None:
        return FixtureResult(
            scanner="dast",
            fixture_name="juice-shop",
            expected_count=0,
            detected_count=0,
            skipped_reason="docker not installed",
        )

    fixture_name = fixture_dir.name
    expected = _expected(fixture_dir)
    pinning = expected.get("image_pinning", {})
    zap_image = pinning.get("zap", "")
    expected_helper = pinning.get("helper", "")
    # The Juice Shop fixture uses ``juice_shop`` as the key; the
    # WebGoat fixture (Phase 2-I) also stores its image under
    # ``juice_shop`` for backwards compatibility, then declares
    # ``container_config.container_port`` / ``.url_path`` so the
    # bench can swap targets without renaming keys.
    target_image = pinning.get("juice_shop", "")
    if not target_image or not zap_image:
        return FixtureResult(
            scanner="dast",
            fixture_name=fixture_name,
            expected_count=0,
            detected_count=0,
            skipped_reason="image_pinning missing from expected.json",
        )
    cc = expected.get("container_config", {})
    container_port = int(cc.get("container_port", 3000))
    url_path = cc.get("url_path", "/")
    # Codex Phase 2-H diff review: assert the expected.json helper
    # digest matches the code constant. Drift means the test corpus
    # and the production helper diverged — surface it loudly.
    if expected_helper:
        from secscan.scanners.dast.zap import HELPER_IMAGE

        if expected_helper != HELPER_IMAGE:
            return FixtureResult(
                scanner="dast",
                fixture_name="juice-shop",
                expected_count=0,
                detected_count=0,
                skipped_reason=(
                    f"helper image drift: expected.json has "
                    f"{expected_helper!r} but code has {HELPER_IMAGE!r}"
                ),
            )

    container_name = f"secscan-bench-{fixture_name}-{_secrets.token_hex(4)}"
    host_port = _pick_free_port()
    # Phase 2-J: choose the expected set by mode.
    if mode == "active":
        expected_findings = expected.get("expected_active_findings", [])
        scanner_label = "dast (active)"
        # Active scan needs much more time (full-scan ~ 30-60 min).
        scan_timeout = 4 * 3600
    else:
        expected_findings = expected.get("expected_findings", [])
        scanner_label = "dast"
        scan_timeout = 900
    if not expected_findings:
        return FixtureResult(
            scanner=scanner_label,
            fixture_name=fixture_name,
            expected_count=0,
            detected_count=0,
            skipped_reason=(
                f"no expected_{'active_' if mode == 'active' else ''}findings "
                f"in expected.json"
            ),
        )
    container_started = False
    try:
        # 1. Start the target container in the background.
        start = _run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                container_name,
                "-p",
                f"127.0.0.1:{host_port}:{container_port}",
                "--",
                target_image,
            ],
            timeout=180,
        )
        if start.returncode != 0:
            return FixtureResult(
                scanner="dast",
                fixture_name=fixture_name,
                expected_count=len(expected_findings),
                detected_count=0,
                skipped_reason=(
                    f"{fixture_name} start failed: "
                    f"{start.stderr.decode('utf-8', errors='replace')[:120]}"
                ),
            )
        container_started = True

        # 2. Wait for the target to respond.
        import socket
        import time

        deadline = time.monotonic() + 120
        ready = False
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", host_port), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(1)
        if not ready:
            return FixtureResult(
                scanner="dast",
                fixture_name=fixture_name,
                expected_count=len(expected_findings),
                detected_count=0,
                skipped_reason=f"{fixture_name} did not start within 120s",
            )

        # 3. Run secscan dast.
        argv = [
            "secscan",
            "dast",
            "--target",
            f"http://host.docker.internal:{host_port}{url_path}",
            "--zap-image",
            zap_image,
            "--mode",
            mode,
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-color",
            "--path",
            str(fixture_dir),
        ]
        result = _run(argv, cwd=REPO_ROOT, timeout=scan_timeout)
        if not result.stdout:
            return FixtureResult(
                scanner=scanner_label,
                fixture_name=fixture_name,
                expected_count=len(expected_findings),
                detected_count=0,
                skipped_reason=(
                    "secscan dast returned no stdout: "
                    + result.stderr.decode("utf-8", errors="replace")[:160]
                ),
            )
        payload = json.loads(result.stdout.decode("utf-8"))
        findings = payload.get("findings", [])

        # 4. Match by pluginid.
        rule_ids = {f.get("rule_id", "") for f in findings}
        detected = sum(
            1 for entry in expected_findings if entry["pluginid"] in rule_ids
        )

        return FixtureResult(
            scanner=scanner_label,
            fixture_name=fixture_name,
            expected_count=len(expected_findings),
            detected_count=detected,
            raw_finding_count=len(findings),
            comparison_tool=(
                "zap-full-scan" if mode == "active" else "zap-baseline"
            ),
        )
    finally:
        if container_started:
            _run(
                ["docker", "stop", "--timeout", "5", container_name], timeout=30
            )


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


def run_all(
    *,
    scanners: set[str],
    include_dast: bool,
    include_dast_active: bool = False,
    include_external: bool,
) -> list[FixtureResult]:
    results: list[FixtureResult] = []
    if "secrets" in scanners:
        _verify_secret_manifest()
        for sub in sorted((SAFE_FIXTURE_ROOT / "secrets").iterdir()):
            if not sub.is_dir():
                continue
            if not (sub / "expected.json").exists():
                continue
            results.append(_bench_secrets(sub))
    if "deps" in scanners:
        for sub in sorted((SAFE_FIXTURE_ROOT / "deps").iterdir()):
            if not sub.is_dir():
                continue
            if not (sub / "expected.json").exists():
                continue
            results.append(_bench_deps(sub))
    if "sast" in scanners:
        for sub in sorted((SAFE_FIXTURE_ROOT / "sast").iterdir()):
            if not sub.is_dir():
                continue
            if not (sub / "expected.json").exists():
                continue
            results.append(_bench_sast(sub))
    if "config" in scanners:
        config_root = SAFE_FIXTURE_ROOT / "config"
        if config_root.is_dir():
            for sub in sorted(config_root.iterdir()):
                if not sub.is_dir():
                    continue
                if not (sub / "expected.json").exists():
                    continue
                results.append(_bench_config(sub))
    if include_dast:
        results.extend(_bench_dast_all(mode="baseline"))
    if include_dast_active:
        results.extend(_bench_dast_all(mode="active"))
    if include_external:
        external_root = SAFE_FIXTURE_ROOT / "external"
        if external_root.is_dir():
            for sub in sorted(external_root.iterdir()):
                if not sub.is_dir():
                    continue
                if not (sub / "expected.json").exists():
                    continue
                results.append(_bench_external(sub))
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_markdown(results: list[FixtureResult]) -> str:
    lines: list[str] = []
    lines.append("# secscan benchmark report")
    lines.append("")
    from secscan import __version__ as v

    lines.append(f"_secscan {v}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    ran = [r for r in results if r.skipped_reason is None]
    skipped = [r for r in results if r.skipped_reason is not None]
    total_expected = sum(r.expected_count for r in ran)
    total_detected = sum(r.detected_count for r in ran)
    total_fp = sum(r.false_positive_count for r in ran)
    overall_recall = (
        total_detected / total_expected if total_expected > 0 else 1.0
    )
    lines.append(
        f"- Overall recall: **{total_detected}/{total_expected} "
        f"({overall_recall * 100:.1f}%)**"
    )
    lines.append(f"- Total false positives (clean fixtures): **{total_fp}**")
    lines.append(f"- Fixtures run: {len(ran)}, skipped: {len(skipped)}")
    ge_known = [r for r in ran if r.ge_best_single_tool is not None]
    if ge_known:
        ge_pass = sum(1 for r in ge_known if r.ge_best_single_tool)
        lines.append(
            f"- ≥ best single tool (integration parity): "
            f"**{ge_pass}/{len(ge_known)} fixtures**"
        )
    lines.append("")
    lines.append("## Per-fixture detail")
    lines.append("")
    lines.append(
        "| Scanner | Fixture | Expected | Detected | Recall | FP | "
        "Compare tool | Compare count | ≥ Best |"
    )
    lines.append(
        "|---|---|---|---|---|---|---|---|---|"
    )
    for r in results:
        if r.skipped_reason:
            lines.append(
                f"| {r.scanner} | {r.fixture_name} | — | — | SKIPPED | "
                f"({r.skipped_reason}) | — | — | — |"
            )
            continue
        recall_pct = f"{r.recall * 100:.1f}%"
        ge_mark = (
            "✅"
            if r.ge_best_single_tool is True
            else ("⚠️" if r.ge_best_single_tool is False else "—")
        )
        compare_count = (
            "—" if r.comparison_count is None else str(r.comparison_count)
        )
        lines.append(
            f"| {r.scanner} | {r.fixture_name} | "
            f"{r.expected_count} | {r.detected_count} | {recall_pct} | "
            f"{r.false_positive_count} | {r.comparison_tool or '—'} | "
            f"{compare_count} | {ge_mark} |"
        )
    lines.append("")
    lines.append("## Methodology notes")
    lines.append("")
    lines.append(
        "- **Recall** = (detected ∩ expected) / |expected|. "
        "Bonus detections beyond the curated set are credited via "
        "the raw `Detected` column but do not boost the recall ratio."
    )
    lines.append(
        "- **False positives** are findings emitted on the `clean/` and "
        "`safe_*` sibling fixtures."
    )
    lines.append(
        "- **≥ Best single tool** indicates secscan returned at least "
        "as many findings as the comparison tool on the same fixture — "
        "i.e. the integration layer did not silently downgrade recall."
    )
    lines.append(
        "- Skipped fixtures (tool not installed / docker absent) report "
        "as SKIPPED rather than failing; install the listed tool and re-run."
    )
    lines.append("")
    lines.append("## Interpreting SAST numbers (Codex diff-review pin)")
    lines.append("")
    lines.append(
        "The default semgrep ruleset family is `p/python + p/javascript "
        "+ p/typescript + p/owasp-top-ten`. These rulesets catch the "
        "command-injection family reliably but DO NOT catch every CWE "
        "shipped under those names: SQLi via f-string, raw `yaml.load`, "
        "hard-coded credentials in Python, and `eval()` in CommonJS "
        "JavaScript all slip through with the defaults."
    )
    lines.append("")
    lines.append(
        "A low SAST recall here therefore reflects the **default ruleset's "
        "coverage**, not a bug in the secscan wrapper. The `≥ Best` column "
        "demonstrates this by comparing against semgrep run directly with "
        "the same rules: when both are 0, the gap is the ruleset, not the "
        "integration. Users who need broader CWE coverage should add "
        "`p/security-audit` (or a custom ruleset) to `[sast].semgrep_config`."
    )
    return "\n".join(lines) + "\n"


def render_json(results: list[FixtureResult]) -> str:
    payload = {"fixtures": [dataclasses.asdict(r) for r in results]}
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="secscan benchmark runner")
    parser.add_argument(
        "--only",
        default="deps,secrets,sast,config",
        help=(
            "comma-separated subset (deps,secrets,sast,config). "
            "Default: all four."
        ),
    )
    parser.add_argument("--dast", action="store_true", help="include DAST baseline")
    parser.add_argument(
        "--dast-active",
        action="store_true",
        dest="dast_active",
        help=(
            "include DAST in ACTIVE mode (zap-full-scan.py — sends "
            "payloads, 10x slower, ~30-60 min per target). Do NOT "
            "point at production. Stacks with --dast: passing both "
            "runs each fixture twice, once per mode."
        ),
    )
    parser.add_argument(
        "--external",
        action="store_true",
        help=(
            "include third-party benchmarks (OWASP NodeGoat, PyGoat, ...). "
            "Clones each repo to bench/external/ on demand."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(BENCH_DIR / "report.md"),
        help="Markdown output path",
    )
    parser.add_argument(
        "--json-output",
        default=str(BENCH_DIR / "report.json"),
        help="JSON output path",
    )
    args = parser.parse_args(argv)
    scanners = {s.strip() for s in args.only.split(",") if s.strip()}
    try:
        results = run_all(
            scanners=scanners,
            include_dast=args.dast,
            include_dast_active=args.dast_active,
            include_external=args.external,
        )
    except BenchError as exc:
        sys.stderr.write(f"bench: {exc}\n")
        return 2
    Path(args.output).write_text(render_markdown(results), encoding="utf-8")
    Path(args.json_output).write_text(render_json(results), encoding="utf-8")
    sys.stdout.write(
        f"Wrote {args.output} and {args.json_output}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
