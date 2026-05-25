"""Phase 2-X: parallel orchestrator regression tests.

Pins the contract Codex's Phase 2-X design review locked in:

1. Parallel mode actually overlaps execution → wall-clock < sum-of-parts.
2. One scanner raising does not block the others.
3. Docker-marked scanners are gated by a Semaphore (≤ docker_max active).
4. Parallel and serial paths produce **byte-identical** RunResult for
   the same input (the by-plan-index merge invariant — Codex MUST-FIX #3).
5. Determinism: same input → same RunResult across many runs.
6. ``max_workers`` validation: any value < 1 raises ``ValueError``
   (Codex MUST-FIX #6).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import pytest

from secscan.config import ProjectConfig
from secscan.models import (
    Finding,
    Location,
    ScanConfig,
    ScanOutcome,
    Severity,
    WorkUnit,
)
from secscan.orchestrator import run_scanners
from secscan.path_safety import resolve_scan_root
from secscan.runner import CommandRunner
from secscan.scanners.base import Scanner

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class _SleepingScanner(Scanner):
    """Scanner that sleeps a fixed duration before returning a single finding.

    Used to assert parallel speedup: with N such scanners each sleeping S
    seconds, serial wall-clock is ~N*S, parallel wall-clock is ~S (modulo
    thread pool overhead).
    """

    name: ClassVar[str] = ""  # overridden by subclasses
    tool_executable: ClassVar[str] = "fake"
    install_hint: ClassVar[str] = "fake"
    sleep_seconds: float = 0.5

    def is_applicable(self, unit: WorkUnit) -> bool:
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        time.sleep(self.sleep_seconds)
        return ScanOutcome(
            scanner=self.name,
            findings=(
                Finding(
                    scanner=self.name,
                    rule_id="r1",
                    severity=Severity.LOW,
                    title="t",
                    message="m",
                    location=Location(file="a.py", line=1),
                    fingerprint=f"fp-{self.name}",
                ),
            ),
            warnings=(),
            tool_version="x",
            error=None,
        )


class _S1(_SleepingScanner):
    name: ClassVar[str] = "secrets"


class _S2(_SleepingScanner):
    name: ClassVar[str] = "deps"


class _S3(_SleepingScanner):
    name: ClassVar[str] = "sast"


@dataclass
class _RaisingScanner(Scanner):
    """Scanner that raises on scan() — to assert exception isolation."""

    name: ClassVar[str] = "config"
    tool_executable: ClassVar[str] = "fake"
    install_hint: ClassVar[str] = "fake"
    exc: BaseException = field(default_factory=lambda: RuntimeError("boom"))

    def is_applicable(self, unit: WorkUnit) -> bool:
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        raise self.exc


@dataclass
class _DockerTrackingScanner(Scanner):
    """Docker-gated scanner that records concurrent activity.

    The shared ``active`` counter (with a lock) lets the test prove the
    Semaphore cap holds: ``peak[0]`` never exceeds the configured
    ``docker_max_workers``.
    """

    name: ClassVar[str] = ""  # overridden
    tool_executable: ClassVar[str] = "docker"
    install_hint: ClassVar[str] = "docker"
    requires_docker: ClassVar[bool] = True

    counter: dict[str, int] = field(default_factory=dict)
    peak: list[int] = field(default_factory=lambda: [0])
    lock: threading.Lock = field(default_factory=threading.Lock)
    sleep_seconds: float = 0.2

    def is_applicable(self, unit: WorkUnit) -> bool:
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        with self.lock:
            self.counter.setdefault("active", 0)
            self.counter["active"] += 1
            if self.counter["active"] > self.peak[0]:
                self.peak[0] = self.counter["active"]
        try:
            time.sleep(self.sleep_seconds)
        finally:
            with self.lock:
                self.counter["active"] -= 1
        return ScanOutcome(
            scanner=self.name,
            findings=(),
            warnings=(),
            tool_version="x",
            error=None,
        )


class _D1(_DockerTrackingScanner):
    name: ClassVar[str] = "config"


class _D2(_DockerTrackingScanner):
    name: ClassVar[str] = "image"


class _D3(_DockerTrackingScanner):
    name: ClassVar[str] = "sbom"


class _D4(_DockerTrackingScanner):
    name: ClassVar[str] = "apifuzz"


class _D5(_DockerTrackingScanner):
    name: ClassVar[str] = "dast"


class _NullRunner:
    """Stand-in CommandRunner — never invoked by these fake scanners."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env=None,
        timeout_seconds: int = 300,
    ):  # pragma: no cover
        raise AssertionError("fake scanners must not call the runner")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scan_root(tmp_path: Path):
    return resolve_scan_root(str(tmp_path))


@pytest.fixture
def minimal_config():
    return ProjectConfig()


@pytest.fixture(autouse=True)
def patch_discovery(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Force every fake scanner to receive exactly one work unit.

    ``discover_for_scanner('deps', root)`` returns zero work units on an
    empty directory; that would skip our deps-named fake before it ever
    runs. We patch the orchestrator's discovery call to hand back one
    unit per scanner so the parallel tests can exercise the plan path
    end-to-end regardless of the underlying file layout.
    """
    from dataclasses import dataclass as _dc

    from secscan import orchestrator as _orch
    from secscan.models import WorkUnit as _WorkUnit

    @_dc(frozen=True)
    class _StubDiscovery:
        work_units: tuple[_WorkUnit, ...]
        warnings: tuple[str, ...] = ()

    def _fake_discover(scanner_name: str, _scan_root):
        return _StubDiscovery(
            work_units=(
                _WorkUnit(root=tmp_path, ecosystem=None, manifest=None),
            )
        )

    monkeypatch.setattr(_orch, "discover_for_scanner", _fake_discover)


# ---------------------------------------------------------------------------
# 1. Parallel speedup
# ---------------------------------------------------------------------------


def test_parallel_wall_clock_shorter_than_serial_sum(scan_root, minimal_config) -> None:
    """3 scanners sleeping 0.4s each: serial ≈ 1.2s, parallel ≈ 0.4s."""
    scanners: list[Scanner] = [
        _S1(sleep_seconds=0.4),
        _S2(sleep_seconds=0.4),
        _S3(sleep_seconds=0.4),
    ]
    t0 = time.monotonic()
    run_scanners(
        scanners,
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=True,
    )
    parallel_wall = time.monotonic() - t0
    # With a 3-thread pool the floor is one sleep + a bit of overhead.
    # We accept up to 0.9s before flagging as "essentially serial".
    assert parallel_wall < 0.9, (
        f"parallel run took {parallel_wall:.2f}s; expected ~0.4s. "
        "Either the pool didn't spin up or scanners ran serially."
    )


# ---------------------------------------------------------------------------
# 2. Exception isolation
# ---------------------------------------------------------------------------


def test_one_scanner_raising_does_not_block_others(scan_root, minimal_config) -> None:
    """A scanner raising RuntimeError must be reported as ScannerError;
    the surviving scanners' findings must reach the RunResult."""
    healthy = _S1(sleep_seconds=0.05)
    healthy_b = _S2(sleep_seconds=0.05)
    broken = _RaisingScanner(exc=RuntimeError("simulated crash"))
    out = run_scanners(
        [healthy, broken, healthy_b],
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=True,
    )
    finding_scanners = {f.scanner for f in out.result.findings}
    error_scanners = {e.scanner for e in out.result.errors}
    assert finding_scanners == {"secrets", "deps"}
    assert "config" in error_scanners
    # The crash reason was redacted+truncated, not raw — that's the
    # _execute_item contract.
    crash_err = next(e for e in out.result.errors if e.scanner == "config")
    assert "RuntimeError" in crash_err.reason
    assert "simulated crash" in crash_err.reason


# ---------------------------------------------------------------------------
# 3. Docker Semaphore cap
# ---------------------------------------------------------------------------


def test_docker_semaphore_caps_concurrent_docker_scanners(
    scan_root, minimal_config
) -> None:
    """Five Docker-marked scanners with a cap of 2 must never have more
    than 2 simultaneously active. Without the gate the peak would be 5."""
    shared_counter: dict[str, int] = {}
    shared_peak: list[int] = [0]
    shared_lock = threading.Lock()
    scanners: list[Scanner] = [
        _D1(counter=shared_counter, peak=shared_peak, lock=shared_lock),
        _D2(counter=shared_counter, peak=shared_peak, lock=shared_lock),
        _D3(counter=shared_counter, peak=shared_peak, lock=shared_lock),
        _D4(counter=shared_counter, peak=shared_peak, lock=shared_lock),
        _D5(counter=shared_counter, peak=shared_peak, lock=shared_lock),
    ]
    run_scanners(
        scanners,
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=True,
        max_workers=8,  # big thread pool — only the Docker sem should gate
        docker_max_workers=2,
    )
    assert shared_peak[0] <= 2, (
        f"peak concurrent docker scanners = {shared_peak[0]}; "
        "Docker semaphore did not cap to 2."
    )
    assert shared_peak[0] >= 2, (
        f"peak concurrent docker scanners = {shared_peak[0]}; "
        "expected some overlap (≥2). The gate may be holding everything serial."
    )


# ---------------------------------------------------------------------------
# 4. Parallel == Serial byte-identical RunResult
# ---------------------------------------------------------------------------


def test_parallel_and_serial_produce_identical_runresult(
    scan_root, minimal_config
) -> None:
    """Same scanners, same inputs: parallel and serial paths must produce
    structurally identical RunResult. This is the Codex MUST-FIX #3 contract
    that --no-parallel is a perf dial, not a behaviour switch."""
    scanners_serial: list[Scanner] = [
        _S1(sleep_seconds=0.01),
        _S2(sleep_seconds=0.01),
        _S3(sleep_seconds=0.01),
    ]
    scanners_parallel: list[Scanner] = [
        _S1(sleep_seconds=0.01),
        _S2(sleep_seconds=0.01),
        _S3(sleep_seconds=0.01),
    ]
    serial = run_scanners(
        scanners_serial,
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=False,
    )
    parallel = run_scanners(
        scanners_parallel,
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=True,
    )
    # Findings: same set, same order (scanner-by-scanner plan order).
    assert tuple(f.fingerprint for f in serial.result.findings) == tuple(
        f.fingerprint for f in parallel.result.findings
    )
    assert serial.result.scanned_scanners == parallel.result.scanned_scanners
    assert serial.result.skipped == parallel.result.skipped
    assert serial.result.warnings == parallel.result.warnings
    assert tuple(e.scanner for e in serial.result.errors) == tuple(
        e.scanner for e in parallel.result.errors
    )


# ---------------------------------------------------------------------------
# 5. Determinism across runs
# ---------------------------------------------------------------------------


def test_parallel_output_is_deterministic_across_runs(
    scan_root, minimal_config
) -> None:
    """Running the parallel orchestrator 5 times on the same input must
    produce the same RunResult fingerprints in the same order each time —
    the by-plan-index re-sort guarantees this even though completion order
    is non-deterministic."""

    def _run() -> tuple[str, ...]:
        scanners: list[Scanner] = [
            _S1(sleep_seconds=0.01),
            _S2(sleep_seconds=0.01),
            _S3(sleep_seconds=0.01),
        ]
        out = run_scanners(
            scanners,
            scan_root=scan_root,
            config=minimal_config,
            runner=_NullRunner(),
            parallel=True,
        )
        return tuple(f.fingerprint for f in out.result.findings)

    reference = _run()
    for _ in range(4):
        assert _run() == reference, (
            "parallel run produced non-deterministic finding order"
        )


# ---------------------------------------------------------------------------
# 6. max_workers validation
# ---------------------------------------------------------------------------


def test_max_workers_zero_is_rejected(scan_root, minimal_config) -> None:
    with pytest.raises(ValueError, match="max_workers must be >= 1"):
        run_scanners(
            [_S1(sleep_seconds=0.01)],
            scan_root=scan_root,
            config=minimal_config,
            runner=_NullRunner(),
            parallel=True,
            max_workers=0,
        )


def test_max_workers_negative_is_rejected(scan_root, minimal_config) -> None:
    with pytest.raises(ValueError, match="max_workers must be >= 1"):
        run_scanners(
            [_S1(sleep_seconds=0.01)],
            scan_root=scan_root,
            config=minimal_config,
            runner=_NullRunner(),
            parallel=True,
            max_workers=-1,
        )


def test_docker_max_workers_zero_is_rejected(scan_root, minimal_config) -> None:
    with pytest.raises(ValueError, match="docker_max_workers must be >= 1"):
        run_scanners(
            [_S1(sleep_seconds=0.01)],
            scan_root=scan_root,
            config=minimal_config,
            runner=_NullRunner(),
            parallel=True,
            docker_max_workers=0,
        )


# ---------------------------------------------------------------------------
# 7. Duplicate scanner instance names (workspace edge case)
# ---------------------------------------------------------------------------


def test_duplicate_named_scanner_instances_do_not_double_replay(
    scan_root, minimal_config
) -> None:
    """Codex Phase 2-X diff review MUST-FIX #3: two scanner instances
    sharing a ``name`` (e.g. two ``deps`` instances scanning different
    ecosystems in a workspace) must each have their results merged
    exactly once. The previous name-keyed aggregation would have
    replayed every "deps" item twice when there were two "deps"
    instances in selected."""
    inst_a = _S2(sleep_seconds=0.01)  # name="deps"
    inst_b = _S2(sleep_seconds=0.01)  # name="deps"
    out = run_scanners(
        [inst_a, inst_b],
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=True,
    )
    # Both instances produce one ``fp-deps`` finding each. With the
    # by-instance-index keying, total should be 2; the buggy
    # by-name keying produced 4 (each item replayed twice).
    finding_fps = [f.fingerprint for f in out.result.findings]
    assert finding_fps.count("fp-deps") == 2, (
        f"expected 2 findings, got {finding_fps.count('fp-deps')}: {finding_fps}"
    )


# ---------------------------------------------------------------------------
# 8. SIGINT cancellation does not block forever on shutdown
# ---------------------------------------------------------------------------


def test_keyboard_interrupt_propagates_without_hang(
    scan_root, minimal_config
) -> None:
    """Codex Phase 2-X diff review MUST-FIX #1: ``KeyboardInterrupt``
    raised inside ``as_completed`` must shutdown the executor with
    ``cancel_futures=True, wait=False`` so the call returns promptly
    even if some workers are mid-sleep. Without the explicit
    shutdown the ``with ThreadPoolExecutor:`` block waits for every
    worker to finish, which would freeze the CLI's SIGINT handler.
    """

    class _RaisingMidCompletion(Scanner):
        name: ClassVar[str] = "secrets"
        tool_executable: ClassVar[str] = "fake"
        install_hint: ClassVar[str] = "fake"

        def is_applicable(self, unit: WorkUnit) -> bool:
            return True

        def scan(self, unit, runner, config):
            # Mimic a CTRL-C arriving mid-scan. The orchestrator's
            # except branch must NOT swallow this; it must call
            # shutdown(cancel_futures=True) and re-raise.
            raise KeyboardInterrupt("simulated ctrl-c")

    scanners: list[Scanner] = [
        _RaisingMidCompletion(),
        _S2(sleep_seconds=2.0),  # would otherwise block the wait
    ]
    t0 = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        run_scanners(
            scanners,
            scan_root=scan_root,
            config=minimal_config,
            runner=_NullRunner(),
            parallel=True,
            max_workers=2,
        )
    elapsed = time.monotonic() - t0
    # Scope of this assertion: ``run_scanners()`` returns promptly.
    # CPython 3.11's executor worker threads are non-daemon, so the
    # interpreter atexit hook may still wait for the 2.0s sleeper at
    # process exit — that's the Phase 2-X v1 known limitation
    # documented on ``run_scanners()``. The fix here is enough to
    # let the CLI's ``main()`` reach its ``except KeyboardInterrupt``
    # branch promptly and start its cleanup; full process-exit
    # responsiveness will come with Phase 2-Y subprocess tracking.
    assert elapsed < 1.5, (
        f"KeyboardInterrupt did not propagate promptly: took {elapsed:.2f}s"
    )


# ---------------------------------------------------------------------------
# 9. Empty plan: no executor, no crash
# ---------------------------------------------------------------------------


@dataclass
class _NotApplicableScanner(Scanner):
    name: ClassVar[str] = "secrets"
    tool_executable: ClassVar[str] = "fake"
    install_hint: ClassVar[str] = "fake"

    def is_applicable(self, unit: WorkUnit) -> bool:
        return False

    def scan(  # pragma: no cover  (never reached)
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        raise AssertionError("scan() must not be called when is_applicable=False")


def test_empty_plan_returns_without_executor(scan_root, minimal_config) -> None:
    """Zero applicable units → parallel path must still return cleanly
    (no ThreadPoolExecutor(max_workers=0) crash)."""
    out = run_scanners(
        [_NotApplicableScanner()],
        scan_root=scan_root,
        config=minimal_config,
        runner=_NullRunner(),
        parallel=True,
    )
    assert out.result.findings == ()
    assert out.result.scanned_scanners == ()
