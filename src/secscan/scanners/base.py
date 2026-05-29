"""Scanner contract.

A Scanner knows how to invoke one external tool, parse its JSON output, and
emit normalized Findings. Scanners do NOT:

- Decide whether a finding "counts" — that's policy.py's job.
- Apply baseline suppression — that's orchestrator + baseline.
- Format output — that's reporter.py.

This separation lets each Scanner stay a thin adapter, easy to test with a
``FakeCommandRunner`` that returns canned subprocess output.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import ClassVar

from ..models import ScanConfig, ScanOutcome, WorkUnit
from ..runner import CommandRunner


class DiffMode(enum.Enum):
    """How a scanner behaves under ``secscan all --since <ref>`` (Phase 2-Y).

    - ``NATIVE``: the scanner has a real differential mode and scans
      only what changed since the baseline (secrets via gitleaks
      ``git --log-opts``, sast via semgrep ``--baseline-commit``).
    - ``ALWAYS``: the scanner runs a FULL scan even in diff mode,
      because its finding set does not track file changes — e.g.
      deps / supply, whose CVEs come from an advisory database that
      can flag an *unchanged* dependency (Codex Phase 2-Y design
      review #4). Gating these on "did the lockfile change?" would be
      a false-negative trap.
    - ``AGNOSTIC``: the scanner has no meaningful notion of a source
      diff (external HTTP target, whole-image CVE scan, whole-tree IaC
      policy). In diff mode it is SKIPPED with an explicit reason — it
      is recorded as skipped, NOT as a clean pass.
    """

    NATIVE = "native"
    ALWAYS = "always"
    AGNOSTIC = "agnostic"


class ToolNotFoundError(RuntimeError):
    """Raised when a scanner's required external tool is not on PATH.

    Carries an install hint for the reporter to display.
    """

    def __init__(self, tool: str, install_hint: str) -> None:
        super().__init__(f"required tool not found: {tool}")
        self.tool = tool
        self.install_hint = install_hint


class Scanner(ABC):
    """Base class for all scanners.

    Subclasses set ``name`` (matches CLI subcommand / config section), and
    ``tool_executable`` (the external binary they invoke).

    **Concurrency contract (Phase 2-X)**: ``scan()`` may be called
    concurrently from multiple threads by the parallel orchestrator
    (``secscan all`` default). A subclass implementation MUST be
    thread-safe — i.e. it must not mutate shared instance state without
    a lock, must not share file handles across calls without protection,
    and must rely only on the per-call ``unit`` / ``runner`` / ``config``
    inputs. ``CommandRunner`` instances passed in are documented to be
    thread-safe; if a subclass needs additional shared state, it must
    serialize access itself.

    ``requires_docker`` informs the orchestrator's Docker-throttling
    Semaphore (default cap: 2 simultaneous Docker scanners) so a fleet
    of image/SBOM/Trivy invocations cannot starve the local daemon.
    Conservatively set to True even for scanners that only *sometimes*
    use Docker (e.g. ``SupplyScanner`` only uses cosign-in-Docker when
    ``verify_images`` is configured) — the cost of an extra semaphore
    slot when Docker isn't actually used is negligible compared to the
    cost of a daemon overload.
    """

    name: ClassVar[str]
    tool_executable: ClassVar[str]
    install_hint: ClassVar[str]
    #: Whether this scanner shells out to Docker. Used by the parallel
    #: orchestrator to cap the number of concurrent Docker-using
    #: scanners. Default False; override to True in scanners that
    #: invoke ``docker run`` or otherwise contend for the local
    #: Docker daemon.
    requires_docker: ClassVar[bool] = False
    #: How this scanner behaves under ``--since`` diff mode (Phase 2-Y).
    #: Default ``AGNOSTIC`` (skipped in diff mode) — a scanner must opt
    #: into NATIVE or ALWAYS deliberately, so a newly-added scanner that
    #: forgets to declare its diff behaviour fails safe (skipped, with a
    #: reason) rather than silently running a full scan that the operator
    #: thought was a delta check.
    diff_mode: ClassVar[DiffMode] = DiffMode.AGNOSTIC

    @abstractmethod
    def is_applicable(self, unit: WorkUnit) -> bool:
        """Whether this scanner should process the given WorkUnit.

        Examples:
        - ``DepsScanner`` returns True only when ``unit.ecosystem`` matches.
        - ``SecretsScanner`` returns True for any WorkUnit.
        """

    @abstractmethod
    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        """Scan ``unit`` and return a normalized outcome.

        Must not raise on tool failure; instead, return a ScanOutcome with
        ``error`` populated. ``ToolNotFoundError`` is the one exception we do
        propagate — it's a configuration problem, not a scan failure, and
        the CLI translates it to exit code 2 with the install hint.

        See the class docstring for the **concurrency contract** —
        subclasses must be thread-safe when the parallel orchestrator
        is in use.
        """
