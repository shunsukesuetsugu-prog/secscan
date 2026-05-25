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

from abc import ABC, abstractmethod
from typing import ClassVar

from ..models import ScanConfig, ScanOutcome, WorkUnit
from ..runner import CommandRunner


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
