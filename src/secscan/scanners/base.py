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
    """

    name: ClassVar[str]
    tool_executable: ClassVar[str]
    install_hint: ClassVar[str]

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
        """
