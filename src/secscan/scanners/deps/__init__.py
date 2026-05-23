"""Dependency-CVE scanners.

Three adapters live here:

- ``npm.py``       — wraps ``npm audit --json``.
- ``pnpm.py``      — wraps ``pnpm audit --json``.
- ``pip_audit.py`` — wraps ``pip-audit -f json``.

``DepsScanner`` (one level up in ``deps_scanner.py``) dispatches to the
right adapter based on ``WorkUnit.package_manager``. Adapters are
intentionally small: argv construction, exit-code classification, JSON
parsing into normalized ``Finding`` instances. They do NOT touch the
filesystem beyond what subprocess needs, and they NEVER raise on tool
failure — that's a ScannerError, not a Python exception.
"""

from .npm import build_findings_from_npm_audit, classify_npm_audit_exit
from .pip_audit import build_findings_from_pip_audit, classify_pip_audit_exit
from .pnpm import build_findings_from_pnpm_audit, classify_pnpm_audit_exit

__all__ = [
    "build_findings_from_npm_audit",
    "build_findings_from_pip_audit",
    "build_findings_from_pnpm_audit",
    "classify_npm_audit_exit",
    "classify_pip_audit_exit",
    "classify_pnpm_audit_exit",
]
