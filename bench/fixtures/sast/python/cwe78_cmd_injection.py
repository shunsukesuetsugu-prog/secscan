"""CWE-78 fixture: command injection via subprocess shell=True.

Expected to be detected by p/python or p/owasp-top-ten semgrep rules.
"""

from __future__ import annotations

import subprocess


def run_user_command(user_input: str) -> None:
    # CWE-78: untrusted input passed to a shell.
    subprocess.run(user_input, shell=True, check=False)  # noqa: S602


def list_dir(path: str) -> str:
    # CWE-78: string concatenation into shell.
    return subprocess.check_output("ls " + path, shell=True).decode()  # noqa: S602
