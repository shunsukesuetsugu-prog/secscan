"""Borderline-clean counterpart to cwe78_cmd_injection.py.

Calls subprocess but uses an argv list + shell=False, which is the
documented safe pattern. A scanner that flags this is a false positive.
"""

from __future__ import annotations

import subprocess


def run_user_command_safely(user_input: str) -> None:
    # NOT a CWE-78: argv list + shell=False.
    subprocess.run(["echo", user_input], shell=False, check=False)


def list_dir_safely(path: str) -> str:
    return subprocess.check_output(["ls", path], shell=False).decode()
