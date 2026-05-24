"""Plain Python module — no secrets, no credential-shaped strings.

Used as the obvious-clean sample for false-positive measurement.
"""

from __future__ import annotations


def add(a: int, b: int) -> int:
    return a + b


def format_user(name: str, age: int) -> str:
    return f"{name} (age {age})"
