"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Iterator[Path]:
    """A clean directory that tests can treat as a project root."""
    (tmp_path / "src").mkdir()
    yield tmp_path
