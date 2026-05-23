"""Scanners — each wraps one or more external tools and emits normalized
Findings. See ``base.py`` for the contract."""

from .base import Scanner, ToolNotFoundError

__all__ = ["Scanner", "ToolNotFoundError"]
