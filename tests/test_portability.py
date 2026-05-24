"""Phase 2-W: cross-platform path helpers.

These tests pin the contract of :mod:`secscan.portability`:

- ``to_docker_host_path`` returns the operator-supplied path
  unchanged on POSIX and converts the drive-letter form to
  Docker Desktop's ``/c/Users/...`` convention on Windows.
- ``path_charset_check`` accepts Windows paths (drive colon,
  backslash, embedded spaces) on Windows but rejects them on
  POSIX. NUL / CR / LF / tab are rejected everywhere.

Tests use ``monkeypatch`` to flip ``IS_WINDOWS`` on a POSIX host
so we can exercise the Windows-side branch without running on
Windows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secscan import portability


class TestToDockerHostPathPosix:
    def test_posix_path_passes_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert (
            portability.to_docker_host_path("/Users/foo/bar")
            == "/Users/foo/bar"
        )

    def test_posix_path_object(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert (
            portability.to_docker_host_path(Path("/Users/foo/bar"))
            == "/Users/foo/bar"
        )

    def test_unicode_path_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert (
            portability.to_docker_host_path("/Users/shunsuke/セキュリティツール")
            == "/Users/shunsuke/セキュリティツール"
        )


class TestToDockerHostPathWindows:
    def test_drive_letter_to_unix_form(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex Phase 2-W diff review MUST-FIX #1: prefer
        ``/c/Users/...`` over ``C:/Users/...`` so the drive
        colon doesn't collide with ``-v <src>:<dst>:<opts>``."""
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        result = portability.to_docker_host_path("C:\\Users\\foo\\bar")
        assert result == "/c/Users/foo/bar"

    def test_drive_letter_already_forward_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        result = portability.to_docker_host_path("D:/Projects/x")
        assert result == "/d/Projects/x"

    def test_drive_letter_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        # Bare drive root: ``C:\`` → ``/c/``
        result = portability.to_docker_host_path("C:\\")
        assert result == "/c/"

    def test_lowercases_drive_letter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        assert (
            portability.to_docker_host_path("X:\\foo")
            == "/x/foo"
        )

    def test_spaces_in_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        # Windows paths frequently contain ``Program Files`` etc.
        result = portability.to_docker_host_path(
            "C:\\Program Files\\Python\\python.exe"
        )
        assert result == "/c/Program Files/Python/python.exe"

    def test_relative_path_REJECTED(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex Phase 2-W diff review MUST-FIX: relative
        Windows paths are refused. ``docker -v subdir/x:/dst``
        would be interpreted as a NAMED VOLUME named ``subdir``,
        not a bind mount — a silent surprise. Force the caller
        to pass an absolute path."""
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        with pytest.raises(
            portability.PortabilityError, match="absolute Windows path"
        ):
            portability.to_docker_host_path("subdir\\file.txt")

    def test_unc_path_REJECTED(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex Phase 2-W diff review MUST-FIX: UNC paths
        (``\\\\server\\share``) are refused. Docker Desktop's
        documentation does not list a proven Unix-style
        conversion. Operators can map the UNC share to a drive
        letter first."""
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        with pytest.raises(
            portability.PortabilityError, match="UNC paths are not supported"
        ):
            portability.to_docker_host_path("\\\\server\\share\\file")


class TestToDockerHostPathErrors:
    def test_int_rejected(self) -> None:
        with pytest.raises(TypeError):
            portability.to_docker_host_path(42)  # type: ignore[arg-type]

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(portability.PortabilityError, match="empty"):
            portability.to_docker_host_path("")

    def test_relative_posix_path_REJECTED(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex Phase 2-W diff review MUST-FIX: same rule on
        POSIX. ``docker -v relative/path:/dst`` is a named-volume
        reference, not a bind mount. The helper requires
        absolute paths."""
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        with pytest.raises(
            portability.PortabilityError, match="absolute path"
        ):
            portability.to_docker_host_path("relative/path")


class TestIsWindowsPath:
    def test_drive_letter_backslash(self) -> None:
        assert portability.is_windows_path("C:\\Users\\foo") is True

    def test_drive_letter_forward_slash(self) -> None:
        assert portability.is_windows_path("D:/Projects/x") is True

    def test_unc_path(self) -> None:
        assert portability.is_windows_path("\\\\server\\share") is True

    def test_posix_path(self) -> None:
        assert portability.is_windows_path("/Users/foo") is False

    def test_relative_path(self) -> None:
        assert portability.is_windows_path("./relative") is False

    def test_bare_name(self) -> None:
        assert portability.is_windows_path("named-volume") is False

    def test_empty(self) -> None:
        assert portability.is_windows_path("") is False

    def test_non_string(self) -> None:
        assert portability.is_windows_path(123) is False  # type: ignore[arg-type]


class TestPathCharsetCheckPosix:
    def test_accepts_posix_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert portability.path_charset_check("/Users/foo/bar")

    def test_accepts_unicode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert portability.path_charset_check(
            "/Users/shunsuke/セキュリティツール"
        )

    def test_rejects_colon_on_posix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert not portability.path_charset_check("/Users/foo:bar")

    def test_rejects_backslash_on_posix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert not portability.path_charset_check("/Users/foo\\bar")

    def test_rejects_whitespace_on_posix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", False)
        assert not portability.path_charset_check("/Users/foo bar/baz")


class TestPathCharsetCheckWindows:
    def test_accepts_drive_letter_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        assert portability.path_charset_check("C:\\Users\\foo\\bar")

    def test_accepts_path_with_spaces(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Windows paths legitimately contain spaces (``Program
        Files``); the validator must allow them since they're
        passed through argv list (no shell expansion)."""
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        assert portability.path_charset_check(
            "C:\\Program Files\\Python\\python.exe"
        )

    def test_rejects_colon_outside_drive_position(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even on Windows, a colon in any position other than
        the drive-letter slot would break -v parsing."""
        monkeypatch.setattr(portability, "IS_WINDOWS", True)
        assert not portability.path_charset_check(
            "C:\\Users\\file:name.txt"
        )


class TestPathCharsetCheckAlwaysRejects:
    """Chars rejected on EVERY OS."""

    def test_nul_byte(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for is_win in (False, True):
            monkeypatch.setattr(portability, "IS_WINDOWS", is_win)
            assert not portability.path_charset_check("/foo\x00bar")
            assert not portability.path_charset_check("C:\\foo\x00bar")

    def test_newline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for is_win in (False, True):
            monkeypatch.setattr(portability, "IS_WINDOWS", is_win)
            assert not portability.path_charset_check("/foo\nbar")

    def test_tab(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for is_win in (False, True):
            monkeypatch.setattr(portability, "IS_WINDOWS", is_win)
            assert not portability.path_charset_check("/foo\tbar")

    def test_empty_string(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert not portability.path_charset_check("")

    def test_non_string(self) -> None:
        assert not portability.path_charset_check(123)  # type: ignore[arg-type]
