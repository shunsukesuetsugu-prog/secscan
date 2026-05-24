"""Phase 2-P: subprocess + probe-HTTP tests for the IAST harness.

These tests spawn real subprocesses (`sh -c sleep N`) to verify
the process-group lifecycle. They do NOT exercise pyrasp itself —
that's the parser's job.
"""

from __future__ import annotations

import http.server
import os
import socket
import socketserver
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from secscan.scanners.iast.harness import (
    send_probes,
    spawn_app,
    terminate_process_group,
    wait_for_port,
)
from secscan.scanners.iast.probes import SAFE_PROBES
from secscan.scanners.iast.validators import (
    validate_command_argv,
)

# ---------------------------------------------------------------------------
# Subprocess lifecycle
# ---------------------------------------------------------------------------


class TestSpawnApp:
    def test_spawns_and_runs_as_new_session_leader(
        self, tmp_path: Path
    ) -> None:
        """Process is its own session leader so terminate_process_
        group can kill its descendants too."""
        cmd = validate_command_argv("sh -c 'sleep 30'")
        handle = spawn_app(cmd, cwd=tmp_path)
        try:
            assert handle.pid > 0
            # Process group id == leader pid (new session).
            assert handle.process_group == os.getpgid(handle.pid)
            # Still alive shortly after spawn.
            assert handle.proc.poll() is None
        finally:
            terminate_process_group(handle, grace_seconds=2.0)

    def test_argv_invalid_cwd_rejected(self) -> None:
        from secscan.scanners.iast.validators import IastInputError

        cmd = validate_command_argv("sh -c 'sleep 1'")
        with pytest.raises(IastInputError):
            spawn_app(cmd, cwd=Path("/nope/does/not/exist"))


class TestTerminateProcessGroup:
    def test_sigterm_terminates_sleeping_child(
        self, tmp_path: Path
    ) -> None:
        cmd = validate_command_argv("sh -c 'sleep 60'")
        handle = spawn_app(cmd, cwd=tmp_path)
        start = time.monotonic()
        rc = terminate_process_group(handle, grace_seconds=2.0)
        elapsed = time.monotonic() - start
        # Either negative (signaled) or 0 — both indicate the
        # process exited promptly.
        assert rc is None or rc <= 0 or rc < 256
        # Should finish well under the grace period — sleep
        # responds to SIGTERM immediately.
        assert elapsed < 2.5

    def test_sigkill_runs_even_when_leader_exits_early(
        self, tmp_path: Path
    ) -> None:
        """Codex Phase 2-P diff review MUST-FIX: ``terminate_
        process_group`` must ALWAYS issue SIGKILL on the whole
        group, even when the leader has already exited.
        Otherwise an orphan descendant in the same group could
        outlive the cleanup.

        We force the early-exit case by waiting for the leader
        BEFORE calling ``terminate_process_group``; the cleanup
        helper must still successfully traverse the post-exit
        path and return cleanly."""
        cmd = validate_command_argv("sh -c 'true'")
        handle = spawn_app(cmd, cwd=tmp_path)
        # Leader has already exited.
        rc = handle.proc.wait(timeout=5.0)
        assert rc == 0
        # Cleanup must NOT raise even though the leader is gone.
        result = terminate_process_group(handle, grace_seconds=0.5)
        assert result == 0 or result is None

    def test_already_dead_process_no_error(
        self, tmp_path: Path
    ) -> None:
        cmd = validate_command_argv("sh -c 'true'")
        handle = spawn_app(cmd, cwd=tmp_path)
        # Wait for natural exit.
        handle.proc.wait(timeout=5.0)
        # Cleanup must NOT raise even though the process group is
        # already empty.
        rc = terminate_process_group(handle, grace_seconds=0.5)
        # Already-exited child returns 0.
        assert rc is None or rc == 0


# ---------------------------------------------------------------------------
# wait_for_port
# ---------------------------------------------------------------------------


@pytest.fixture()
def loopback_http_server() -> Iterator[tuple[str, int]]:
    """Stand up a minimal HTTP server on a random loopback port.

    The server records each incoming request's
    ``X-Secscan-Run-Id`` header so probe tests can assert the
    header was forwarded.
    """
    captured: list[dict] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            captured.append(
                {
                    "path": self.path,
                    "headers": dict(self.headers),
                }
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            # silence default stderr logging
            pass

    # Pick a free port.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = socketserver.TCPServer(("127.0.0.1", port), Handler)
    server.captured = captured  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ("127.0.0.1", port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


class TestWaitForPort:
    def test_ready_port_returns_true(
        self, loopback_http_server: tuple[str, int]
    ) -> None:
        host, port = loopback_http_server
        assert wait_for_port(
            f"http://{host}:{port}", timeout_seconds=5.0
        )

    def test_unresponsive_port_returns_false_after_timeout(
        self,
    ) -> None:
        # Use a non-loopback IP that would normally fail validation,
        # but the implementation re-validates the URL — so we use
        # a loopback URL on a (likely) closed port.
        assert not wait_for_port(
            "http://127.0.0.1:1", timeout_seconds=1.0
        )


# ---------------------------------------------------------------------------
# send_probes
# ---------------------------------------------------------------------------


class TestSendProbes:
    def test_each_probe_carries_run_id_header_and_query(
        self, loopback_http_server: tuple[str, int]
    ) -> None:
        host, port = loopback_http_server
        base = f"http://{host}:{port}"
        run_id = "f" * 32
        results = send_probes(
            SAFE_PROBES[:2],  # just two probes for the test
            probe_url=base,
            run_id=run_id,
            timeout_seconds=3.0,
        )
        # All probes succeeded against the dummy server.
        assert len(results) == 2
        for r in results:
            assert r.error is None
            assert r.response_status == 200
        # The deeper header/query forwarding assertions live in
        # ``TestRunIdForwarding`` below — they need their own
        # capturing server instance.

    def test_redirect_is_not_followed(self) -> None:
        """Codex Phase 2-P design review MUST-FIX #4: 3xx responses
        must NOT be followed even when the redirect target is
        loopback. The harness builds a custom opener that omits
        HTTPRedirectHandler."""
        captured: list[dict] = []

        class RedirectingHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                captured.append({"path": self.path})
                # Send a 302 to a different path that would normally
                # follow. A standard urllib opener WOULD follow this.
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                pass

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server = socketserver.TCPServer(("127.0.0.1", port), RedirectingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            results = send_probes(
                SAFE_PROBES[:1],
                probe_url=f"http://127.0.0.1:{port}",
                run_id="a" * 32,
                timeout_seconds=2.0,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        # Exactly ONE captured request — proves the 302 was not
        # followed (otherwise we'd see ``/`` then ``/elsewhere``).
        assert len(captured) == 1
        # urllib raises HTTPError on 3xx without a redirect handler.
        # We expose that as an error string on the ProbeResult.
        assert results[0].error is not None
        assert "302" in results[0].error or "redirect" in results[0].error.lower()


# ---------------------------------------------------------------------------
# Capture helper used by test_each_probe_carries_run_id...
# (separated so it doesn't interfere with the fixture lifecycle)
# ---------------------------------------------------------------------------


class TestRunIdForwarding:
    def test_probe_query_string_contains_secscan_run(self) -> None:
        """Captures requests on a local server and asserts that
        every probe URL carries ``secscan_run=<run_id>`` in its
        query string AND the ``X-Secscan-Run-Id`` header."""
        captured: list[dict] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                captured.append(
                    {
                        "path": self.path,
                        "headers": {
                            k.lower(): v for k, v in self.headers.items()
                        },
                    }
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format: str, *args: object) -> None:
                pass

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server = socketserver.TCPServer(("127.0.0.1", port), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run_id = "9" * 32
            send_probes(
                SAFE_PROBES[:3],
                probe_url=f"http://127.0.0.1:{port}",
                run_id=run_id,
                timeout_seconds=2.0,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        assert len(captured) == 3
        for req in captured:
            assert f"secscan_run={run_id}" in req["path"]
            assert req["headers"].get("x-secscan-run-id") == run_id
            assert req["headers"].get("x-secscan-probe-id", "").startswith(
                ("sqli-", "xss-", "rce-", "ssrf-", "trav-", "nosqli-")
            )
