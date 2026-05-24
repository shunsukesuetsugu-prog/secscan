"""argv construction tests for the docker invocation.

The structural assertions here guard the contract that Codex 2nd
review pinned for Phase 2-D:

- ``docker run <opts> -- <image> <cmd>`` so the image cannot be
  flag-interpreted (``--`` separator is mandatory and must precede
  the image).
- ``--cap-drop=ALL`` is always present.
- ``--network=bridge`` is the default; ``host`` is opt-in.
- The image reference is always validated at argv-build time.
"""

from __future__ import annotations

import pytest

from secscan.scanners.dast._pinned import DEFAULT_ZAP_IMAGE
from secscan.scanners.dast.zap import (
    DastInputError,
    ZapInvocation,
    build_argv,
)

_TARGET = "https://example.com/"
_DIGEST = "f" * 64
_IMAGE = f"zaproxy/zap-stable@sha256:{_DIGEST}"


def _invocation(**overrides: object) -> ZapInvocation:
    base: dict[str, object] = {
        "target_url": _TARGET,
        "image_ref": _IMAGE,
    }
    base.update(overrides)
    return ZapInvocation(**base)  # type: ignore[arg-type]


class TestBuildArgv:
    def test_base_shape(self) -> None:
        argv = build_argv(_invocation())
        assert argv[0] == "docker"
        assert argv[1] == "run"
        assert "--rm" in argv
        assert "--cap-drop=ALL" in argv
        assert "--network=bridge" in argv

    def test_separator_present_and_precedes_image(self) -> None:
        argv = build_argv(_invocation())
        sep = argv.index("--")
        image_idx = argv.index(_IMAGE)
        # The `--` separator must come immediately before the image so
        # docker cannot interpret the image as a flag.
        assert sep < image_idx
        assert argv[sep + 1] == _IMAGE

    def test_zap_baseline_command_after_image(self) -> None:
        argv = build_argv(_invocation())
        image_idx = argv.index(_IMAGE)
        assert argv[image_idx + 1] == "zap-baseline.py"

    def test_target_url_passed_with_t_flag(self) -> None:
        argv = build_argv(_invocation())
        # find the -t that's right before the URL
        # (the docker -t allocates a tty earlier in the argv; the URL
        # follows a `-t` after ``zap-baseline.py``)
        # Locate the ZAP-side `-t` by scanning the slice after the image.
        image_idx = argv.index(_IMAGE)
        zap_tail = argv[image_idx + 1 :]
        t_idx = zap_tail.index("-t")
        assert zap_tail[t_idx + 1] == _TARGET

    def test_report_arg_only_with_volume_or_dir(self) -> None:
        """Phase 2-H: ``-J report.json`` only appears when the
        invocation declares where the report should land (either
        a bind mount or a named volume). Without either, ZAP would
        refuse the report flag (``/zap/wrk`` unmounted), so the
        argv builder omits it."""
        # No mount declared → no ``-J`` flag.
        argv = build_argv(_invocation())
        assert "-J" not in argv

        # Named volume declared → ``-J report.json`` (relative to
        # the in-container /zap/wrk mount).
        argv_vol = build_argv(_invocation(report_volume="secscan-zap-abc"))
        j_idx = argv_vol.index("-J")
        assert argv_vol[j_idx + 1] == "report.json"
        # Old ``-J /dev/stdout`` pattern is gone — ZAP rejects it.
        assert "/dev/stdout" not in argv_vol

    def test_host_network_opt_in(self) -> None:
        argv_host = build_argv(_invocation(network_mode="host"))
        argv_default = build_argv(_invocation())
        assert "--network=host" in argv_host
        assert "--network=bridge" in argv_default
        assert "--network=host" not in argv_default

    def test_invalid_network_mode_rejected(self) -> None:
        with pytest.raises(DastInputError, match="network_mode"):
            build_argv(_invocation(network_mode="none"))

    def test_ajax_spider_adds_j_flag(self) -> None:
        argv = build_argv(_invocation(ajax_spider=True))
        assert "-j" in argv
        argv_without = build_argv(_invocation(ajax_spider=False))
        assert "-j" not in argv_without

    def test_config_file_propagated(self) -> None:
        argv = build_argv(_invocation(config_file="/zap/context.xml"))
        n_idx = argv.index("-n")
        assert argv[n_idx + 1] == "/zap/context.xml"

    def test_no_config_file_no_n_flag(self) -> None:
        argv = build_argv(_invocation(config_file=None))
        assert "-n" not in argv

    def test_image_validated_at_argv_build(self) -> None:
        """Even when callers construct ZapInvocation directly with an
        invalid image, build_argv must re-validate."""
        with pytest.raises(DastInputError):
            build_argv(_invocation(image_ref="-rm" + _IMAGE))

    def test_default_image_constant_is_validatable(self) -> None:
        """The pinned default in ``_pinned.py`` must satisfy the
        validator — otherwise the scanner would always reject the
        default before the operator could see the docker-pull error.
        """
        # Default has an all-zero digest by design; that's still
        # structurally valid even though it won't pull.
        argv = build_argv(_invocation(image_ref=DEFAULT_ZAP_IMAGE))
        assert DEFAULT_ZAP_IMAGE in argv

    def test_no_docker_socket_mount(self) -> None:
        """Defense in depth: the argv must never include a ``-v`` that
        binds the docker socket. (We don't add ``-v`` at all in MVP.)"""
        argv = build_argv(_invocation(config_file="/zap/context.xml"))
        # Make sure no positional flag maps /var/run/docker.sock to a
        # container path. We assert the broader property: no -v.
        assert "-v" not in argv

    def test_image_passed_via_separator_means_flag_lookalikes_safe(self) -> None:
        """Smoke: even with a digest that looks unusual, the image
        sits after the `--` separator so docker won't try to parse it.
        """
        weird_digest = "0123456789abcdef" * 4  # 64 hex chars
        weird_image = f"zaproxy/zap-stable@sha256:{weird_digest}"
        argv = build_argv(_invocation(image_ref=weird_image))
        sep_idx = argv.index("--")
        assert argv[sep_idx + 1] == weird_image
