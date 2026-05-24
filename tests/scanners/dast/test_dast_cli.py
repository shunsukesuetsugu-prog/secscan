"""CLI integration tests for ``secscan dast`` and ``secscan all`` DAST gating.

We don't actually run docker. The tests check argument parsing,
the conditional inclusion of DastScanner in the registered instance
list (depending on whether a target is configured), and the
``--zap-image`` / ``--ajax-spider`` / ``--zap-network`` CLI overrides.
"""

from __future__ import annotations

import argparse

import pytest

from secscan import cli as cli_module
from secscan.config import DastConfig, ProjectConfig
from secscan.scanners.dast import DastScanner

_DIGEST = "2" * 64


def _config_with_target(target: str = "https://example.com/") -> ProjectConfig:
    return ProjectConfig(dast=DastConfig(target=target))


class TestBuildScannerInstances:
    def test_dast_excluded_when_no_target_and_not_dast_command(self) -> None:
        cfg = ProjectConfig()
        instances = cli_module._build_scanner_instances(cfg, command="all")
        names = [s.name for s in instances]
        assert "dast" not in names
        assert {"secrets", "deps", "sast"} <= set(names)

    def test_dast_included_when_target_configured(self) -> None:
        cfg = _config_with_target()
        instances = cli_module._build_scanner_instances(cfg, command="all")
        names = [s.name for s in instances]
        assert "dast" in names

    def test_dast_included_when_command_is_dast(self) -> None:
        cfg = ProjectConfig()
        instances = cli_module._build_scanner_instances(cfg, command="dast")
        names = [s.name for s in instances]
        # Even without a configured target, the dast subcommand
        # registers the scanner so its error path can surface the
        # missing-target message in the report.
        assert "dast" in names

    def test_dast_excluded_in_baseline_command_without_target(self) -> None:
        cfg = ProjectConfig()
        instances = cli_module._build_scanner_instances(cfg, command="baseline")
        names = [s.name for s in instances]
        assert "dast" not in names


class TestCliArgumentParsing:
    def test_dast_requires_target(self) -> None:
        parser = cli_module._build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["dast"])

    def test_dast_accepts_target_and_overrides(self) -> None:
        parser = cli_module._build_parser()
        args = parser.parse_args(
            [
                "dast",
                "--target",
                "https://example.com/",
                "--zap-image",
                f"zaproxy/zap-stable@sha256:{_DIGEST}",
                "--ajax-spider",
                "--zap-network",
                "host",
            ]
        )
        assert args.target == "https://example.com/"
        assert args.zap_image == f"zaproxy/zap-stable@sha256:{_DIGEST}"
        assert args.ajax_spider is True
        assert args.zap_network == "host"

    def test_dast_zap_config_file_arg(self) -> None:
        parser = cli_module._build_parser()
        args = parser.parse_args(
            ["dast", "--target", "https://example.com/", "--zap-config-file", "/zap/ctx.xml"]
        )
        assert args.zap_config_file == "/zap/ctx.xml"


class TestApplyCliOverrides:
    def test_target_override(self) -> None:
        args = argparse.Namespace(
            target="https://override.example.com/",
            zap_image=None,
            ajax_spider=False,
            zap_config_file=None,
            zap_network=None,
        )
        cfg = cli_module._apply_cli_overrides(ProjectConfig(), args)
        assert cfg.dast.target == "https://override.example.com/"

    def test_zap_image_override(self) -> None:
        image = f"zaproxy/zap-stable@sha256:{_DIGEST}"
        args = argparse.Namespace(
            target=None,
            zap_image=image,
            ajax_spider=False,
            zap_config_file=None,
            zap_network=None,
        )
        cfg = cli_module._apply_cli_overrides(ProjectConfig(), args)
        assert cfg.dast.image == image

    def test_ajax_spider_override(self) -> None:
        args = argparse.Namespace(
            target=None,
            zap_image=None,
            ajax_spider=True,
            zap_config_file=None,
            zap_network=None,
        )
        cfg = cli_module._apply_cli_overrides(ProjectConfig(), args)
        assert cfg.dast.ajax_spider is True

    def test_network_override_validation_at_config_layer(self) -> None:
        """``--zap-network`` is constrained by ``choices=`` in argparse,
        so the override path itself doesn't need to validate. But the
        argparse layer should reject anything outside the choice list."""
        parser = cli_module._build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                [
                    "dast",
                    "--target",
                    "https://example.com/",
                    "--zap-network",
                    "none",
                ]
            )

    def test_no_target_means_no_override(self) -> None:
        """When ``--target`` isn't on the namespace at all (running
        a non-dast subcommand), the config should be untouched."""
        args = argparse.Namespace()
        cfg = cli_module._apply_cli_overrides(ProjectConfig(), args)
        assert cfg.dast.target == ""


class TestRegisteredNames:
    def test_dast_in_registry(self) -> None:
        assert "dast" in cli_module._REGISTERED_NAMES

    def test_dast_class_in_all_scanners(self) -> None:
        assert DastScanner in cli_module.ALL_SCANNERS
