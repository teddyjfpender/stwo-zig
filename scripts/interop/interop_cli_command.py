"""Compatibility facade for the canonical interop CLI command contract."""

from __future__ import annotations

try:
    from interop_cli_lib.command import build_command, installed_binary, run_command
except ModuleNotFoundError:
    from scripts.interop_cli_lib.command import build_command, installed_binary, run_command

__all__ = ("build_command", "installed_binary", "run_command")
