"""Compatibility facade for the canonical interop CLI command contract."""

from __future__ import annotations
if __package__ in (None, ""):  # run as a file: make `scripts.*` importable
    __import__("sys").path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from scripts.interop.interop_cli_lib.command import build_command, installed_binary, run_command

__all__ = ("build_command", "installed_binary", "run_command")
