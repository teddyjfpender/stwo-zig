#!/usr/bin/env python3
"""Canonical build and one-shot commands for the Zig interop CLI."""

from __future__ import annotations

from pathlib import Path

from scripts.repo.zig_protocol_lib.command import aggregate_run_command


def installed_binary(root: Path) -> Path:
    return root / "zig-out" / "bin" / "interop_cli"


def build_command(optimize: str, cpu: str = "baseline") -> list[str]:
    command = ["zig", "build", "interop-cli", f"-Doptimize={optimize}"]
    if cpu != "baseline":
        command.append(f"-Dcpu={cpu}")
    return command


def run_command(*arguments: str) -> list[str]:
    return aggregate_run_command("src/products/native/tools/interop/main.zig", *arguments)
