#!/usr/bin/env python3
"""Validate the static RISC-V registry, artifact, and CLI release contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from riscv_release_gate_lib.contract import (
        core_purity_errors,
        frontend_layering_errors,
        repository_contract_errors,
        structure_errors,
    )
except ModuleNotFoundError:  # Imported through the repository package in tests.
    from scripts.riscv_release_gate_lib.contract import (
        core_purity_errors,
        frontend_layering_errors,
        repository_contract_errors,
        structure_errors,
    )


ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--all", action="store_true", help="validate every static release surface")
    selector.add_argument("--structure", action="store_true", help="validate repository boundaries")
    selector.add_argument("--core-purity", action="store_true", help="validate the generic core boundary")
    selector.add_argument(
        "--frontend-layering",
        action="store_true",
        help="validate the backend-neutral RISC-V frontend boundary",
    )
    parser.add_argument("--phase", choices=("candidate", "promoted"), default="candidate")
    args = parser.parse_args(argv)
    if args.all:
        errors = repository_contract_errors(ROOT, args.phase) + structure_errors(ROOT)
        label = f"{args.phase} phase"
    elif args.structure:
        errors = structure_errors(ROOT)
        label = "repository structure"
    elif args.core_purity:
        errors = core_purity_errors(ROOT)
        label = "core purity"
    else:
        errors = frontend_layering_errors(ROOT)
        label = "RISC-V frontend layering"
    for error in errors:
        print(f"riscv release contract: {error}", file=sys.stderr)
    if not errors:
        print(f"riscv release contract: {label} is internally consistent")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
