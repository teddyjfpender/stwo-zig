#!/usr/bin/env python3
"""Capture or check the reviewed formal node layout for AIR IR v2 programs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from .riscv_refinement_lib import air_program_layout, codec
except ImportError:
    from riscv_refinement_lib import air_program_layout, codec


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATED_AIR = "formal/riscv-refinement/generated/air"


def _git_revision(revision: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise air_program_layout.LayoutError(
            f"cannot resolve reviewed revision {revision!r}"
        ) from exc
    return result


def _reviewed_from_git(revision: str) -> tuple[str, dict[str, dict[str, Any]]]:
    resolved = _git_revision(revision)
    programs: dict[str, dict[str, Any]] = {}
    for mnemonic in air_program_layout.MNEMONICS:
        object_name = f"{resolved}:{GENERATED_AIR}/{mnemonic}.air-ir-v2.json"
        try:
            encoded = subprocess.run(
                ["git", "show", object_name],
                cwd=REPOSITORY_ROOT,
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
            payload = json.loads(encoded)
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise air_program_layout.LayoutError(
                f"cannot read reviewed AIR program {object_name}"
            ) from exc
        if not isinstance(payload, dict):
            raise air_program_layout.LayoutError(
                f"reviewed AIR program {object_name} is not an object"
            )
        programs[mnemonic] = payload
    return resolved, programs


def _candidate_inventory(directory: Path) -> dict[str, dict[str, Any]]:
    programs: dict[str, dict[str, Any]] = {}
    for mnemonic in air_program_layout.MNEMONICS:
        path = directory / f"{mnemonic}.unsigned.json"
        try:
            payload = codec.load_json(path)
        except (OSError, UnicodeError, ValueError) as exc:
            raise air_program_layout.LayoutError(
                f"cannot read candidate AIR program {path}"
            ) from exc
        if not isinstance(payload, dict):
            raise air_program_layout.LayoutError(
                f"candidate AIR program {path} is not an object"
            )
        programs[mnemonic] = payload
    expected = {
        f"{mnemonic}.unsigned.json" for mnemonic in air_program_layout.MNEMONICS
    }
    try:
        actual = {path.name for path in directory.iterdir()}
    except OSError as exc:
        raise air_program_layout.LayoutError(
            f"cannot enumerate candidate AIR directory {directory}"
        ) from exc
    if actual != expected:
        raise air_program_layout.LayoutError(
            "candidate AIR program directory has missing or extra artifacts"
        )
    return programs


def capture(revision: str, receipt_path: Path) -> str:
    resolved, programs = _reviewed_from_git(revision)
    receipt = air_program_layout.build_receipt(programs, resolved)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(codec.canonical_bytes(receipt))
    return (
        f"captured {len(programs)} reviewed AIR node layouts at {resolved}: "
        f"{receipt['canonical_digest']}"
    )


def check(candidate_dir: Path, receipt_path: Path) -> str:
    receipt = air_program_layout.load_receipt(receipt_path)
    candidates = _candidate_inventory(candidate_dir)
    normalized = air_program_layout.normalize_inventory(candidates, receipt)
    return (
        f"AIR node layout: {len(normalized)} typed programs normalize exactly "
        "to the reviewed unsigned formal inputs"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--revision", default="HEAD")
    capture_parser.add_argument(
        "--receipt",
        type=Path,
        default=REPOSITORY_ROOT / air_program_layout.RECEIPT_RELATIVE_PATH,
    )
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--candidate-dir", type=Path, required=True)
    check_parser.add_argument(
        "--receipt",
        type=Path,
        default=REPOSITORY_ROOT / air_program_layout.RECEIPT_RELATIVE_PATH,
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            print(capture(args.revision, args.receipt))
        else:
            print(check(args.candidate_dir, args.receipt))
    except air_program_layout.LayoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
