#!/usr/bin/env python3
"""Inspect an archived CP-11 receipt; archived receipts always fail admission."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    from riscv_release_gate_lib.contract import receipt_errors
except ModuleNotFoundError:  # Imported as scripts.riscv_release_evidence in tests.
    from scripts.riscv_release_gate_lib.contract import receipt_errors


MAX_RECEIPT_BYTES = 64 * 1024 * 1024


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--candidate")
    candidate.add_argument("--candidate-head", action="store_true")
    parser.add_argument(
        "--at-receipt-time",
        action="store_true",
        help="validate immutable evidence at its recorded creation time",
    )
    args = parser.parse_args(argv)
    expected_candidate = args.candidate
    if args.candidate_head:
        expected_candidate = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
    try:
        if args.receipt.stat().st_size > MAX_RECEIPT_BYTES:
            raise ValueError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes")
        payload = json.loads(
            args.receipt.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (OSError, ValueError) as error:
        print(f"riscv release evidence: cannot read receipt: {error}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("riscv release evidence: receipt root must be an object", file=sys.stderr)
        return 1
    try:
        validation_time = None
        if args.at_receipt_time:
            created_at = payload.get("created_at_unix")
            if isinstance(created_at, bool) or not isinstance(created_at, int):
                raise ValueError("receipt created_at_unix is not an integer")
            validation_time = created_at
        errors = receipt_errors(payload, expected_candidate, now=validation_time)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"riscv release evidence: invalid evidence contract: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"riscv release evidence: {error}", file=sys.stderr)
    if not errors:
        print("riscv release evidence: oracle receipt is current, complete, and candidate-bound")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
