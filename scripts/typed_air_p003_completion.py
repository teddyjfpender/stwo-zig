#!/usr/bin/env python3
"""Validate P-003 producer closure and emit fail-closed scaling blockers.

The sixteen-family matrix is the normative whole-prover authority.  The Zig
site inventory is a narrower executable ledger, so this gate independently
checks both and refuses to turn partial site coverage into a V4/scaling claim.
An admitted R-006 host is necessary but never sufficient: every CPU and Metal
family must also be complete before the existing R-006 capture tool may run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY = SCRIPT_DIR.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.typed_air_r006_capture_lib.codec import (  # noqa: E402
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    write_new,
)
from scripts.typed_air_r006_capture_lib.model import CaptureError  # noqa: E402
from scripts.typed_air_r006_capture_lib.preflight import (  # noqa: E402
    LEGACY_PREFLIGHT_SCHEMA,
    validate_host_preflight,
    validate_legacy_host_preflight,
)
from scripts.typed_air_work_profile_contract_lib import (  # noqa: E402
    FAMILY_IDS,
    MATRIX_PATH,
    MATRIX_SCHEMA,
    SCHEMA_VERSION,
    SITE_IDS,
    MatrixContractError,
    inventory_authority,
)
from scripts.typed_air_work_profile_contract_lib import (  # noqa: E402
    validate_matrix as validate_source_matrix,
)


BLOCKER_SCHEMA = "stwo.typed-air.p003-scaling-blocker-receipt.v1"
DEFAULT_MATRIX = REPOSITORY / MATRIX_PATH
BLOCKER_FIELDS = {
    "blockers",
    "captured_at_utc",
    "classification",
    "content_sha256",
    "coverage",
    "host_preflight",
    "inventory",
    "matrix",
    "scaling",
    "schema",
    "schema_version",
    "terminal_v4_seal_authorized",
}


class CompletionError(CaptureError):
    """The reviewed closure matrix or blocker receipt is malformed."""


def _load_json(path: Path, label: str) -> Any:
    try:
        return decode_strict(path.read_bytes())
    except (OSError, CaptureError) as error:
        raise CompletionError(f"cannot read {label} {path}: {error}") from error


def _inventory_authority(path: Path) -> dict[str, Any]:
    try:
        return inventory_authority(path)
    except MatrixContractError as error:
        raise CompletionError(str(error)) from error


def validate_matrix(path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    try:
        return validate_source_matrix(REPOSITORY, path)
    except MatrixContractError as error:
        raise CompletionError(str(error)) from error


def _relative_matrix_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPOSITORY.resolve()).as_posix()
    except ValueError as error:
        raise CompletionError("matrix must remain inside the repository") from error


def _coverage_blockers(coverage: dict[str, Any]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    for lane in ("cpu", "metal", "joint"):
        counts = coverage[lane]
        if counts["complete"] != coverage["family_count"]:
            blockers.append(
                {
                    "code": f"P003_{lane.upper()}_CLOSURE_INCOMPLETE",
                    "detail": (
                        f"{lane} closure is {counts['complete']} complete, "
                        f"{counts['partial']} partial, {counts['absent']} absent"
                    ),
                }
            )
    return blockers


def build_blocker_receipt(
    matrix_path: Path,
    host_preflight_value: Any,
) -> dict[str, Any]:
    report = validate_matrix(matrix_path)
    preflight = validate_host_preflight(host_preflight_value, require_admitted=False)
    return _build_blocker_receipt(matrix_path, report, preflight)


def _build_blocker_receipt(
    matrix_path: Path,
    report: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    blockers = _coverage_blockers(report["coverage"])
    if not preflight["admissible"]:
        blockers.append(
            {
                "code": "R006_HOST_PREFLIGHT_REJECTED",
                "detail": "; ".join(preflight["reasons"]),
            }
        )
    if not blockers:
        raise CompletionError(
            "P-003 closure and host are admitted; run the existing R-006 capture tool "
            "instead of emitting a blocker receipt"
        )
    result: dict[str, Any] = {
        "schema": BLOCKER_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "captured_at_utc": preflight["captured_at_utc"],
        "classification": "r006-scaling-capture-blocked",
        "matrix": {
            "path": _relative_matrix_path(matrix_path),
            "schema": MATRIX_SCHEMA,
            "sha256": report["matrix_sha256"],
        },
        "inventory": report["inventory"],
        "coverage": report["coverage"],
        "host_preflight": preflight,
        "terminal_v4_seal_authorized": False,
        "scaling": {
            "status": "blocked",
            "r006_scaling_receipt": None,
        },
        "blockers": blockers,
    }
    result["content_sha256"] = content_digest(result)
    return result


def validate_blocker_receipt(
    matrix_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    value = _load_json(receipt_path, "P-003 blocker receipt")
    receipt = exact_object(value, BLOCKER_FIELDS, "P-003 blocker receipt")
    if (
        receipt["schema"] != BLOCKER_SCHEMA
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["content_sha256"] != content_digest(receipt)
    ):
        raise CompletionError("P-003 blocker receipt authority changed")
    preflight_value = receipt["host_preflight"]
    if (
        type(preflight_value) is dict
        and preflight_value.get("schema") == LEGACY_PREFLIGHT_SCHEMA
    ):
        preflight = validate_legacy_host_preflight(preflight_value)
    else:
        preflight = validate_host_preflight(
            preflight_value, require_admitted=False
        )
    expected = _build_blocker_receipt(
        matrix_path, validate_matrix(matrix_path), preflight
    )
    if receipt != expected:
        raise CompletionError("P-003 blocker receipt differs from independent recomputation")
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-matrix")
    validate.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    validate.add_argument("--quiet", action="store_true")

    emit = commands.add_parser("emit-blocker")
    emit.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    emit.add_argument("--host-preflight", type=Path, required=True)
    emit.add_argument("--output", type=Path, required=True)

    replay = commands.add_parser("validate-blocker")
    replay.add_argument("receipt", type=Path)
    replay.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate-matrix":
            report = validate_matrix(args.matrix)
            if not args.quiet:
                print(canonical_bytes({
                    "schema": MATRIX_SCHEMA,
                    "matrix_sha256": report["matrix_sha256"],
                    "inventory": report["inventory"],
                    "coverage": report["coverage"],
                }).decode("ascii"), end="")
            return 0
        if args.command == "emit-blocker":
            preflight = _load_json(args.host_preflight, "R-006 host preflight")
            receipt = build_blocker_receipt(args.matrix, preflight)
            write_new(args.output, canonical_bytes(receipt))
            print(canonical_bytes(receipt).decode("ascii"), end="")
            return 2
        if args.command == "validate-blocker":
            receipt = validate_blocker_receipt(args.matrix, args.receipt)
            print(canonical_bytes({
                "schema": BLOCKER_SCHEMA,
                "status": "VALID_BLOCKER",
                "content_sha256": receipt["content_sha256"],
            }).decode("ascii"), end="")
            return 0
    except CaptureError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
