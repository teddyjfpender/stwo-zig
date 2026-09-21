"""Seal retained degree5 Poseidon A/B tool-stream telemetry.

The retained stderr contains one canonical A/B record, three canonical
prepared-domain telemetry records, and an external process timing trailer.
No executable or proof artifact was retained, so the result is useful for
stage diagnosis and arm ordering only, never proof correctness or E2E claims.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.poseidon-degree5-retained-telemetry-evidence.v1"
STATUS = "tool-stream-stage-diagnostic-nonpromotable"
AB_SCHEMA = "stwo.riscv.poseidon-degree5-ab.v1"
TELEMETRY_SCHEMA = "stwo.riscv.poseidon-degree5-prepared-telemetry.v1"
PREFIX = (
    "benchmark-riscv-degree5-poseidon\n"
    "+- riscv test suite guard\n"
    "   +- run test stderr\n"
)
AB_KEYS = (
    "schema", "production", "log_size", "call_count", "engine_workers",
    "legacy_main_columns", "degree5_main_columns", "legacy_never",
    "degree5_never", "legacy_always", "degree5_always",
)
MEASUREMENT_KEYS = ("prove_ns", "verify_ns", "proof_bytes")
TELEMETRY_KEYS = (
    "schema", "arm", "prepare_ns", "layout_ns", "source_stage_ns",
    "twiddle_ns", "retained_extension_ns", "recomputed_extension_ns",
    "finalize_ns", "row_evaluation_ns", "source_columns",
    "borrowed_columns", "retained_columns", "recomputed_columns",
    "evaluated_rows",
)
ARMS = ("degree5_never_a", "degree5_never_b", "degree5_always")


class PoseidonD5TelemetryEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PoseidonD5TelemetryEvidenceError(message)


def _integer(value: Any, where: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _identity(path: Path, where: str, *, allow_empty: bool = False) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where)
    _require(allow_empty or raw, f"{where} is empty")
    return {"path": str(path), "bytes": len(raw),
            "sha256": protocol.sha256_bytes(raw)}


def _validate_identity(value: Any, where: str,
                       *, allow_empty: bool = False) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute()
             and value == _identity(Path(value["path"]), where,
                                    allow_empty=allow_empty),
             f"{where} identity differs")
    return value


def _measurement(value: Any, where: str) -> dict[str, int]:
    _require(type(value) is dict and tuple(value) == MEASUREMENT_KEYS,
             f"{where} keys differ")
    for field in MEASUREMENT_KEYS:
        _integer(value[field], f"{where} {field}", minimum=1)
    return value


def _parse(stderr_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = store.read_regular(
        stderr_path.absolute(), "degree5 retained stderr", maximum=64 * 1024,
    )
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise PoseidonD5TelemetryEvidenceError(
            "degree5 retained stderr is not ASCII",
        ) from error
    _require(text.startswith(PREFIX), "degree5 retained stderr prefix differs")
    lines = text[len(PREFIX):].splitlines()
    _require(len(lines) >= 4, "degree5 retained stderr records are absent")
    try:
        ab = json.loads(lines[0])
        telemetry = [json.loads(line) for line in lines[1:4]]
    except json.JSONDecodeError as error:
        raise PoseidonD5TelemetryEvidenceError(
            "degree5 retained telemetry JSON differs",
        ) from error
    for index, value in enumerate((ab, *telemetry)):
        expected = json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
        )
        _require(lines[index] == expected,
                 f"degree5 retained JSON record {index} is not canonical")
    _require(type(ab) is dict and tuple(ab) == AB_KEYS
             and ab["schema"] == AB_SCHEMA and ab["production"] is False,
             "degree5 A/B authority differs")
    for field in (
        "log_size", "call_count", "engine_workers", "legacy_main_columns",
        "degree5_main_columns",
    ):
        _integer(ab[field], f"degree5 A/B {field}", minimum=1)
    _require(
        ab["log_size"] == 16 and ab["call_count"] == 1 << 16
        and ab["engine_workers"] == 4
        and ab["legacy_main_columns"] == 445
        and ab["degree5_main_columns"] == 239
        and type(ab["legacy_never"]) is list and len(ab["legacy_never"]) == 2
        and type(ab["degree5_never"]) is list and len(ab["degree5_never"]) == 2,
        "degree5 A/B geometry/count differs",
    )
    for index, measurement in enumerate(ab["legacy_never"]):
        _measurement(measurement, f"legacy never {index}")
    for index, measurement in enumerate(ab["degree5_never"]):
        _measurement(measurement, f"degree5 never {index}")
    _measurement(ab["legacy_always"], "legacy always")
    _measurement(ab["degree5_always"], "degree5 always")
    _require(
        len({row["proof_bytes"] for row in ab["legacy_never"]
             + [ab["legacy_always"]]}) == 1
        and len({row["proof_bytes"] for row in ab["degree5_never"]
                 + [ab["degree5_always"]]}) == 1,
        "degree5 proof-byte arm parity differs",
    )
    for index, (row, arm) in enumerate(zip(telemetry, ARMS)):
        _require(type(row) is dict and tuple(row) == TELEMETRY_KEYS
                 and row["schema"] == TELEMETRY_SCHEMA and row["arm"] == arm,
                 f"degree5 telemetry row {index} authority differs")
        for field in TELEMETRY_KEYS[2:]:
            _integer(row[field], f"degree5 telemetry row {index} {field}")
        phase_sum = sum(row[field] for field in (
            "layout_ns", "source_stage_ns", "twiddle_ns",
            "retained_extension_ns", "recomputed_extension_ns", "finalize_ns",
        ))
        _require(
            row["prepare_ns"] == phase_sum
            and row["source_columns"] == 249
            and row["borrowed_columns"] == 0
            and row["retained_columns"] + row["recomputed_columns"] == 249
            and row["evaluated_rows"] == 1 << 18
            and row["row_evaluation_ns"] > row["prepare_ns"],
            f"degree5 telemetry row {index} closure differs",
        )
    _require(
        telemetry[0]["retained_columns"] == telemetry[1]["retained_columns"] == 0
        and telemetry[0]["recomputed_columns"]
        == telemetry[1]["recomputed_columns"] == 249
        and telemetry[2]["retained_columns"] == 249
        and telemetry[2]["recomputed_columns"] == 0,
        "degree5 retention telemetry differs",
    )
    return ab, telemetry


def _normalized(stderr_path: Path, stdout_path: Path) -> dict[str, Any]:
    ab, telemetry = _parse(stderr_path)
    stdout = _identity(stdout_path, "degree5 retained stdout", allow_empty=True)
    _require(stdout["bytes"] == 0, "degree5 retained stdout is not empty")
    try:
        timing_identity, timing = allocator_evidence._timing(stderr_path)
    except allocator_evidence.AllocatorExecutionEvidenceError as error:
        raise PoseidonD5TelemetryEvidenceError(str(error)) from error
    legacy_never_sum = sum(row["prove_ns"] for row in ab["legacy_never"])
    degree5_never_sum = sum(row["prove_ns"] for row in ab["degree5_never"])
    measured_arms = {
        "legacy_never": legacy_never_sum // len(ab["legacy_never"]),
        "degree5_never": degree5_never_sum // len(ab["degree5_never"]),
        "legacy_always": ab["legacy_always"]["prove_ns"],
        "degree5_always": ab["degree5_always"]["prove_ns"],
    }
    best_measured_arm = min(measured_arms, key=measured_arms.__getitem__)
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "stderr_time_log": timing_identity,
            "stdout_log": stdout,
        },
        "source_records": {
            "ab": copy.deepcopy(ab),
            "prepared_telemetry": copy.deepcopy(telemetry),
        },
        "stage_ranking": {
            "best_measured_arm": best_measured_arm,
            "legacy_never_prove_sum_ns": legacy_never_sum,
            "legacy_never_sample_count": 2,
            "degree5_never_prove_sum_ns": degree5_never_sum,
            "degree5_never_sample_count": 2,
            "legacy_always_prove_ns": ab["legacy_always"]["prove_ns"],
            "degree5_always_prove_ns": ab["degree5_always"]["prove_ns"],
            "degree5_never_faster_than_legacy_never": (
                degree5_never_sum < legacy_never_sum
            ),
            "degree5_retained_regresses_vs_legacy_retained": (
                ab["degree5_always"]["prove_ns"]
                > ab["legacy_always"]["prove_ns"]
            ),
            "row_evaluation_dominates_degree5_prepare": all(
                row["row_evaluation_ns"] > row["prepare_ns"]
                for row in telemetry
            ),
        },
        "process_measurement": timing,
        "claim_boundary": {
            "scope": "retained-tool-stream-stage-telemetry-only",
            "production_active": False,
            "executable_custody": None,
            "proof_artifacts_retained": False,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "performance_claim_eligible": False,
            "production_promotion_eligible": False,
        },
    })


def build(stderr_path: Path, stdout_path: Path) -> dict[str, Any]:
    return _normalized(stderr_path.absolute(), stdout_path.absolute())


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "source_records", "stage_ranking",
        "process_measurement", "claim_boundary", "content_sha256",
    }, "degree5 telemetry evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "degree5 telemetry evidence authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "stderr_time_log", "stdout_log",
    }, "degree5 telemetry evidence inputs differ")
    _validate_identity(inputs["stderr_time_log"], "degree5 stderr/time log")
    _validate_identity(inputs["stdout_log"], "degree5 stdout log", allow_empty=True)
    expected = build(
        Path(inputs["stderr_time_log"]["path"]),
        Path(inputs["stdout_log"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "degree5 telemetry evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "degree5 telemetry evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "degree5 telemetry evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--stderr-time-log", type=Path, required=True)
    create.add_argument("--stdout-log", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        output, staging = arguments.output.absolute(), arguments.staging_directory.absolute()
        store.require_directory(output.parent, "degree5 evidence parent")
        store.require_directory(staging, "degree5 evidence staging", create=True)
        value = build(arguments.stderr_time_log, arguments.stdout_log)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        PoseidonD5TelemetryEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
