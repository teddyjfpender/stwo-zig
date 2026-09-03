"""Normalize retained Ethereum optimization diagnostics without promoting them."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from fractions import Fraction
from pathlib import Path
import json
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_zisk_final_evidence as zisk_evidence  # noqa: E402
import ethereum_block_corpus as corpus_protocol  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


EVIDENCE_SCHEMA = "stwo.ethereum.optimization-input-evidence.v1"
GEOMETRY_SCHEMA = "stwo.ethereum.poseidon-v4-leaf-pre-engine-geometry.v1"
CALL_ARTIFACT_SCHEMA = "stwo.ethereum.poseidon-provider-call-artifact.v1"
TRIAL_CAP_NS = 120_000_000_000
TIME_LINE = re.compile(r"^(real|user|sys) ([0-9]+(?:\.[0-9]+)?)$", re.MULTILINE)
WORKLOAD_FAMILIES = ("load_store", "base_alu_imm", "branch_lt", "branch_eq")


class OptimizationEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OptimizationEvidenceError(message)


def _read_json(path: Path, where: str) -> dict[str, Any]:
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict, f"{where} must be an object")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    path = Path(value["path"])
    _require(path.is_absolute(), f"{where}.path differs")
    store.validate_file_identity(path, {
        "bytes": value["bytes"], "sha256": value["sha256"],
    }, where)
    return value


def _zig_content(path: Path, value: dict[str, Any], schema: str,
                 where: str) -> None:
    """Validate the producer's prefix seal, including its canonical LF."""
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    canonical = (json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    _require(raw == canonical and value.get("schema") == schema,
             f"{where} canonical transport differs")
    prefix = b'{"content_sha256":"'
    end = len(prefix) + 64
    _require(raw.startswith(prefix) and len(raw) > end + 1
             and raw[end:end + 2] == b'",',
             f"{where} content authority differs")
    expected = raw[len(prefix):end].decode("ascii")
    _require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None
             and value.get("content_sha256") == expected,
             f"{where} content authority differs")
    unsigned = b"{" + raw[end + 2:]
    _require(protocol.sha256_bytes(unsigned) == expected,
             f"{where} content authority differs")


def _seconds_ns(value: str, where: str) -> int:
    try:
        scaled = Decimal(value) * Decimal(1_000_000_000)
    except InvalidOperation as error:
        raise OptimizationEvidenceError(f"{where} differs") from error
    _require(scaled >= 0 and scaled == scaled.to_integral_value(), f"{where} differs")
    return int(scaled)


def _rusage(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path, "failed prove timing", maximum=1024 * 1024)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise OptimizationEvidenceError("failed prove timing is not UTF-8") from error
    timing = TIME_LINE.findall(text)
    _require(len(timing) == 3 and [item[0] for item in timing]
             == ["real", "user", "sys"], "failed prove timing lines differ")

    def field(label: str) -> int:
        found = re.findall(rf"^\s*([0-9]+)  {re.escape(label)}$", text, re.MULTILINE)
        _require(len(found) == 1, f"failed prove {label} differs")
        return int(found[0])

    errors = [line for line in text.splitlines() if line.startswith("error: ")]
    _require(len(errors) == 1, "failed prove error classification differs")
    result = {
        "error": errors[0][7:],
        "timing": {
            "wall_ns": _seconds_ns(timing[0][1], "failed prove wall"),
            "user_ns": _seconds_ns(timing[1][1], "failed prove user"),
            "system_ns": _seconds_ns(timing[2][1], "failed prove system"),
        },
        "maximum_resident_set_bytes": field("maximum resident set size"),
        "peak_memory_footprint_bytes": field("peak memory footprint"),
        "swaps": field("swaps"),
    }
    result["within_trial_cap"] = result["timing"]["wall_ns"] <= TRIAL_CAP_NS
    return result


def _rounded_ratio(numerator: int, denominator: int, *, scale: int,
                   places: int) -> str:
    quantum = Decimal(1).scaleb(-places)
    value = Decimal(numerator) * Decimal(scale) / Decimal(denominator)
    return format(value.quantize(quantum, rounding=ROUND_HALF_UP), f".{places}f")


def _corpus_workload(bundle: Path) -> dict[str, Any]:
    """Recompute workload facts from the retained, hash-chained execution journal."""
    bundle = bundle.absolute()
    store.require_directory(bundle, "execution capture bundle")
    plan_path = bundle / "plan.json"
    journal_path = bundle / "execution.ndjson"
    receipt_path = bundle / "receipt.json"
    receipt = segmented.validate_bundle(bundle)
    plan = _read_json(plan_path, "execution capture plan")
    journal_raw = store.read_regular(
        journal_path, "execution capture journal",
        maximum=segmented.MAX_JOURNAL_BYTES,
    )
    records = [json.loads(line)["payload"]
               for line in journal_raw.splitlines(keepends=True)]
    segments = records[1:-1]
    summary = records[-1]
    fixture = corpus_protocol.load()["fixtures"][0]
    stwo_input = fixture["semantic_io"]["guest_transports"]["stwo_input"]
    stwo_output = fixture["semantic_io"]["guest_transports"]["stwo_output"]
    plan_input = plan.get("input")
    _require(plan.get("execution_profile") == "rv32im-zkvm-ethereum-v1"
             and type(plan_input) is dict
             and plan_input.get("bytes") == stwo_input["bytes"]
             and plan_input.get("sha256") == stwo_input["sha256"]
             and receipt.get("output_sha256") == stwo_output["sha256"],
             "optimization corpus fixture binding differs")
    _require(len(segments) == receipt["segment_count"] == 210,
             "optimization corpus segment count differs")
    _require(sum(value["cycle_count"] for value in segments)
             == receipt["total_cycles"] == 880_760_229,
             "optimization corpus cycle count differs")
    inclusions = sum(
        value["entry"]["rw_memory_nonzero_words"]
        + value["exit"]["rw_memory_nonzero_words"]
        for value in segments
    )
    touched = sum(
        value["exit"]["memory_access_clock_entries"] for value in segments
    )
    _require(all(value["entry"]["memory_access_clock_entries"] == 0
                 for value in segments),
             "optimization corpus leaf-local clock reset differs")
    _require(inclusions == 898_968_604 and touched == 6_541_934,
             "optimization corpus memory workload differs")
    family_rows = {value["family"]: value["rows"]
                   for value in summary["opcode_family_rows"]}
    mix = {}
    for family in WORKLOAD_FAMILIES:
        rows = family_rows[family]
        mix[family] = {
            "rows": rows,
            "share": {
                "numerator": rows,
                "denominator": receipt["total_core_trace_rows"],
            },
            "percent_rounded_3dp": _rounded_ratio(
                rows, receipt["total_core_trace_rows"], scale=100, places=3,
            ),
        }
    _require({family: mix[family]["percent_rounded_3dp"]
              for family in WORKLOAD_FAMILIES} == {
                  "load_store": "31.817",
                  "base_alu_imm": "28.400",
                  "branch_lt": "12.948",
                  "branch_eq": "12.774",
              }, "optimization corpus opcode mix differs")
    return {
        "claim_boundary": "execution-workload-diagnostic-not-a-proof",
        "bundle": {
            "plan": _identity(plan_path, "execution capture plan"),
            "journal": _identity(journal_path, "execution capture journal"),
            "receipt": _identity(receipt_path, "execution capture receipt"),
        },
        "execution_profile": "rv32im-zkvm-ethereum-v1",
        "fixture": {
            "fixture_id": fixture["fixture_id"],
            "chain_id": fixture["block"]["chain_id"],
            "block_number": fixture["block"]["number"],
            "stwo_input": stwo_input,
            "stwo_output": stwo_output,
        },
        "segment_count": len(segments),
        "total_cycles": receipt["total_cycles"],
        "total_core_trace_rows": receipt["total_core_trace_rows"],
        "total_external_trace_rows": receipt["total_external_trace_rows"],
        "entry_exit_nonzero_word_inclusions": inclusions,
        "touched_transitions": touched,
        "boundary_to_touched_amplification": {
            "numerator": inclusions,
            "denominator": touched,
            "multiple_rounded_4dp": _rounded_ratio(
                inclusions, touched, scale=1, places=4,
            ),
        },
        "opcode_mix": mix,
        "production_promotion_eligible": False,
    }


def _geometry(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _read_json(path, "segment geometry")
    _zig_content(path, value, GEOMETRY_SCHEMA, "segment geometry")
    _require(value.get("status") == "diagnostic-nonpromotable"
             and value.get("segment_index") == 0
             and value.get("engine_initialized") is False
             and value.get("proof_started") is False
             and value.get("recursive_admissible") is False,
             "segment geometry claim boundary differs")
    legacy = value["legacy_poseidon"]
    _require(type(legacy) is dict and legacy.get("main_column_count") == 445
             and legacy.get("log_size") == 24 and legacy.get("n_rows") > 0,
             "segment geometry legacy provider differs")
    candidates = {}
    for name, profile in (("degree5", value["candidate_degree5"]),
                          ("degree6", value["candidate_degree6"])):
        residency = profile["residency"]
        candidates[name] = {
            "candidate_identity_sha256": profile["candidate_identity_sha256"],
            "main_columns": profile["geometry"]["main_columns"],
            "maximum_constraint_degree": profile["geometry"][
                "maximum_constraint_degree"
            ],
            "staged_peak_lower_bound_bytes": residency[
                "staged_peak_lower_bound_bytes"
            ],
            "retention_policy": residency["retention_policy"],
        }
    return value, {
        "identity": _identity(path, "segment geometry"),
        "content_sha256": value["content_sha256"],
        "segment_index": 0,
        "legacy_poseidon": {
            "main_column_count": legacy["main_column_count"],
            "log_size": legacy["log_size"],
            "n_rows": legacy["n_rows"],
        },
        "candidates": candidates,
        "production_eligible": False,
    }


def _calls(
    path: Path, geometry: dict[str, Any], geometry_projection: dict[str, Any],
) -> dict[str, Any]:
    value = _read_json(path, "provider call artifact")
    _zig_content(path, value, CALL_ARTIFACT_SCHEMA, "provider call artifact")
    _require(value.get("status") == "authenticated-call-custody-nonproduction"
             and value.get("segment_index") == 0
             and value.get("ordered_calls_air_bound") is False
             and value.get("production_eligible") is False
             and value.get("recursive_admissible") is False,
             "provider call claim boundary differs")
    geometry_identity = value["geometry_snapshot"]
    _require(geometry_identity["sha256"] == geometry_projection["identity"]["sha256"]
             and value["geometry_snapshot_content_sha256"]
             == geometry["content_sha256"],
             "provider call geometry binding differs")
    calls = value["calls"]
    _validate_identity(calls, "provider call list")
    _require(value["call_count"] == geometry["legacy_poseidon"]["n_rows"],
             "provider call count differs from geometry")
    return {
        "identity": _identity(path, "provider call artifact"),
        "content_sha256": value["content_sha256"],
        "calls": calls,
        "call_count": value["call_count"],
        "call_list_commitment_sha256": value["call_list_commitment_sha256"],
        "ordered_calls_air_bound": False,
        "production_eligible": False,
    }


def extract(
    geometry_path: Path, call_artifact_path: Path, failed_prove_timing: Path,
    clean_zisk_receipt: Path, execution_bundle: Path,
) -> dict[str, Any]:
    geometry, geometry_projection = _geometry(geometry_path.absolute())
    calls = _calls(call_artifact_path.absolute(), geometry, geometry_projection)
    failed = _rusage(failed_prove_timing.absolute())
    zisk = zisk_evidence.evidence(clean_zisk_receipt.absolute())
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "diagnostic-inputs-replayed-nonpromotable",
        "segment_geometry": geometry_projection,
        "provider_calls": calls,
        "failed_combined_prove": {
            "identity": _identity(failed_prove_timing, "failed prove timing"),
            **failed,
            "correctness_passed": False,
            "ranking_eligible": False,
        },
        "corpus_workload": _corpus_workload(execution_bundle),
        "zisk_peer": zisk,
        "optimization_boundary": {
            "per_trial_cap_ns": TRIAL_CAP_NS,
            "legacy_failed_attempt_is_a_ranked_trial": False,
            "geometry_is_a_measurement": False,
            "call_capture_is_a_proof": False,
            "zisk_is_the_stwo_optimization_baseline": False,
            "production_promotion_eligible": False,
        },
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "segment_geometry", "provider_calls",
        "failed_combined_prove", "corpus_workload", "zisk_peer",
        "optimization_boundary", "content_sha256",
    }, "optimization input evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "optimization input evidence identity differs")
    paths = (
        Path(value["segment_geometry"]["identity"]["path"]),
        Path(value["provider_calls"]["identity"]["path"]),
        Path(value["failed_combined_prove"]["identity"]["path"]),
        Path(value["zisk_peer"]["receipt"]["path"]),
        Path(value["corpus_workload"]["bundle"]["receipt"]["path"]).parent,
    )
    _require(value == extract(*paths), "optimization input evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "optimization input evidence",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "optimization input evidence is not canonical JSON")
    return validate(value)


def normalize_microbench(
    *, family: str, source_result: Path, configuration_sha256: str,
    correctness_passed: bool, fresh_verification: bool, work_unit: str,
    work_count: int, wall_ns: int, peak_rss_bytes: int,
    estimated_e2e_wall_ns: int | None,
) -> dict[str, Any]:
    """Normalize a producer-validated microbench result after its adapter checks it."""
    _require(family in ("provider", "precompile"), "microbench family differs")
    _require(type(configuration_sha256) is str
             and re.fullmatch(r"[0-9a-f]{64}", configuration_sha256) is not None,
             "microbench configuration identity differs")
    _require(type(work_unit) is str and work_unit
             and type(work_count) is int and work_count > 0
             and type(wall_ns) is int and 0 < wall_ns <= TRIAL_CAP_NS
             and type(peak_rss_bytes) is int and peak_rss_bytes > 0,
             "microbench measurement differs")
    _require(estimated_e2e_wall_ns is None
             or type(estimated_e2e_wall_ns) is int and estimated_e2e_wall_ns > 0,
             "microbench E2E estimate differs")
    eligible = correctness_passed is True and fresh_verification is True
    return protocol.seal({
        "schema": "stwo.ethereum.optimization-microbench-observation.v1",
        "family": family,
        "source_result": _identity(source_result, f"{family} microbench result"),
        "configuration_sha256": configuration_sha256,
        "correctness_passed": correctness_passed,
        "fresh_verification": fresh_verification,
        "work": {"unit": work_unit, "count": work_count},
        "timing": {"wall_ns": wall_ns},
        "throughput": {"numerator": work_count * 1_000_000_000,
                       "denominator": wall_ns},
        "peak_rss_bytes": peak_rss_bytes,
        "estimated_e2e_wall_ns": estimated_e2e_wall_ns,
        "ranking_eligible": eligible,
        "promotion_eligible": False,
    })


def rank_microbenches(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    eligible = [value for value in values if value.get("ranking_eligible") is True]
    _require(len({value["configuration_sha256"] for value in eligible}) == len(eligible),
             "microbench ranking contains duplicate configurations")
    return sorted(eligible, key=lambda value: (
        value["estimated_e2e_wall_ns"] is None,
        value["estimated_e2e_wall_ns"] or 0,
        value["peak_rss_bytes"],
        -Fraction(value["throughput"]["numerator"],
                  value["throughput"]["denominator"]),
        value["configuration_sha256"],
    ))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--geometry", type=Path, required=True)
    create.add_argument("--call-artifact", type=Path, required=True)
    create.add_argument("--failed-prove-timing", type=Path, required=True)
    create.add_argument("--clean-zisk-receipt", type=Path, required=True)
    create.add_argument("--execution-bundle", type=Path, required=True)
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
        value = extract(
            arguments.geometry, arguments.call_artifact,
            arguments.failed_prove_timing, arguments.clean_zisk_receipt,
            arguments.execution_bundle,
        )
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "optimization evidence parent")
        store.require_directory(staging, "optimization evidence staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        OptimizationEvidenceError, zisk_evidence.ZiskFinalEvidenceError,
        protocol.ProofProtocolError, segmented.ContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
