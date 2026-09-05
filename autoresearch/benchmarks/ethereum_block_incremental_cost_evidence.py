"""Capture and replay the compact-tape incremental memory cost diagnostic."""

from __future__ import annotations

import argparse
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

from scripts import ethereum_block_proof_process as child_process  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.incremental-memory-cost-evidence.v1"
RANKING_SCHEMA_V1 = "stwo.ethereum.optimization-geometry-ranking.v1"
RANKING_SCHEMA = "stwo.ethereum.optimization-geometry-ranking.v2"
CLAIM_BOUNDARY = "geometry-cost-diagnostic-not-a-proof"
MAX_TRIAL_SECONDS = 120
MAX_OUTPUT_BYTES = 1024 * 1024
POLL_SECONDS = 0.01
OUTPUT_KEYS = {
    "segment_index", "touched_words", "changed_words", "changed_bytes",
    "entry_hash_calls", "exit_hash_calls", "total_hash_calls",
    "provider_log_size", "path",
}
REFERENCE_65 = {
    "segment_count": 65,
    "touched_words": 3_525_764,
    "changed_words": 1_404_655,
    "changed_bytes": 5_181_423,
    "entry_hash_calls": 14_697_863,
    "exit_hash_calls": 5_665_139,
    "total_hash_calls": 20_363_002,
    "median_total_hash_calls": 140_705,
    "padded_rows_sum": 30_875_648,
    "provider_log_histogram": [
        {"log_size": 13, "segment_count": 1},
        {"log_size": 15, "segment_count": 2},
        {"log_size": 16, "segment_count": 2},
        {"log_size": 17, "segment_count": 20},
        {"log_size": 18, "segment_count": 27},
        {"log_size": 19, "segment_count": 6},
        {"log_size": 20, "segment_count": 5},
        {"log_size": 22, "segment_count": 1},
        {"log_size": 23, "segment_count": 1},
    ],
}


class IncrementalCostEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IncrementalCostEvidenceError(message)


def _identity(path: Path, where: str, *, allow_empty: bool = False) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where)
    _require(allow_empty or len(raw) > 0, f"{where} is empty")
    return {
        "path": str(path), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_identity(value: Any, where: str, *,
                       allow_empty: bool = False) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    path = Path(value["path"])
    _require(path.is_absolute() and value == _identity(
        path, where, allow_empty=allow_empty,
    ), f"{where} identity differs")
    return value


def _canonical_output(line: bytes, where: str) -> dict[str, Any]:
    _require(line.endswith(b"\n"), f"{where} framing differs")
    value = store.decode_strict(line)
    _require(type(value) is dict and set(value) == OUTPUT_KEYS,
             f"{where} keys differ")
    encoded = (json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    _require(line == encoded, f"{where} is not canonical JSON")
    return value


def _positive(value: Any, where: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _records(stderr: bytes, tapes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lines = stderr.splitlines(keepends=True)
    _require(len(lines) == len(tapes) and len(lines) > 0,
             "incremental cost output count differs")
    result = []
    for index, (line, tape) in enumerate(zip(lines, tapes, strict=True)):
        value = _canonical_output(line, f"incremental cost output {index}")
        _require(value["segment_index"] == index
                 and value["path"] == tape["path"],
                 "incremental cost output order differs")
        for field in (
            "touched_words", "changed_words", "changed_bytes",
            "entry_hash_calls", "exit_hash_calls", "total_hash_calls",
        ):
            _positive(value[field], f"incremental cost {field}", allow_zero=True)
        _require(value["changed_words"] <= value["touched_words"]
                 and value["changed_bytes"] <= value["changed_words"] * 4
                 and value["total_hash_calls"]
                 == value["entry_hash_calls"] + value["exit_hash_calls"],
                 "incremental cost row does not close")
        expected_log = (max(4, (value["total_hash_calls"] - 1).bit_length())
                        if value["total_hash_calls"] else 0)
        _require(value["provider_log_size"] == expected_log,
                 "incremental cost provider log differs")
        result.append(value)
    return result


def _rounded_percent(numerator: int, denominator: int) -> str:
    value = Decimal(numerator) * Decimal(100) / Decimal(denominator)
    return format(value.quantize(Decimal("0.00001"), rounding=ROUND_HALF_UP), ".5f")


def _aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        field: sum(record[field] for record in records)
        for field in (
            "touched_words", "changed_words", "changed_bytes",
            "entry_hash_calls", "exit_hash_calls", "total_hash_calls",
        )
    }
    sorted_calls = sorted(record["total_hash_calls"] for record in records)
    _require(len(sorted_calls) % 2 == 1, "incremental cost median is not singular")
    histogram: dict[int, int] = {}
    for record in records:
        log_size = record["provider_log_size"]
        histogram[log_size] = histogram.get(log_size, 0) + 1
    padded_rows = sum(
        0 if record["provider_log_size"] == 0
        else 1 << record["provider_log_size"]
        for record in records
    )
    return {
        "segment_count": len(records),
        **totals,
        "median_total_hash_calls": sorted_calls[len(sorted_calls) // 2],
        "provider_log_histogram": [
            {"log_size": log_size, "segment_count": histogram[log_size]}
            for log_size in sorted(histogram)
        ],
        "padded_rows_sum": padded_rows,
    }


def _models(aggregate: dict[str, Any]) -> dict[str, Any]:
    count = aggregate["segment_count"]
    padded = aggregate["padded_rows_sum"]
    fixed_cells = count * (1 << 24) * 445
    degree6_cells = padded * 161
    legacy_incremental_cells = padded * 445

    def reduction(candidate: int) -> dict[str, Any]:
        return {
            "baseline_cells": fixed_cells,
            "candidate_cells": candidate,
            "reduction": {
                "numerator": fixed_cells - candidate,
                "denominator": fixed_cells,
                "percent_rounded_5dp": _rounded_percent(
                    fixed_cells - candidate, fixed_cells,
                ),
            },
        }

    return {
        "model_boundary": "column-cell-geometry-only-no-proof-timing-model",
        "fixed_legacy_445_log24": {"cells": fixed_cells},
        "degree6_161_incremental": reduction(degree6_cells),
        "legacy_445_incremental": reduction(legacy_incremental_cells),
        "estimated_end_to_end_wall_ns": None,
    }


def _reference_admitted(aggregate: dict[str, Any], records: list[dict[str, Any]]) -> bool:
    return aggregate == REFERENCE_65 and records[0] == {
        "segment_index": 0,
        "touched_words": 725_948,
        "changed_words": 363_382,
        "changed_bytes": 1_421_678,
        "entry_hash_calls": 2_903_950,
        "exit_hash_calls": 1_446_591,
        "total_hash_calls": 4_350_541,
        "provider_log_size": 23,
        "path": records[0]["path"],
    }


def _run(argv: list[str], staging: Path, timeout_seconds: int) -> tuple[bytes, bytes, dict[str, Any]]:
    _require(type(timeout_seconds) is int and 0 < timeout_seconds <= MAX_TRIAL_SECONDS,
             "incremental cost timeout differs")
    stdout = tempfile.TemporaryFile(prefix="incremental.stdout.", dir=staging)
    stderr = tempfile.TemporaryFile(prefix="incremental.stderr.", dir=staging)
    started = time.monotonic_ns()
    try:
        child = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            start_new_session=True,
        )
    except OSError as error:
        stdout.close()
        stderr.close()
        raise IncrementalCostEvidenceError(
            "incremental cost tool failed to launch"
        ) from error
    deadline = time.monotonic() + timeout_seconds
    outcome = None
    failure = None
    while outcome is None:
        outcome = child_process._wait4_nohang(child)
        if outcome is not None:
            break
        if max(os.fstat(stdout.fileno()).st_size,
               os.fstat(stderr.fileno()).st_size) > MAX_OUTPUT_BYTES:
            failure = "incremental cost output exceeded its bound"
            break
        if time.monotonic() >= deadline:
            failure = "incremental cost tool timed out"
            break
        time.sleep(POLL_SECONDS)
    if failure is not None:
        child_process._terminate_group(child)
        stdout.close()
        stderr.close()
        raise IncrementalCostEvidenceError(failure)
    _require(outcome is not None, "incremental cost wait differs")
    return_code, usage = outcome
    clean_group = child_process.drain_process_group(child, "incremental cost")
    ended = time.monotonic_ns()
    stdout.seek(0)
    stderr.seek(0)
    stdout_raw = stdout.read(MAX_OUTPUT_BYTES + 1)
    stderr_raw = stderr.read(MAX_OUTPUT_BYTES + 1)
    stdout.close()
    stderr.close()
    _require(clean_group and return_code == 0
             and len(stdout_raw) <= MAX_OUTPUT_BYTES
             and len(stderr_raw) <= MAX_OUTPUT_BYTES,
             "incremental cost process did not complete cleanly")
    max_rss = round(usage.ru_maxrss)
    max_rss_bytes = max_rss if sys.platform == "darwin" else max_rss * 1024
    return stdout_raw, stderr_raw, {
        "exit_code": return_code,
        "timeout_seconds": timeout_seconds,
        "timing": {
            "wall_ns": ended - started,
            "user_ns": max(0, round(usage.ru_utime * 1_000_000_000)),
            "system_ns": max(0, round(usage.ru_stime * 1_000_000_000)),
        },
        "maximum_resident_set_bytes": max_rss_bytes,
        "maximum_resident_set_source": (
            "darwin-wait4-ru_maxrss-bytes" if sys.platform == "darwin"
            else "wait4-ru_maxrss-kib-normalized-to-bytes"
        ),
        "process_group_drained": True,
    }


def capture(
    *, tool: Path, tool_source: Path, tape_directory: Path,
    segment_count: int, timeout_seconds: int, output: Path, staging: Path,
) -> dict[str, Any]:
    tool = tool.absolute()
    tool_source = tool_source.absolute()
    tape_directory = tape_directory.absolute()
    output = output.absolute()
    staging = staging.absolute()
    _require(os.access(tool, os.X_OK), "incremental cost tool is not executable")
    store.require_directory(tape_directory, "incremental cost tape directory")
    store.require_directory(output.parent, "incremental cost evidence parent")
    store.require_directory(staging, "incremental cost staging", create=True)
    _positive(segment_count, "incremental cost segment count")
    tapes = []
    for index in range(segment_count):
        path = tape_directory / f"segment-{index:06d}.stwemt01"
        tapes.append(_identity(path, f"incremental cost tape {index}"))
    argv = [str(tool), *(tape["path"] for tape in tapes)]
    stdout_raw, stderr_raw, process = _run(argv, staging, timeout_seconds)
    _require(stdout_raw == b"", "incremental cost stdout is not empty")
    records = _records(stderr_raw, tapes)
    aggregate = _aggregate(records)
    stdout_path = output.with_name(f"{output.stem}.stdout")
    stderr_path = output.with_name(f"{output.stem}.stderr")
    store.publish_new_or_identical(stdout_path, stdout_raw, staging_directory=staging)
    store.publish_new_or_identical(stderr_path, stderr_raw, staging_directory=staging)
    reference = _reference_admitted(aggregate, records)
    value = protocol.seal({
        "schema": SCHEMA,
        "status": "captured-geometry-diagnostic-only",
        "claim_boundary": CLAIM_BOUNDARY,
        "tool": _identity(tool, "incremental cost tool"),
        "tool_source": _identity(tool_source, "incremental cost tool source"),
        "argv": argv,
        "tapes": tapes,
        "transport": {
            "stdout": _identity(stdout_path, "incremental cost stdout", allow_empty=True),
            "stderr": _identity(stderr_path, "incremental cost stderr"),
        },
        "process": process,
        "aggregate": aggregate,
        "segment0": records[0],
        "models": _models(aggregate),
        "ranking": {
            "scope": "geometry-cost-model-only",
            "reference_65_admitted": reference,
            "diagnostic_eligible": process["timing"]["wall_ns"]
            <= MAX_TRIAL_SECONDS * 1_000_000_000,
            "proof_correctness": None,
            "fresh_verification": None,
            "production_promotion_eligible": False,
        },
    })
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "claim_boundary", "tool", "tool_source", "argv",
        "tapes", "transport", "process", "aggregate", "segment0", "models",
        "ranking", "content_sha256",
    }, "incremental cost evidence keys differ")
    _require(value["schema"] == SCHEMA
             and value["status"] == "captured-geometry-diagnostic-only"
             and value["claim_boundary"] == CLAIM_BOUNDARY
             and value["content_sha256"] == protocol.content_sha256(value),
             "incremental cost evidence authority differs")
    _validate_identity(value["tool"], "incremental cost tool")
    _validate_identity(value["tool_source"], "incremental cost tool source")
    _require(os.access(value["tool"]["path"], os.X_OK),
             "incremental cost tool is not executable")
    tapes = value["tapes"]
    _require(type(tapes) is list and tapes, "incremental cost tapes differ")
    for index, tape in enumerate(tapes):
        _validate_identity(tape, f"incremental cost tape {index}")
        _require(Path(tape["path"]).name == f"segment-{index:06d}.stwemt01",
                 "incremental cost tape order differs")
    expected_argv = [value["tool"]["path"], *(tape["path"] for tape in tapes)]
    _require(value["argv"] == expected_argv, "incremental cost argv differs")
    transport = value["transport"]
    _require(type(transport) is dict and set(transport) == {"stdout", "stderr"},
             "incremental cost transport differs")
    _validate_identity(transport["stdout"], "incremental cost stdout", allow_empty=True)
    _validate_identity(transport["stderr"], "incremental cost stderr")
    stdout = store.read_regular(Path(transport["stdout"]["path"]),
                                "incremental cost stdout", maximum=MAX_OUTPUT_BYTES)
    stderr = store.read_regular(Path(transport["stderr"]["path"]),
                                "incremental cost stderr", maximum=MAX_OUTPUT_BYTES)
    _require(stdout == b"", "incremental cost stdout is not empty")
    records = _records(stderr, tapes)
    aggregate = _aggregate(records)
    _require(value["aggregate"] == aggregate and value["segment0"] == records[0]
             and value["models"] == _models(aggregate),
             "incremental cost replay differs")
    process = value["process"]
    _require(type(process) is dict and set(process) == {
        "exit_code", "timeout_seconds", "timing", "maximum_resident_set_bytes",
        "maximum_resident_set_source", "process_group_drained",
    } and process["exit_code"] == 0
             and type(process["timeout_seconds"]) is int
             and 0 < process["timeout_seconds"] <= MAX_TRIAL_SECONDS
             and process["process_group_drained"] is True
             and type(process["maximum_resident_set_bytes"]) is int
             and process["maximum_resident_set_bytes"] > 0,
             "incremental cost process receipt differs")
    timing = process["timing"]
    _require(type(timing) is dict
             and set(timing) == {"wall_ns", "user_ns", "system_ns"}
             and all(type(item) is int and item >= 0 for item in timing.values())
             and 0 < timing["wall_ns"] <= MAX_TRIAL_SECONDS * 1_000_000_000,
             "incremental cost timing differs")
    ranking = value["ranking"]
    _require(ranking == {
        "scope": "geometry-cost-model-only",
        "reference_65_admitted": _reference_admitted(aggregate, records),
        "diagnostic_eligible": True,
        "proof_correctness": None,
        "fresh_verification": None,
        "production_promotion_eligible": False,
    }, "incremental cost ranking boundary differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "incremental cost evidence",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "incremental cost evidence is not canonical JSON")
    return validate(value)


def _ranking_record_v1(evidence_path: Path) -> dict[str, Any]:
    evidence_path = evidence_path.absolute()
    value = load(evidence_path)
    models = value["models"]
    alternatives = [
        {
            "model": "degree6-161-incremental",
            "main_cells": models["degree6_161_incremental"]["candidate_cells"],
        },
        {
            "model": "legacy-445-incremental",
            "main_cells": models["legacy_445_incremental"]["candidate_cells"],
        },
        {
            "model": "legacy-445-fixed-log24",
            "main_cells": models["fixed_legacy_445_log24"]["cells"],
        },
    ]
    alternatives.sort(key=lambda item: (item["main_cells"], item["model"]))
    for index, alternative in enumerate(alternatives, 1):
        alternative["geometry_rank"] = index
        alternative["measured_proof_performance"] = False
    configuration = {
        "tool_sha256": value["tool"]["sha256"],
        "tool_source_sha256": value["tool_source"]["sha256"],
        "segment_count": value["aggregate"]["segment_count"],
        "model": "incremental-provider-padding-degree6-v1",
    }
    configuration_sha256 = protocol.sha256_bytes(protocol.canonical_bytes(configuration))
    wall_ns = value["process"]["timing"]["wall_ns"]
    touched = value["aggregate"]["touched_words"]
    return protocol.seal({
        "schema": RANKING_SCHEMA_V1,
        "status": "ranked-geometry-diagnostic-only",
        "source_evidence": _identity(evidence_path, "incremental cost evidence"),
        "source_content_sha256": value["content_sha256"],
        "configuration": configuration,
        "configuration_sha256": configuration_sha256,
        "correctness": {
            "canonical_tapes_decoded": True,
            "reference_65_admitted": value["ranking"]["reference_65_admitted"],
            "proof_correctness": None,
            "fresh_verification": None,
        },
        "measurement": {
            "scope": "incremental-cost-extractor-process-only",
            "wall_ns": wall_ns,
            "peak_rss_bytes": value["process"]["maximum_resident_set_bytes"],
            "throughput": {
                "unit": "touched-words-per-second",
                "numerator": touched * 1_000_000_000,
                "denominator": wall_ns,
            },
            "estimated_end_to_end_wall_ns": None,
        },
        "ranked_alternatives": alternatives,
        "eligibility": {
            "diagnostic_ranking": value["ranking"]["reference_65_admitted"],
            "apples_to_apples_comparison": False,
            "production_promotion": False,
        },
    })


def _proof_bridge(value: dict[str, Any]) -> dict[str, Any]:
    stderr = store.read_regular(
        Path(value["transport"]["stderr"]["path"]),
        "incremental cost stderr", maximum=MAX_OUTPUT_BYTES,
    )
    records = _records(stderr, value["tapes"])
    histogram: dict[int, int] = {}
    total_calls = 0
    padded_rows = 0
    for record in records:
        calls = 2 * record["entry_hash_calls"]
        total_calls += calls
        log_size = max(4, (calls - 1).bit_length()) if calls else 0
        histogram[log_size] = histogram.get(log_size, 0) + 1
        padded_rows += 0 if log_size == 0 else 1 << log_size
    fixed_cells = value["models"]["fixed_legacy_445_log24"]["cells"]

    def candidate(name: str, columns: int) -> dict[str, Any]:
        cells = padded_rows * columns
        return {
            "model": name,
            "main_columns": columns,
            "main_cells": cells,
            "reduction_from_fixed_legacy": {
                "numerator": fixed_cells - cells,
                "denominator": fixed_cells,
                "percent_rounded_5dp": _rounded_percent(
                    fixed_cells - cells, fixed_cells,
                ),
            },
        }

    sources = []
    for name in (
        "incremental_frontier_v1.zig",
        "incremental_frontier_component_v1.zig",
        "incremental_transition_v1.zig",
    ):
        path = (REPOSITORY / "src/frontends/riscv/air/memory_commitment" / name)
        sources.append(_identity(path, f"proof bridge source {name}"))
    return {
        "profile": "incremental_frontier_v1",
        "source_files": sources,
        "per_leaf_call_formula": "2*entry_hash_calls",
        "semantic_boundary": (
            "entry-and-exit-roots-use-entry-induced-touched-topology;"
            "not-the-changed-only-target"
        ),
        "total_bridge_calls": total_calls,
        "provider_log_histogram": [
            {"log_size": log_size, "segment_count": histogram[log_size]}
            for log_size in sorted(histogram)
        ],
        "padded_rows_sum": padded_rows,
        "models": [
            candidate("degree6-161-proof-bridge", 161),
            candidate("legacy-445-proof-bridge", 445),
        ],
        "proof_bridge_source_green": True,
        "fresh_stark": False,
        "production_eligible": False,
    }


def ranking_record(evidence_path: Path) -> dict[str, Any]:
    previous = _ranking_record_v1(evidence_path)
    unsigned = {
        key: value for key, value in previous.items()
        if key not in {"schema", "status", "content_sha256"}
    }
    source = load(evidence_path.absolute())
    return protocol.seal({
        "schema": RANKING_SCHEMA,
        "status": "ranked-geometry-diagnostic-with-proof-bridge",
        **unsigned,
        "implemented_proof_bridge": _proof_bridge(source),
    })


def validate_ranking(value: Any) -> dict[str, Any]:
    common_keys = {
        "schema", "status", "source_evidence", "source_content_sha256",
        "configuration", "configuration_sha256", "correctness", "measurement",
        "ranked_alternatives", "eligibility", "content_sha256",
    }
    _require(type(value) is dict
             and value.get("schema") in {RANKING_SCHEMA_V1, RANKING_SCHEMA},
             "incremental cost ranking authority differs")
    expected_keys = (common_keys if value["schema"] == RANKING_SCHEMA_V1
                     else common_keys | {"implemented_proof_bridge"})
    _require(set(value) == expected_keys
             and value["content_sha256"] == protocol.content_sha256(value),
             "incremental cost ranking keys differ")
    source = _validate_identity(
        value["source_evidence"], "incremental cost evidence",
    )
    expected = (_ranking_record_v1(Path(source["path"]))
                if value["schema"] == RANKING_SCHEMA_V1
                else ranking_record(Path(source["path"])))
    _require(value == expected,
             "incremental cost ranking replay differs")
    return value


def load_ranking(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "incremental cost ranking",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "incremental cost ranking is not canonical JSON")
    return validate_ranking(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--tool", type=Path, required=True)
    capture_parser.add_argument("--tool-source", type=Path, required=True)
    capture_parser.add_argument("--tape-directory", type=Path, required=True)
    capture_parser.add_argument("--segment-count", type=int, required=True)
    capture_parser.add_argument("--timeout-seconds", type=int, default=120)
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    rank = commands.add_parser("create-ranking")
    rank.add_argument("--evidence", type=Path, required=True)
    rank.add_argument("--output", type=Path, required=True)
    rank.add_argument("--staging-directory", type=Path, required=True)
    replay_rank = commands.add_parser("replay-ranking")
    replay_rank.add_argument("--ranking", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
        elif arguments.command == "replay-ranking":
            load_ranking(arguments.ranking)
        elif arguments.command == "create-ranking":
            value = ranking_record(arguments.evidence)
            output = arguments.output.absolute()
            staging = arguments.staging_directory.absolute()
            store.require_directory(output.parent, "incremental ranking parent")
            store.require_directory(staging, "incremental ranking staging", create=True)
            store.publish_new_or_identical(
                output, protocol.canonical_bytes(value), staging_directory=staging,
            )
        else:
            capture(
                tool=arguments.tool, tool_source=arguments.tool_source,
                tape_directory=arguments.tape_directory,
                segment_count=arguments.segment_count,
                timeout_seconds=arguments.timeout_seconds,
                output=arguments.output, staging=arguments.staging_directory,
            )
        return 0
    except (
        IncrementalCostEvidenceError, protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
