"""Seal the complete ECRECOVER-candidate PC and symbol census.

The retained observation is fully checked against the exact 31-segment V3
journal.  Creation also runs a bounded `nm -n -C` over the exact ELF, retains
that output, and deterministically assigns every observed PC to a symbol.  The
result is a no-extrapolation execution diagnostic, never AIR/proof/E2E evidence.
"""

from __future__ import annotations

import argparse
import bisect
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_ecrecover_execution_evidence as execution  # noqa: E402
import ethereum_block_pc_hotspot_contract as hotspot_contract  # noqa: E402
import ethereum_block_pc_hotspot_evidence as hotspot_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.ecrecover-pc-census-evidence.v1"
STATUS = "complete-execution-symbol-census-diagnostic-nonpromotable"
NM_TIMEOUT_SECONDS = 10
MAX_NM_BYTES = 32 * 1024 * 1024
TOP_SYMBOL_LIMIT = 64
NM_LINE = re.compile(r"^([0-9a-fA-F]+)\s+([tT])\s+(.+)$")
NAMED_SELECTORS = (
    ("memcpy", lambda name: name == "__wrap_memcpy"),
    ("sha256-compress", lambda name: name == "sha2::sha256::compress256"),
    ("mainnet-execution-handler", lambda name: (
        "revm_handler::mainnet_handler::MainnetHandler<" in name
        and name.endswith("as revm_handler::handler::Handler>::execution")
    )),
    ("mpt-rlp-node-decode", lambda name: (
        "zeth_mpt::mpt::node::Node<" in name
        and name.endswith("as alloy_rlp::decode::Decodable>::decode")
    )),
    ("bytecode-analyze-legacy", lambda name: (
        name == "revm_bytecode::legacy::analysis::analyze_legacy"
    )),
    ("mpt-resolve-digests", lambda name: (
        "zeth_mpt::mpt::node::Node<" in name
        and ">::resolve_digests::<alloy_primitives::bytes_::Bytes>" in name
    )),
    ("native-keccak256", lambda name: name == "native_keccak256"),
)


class EcrecoverPcCensusEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EcrecoverPcCensusEvidenceError(message)


def _identity(
    path: Path, where: str, *, allow_empty: bool = False,
) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where)
    _require(allow_empty or raw, f"{where} is empty")
    return {
        "path": str(path), "bytes": len(raw),
        "sha256": protocol.sha256_bytes(raw),
    }


def _validate_identity(
    value: Any, where: str, *, allow_empty: bool = False,
) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute()
             and value == _identity(
                 Path(value["path"]), where, allow_empty=allow_empty,
             ), f"{where} identity differs")
    return value


def _parse_symbols(raw: bytes) -> list[tuple[int, str]]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EcrecoverPcCensusEvidenceError(
            "ECRECOVER symbol map is not UTF-8",
        ) from error
    symbols: list[tuple[int, str]] = []
    for line in text.splitlines():
        match = NM_LINE.fullmatch(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        name = match.group(3)
        _require(name != "", "ECRECOVER symbol name is empty")
        if symbols and symbols[-1][0] == address:
            if not name.startswith(".") or symbols[-1][1].startswith("."):
                symbols[-1] = (address, name)
        else:
            _require(not symbols or address >= symbols[-1][0],
                     "ECRECOVER symbol map is not ordered")
            symbols.append((address, name))
    _require(symbols and symbols[0][0] <= 0x400,
             "ECRECOVER text symbols are absent")
    return symbols


def _symbol_projection(
    observation: dict[str, Any], symbol_map_path: Path,
) -> dict[str, Any]:
    raw = store.read_regular(
        symbol_map_path.absolute(), "ECRECOVER symbol map",
        maximum=MAX_NM_BYTES,
    )
    symbols = _parse_symbols(raw)
    addresses = [address for address, _ in symbols]
    counts: dict[str, int] = {}
    unmapped = 0
    for row in observation["per_pc"]:
        index = bisect.bisect_right(addresses, row["pc"]) - 1
        if index < 0:
            unmapped += row["count"]
            continue
        name = symbols[index][1]
        counts[name] = counts.get(name, 0) + row["count"]
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    named = []
    for role, predicate in NAMED_SELECTORS:
        matches = [(name, count) for name, count in counts.items()
                   if predicate(name)]
        _require(len(matches) == 1,
                 f"ECRECOVER named symbol {role} differs")
        name, count = matches[0]
        named.append({"role": role, "symbol": name, "observed_rows": count})
    mapped = sum(counts.values())
    _require(
        mapped + unmapped == observation["retired_instructions"]
        and unmapped == 0,
        "ECRECOVER symbol assignment closure differs",
    )
    return {
        "algorithm": "greatest-text-symbol-address-not-after-pc-v1",
        "same_address_policy": "last-nondot-symbol-else-last-symbol",
        "symbol_map": _identity(symbol_map_path, "ECRECOVER symbol map"),
        "mapped_rows": mapped,
        "unmapped_rows": unmapped,
        "distinct_mapped_symbols": len(counts),
        "top_symbol_limit": TOP_SYMBOL_LIMIT,
        "top_symbols": [
            {"symbol": name, "observed_rows": count}
            for name, count in ranked[:TOP_SYMBOL_LIMIT]
        ],
        "named_symbol_totals": named,
    }


def _build_loaded(
    execution_value: dict[str, Any], execution_identity: dict[str, Any],
    observation_path: Path, observer_executable: Path, observer_source: Path,
    timing_log: Path, nm_executable: Path, symbol_map_path: Path,
    nm_stdout_identity: dict[str, Any], nm_stderr_identity: dict[str, Any],
    nm_wall_ns: int,
) -> dict[str, Any]:
    _require(execution_value["schema"] == execution.SCHEMA,
             "ECRECOVER PC execution schema differs")
    boundary = execution_value["claim_boundary"]
    _require(
        boundary["production_active"] is False
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and execution_value["semantics"][
            "general_invalid_input_semantics_satisfied"
        ] is False,
        "ECRECOVER PC execution boundary differs",
    )
    inputs = execution_value["inputs"]
    candidate = execution_value["executions"]["ecrecover_success_candidate"]
    elf = inputs["candidate_elf"]
    input_identity = inputs["common_input"]
    journal = inputs["candidate_journal"]
    try:
        sample = hotspot_contract.sample_authority(
            journal_path=Path(journal["path"]), elf=elf,
            input_identity=input_identity, first_segment_index=0,
            segment_count=candidate["segment_count"],
        )
        raw = store.read_regular(
            observation_path.absolute(), "ECRECOVER PC observation",
            maximum=hotspot_evidence.MAX_OBSERVATION_BYTES,
        )
        observation = hotspot_contract.decode_observation(
            raw, sample=sample, elf=elf, input_identity=input_identity,
            source=journal,
        )
        timing_identity, timing = allocator_evidence._timing(timing_log)
    except (
        hotspot_contract.PcHotspotContractError,
        allocator_evidence.AllocatorExecutionEvidenceError,
    ) as error:
        raise EcrecoverPcCensusEvidenceError(str(error)) from error
    _require(
        sample["first_segment_index"] == 0
        and sample["segment_count"] == candidate["segment_count"]
        and observation["retired_instructions"]
        == candidate["total_core_trace_rows"]
        and observation["sampled_cycles"] == candidate["total_cycles"],
        "ECRECOVER PC complete-execution join differs",
    )
    projection = _symbol_projection(observation, symbol_map_path)
    canonical_totals = {
        "retired_instructions": observation["retired_instructions"],
        "per_pc_count_sum": sum(row["count"] for row in observation["per_pc"]),
        "transition_count": observation["transition_count"],
        "opcode_transition_count_sum": sum(
            row["count"] for row in observation["opcode_transitions"]
        ),
        "basic_edge_count_sum": sum(
            row["count"] for row in observation["basic_edges"]
        ),
        "distinct_pc_count": observation["distinct_pc_count"],
        "distinct_basic_edge_count": observation["distinct_basic_edge_count"],
    }
    _require(
        canonical_totals["per_pc_count_sum"]
        == canonical_totals["retired_instructions"]
        and canonical_totals["opcode_transition_count_sum"]
        == canonical_totals["transition_count"],
        "ECRECOVER PC canonical totals differ",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "ecrecover_execution_evidence": execution_identity,
            "observation": _identity(
                observation_path, "ECRECOVER PC observation",
            ),
            "observer_executable": _identity(
                observer_executable, "ECRECOVER PC observer executable",
            ),
            "observer_source": _identity(
                observer_source, "ECRECOVER PC observer source",
            ),
            "observer_timing_log": timing_identity,
            "candidate_elf": elf,
            "candidate_journal": journal,
            "input": input_identity,
            "nm_executable": _identity(nm_executable, "ECRECOVER nm executable"),
            "nm_stdout": nm_stdout_identity,
            "nm_stderr": nm_stderr_identity,
        },
        "sample": {
            **sample,
            "sample_is_complete_execution": True,
            "no_extrapolation": True,
        },
        "observation_content_sha256": observation["content_sha256"],
        "canonical_totals": canonical_totals,
        "symbol_projection": projection,
        "observer_process_measurement": {
            **timing,
            "scope": "external-time-wrapper-around-retained-observer",
            "argv_process_receipt_retained": False,
            "performance_claim_eligible": False,
        },
        "symbol_process": {
            "argv": [str(nm_executable.absolute()), "-n", "-C", elf["path"]],
            "exit_code": 0,
            "timeout_seconds": NM_TIMEOUT_SECONDS,
            "wall_ns": nm_wall_ns,
            "stdout": nm_stdout_identity,
            "stderr": nm_stderr_identity,
            "process_receipt_retained": True,
        },
        "claim_boundary": {
            "scope": "complete-execution-retirement-symbol-census-only",
            "production_active": False,
            "general_invalid_ecrecover_semantics_satisfied": False,
            "no_extrapolation": True,
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "performance_claim_eligible": False,
            "production_promotion_eligible": False,
        },
    })


def _capture_path(
    source: Path, destination: Path, staging: Path, where: str,
) -> Path:
    raw = store.read_regular(source.absolute(), where)
    store.publish_new_or_identical(
        destination.absolute(), raw, staging_directory=staging.absolute(),
    )
    return destination.absolute()


def _run_nm(
    nm_executable: Path, elf: Path, custody: Path, staging: Path,
) -> tuple[Path, Path, int]:
    argv = [str(nm_executable.absolute()), "-n", "-C", str(elf.absolute())]
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=NM_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EcrecoverPcCensusEvidenceError(
            "ECRECOVER nm process failed",
        ) from error
    wall_ns = time.monotonic_ns() - started
    _require(result.returncode == 0 and len(result.stdout) <= MAX_NM_BYTES
             and result.stdout and result.stderr == b"",
             "ECRECOVER nm process output differs")
    stdout = custody / "nm.stdout"
    stderr = custody / "nm.stderr"
    store.publish_new_or_identical(
        stdout, result.stdout, staging_directory=staging,
    )
    store.publish_new_or_identical(
        stderr, result.stderr, staging_directory=staging,
    )
    return stdout, stderr, wall_ns


def create(
    execution_path: Path, observation_path: Path, observer_executable: Path,
    observer_source: Path, timing_log: Path, nm_executable: Path,
    output: Path, staging: Path,
) -> dict[str, Any]:
    output, staging = output.absolute(), staging.absolute()
    store.require_directory(output.parent, "ECRECOVER PC evidence parent")
    store.require_directory(staging, "ECRECOVER PC staging", create=True)
    custody = output.with_name(f"{output.stem}.custody")
    store.require_directory(custody, "ECRECOVER PC custody", create=True)
    captured = {
        "observation": _capture_path(
            observation_path, custody / "observation.json", staging,
            "ECRECOVER PC observation",
        ),
        "observer": _capture_path(
            observer_executable, custody / "riscv-pc-hotspot-observer", staging,
            "ECRECOVER PC observer executable",
        ),
        "source": _capture_path(
            observer_source, custody / "pc-hotspot-main.zig", staging,
            "ECRECOVER PC observer source",
        ),
        "timing": _capture_path(
            timing_log, custody / "observer.stderr-time.log", staging,
            "ECRECOVER PC timing log",
        ),
        # macOS system binaries are platform-signed and cannot be relocated
        # byte-for-byte and still execute.  Bind and run the absolute system
        # path; the retained stdout makes replay independent of rerunning it.
        "nm": nm_executable.absolute(),
    }
    _identity(captured["nm"], "ECRECOVER nm executable")
    execution_path = execution_path.absolute()
    execution_value = execution.load(execution_path)
    elf = Path(execution_value["inputs"]["candidate_elf"]["path"])
    nm_stdout, nm_stderr, nm_wall_ns = _run_nm(
        captured["nm"], elf, custody, staging,
    )
    value = _build_loaded(
        execution_value, _identity(execution_path, "ECRECOVER execution evidence"),
        captured["observation"], captured["observer"], captured["source"],
        captured["timing"], captured["nm"], nm_stdout,
        _identity(nm_stdout, "ECRECOVER nm stdout"),
        _identity(nm_stderr, "ECRECOVER nm stderr", allow_empty=True),
        nm_wall_ns,
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "sample", "observation_content_sha256",
        "canonical_totals", "symbol_projection", "observer_process_measurement",
        "symbol_process", "claim_boundary", "content_sha256",
    }, "ECRECOVER PC evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "ECRECOVER PC evidence authority differs")
    inputs = value["inputs"]
    names = (
        "ecrecover_execution_evidence", "observation", "observer_executable",
        "observer_source", "observer_timing_log", "candidate_elf",
        "candidate_journal", "input", "nm_executable", "nm_stdout",
        "nm_stderr",
    )
    _require(type(inputs) is dict and set(inputs) == set(names),
             "ECRECOVER PC evidence inputs differ")
    for name in names:
        _validate_identity(
            inputs[name], f"ECRECOVER PC {name}", allow_empty=name == "nm_stderr",
        )
    execution_path = Path(inputs["ecrecover_execution_evidence"]["path"])
    expected = _build_loaded(
        execution.load(execution_path), inputs["ecrecover_execution_evidence"],
        Path(inputs["observation"]["path"]),
        Path(inputs["observer_executable"]["path"]),
        Path(inputs["observer_source"]["path"]),
        Path(inputs["observer_timing_log"]["path"]),
        Path(inputs["nm_executable"]["path"]),
        Path(inputs["nm_stdout"]["path"]), inputs["nm_stdout"],
        inputs["nm_stderr"], value["symbol_process"]["wall_ns"],
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "ECRECOVER PC evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "ECRECOVER PC evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "ECRECOVER PC evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    for name in (
        "execution-evidence", "observation", "observer-executable",
        "observer-source", "timing-log", "nm-executable", "output",
        "staging-directory",
    ):
        create_parser.add_argument(f"--{name}", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        create(
            arguments.execution_evidence, arguments.observation,
            arguments.observer_executable, arguments.observer_source,
            arguments.timing_log, arguments.nm_executable,
            arguments.output, arguments.staging_directory,
        )
        return 0
    except (
        EcrecoverPcCensusEvidenceError,
        execution.EcrecoverExecutionEvidenceError,
        hotspot_contract.PcHotspotContractError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
