"""Semantic contract for sealed function-load value observations."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


OBSERVATION_SCHEMA = "stwo.riscv.function-load-value-observation.v1"
OBSERVATION_STATUS = "captured-diagnostic-only"
CLAIM_BOUNDARY = "execution-observation-only-not-air-or-proof"
PROFILE = "rv32im-zkvm-ethereum-v1"
CLOCK_FRAME = "leaf_local"
VALUE_SOURCE = "retired-row-rd-val"
MAX_SAMPLE_SEGMENTS = 64
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
OBSERVATION_KEYS = {
    "claim_boundary",
    "clock_frame",
    "content_sha256",
    "distinct_value_count",
    "elf_sha256",
    "entry_count",
    "entry_instruction_word",
    "entry_pc",
    "execution_profile",
    "first_global_cycle",
    "first_segment_index",
    "histogram",
    "input_sha256",
    "maximum_value",
    "minimum_value",
    "pending_entry_count",
    "production",
    "retired_instructions",
    "sampled_cycles",
    "schema",
    "segment_count",
    "source_sha256",
    "status",
    "value_count",
    "value_imm",
    "value_instruction_word",
    "value_pc",
    "value_rd",
    "value_rs1",
    "value_source",
    "value_sum",
}


class FunctionValueContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FunctionValueContractError(message)


def integer(
    value: Any,
    where: str,
    *,
    minimum: int = 0,
    maximum: int = U64_MAX,
) -> int:
    require(
        type(value) is int and minimum <= value <= maximum,
        f"{where} differs",
    )
    return value


def sha256(value: Any, where: str) -> str:
    require(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"{where} differs",
    )
    return value


def sample_authority(
    *,
    journal_path: Path,
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    segment_count: int,
) -> dict[str, Any]:
    raw = store.read_regular(
        journal_path,
        "function-value execution journal",
        maximum=segmented.MAX_JOURNAL_BYTES,
    )
    require(raw.endswith(b"\n"), "function-value journal framing differs")
    lines = raw.splitlines(keepends=True)
    try:
        segmented.validate_records(lines, require_complete=True)
    except (segmented.ContractError, protocol.ProofProtocolError, ValueError) as error:
        raise FunctionValueContractError(
            "function-value execution journal is invalid"
        ) from error
    records = [store.decode_strict(line)["payload"] for line in lines]
    header = records[0]
    segments = records[1:-1]
    integer(
        segment_count,
        "function-value segment count",
        minimum=1,
        maximum=MAX_SAMPLE_SEGMENTS,
    )
    require(
        header["schema"] == segmented.HEADER_SCHEMA
        and header["profile"] == PROFILE
        and header["clock_frame"] == CLOCK_FRAME
        and header["strict_completion"] is True
        and header["trace_retention"] == "segment-owned",
        "function-value journal authority differs",
    )
    require(
        (header["elf_bytes"], header["elf_sha256"])
        == (elf["bytes"], elf["sha256"]),
        "function-value ELF differs from journal",
    )
    require(
        (header["input_bytes"], header["input_sha256"])
        == (input_identity["bytes"], input_identity["sha256"]),
        "function-value input differs from journal",
    )
    require(segment_count <= len(segments),
            "function-value sample exceeds journal")
    selected = segments[:segment_count]
    require(
        all(
            segment["segment_index"] == index
            and segment["cycle_count"] > 0
            and segment["core_trace_rows"] > 0
            for index, segment in enumerate(selected)
        ),
        "function-value sampled segment authority differs",
    )
    return {
        "clock_frame": header["clock_frame"],
        "execution_profile": header["profile"],
        "first_global_cycle": selected[0]["global_first_cycle"],
        "first_segment_index": 0,
        "last_segment_index": segment_count - 1,
        "retired_instructions": sum(
            segment["core_trace_rows"] for segment in selected
        ),
        "sampled_cycles": sum(segment["cycle_count"] for segment in selected),
        "segment_count": segment_count,
        "segment_step_budget": header["segment_step_budget"],
    }


def validate_observation(value: Any) -> dict[str, Any]:
    require(
        type(value) is dict and set(value) == OBSERVATION_KEYS,
        "function-value observation keys differ",
    )
    require(
        value["schema"] == OBSERVATION_SCHEMA
        and value["status"] == OBSERVATION_STATUS
        and value["claim_boundary"] == CLAIM_BOUNDARY
        and value["execution_profile"] == PROFILE
        and value["clock_frame"] == CLOCK_FRAME
        and value["value_source"] == VALUE_SOURCE
        and value["production"] is False,
        "function-value observation authority differs",
    )
    sha256(value["elf_sha256"], "function-value ELF SHA")
    sha256(value["input_sha256"], "function-value input SHA")
    sha256(value["source_sha256"], "function-value journal SHA")
    sha256(value["content_sha256"], "function-value content SHA")
    require(
        value["content_sha256"] == protocol.content_sha256(value),
        "function-value observation content seal differs",
    )
    for field in (
        "entry_instruction_word",
        "entry_pc",
        "maximum_value",
        "minimum_value",
        "value_instruction_word",
        "value_pc",
    ):
        integer(value[field], f"function-value {field}", maximum=U32_MAX)
    integer(value["value_rd"], "function-value value_rd", maximum=31)
    integer(value["value_rs1"], "function-value value_rs1", maximum=31)
    integer(
        value["value_imm"],
        "function-value value_imm",
        minimum=I32_MIN,
        maximum=I32_MAX,
    )
    integer(
        value["first_segment_index"],
        "function-value first segment index",
        maximum=U32_MAX,
    )
    integer(
        value["segment_count"],
        "function-value segment count",
        minimum=1,
        maximum=MAX_SAMPLE_SEGMENTS,
    )
    for field in (
        "first_global_cycle",
        "sampled_cycles",
        "retired_instructions",
        "entry_count",
        "value_count",
        "value_sum",
    ):
        integer(
            value[field],
            f"function-value {field}",
            minimum=1 if field != "value_sum" else 0,
        )
    integer(
        value["pending_entry_count"],
        "function-value pending entry count",
        maximum=1,
    )
    integer(
        value["distinct_value_count"],
        "function-value distinct value count",
        minimum=1,
    )
    require(
        value["first_segment_index"] == 0
        and value["entry_pc"] != value["value_pc"]
        and value["entry_count"]
        == value["value_count"] + value["pending_entry_count"]
        and value["entry_count"] + value["value_count"]
        <= value["retired_instructions"]
        and value["retired_instructions"] <= value["sampled_cycles"]
        and value["minimum_value"] <= value["maximum_value"],
        "function-value observation closure differs",
    )
    histogram = value["histogram"]
    require(type(histogram) is list and histogram,
            "function-value histogram differs")
    previous = -1
    count_sum = 0
    value_sum = 0
    for index, row in enumerate(histogram):
        require(
            type(row) is dict and set(row) == {"count", "value"},
            f"function-value histogram row {index} keys differ",
        )
        count = integer(
            row["count"],
            f"function-value histogram count {index}",
            minimum=1,
        )
        observed = integer(
            row["value"],
            f"function-value histogram value {index}",
            maximum=U32_MAX,
        )
        require(observed > previous,
                "function-value histogram order differs")
        previous = observed
        count_sum += count
        value_sum += observed * count
        require(count_sum <= U64_MAX and value_sum <= U64_MAX,
                "function-value histogram overflows u64")
    require(
        len(histogram) == value["distinct_value_count"]
        and count_sum == value["value_count"]
        and value_sum == value["value_sum"]
        and histogram[0]["value"] == value["minimum_value"]
        and histogram[-1]["value"] == value["maximum_value"],
        "function-value histogram closure differs",
    )
    return value


def decode_observation(
    raw: bytes,
    *,
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    journal: dict[str, Any],
    sample: dict[str, Any],
) -> dict[str, Any]:
    value = store.decode_strict(raw)
    require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "function-value observation is not canonical newline-framed JSON",
    )
    validate_observation(value)
    require(
        value["elf_sha256"] == elf["sha256"]
        and value["input_sha256"] == input_identity["sha256"]
        and value["source_sha256"] == journal["sha256"],
        "function-value observation input custody differs",
    )
    for field in (
        "clock_frame",
        "execution_profile",
        "first_global_cycle",
        "first_segment_index",
        "retired_instructions",
        "sampled_cycles",
        "segment_count",
    ):
        require(value[field] == sample[field],
                f"function-value observation {field} differs from journal")
    return value
