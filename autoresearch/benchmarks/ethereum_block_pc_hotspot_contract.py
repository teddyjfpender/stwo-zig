"""Semantic contract for bounded RISC-V retirement hotspot observations."""

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


OBSERVATION_SCHEMA = "stwo.riscv.retirement-pc-hotspot-observation.v1"
OBSERVATION_STATUS = "captured-diagnostic-only"
TRANSITION_SCOPE = (
    "within-segment-adjacent-observed-core-rows-"
    "external-retirements-omitted"
)
MAX_TOP_BASIC_EDGE_LIMIT = 1024
OBSERVATION_KEYS = {
    "schema",
    "status",
    "production",
    "execution_profile",
    "clock_frame",
    "elf_sha256",
    "input_sha256",
    "source_sha256",
    "first_segment_index",
    "segment_count",
    "first_global_cycle",
    "sampled_cycles",
    "retired_instructions",
    "transition_scope",
    "transition_count",
    "distinct_pc_count",
    "distinct_basic_edge_count",
    "per_pc",
    "opcode_transitions",
    "basic_edges",
    "content_sha256",
}


class PcHotspotContractError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PcHotspotContractError(message)


def _integer(
    value: Any,
    where: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 64) - 1,
) -> int:
    _require(
        type(value) is int and minimum <= value <= maximum,
        f"{where} differs",
    )
    return value


def _read_journal(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = store.read_regular(
        path, "PC hotspot execution journal", maximum=segmented.MAX_JOURNAL_BYTES,
    )
    _require(raw.endswith(b"\n"), "PC hotspot execution journal framing differs")
    lines = raw.splitlines(keepends=True)
    try:
        segmented.validate_records(lines, require_complete=True)
    except (segmented.ContractError, ValueError) as error:
        raise PcHotspotContractError(
            "PC hotspot execution journal is invalid"
        ) from error
    records = [store.decode_strict(line)["payload"] for line in lines]
    header = records[0]
    _require(
        header["schema"] == segmented.HEADER_SCHEMA
        and header["profile"] == segmented.PROFILE_ETHEREUM
        and header["clock_frame"] == segmented.CLOCK_FRAME_LEAF_LOCAL,
        "PC hotspot journal authority differs",
    )
    return header, records[1:-1]


def sample_authority(
    *,
    journal_path: Path,
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    first_segment_index: int,
    segment_count: int,
) -> dict[str, Any]:
    header, segments = _read_journal(journal_path)
    _integer(
        first_segment_index,
        "PC hotspot first segment index",
        maximum=(1 << 32) - 1,
    )
    _require(
        first_segment_index == 0,
        "PC hotspot sample must be a journal-bound segment-zero prefix",
    )
    _integer(
        segment_count,
        "PC hotspot segment count",
        minimum=1,
        maximum=(1 << 32) - 1,
    )
    _require(
        first_segment_index + segment_count <= len(segments),
        "PC hotspot segment range exceeds the journal",
    )
    _require(
        (header["elf_bytes"], header["elf_sha256"])
        == (elf["bytes"], elf["sha256"]),
        "PC hotspot ELF differs from the journal",
    )
    _require(
        (header["input_bytes"], header["input_sha256"])
        == (input_identity["bytes"], input_identity["sha256"]),
        "PC hotspot input differs from the journal",
    )
    selected = segments[first_segment_index:first_segment_index + segment_count]
    family_rows = {family: 0 for family in segmented.FAMILIES}
    for segment in selected:
        _require(
            segment["unclassified_core_rows"] == 0
            and segment["core_trace_rows"] > 0,
            "PC hotspot sampled segment core-row authority differs",
        )
        for row in segment["opcode_family_rows"]:
            family_rows[row["family"]] += row["rows"]
    return {
        "execution_profile": header["profile"],
        "clock_frame": header["clock_frame"],
        "first_segment_index": first_segment_index,
        "last_segment_index": first_segment_index + segment_count - 1,
        "segment_count": segment_count,
        "first_global_cycle": selected[0]["global_first_cycle"],
        "sampled_cycles": sum(segment["cycle_count"] for segment in selected),
        "retired_instructions": sum(
            segment["core_trace_rows"] for segment in selected
        ),
        "opcode_family_rows": [
            {"family": family, "rows": family_rows[family]}
            for family in segmented.FAMILIES
        ],
        "transition_scope": TRANSITION_SCOPE,
    }


def _pc_rows(value: Any) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    _require(type(value) is list and value, "PC hotspot per-PC rows differ")
    by_pc: dict[int, dict[str, Any]] = {}
    previous = -1
    for index, row in enumerate(value):
        _require(
            type(row) is dict and set(row) == {"pc", "opcode_family", "count"},
            f"PC hotspot per-PC row {index} keys differ",
        )
        pc = _integer(row["pc"], f"PC hotspot PC {index}", maximum=(1 << 32) - 1)
        _require(pc % 4 == 0 and pc > previous, "PC hotspot PCs are not canonical")
        _require(
            row["opcode_family"] in segmented.FAMILIES,
            "PC hotspot opcode family differs",
        )
        _integer(row["count"], f"PC hotspot PC count {index}", minimum=1)
        by_pc[pc] = row
        previous = pc
    return value, by_pc


def _basic_edges(
    value: Any,
    by_pc: dict[int, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], int]]:
    _require(type(value) is list, "PC hotspot basic edges differ")
    previous = (-1, -1)
    transitions: dict[tuple[str, str], int] = {}
    outgoing = {pc: 0 for pc in by_pc}
    incoming = {pc: 0 for pc in by_pc}
    for index, edge in enumerate(value):
        _require(
            type(edge) is dict and set(edge) == {"from_pc", "to_pc", "count"},
            f"PC hotspot basic edge {index} keys differ",
        )
        pair = (
            _integer(
                edge["from_pc"], f"PC hotspot edge {index} from PC",
                maximum=(1 << 32) - 1,
            ),
            _integer(
                edge["to_pc"], f"PC hotspot edge {index} to PC",
                maximum=(1 << 32) - 1,
            ),
        )
        _require(
            pair[0] % 4 == 0
            and pair[1] % 4 == 0
            and pair > previous
            and pair[0] in by_pc
            and pair[1] in by_pc,
            "PC hotspot basic-edge authority differs",
        )
        count = _integer(
            edge["count"], f"PC hotspot edge {index} count", minimum=1,
        )
        outgoing[pair[0]] += count
        incoming[pair[1]] += count
        family_pair = (
            by_pc[pair[0]]["opcode_family"],
            by_pc[pair[1]]["opcode_family"],
        )
        transitions[family_pair] = transitions.get(family_pair, 0) + count
        previous = pair
    _require(
        all(outgoing[pc] <= row["count"] for pc, row in by_pc.items())
        and all(incoming[pc] <= row["count"] for pc, row in by_pc.items()),
        "PC hotspot edge incidence exceeds PC counts",
    )
    return value, transitions


def _transition_rows(
    value: Any,
    expected: dict[tuple[str, str], int],
) -> list[dict[str, Any]]:
    _require(type(value) is list, "PC hotspot transition matrix differs")
    actual: dict[tuple[str, str], int] = {}
    previous = ("", "")
    for index, row in enumerate(value):
        _require(
            type(row) is dict
            and set(row) == {"from_family", "to_family", "count"},
            f"PC hotspot transition row {index} keys differ",
        )
        pair = (row["from_family"], row["to_family"])
        _require(
            pair[0] in segmented.FAMILIES
            and pair[1] in segmented.FAMILIES
            and pair > previous,
            "PC hotspot transition order differs",
        )
        actual[pair] = _integer(
            row["count"], f"PC hotspot transition {index} count", minimum=1,
        )
        previous = pair
    _require(actual == expected, "PC hotspot transition matrix does not replay")
    return value


def top_edges(edges: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    _integer(
        limit,
        "PC hotspot top basic-edge limit",
        minimum=1,
        maximum=MAX_TOP_BASIC_EDGE_LIMIT,
    )
    return sorted(
        edges,
        key=lambda edge: (-edge["count"], edge["from_pc"], edge["to_pc"]),
    )[:limit]


def validate_observation(
    value: Any,
    *,
    sample: dict[str, Any],
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    _require(
        type(value) is dict and set(value) == OBSERVATION_KEYS,
        "PC hotspot observation keys differ",
    )
    _require(
        value["schema"] == OBSERVATION_SCHEMA
        and value["status"] == OBSERVATION_STATUS
        and value["production"] is False
        and value["content_sha256"] == protocol.content_sha256(value),
        "PC hotspot observation authority differs",
    )
    for field in (
        "first_segment_index",
        "segment_count",
        "first_global_cycle",
        "sampled_cycles",
        "retired_instructions",
        "transition_count",
        "distinct_pc_count",
        "distinct_basic_edge_count",
    ):
        _integer(value[field], f"PC hotspot observation {field}")
    exact_fields = {
        "execution_profile": sample["execution_profile"],
        "clock_frame": sample["clock_frame"],
        "elf_sha256": elf["sha256"],
        "input_sha256": input_identity["sha256"],
        "source_sha256": source["sha256"],
        "first_segment_index": sample["first_segment_index"],
        "segment_count": sample["segment_count"],
        "first_global_cycle": sample["first_global_cycle"],
        "sampled_cycles": sample["sampled_cycles"],
        "retired_instructions": sample["retired_instructions"],
        "transition_scope": TRANSITION_SCOPE,
    }
    _require(
        all(value[field] == expected for field, expected in exact_fields.items()),
        "PC hotspot observation source projection differs",
    )
    pc_rows, by_pc = _pc_rows(value["per_pc"])
    family_counts = {family: 0 for family in segmented.FAMILIES}
    for row in pc_rows:
        family_counts[row["opcode_family"]] += row["count"]
    expected_families = {
        row["family"]: row["rows"] for row in sample["opcode_family_rows"]
    }
    retired = sum(row["count"] for row in pc_rows)
    _require(
        retired == sample["retired_instructions"]
        and family_counts == expected_families
        and value["distinct_pc_count"] == len(pc_rows),
        "PC hotspot PC totals do not close against the journal",
    )
    edges, recomputed_transitions = _basic_edges(value["basic_edges"], by_pc)
    transition_count = sum(edge["count"] for edge in edges)
    expected_transition_count = retired - sample["segment_count"]
    _require(
        value["distinct_basic_edge_count"] == len(edges)
        and value["transition_count"] == transition_count
        and transition_count == expected_transition_count,
        "PC hotspot edge totals do not close",
    )
    outgoing = {pc: 0 for pc in by_pc}
    incoming = {pc: 0 for pc in by_pc}
    for edge in edges:
        outgoing[edge["from_pc"]] += edge["count"]
        incoming[edge["to_pc"]] += edge["count"]
    _require(
        sum(by_pc[pc]["count"] - outgoing[pc] for pc in by_pc)
        == sample["segment_count"]
        and sum(by_pc[pc]["count"] - incoming[pc] for pc in by_pc)
        == sample["segment_count"],
        "PC hotspot segment-boundary edge deficits differ",
    )
    _transition_rows(value["opcode_transitions"], recomputed_transitions)
    return value


def decode_observation(
    raw: bytes,
    *,
    sample: dict[str, Any],
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "PC hotspot observation is not canonical JSON",
    )
    return validate_observation(
        value,
        sample=sample,
        elf=elf,
        input_identity=input_identity,
        source=source,
    )
