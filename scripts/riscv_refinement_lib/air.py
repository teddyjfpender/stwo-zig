"""Validate and package the production symbolic AIR for LUI and ADDI."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import codec
from .model import M31_MODULUS, SCHEMA_VERSION, RefinementError

Expr = tuple[Any, ...]
BASE_KEYS = {
    "columns",
    "constraints",
    "family",
    "lookups",
    "modulus",
    "nodes",
    "notes",
    "unmodelled_bus_requests",
}
PACKAGED_KEYS = BASE_KEYS | {
    "canonical_digest",
    "kind",
    "opcode",
    "production_binding",
    "projection",
    "schema_version",
}
EXPECTED_COLUMNS = {
    "lui": (
        ("enabler", "witness"),
        ("clock", "input"),
        ("pc", "input"),
        ("rd_addr", "input"),
        ("rd_previous_0", "input"),
        ("rd_previous_1", "input"),
        ("rd_previous_2", "input"),
        ("rd_previous_3", "input"),
        ("rd_previous_clock", "input"),
        ("rd_next_0", "output"),
        ("rd_next_1", "output"),
        ("rd_next_2", "output"),
        ("rd_next_3", "output"),
        ("imm_0", "witness"),
        ("imm_1", "witness"),
        ("imm_2", "witness"),
        ("destination_nonzero", "witness"),
        ("destination_inverse", "witness"),
        ("bus_value_18", "input"),
        ("bus_value_19", "output"),
        ("bus_value_20", "output"),
        ("bus_value_21", "output"),
    ),
    "base_alu_imm": (
        ("clk", "input"),
        ("pc", "input"),
        ("rd_addr", "input"),
        ("rd_previous_0", "input"),
        ("rd_previous_1", "input"),
        ("rd_previous_2", "input"),
        ("rd_previous_3", "input"),
        ("rd_previous_clock", "input"),
        ("rd_next_0", "output"),
        ("rd_next_1", "output"),
        ("rd_next_2", "output"),
        ("rd_next_3", "output"),
        ("rs1_addr", "input"),
        ("rs1_previous_0", "input"),
        ("rs1_previous_1", "input"),
        ("rs1_previous_2", "input"),
        ("rs1_previous_3", "input"),
        ("rs1_previous_clock", "input"),
        ("rs1_next_0", "output"),
        ("rs1_next_1", "output"),
        ("rs1_next_2", "output"),
        ("rs1_next_3", "output"),
        ("imm_0", "witness"),
        ("imm_1", "witness"),
        ("imm_msb", "witness"),
        ("is_addi", "witness"),
        ("is_xori", "witness"),
        ("is_ori", "witness"),
        ("is_andi", "witness"),
        ("result_0", "witness"),
        ("result_1", "witness"),
        ("result_2", "witness"),
        ("result_3", "witness"),
        ("destination_nonzero", "witness"),
        ("destination_inverse", "witness"),
        ("bus_value_35", "input"),
        ("bus_value_36", "input"),
        ("bus_value_37", "output"),
        ("bus_value_38", "output"),
        ("bus_value_39", "output"),
        ("bus_value_40", "output"),
    ),
}
EXPECTED_UNMODELLED_BUS_REQUESTS = {
    "lui": 5,
    "base_alu_imm": 7,
}
EXTRACTION_NOTE = (
    "Extracted from the shipped AIR by instantiating air/semantics over a\n"
    "recording scalar; the QM31 instantiation of the same source is what the\n"
    "prover evaluates, and a differential test pins the two together on random\n"
    "assignments.  Covered: per-row witness uniqueness of the emitted machine\n"
    "state, given the fetched instruction and the consumed bus values, granting\n"
    "that a live lookup numerator implies table membership.  NOT covered:\n"
    "anything cross-row or multiset -- the LogUp memory argument, clock\n"
    "monotonicity, state-chain telescoping, program binding, public boundary\n"
    "closure -- nor completeness, nor agreement with Sail."
)


def col(name: str) -> Expr:
    return ("col", name)


def const(value: int) -> Expr:
    return ("const", value % M31_MODULUS)


def neg(value: Expr) -> Expr:
    return ("neg", value)


def add(lhs: Expr, rhs: Expr) -> Expr:
    return ("add", lhs, rhs)


def sub(lhs: Expr, rhs: Expr) -> Expr:
    return ("sub", lhs, rhs)


def mul(lhs: Expr, rhs: Expr) -> Expr:
    return ("mul", lhs, rhs)


def bit(value: Expr) -> Expr:
    return mul(value, sub(value, const(1)))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_schema(payload: dict[str, Any], family: str) -> None:
    keys = set(payload)
    if keys not in (BASE_KEYS, PACKAGED_KEYS):
        raise RefinementError(
            f"{family}: AIR object keys drifted; got {sorted(keys)}"
        )
    if payload.get("notes") != EXTRACTION_NOTE:
        raise RefinementError(f"{family}: AIR extraction note drifted")
    if (
        payload.get("unmodelled_bus_requests")
        != EXPECTED_UNMODELLED_BUS_REQUESTS[family]
    ):
        raise RefinementError(f"{family}: unmodelled bus-request count drifted")
    columns = payload.get("columns")
    if not isinstance(columns, list):
        raise RefinementError(f"{family}: AIR columns must be an array")
    observed: list[tuple[str, str]] = []
    for index, column in enumerate(columns):
        if not isinstance(column, dict):
            raise RefinementError(f"{family}: columns[{index}] is not an object")
        if set(column) != {"name", "role"}:
            raise RefinementError(f"{family}: columns[{index}] keys drifted")
        if not isinstance(column["name"], str) or not isinstance(
            column["role"], str
        ):
            raise RefinementError(f"{family}: columns[{index}] has non-string metadata")
        observed.append((column["name"], column["role"]))
    if tuple(observed) != EXPECTED_COLUMNS[family]:
        raise RefinementError(f"{family}: ordered column contract drifted")
    if len({name for name, _ in observed}) != len(observed):
        raise RefinementError(f"{family}: duplicate AIR column name")
    if keys == PACKAGED_KEYS:
        if payload.get("kind") != "stwo-riscv-refinement-air":
            raise RefinementError(f"{family}: packaged AIR kind drifted")
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise RefinementError(f"{family}: packaged AIR schema drifted")
        if payload.get("canonical_digest") != codec.content_digest(payload):
            raise RefinementError(f"{family}: packaged AIR digest is invalid")
        _validate_packaging(payload, family)


def _validate_packaging(payload: dict[str, Any], family: str) -> None:
    opcode = "lui" if family == "lui" else "addi"
    expected_opcode = {
        "id": 35 if family == "lui" else 10,
        "mnemonic": opcode,
        "family": family,
        "selector": (
            {"enabler": 1}
            if family == "lui"
            else {
                "is_addi": 1,
                "is_xori": 0,
                "is_ori": 0,
                "is_andi": 0,
            }
        ),
    }
    expected_projection = {
        "program_lookup": 0,
        "state_consume_lookup": 1 if family == "lui" else 2,
        "state_emit_lookup": 2 if family == "lui" else 3,
        "source_access_lookups": [] if family == "lui" else [4, 5],
        "destination_access_lookups": [4, 5] if family == "lui" else [13, 14],
        "next_pc_column": "bus_value_19" if family == "lui" else "bus_value_37",
    }
    if payload.get("opcode") != expected_opcode:
        raise RefinementError(f"{family}: opcode projection drifted")
    if payload.get("projection") != expected_projection:
        raise RefinementError(f"{family}: relation projection drifted")
    binding = payload.get("production_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "differential_trials_per_family",
        "extractor",
        "level",
        "source_closure_sha256",
        "source_ir_sha256",
    }:
        raise RefinementError(f"{family}: production binding schema drifted")
    if (
        binding["level"] != "level-1-exact-shape-normalizer"
        or binding["extractor"] != "src/frontends/riscv/air/extract/mod.zig"
        or binding["differential_trials_per_family"] != 8
        or not isinstance(binding["source_ir_sha256"], str)
        or len(binding["source_ir_sha256"]) != 64
        or not isinstance(binding["source_closure_sha256"], str)
        or len(binding["source_closure_sha256"]) != 64
    ):
        raise RefinementError(f"{family}: production binding identity drifted")


def _decode_nodes(payload: dict[str, Any]) -> list[Expr]:
    raw_nodes = payload.get("nodes")
    if not isinstance(raw_nodes, list):
        raise RefinementError("AIR IR must carry a flat nodes array")
    nodes: list[Expr] = []
    for index, raw in enumerate(raw_nodes):
        if not isinstance(raw, dict):
            raise RefinementError(f"nodes[{index}] is not an object")
        op = raw.get("op")
        if op == "col":
            if set(raw) != {"name", "op"} or not isinstance(raw["name"], str):
                raise RefinementError(f"nodes[{index}] has malformed column shape")
            node = col(raw["name"])
        elif op == "const":
            if (
                set(raw) != {"op", "value"}
                or not _is_int(raw["value"])
                or not 0 <= raw["value"] < M31_MODULUS
            ):
                raise RefinementError(f"nodes[{index}] has malformed constant shape")
            node = const(raw["value"])
        else:
            if set(raw) != {"args", "op"}:
                raise RefinementError(f"nodes[{index}] has unknown keys")
            args = raw.get("args")
            if not isinstance(args, list):
                raise RefinementError(f"nodes[{index}] has no args array")
            if any(not _is_int(arg) or not 0 <= arg < index for arg in args):
                raise RefinementError(f"nodes[{index}] has a forward or invalid edge")
            if op == "neg" and len(args) == 1:
                node = neg(nodes[args[0]])
            elif op in {"add", "sub", "mul"} and len(args) == 2:
                node = (str(op), nodes[args[0]], nodes[args[1]])
            else:
                raise RefinementError(f"nodes[{index}] has unsupported shape")
        nodes.append(node)
    return nodes


def _roots(payload: dict[str, Any], nodes: list[Expr]) -> list[Expr]:
    roots = payload.get("constraints")
    if not isinstance(roots, list) or any(
        not _is_int(root) or not 0 <= root < len(nodes) for root in roots
    ):
        raise RefinementError("AIR IR constraints must be node indexes")
    return [nodes[root] for root in roots]


def _lookups(payload: dict[str, Any], nodes: list[Expr]) -> list[tuple[Any, ...]]:
    result: list[tuple[Any, ...]] = []
    raw_lookups = payload.get("lookups")
    if not isinstance(raw_lookups, list):
        raise RefinementError("AIR IR must carry a lookups array")
    try:
        for index, lookup in enumerate(raw_lookups):
            if not isinstance(lookup, dict) or set(lookup) != {
                "domain",
                "label",
                "numerator",
                "tuple",
            }:
                raise RefinementError(f"lookups[{index}] has malformed keys")
            if not isinstance(lookup["domain"], str) or lookup["label"] not in {
                "consumed",
                "emitted",
                "request",
            }:
                raise RefinementError(f"lookups[{index}] metadata is malformed")
            numerator = lookup["numerator"]
            tuple_indexes = lookup["tuple"]
            if (
                not _is_int(numerator)
                or not 0 <= numerator < len(nodes)
                or not isinstance(tuple_indexes, list)
                or any(
                    not _is_int(node_index)
                    or not 0 <= node_index < len(nodes)
                    for node_index in tuple_indexes
                )
            ):
                raise RefinementError(f"lookups[{index}] has invalid node indexes")
            result.append(
                (
                    lookup["label"],
                    lookup["domain"],
                    nodes[numerator],
                    tuple(nodes[node_index] for node_index in tuple_indexes),
                )
            )
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise RefinementError("AIR IR contains a malformed lookup") from exc
    return result


def _expected_lui() -> tuple[list[Expr], list[tuple[Any, ...]]]:
    e = col("enabler")
    rd = col("rd_addr")
    nz = col("destination_nonzero")
    pc = col("pc")
    clock = col("clock")
    i0, i1, i2 = col("imm_0"), col("imm_1"), col("imm_2")
    result = (const(0), mul(i0, const(16)), i1, i2)
    access_clock = add(mul(sub(clock, const(1)), const(4)), const(1))
    immediate = add(add(i0, mul(i1, const(16))), mul(i2, const(4096)))
    next_pc = add(pc, const(4))
    next_clock = add(clock, const(1))
    constraints = [
        bit(e),
        bit(nz),
        mul(rd, sub(const(1), nz)),
        sub(mul(rd, col("destination_inverse")), nz),
        *[
            sub(col(f"rd_next_{index}"), mul(nz, limb))
            for index, limb in enumerate(result)
        ],
        sub(e, const(1)),
        sub(col("bus_value_18"), immediate),
        sub(col("bus_value_19"), next_pc),
        sub(col("bus_value_20"), next_clock),
        sub(col("bus_value_21"), access_clock),
    ]
    lookups = [
        (
            "request",
            "program_access",
            neg(e),
            (pc, const(35), rd, immediate, const(0)),
        ),
        ("consumed", "registers_state", neg(e), (pc, clock)),
        ("emitted", "registers_state", e, (next_pc, next_clock)),
        ("request", "range_check_8_8_4", neg(e), (i1, i2, i0)),
        (
            "consumed",
            "memory_access",
            neg(e),
            (
                const(0),
                rd,
                col("rd_previous_clock"),
                *(col(f"rd_previous_{index}") for index in range(4)),
            ),
        ),
        (
            "emitted",
            "memory_access",
            e,
            (
                const(0),
                rd,
                access_clock,
                *(col(f"rd_next_{index}") for index in range(4)),
            ),
        ),
        (
            "request",
            "range_check_20",
            neg(e),
            (sub(sub(access_clock, col("rd_previous_clock")), const(1)),),
        ),
    ]
    return constraints, lookups


def _expected_addi() -> tuple[list[Expr], list[tuple[Any, ...]]]:
    flags = [
        col("is_addi"),
        col("is_xori"),
        col("is_ori"),
        col("is_andi"),
    ]
    add_flag, xor_flag, or_flag, and_flag = flags
    active = add(add(add(add_flag, xor_flag), or_flag), and_flag)
    sign = col("imm_msb")
    i0, i1 = col("imm_0"), col("imm_1")
    imm = (
        i0,
        add(i1, mul(sign, const(248))),
        mul(sign, const(255)),
        mul(sign, const(255)),
    )
    carry = const(0)
    carry_constraints: list[Expr] = []
    for index in range(4):
        numerator = sub(
            add(add(col(f"rs1_next_{index}"), imm[index]), carry),
            col(f"result_{index}"),
        )
        carry = mul(numerator, const(8388608))
        carry_constraints.append(mul(add_flag, bit(carry)))
    rd = col("rd_addr")
    nz = col("destination_nonzero")
    clock = col("clk")
    source_clock = add(mul(sub(clock, const(1)), const(4)), const(1))
    destination_clock = add(mul(sub(clock, const(1)), const(4)), const(2))
    next_pc = add(col("pc"), const(4))
    next_clock = add(clock, const(1))
    bitwise_active = add(add(xor_flag, or_flag), and_flag)
    operation = add(mul(xor_flag, const(2)), or_flag)
    opcode = add(
        add(
            add(mul(add_flag, const(10)), mul(xor_flag, const(13))),
            mul(or_flag, const(14)),
        ),
        mul(and_flag, const(15)),
    )
    unsigned_imm = add(add(i0, mul(i1, const(256))), mul(sign, const(2048)))
    constraints = [
        bit(active),
        *(bit(flag) for flag in flags),
        bit(sign),
        *carry_constraints,
        bit(nz),
        mul(rd, sub(const(1), nz)),
        sub(mul(rd, col("destination_inverse")), nz),
        *[
            sub(col(f"rd_next_{index}"), mul(nz, col(f"result_{index}")))
            for index in range(4)
        ],
        *[
            mul(
                active,
                sub(col(f"rs1_next_{index}"), col(f"rs1_previous_{index}")),
            )
            for index in range(4)
        ],
        sub(active, const(1)),
        sub(col("bus_value_35"), opcode),
        sub(col("bus_value_36"), unsigned_imm),
        sub(col("bus_value_37"), next_pc),
        sub(col("bus_value_38"), next_clock),
        sub(col("bus_value_39"), source_clock),
        sub(col("bus_value_40"), destination_clock),
    ]
    lookups = [
        (
            "request",
            "program_access",
            neg(active),
            (col("pc"), opcode, rd, col("rs1_addr"), unsigned_imm),
        ),
        (
            "request",
            "range_check_8_11",
            neg(active),
            (i0, mul(i1, const(256))),
        ),
        ("consumed", "registers_state", neg(active), (col("pc"), clock)),
        (
            "emitted",
            "registers_state",
            active,
            (next_pc, next_clock),
        ),
        (
            "consumed",
            "memory_access",
            neg(active),
            (
                const(0),
                col("rs1_addr"),
                col("rs1_previous_clock"),
                *(col(f"rs1_previous_{index}") for index in range(4)),
            ),
        ),
        (
            "emitted",
            "memory_access",
            active,
            (
                const(0),
                col("rs1_addr"),
                source_clock,
                *(col(f"rs1_next_{index}") for index in range(4)),
            ),
        ),
        (
            "request",
            "range_check_20",
            neg(active),
            (sub(sub(source_clock, col("rs1_previous_clock")), const(1)),),
        ),
        *[
            (
                "request",
                "bitwise",
                neg(bitwise_active),
                (col(f"rs1_next_{index}"), imm[index], col(f"result_{index}"), operation),
            )
            for index in range(4)
        ],
        (
            "request",
            "range_check_8_8",
            neg(active),
            (col("result_0"), col("result_1")),
        ),
        (
            "request",
            "range_check_8_8",
            neg(active),
            (col("result_2"), col("result_3")),
        ),
        (
            "consumed",
            "memory_access",
            neg(active),
            (
                const(0),
                rd,
                col("rd_previous_clock"),
                *(col(f"rd_previous_{index}") for index in range(4)),
            ),
        ),
        (
            "emitted",
            "memory_access",
            active,
            (
                const(0),
                rd,
                destination_clock,
                *(col(f"rd_next_{index}") for index in range(4)),
            ),
        ),
        (
            "request",
            "range_check_20",
            neg(active),
            (sub(sub(destination_clock, col("rd_previous_clock")), const(1)),),
        ),
    ]
    return constraints, lookups


def _validate_exact(
    payload: dict[str, Any],
    family: str,
    expected: Callable[[], tuple[list[Expr], list[tuple[Any, ...]]]],
) -> None:
    _validate_schema(payload, family)
    if payload.get("modulus") != M31_MODULUS:
        raise RefinementError(f"{family}: wrong M31 modulus")
    if payload.get("family") != family:
        raise RefinementError(f"{family}: wrong family name")
    nodes = _decode_nodes(payload)
    constraints, lookups = expected()
    actual_constraints = _roots(payload, nodes)
    actual_lookups = _lookups(payload, nodes)
    referenced = set(payload["constraints"])
    for lookup in payload["lookups"]:
        referenced.add(lookup["numerator"])
        referenced.update(lookup["tuple"])
    frontier = list(referenced)
    while frontier:
        node_index = frontier.pop()
        for argument in payload["nodes"][node_index].get("args", ()):
            if argument not in referenced:
                referenced.add(argument)
                frontier.append(argument)
    if referenced != set(range(len(nodes))):
        raise RefinementError(f"{family}: AIR DAG contains unused nodes")
    if actual_constraints != constraints:
        raise RefinementError(
            f"{family}: production constraint shape drifted; review the proof bridge"
        )
    if actual_lookups != lookups:
        raise RefinementError(
            f"{family}: production lookup shape drifted; review the proof bridge"
        )


def validate_family(payload: dict[str, Any], family: str) -> None:
    if family == "lui":
        _validate_exact(payload, family, _expected_lui)
    elif family == "base_alu_imm":
        _validate_exact(payload, family, _expected_addi)
    else:
        raise RefinementError(f"unsupported pilot AIR family {family}")


def package_air(
    source_path: Path,
    opcode: str,
    source_digests: dict[str, str],
) -> dict[str, Any]:
    family = "lui" if opcode == "lui" else "base_alu_imm"
    payload = codec.load_json(source_path)
    validate_family(payload, family)
    result = dict(payload)
    result.update(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "stwo-riscv-refinement-air",
            "opcode": {
                "id": 35 if opcode == "lui" else 10,
                "mnemonic": opcode,
                "family": family,
                "selector": (
                    {"enabler": 1}
                    if opcode == "lui"
                    else {
                        "is_addi": 1,
                        "is_xori": 0,
                        "is_ori": 0,
                        "is_andi": 0,
                    }
                ),
            },
            "production_binding": {
                "level": "level-1-exact-shape-normalizer",
                "source_ir_sha256": codec.sha256_file(source_path),
                "source_closure_sha256": codec.sha256_bytes(
                    codec.canonical_bytes(source_digests)
                ),
                "extractor": "src/frontends/riscv/air/extract/mod.zig",
                "differential_trials_per_family": 8,
            },
            "projection": {
                "program_lookup": 0,
                "state_consume_lookup": 1 if opcode == "lui" else 2,
                "state_emit_lookup": 2 if opcode == "lui" else 3,
                "source_access_lookups": [] if opcode == "lui" else [4, 5],
                "destination_access_lookups": [4, 5] if opcode == "lui" else [13, 14],
                "next_pc_column": (
                    "bus_value_19" if opcode == "lui" else "bus_value_37"
                ),
            },
        }
    )
    result["canonical_digest"] = codec.content_digest(result)
    return result
