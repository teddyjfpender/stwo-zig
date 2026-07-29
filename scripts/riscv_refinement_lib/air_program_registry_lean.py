"""Render the strict Lean registry for every production AIR IR v2 program."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from . import codec

FAMILY = {
    "base_alu_reg": "baseAluReg",
    "base_alu_imm": "baseAluImm",
    "shifts_reg": "shiftsReg",
    "shifts_imm": "shiftsImm",
    "lt_reg": "ltReg",
    "lt_imm": "ltImm",
    "branch_eq": "branchEq",
    "branch_lt": "branchLt",
    "lui": "lui",
    "auipc": "auipc",
    "jalr": "jalr",
    "jal": "jal",
    "load_store": "loadStore",
    "mul": "mul",
    "mulh": "mulh",
    "div": "div",
    "fence": "fence",
}
DOMAIN = {
    "registers_state": "registersState",
    "memory_access": "memoryAccess",
    "program_access": "programAccess",
    "merkle": "merkle",
    "poseidon2": "poseidon2",
    "poseidon2_io": "poseidon2Io",
    "bitwise": "bitwise",
    "range_check_20": "rangeCheck20",
    "range_check_8_11": "rangeCheck811",
    "range_check_8_8_4": "rangeCheck884",
    "range_check_8_8": "rangeCheck88",
    "range_check_m31": "rangeCheckM31",
}
TABLE = {
    "bitwise": "bitwise",
    "range_check_20": "rangeCheck20",
    "range_check_8_11": "rangeCheck811",
    "range_check_8_8_4": "rangeCheck884",
    "range_check_8_8": "rangeCheck88",
    "range_check_m31": "rangeCheckM31",
}


def _string(value: str) -> str:
    return codec.canonical_bytes(value).decode("ascii")


def _array(values: Iterable[str]) -> str:
    return "#[" + ", ".join(values) + "]"


def _list(values: Iterable[str]) -> str:
    return "[" + ", ".join(values) + "]"


def _option(value: Any, render_value: Any = str) -> str:
    return "none" if value is None else f"some {render_value(value)}"


def _node(node: Mapping[str, Any]) -> str:
    operation = node["op"]
    if operation == "const":
        return f"ExprNode.const (M31.reduce {node['value']})"
    if operation == "col":
        return f"ExprNode.column {node['column']}"
    args = node["args"]
    if operation == "neg":
        return f"ExprNode.neg {args[0]}"
    return f"ExprNode.{operation} {args[0]} {args[1]}"


def _local_node(index: int, node: Mapping[str, Any]) -> str:
    operation = node["op"]
    if operation == "const":
        return f"LocalExprNode.const (M31.reduce {node['value']})"
    if operation == "col":
        return f"LocalExprNode.column {node['column']}"
    offsets = [index - argument - 1 for argument in node["args"]]
    if any(offset < 0 for offset in offsets):
        raise ValueError("AIR IR v2 local node has a forward reference")
    if operation == "neg":
        return f"LocalExprNode.neg {offsets[0]}"
    return f"LocalExprNode.{operation} {offsets[0]} {offsets[1]}"


def _event(event: Mapping[str, Any]) -> str:
    if event["kind"] == "constraint":
        return (
            ".constraint { "
            f"ordinal := {event['ordinal']}, root := {event['root']}"
            " }"
        )
    table = _option(event["table_id"], lambda value: f".{TABLE[value]}")
    access = _option(event["access_ordinal"])
    return (
        ".lookup { "
        f"ordinal := {event['ordinal']}, "
        f"domain := .{DOMAIN[event['domain']]}, "
        f"numerator := {event['numerator']}, "
        f"tuple := {_array(str(value) for value in event['tuple'])}, "
        f"role := .{event['role']}, "
        f"tableId := {table}, "
        "liveness := .nonzeroNumerator, "
        f"accessOrdinal := {access}"
        " }"
    )


def _source_program(mnemonic: str, payload: Mapping[str, Any]) -> list[str]:
    selector = payload["opcode_selector"]
    projection = payload["projection"]
    return [
        f"def {mnemonic}Source : ConstraintProgram where",
        f"  schemaVersion := {payload['schema_version']}",
        f"  kind := {_string(payload['kind'])}",
        "  field := { "
        f"name := {_string(payload['field']['name'])}, "
        f"modulus := {payload['field']['modulus']}"
        " }",
        f"  family := .{FAMILY[payload['family']]}",
        "  columns := "
        + _array(
            (
                "{ "
                f"index := {column['index']}, "
                f"name := {_string(column['name'])}, "
                f"role := .{column['role']}"
                " }"
            )
            for column in payload["columns"]
        ),
        f"  nodes := {_array(_node(node) for node in payload['nodes'])}",
        f"  activeRow := {payload['active_row']}",
        "  opcodeSelector := { "
        f"manifestId := {selector['manifest_id']}, "
        f"mnemonic := {_string(selector['mnemonic'])}, "
        f"expression := {selector['expression']}"
        " }",
        "  fixedTables := "
        + _array(
            (
                "{ "
                f"id := .{TABLE[table['id']]}, "
                f"domain := .{DOMAIN[table['domain']]}, "
                f"arity := {table['arity']}, "
                f"logSize := {table['log_size']}, "
                f"schemaSha256 := {_string(table['schema_sha256'])}"
                " }"
            )
            for table in payload["fixed_tables"]
        ),
        f"  events := {_array(_event(event) for event in payload['events'])}",
        "  projection := { "
        f"programEvent := {projection['program_event']}, "
        "stateEvents := "
        f"{_array(str(value) for value in projection['state_events'])}, "
        "sourceEvents := "
        f"{_array(str(value) for value in projection['source_events'])}, "
        "destinationEvents := "
        f"{_array(str(value) for value in projection['destination_events'])}, "
        f"nextPc := {projection['next_pc']}"
        " }",
        "  sourceIdentity := { "
        f"builder := {_string(payload['source_identity']['builder'])}, "
        "sourceClosureSha256 := "
        f"{_string(payload['source_identity']['source_closure_sha256'])}, "
        "files := "
        + _array(
            (
                "{ "
                f"path := {_string(source['path'])}, "
                f"sha256 := {_string(source['sha256'])}"
                " }"
            )
            for source in payload["source_identity"]["files"]
        )
        + " }",
        f"  contentDigest := {_string(payload['content_digest'])}",
        "",
        f"def {mnemonic} : LocalProgram where",
        f"  source := {mnemonic}Source",
        "  nodes := "
        + _list(
            _local_node(index, node)
            for index, node in enumerate(payload["nodes"])
        ),
        "",
        "set_option maxRecDepth 20000 in",
        f"theorem {mnemonic}SymbolicCertificate : {mnemonic}.SymbolicCertificate := by",
        "  constructor <;> rfl",
        "",
    ]


def render(
    programs: Mapping[str, bytes],
    opcodes: Iterable[tuple[int, str, str]],
) -> bytes:
    entries = list(opcodes)
    lines = [
        "-- GENERATED FILE. DO NOT EDIT.",
        "-- Generator: scripts/riscv_refinement.py",
        "-- Regenerate: python3 scripts/riscv_refinement.py generate",
        "-- Binding: exact canonical production AIR IR v2 for all 46 selectors.",
        "",
        "import RiscvRefinement.Air",
        "",
        "namespace RiscvRefinement.Air.Generated.Programs",
        "",
    ]
    for _, mnemonic, _ in entries:
        payload = json.loads(programs[mnemonic])
        encoded = _string(programs[mnemonic].decode("ascii"))
        lines.extend(
            [
                f"def {mnemonic}Json : String :=",
                f"  {encoded}",
                "",
                *_source_program(mnemonic, payload),
            ]
        )
    lines.extend(
        [
            "structure Entry where",
            "  mnemonic : String",
            "  encoded : String",
            "  program : LocalProgram",
            "  symbolicCertificate : program.SymbolicCertificate",
            "",
            "def all : List Entry := [",
            *[
                "  { "
                f'mnemonic := "{mnemonic}", '
                f"encoded := {mnemonic}Json, "
                f"program := {mnemonic}, "
                f"symbolicCertificate := {mnemonic}SymbolicCertificate"
                " },"
                for _, mnemonic, _ in entries
            ],
            "]",
            "",
            "def allBindingsValid : Bool :=",
            "  all.all fun entry =>",
            "    entry.program.matchesCanonicalJson entry.encoded",
            "",
            "#guard allBindingsValid",
            "",
            "end RiscvRefinement.Air.Generated.Programs",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")
