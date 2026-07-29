"""Frozen constants for the versioned production AIR program contract."""

from __future__ import annotations

import re

AIR_IR_SCHEMA_VERSION = 2
AIR_IR_KIND = "stwo-riscv-air-constraint-program"
M31_NAME = "M31"
M31_TYPE = "m31"
LOOKUP_LIVENESS = "nonzero_numerator"
FAMILIES = frozenset(
    {
        "auipc",
        "base_alu_imm",
        "base_alu_reg",
        "branch_eq",
        "branch_lt",
        "div",
        "fence",
        "jal",
        "jalr",
        "load_store",
        "lt_imm",
        "lt_reg",
        "lui",
        "mul",
        "mulh",
        "shifts_imm",
        "shifts_reg",
    }
)
FAMILY_OPCODES = {
    "base_alu_reg": frozenset(
        {(0, "add"), (1, "sub"), (5, "xor"), (8, "or"), (9, "and")}
    ),
    "base_alu_imm": frozenset(
        {(10, "addi"), (13, "xori"), (14, "ori"), (15, "andi")}
    ),
    "shifts_reg": frozenset({(2, "sll"), (6, "srl"), (7, "sra")}),
    "shifts_imm": frozenset({(16, "slli"), (17, "srli"), (18, "srai")}),
    "lt_reg": frozenset({(3, "slt"), (4, "sltu")}),
    "lt_imm": frozenset({(11, "slti"), (12, "sltiu")}),
    "branch_eq": frozenset({(27, "beq"), (28, "bne")}),
    "branch_lt": frozenset(
        {(29, "blt"), (30, "bge"), (31, "bltu"), (32, "bgeu")}
    ),
    "lui": frozenset({(35, "lui")}),
    "auipc": frozenset({(36, "auipc")}),
    "jalr": frozenset({(34, "jalr")}),
    "jal": frozenset({(33, "jal")}),
    "load_store": frozenset(
        {
            (19, "lb"),
            (20, "lh"),
            (21, "lw"),
            (22, "lbu"),
            (23, "lhu"),
            (24, "sb"),
            (25, "sh"),
            (26, "sw"),
        }
    ),
    "mul": frozenset({(37, "mul")}),
    "mulh": frozenset({(38, "mulh"), (39, "mulhsu"), (40, "mulhu")}),
    "div": frozenset(
        {(41, "div"), (42, "divu"), (43, "rem"), (44, "remu")}
    ),
    "fence": frozenset({(45, "fence")}),
}

BUS_ARITIES = {
    "registers_state": 2,
    "memory_access": 7,
    "program_access": 5,
    "merkle": 4,
    "poseidon2": 16,
    "poseidon2_io": 32,
}
FIXED_TABLES = (
    ("bitwise", 4, 18),
    ("range_check_20", 1, 20),
    ("range_check_8_11", 2, 19),
    ("range_check_8_8_4", 3, 20),
    ("range_check_8_8", 2, 16),
    ("range_check_m31", 2, 15),
)
FIXED_ARITIES = {name: arity for name, arity, _ in FIXED_TABLES}
DOMAIN_ARITIES = BUS_ARITIES | FIXED_ARITIES
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

TOP_LEVEL_KEYS = {
    "active_row",
    "columns",
    "content_digest",
    "events",
    "family",
    "field",
    "fixed_tables",
    "kind",
    "nodes",
    "opcode_selector",
    "projection",
    "schema_version",
    "source_identity",
}
UNSIGNED_TOP_LEVEL_KEYS = TOP_LEVEL_KEYS - {"content_digest", "source_identity"}

SOURCE_IDENTITY_BUILDER = "src/frontends/riscv/air/constraint_program.zig"
COMMON_SOURCE_PATHS = (
    "src/core/fields/cm31.zig",
    "src/core/fields/m31.zig",
    "src/core/fields/qm31.zig",
    "src/frontends/riscv/access_clock.zig",
    "src/frontends/riscv/air/constraint_program.zig",
    "src/frontends/riscv/air/extract/model.zig",
    "src/frontends/riscv/air/extract/program.zig",
    "src/frontends/riscv/air/extract/program_json.zig",
    "src/frontends/riscv/air/extract/symbolic.zig",
    "src/frontends/riscv/air/lookups/entry.zig",
    "src/frontends/riscv/air/lookups/opcode_entries.zig",
    "src/frontends/riscv/air/lookups/tables/schema.zig",
    "src/frontends/riscv/air/program/opcode.zig",
    "src/frontends/riscv/air/semantic_eval.zig",
    "src/frontends/riscv/air/semantics/common.zig",
    "src/frontends/riscv/air/semantics/mod.zig",
    "src/frontends/riscv/opcode_manifest.zig",
    "src/frontends/riscv/runner/trace.zig",
)

FAMILY_SEMANTIC_PATHS = {
    "base_alu_reg": ("src/frontends/riscv/air/semantics/base_alu_reg.zig",),
    "base_alu_imm": ("src/frontends/riscv/air/semantics/base_alu_imm.zig",),
    "shifts_reg": (
        "src/frontends/riscv/air/semantics/shift_common.zig",
        "src/frontends/riscv/air/semantics/shifts_reg.zig",
    ),
    "shifts_imm": (
        "src/frontends/riscv/air/semantics/shift_common.zig",
        "src/frontends/riscv/air/semantics/shifts_imm.zig",
    ),
    "lt_reg": ("src/frontends/riscv/air/semantics/lt_reg.zig",),
    "lt_imm": ("src/frontends/riscv/air/semantics/lt_imm.zig",),
    "branch_eq": (
        "src/frontends/riscv/air/semantics/branch_eq.zig",
        "src/frontends/riscv/air/semantics/control_common.zig",
    ),
    "branch_lt": (
        "src/frontends/riscv/air/semantics/branch_lt.zig",
        "src/frontends/riscv/air/semantics/control_common.zig",
    ),
    "lui": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/lui.zig",
    ),
    "auipc": (
        "src/frontends/riscv/air/semantics/auipc.zig",
        "src/frontends/riscv/air/semantics/control_common.zig",
    ),
    "jalr": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/jalr.zig",
    ),
    "jal": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/jal.zig",
    ),
    "load_store": ("src/frontends/riscv/air/semantics/load_store.zig",),
    "mul": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/mul.zig",
    ),
    "mulh": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/mulh.zig",
    ),
    "div": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/div.zig",
    ),
    "fence": (
        "src/frontends/riscv/air/semantics/control_common.zig",
        "src/frontends/riscv/air/semantics/fence.zig",
    ),
}

FAMILY_SOURCE_PATHS = {
    family: tuple(sorted((*COMMON_SOURCE_PATHS, *FAMILY_SEMANTIC_PATHS[family])))
    for family in FAMILIES
}

# Backward-compatible name used by the LUI decoder tests and frozen contract.
LUI_SOURCE_PATHS = FAMILY_SOURCE_PATHS["lui"]

OPCODES = tuple(
    sorted(
        (
            manifest_id,
            mnemonic,
            family,
        )
        for family, members in FAMILY_OPCODES.items()
        for manifest_id, mnemonic in members
    )
)
OPCODE_FAMILY = {
    mnemonic: family for _, mnemonic, family in OPCODES
}
