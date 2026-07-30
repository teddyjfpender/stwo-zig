"""Pinned source, generator, proof, and artifact closures for rendering."""

from __future__ import annotations

from . import air_program

SOURCE_PATHS = (
    "build.zig",
    "build.zig.zon",
    "build_support/build.zig.zon",
    "build_support/graph/delegation.zig",
    "build_support/internal_build.zig",
    "build_support/products/catalog.zig",
    "build_support/products/matrix.zig",
    "build_support/products/package_dependencies.zig",
    "build_support/products/product_specs.zig",
    "build_support/products/riscv_cpu.zig",
    "build_support/products/riscv_refinement.zig",
    "build_support/products/riscv_test_filter.zig",
    "src/core/build.zig",
    "src/core/build.zig.zon",
    "src/core/mod.zig",
    "src/frontends/riscv/refinement_ir_export_test.zig",
    "src/frontends/riscv/refinement_program_export_test.zig",
)
SOURCE_TREES = (
    "build_support/graph",
    "src/core/fields",
    "src/frontends/riscv",
)

GENERATOR_PATHS = (
    ".github/workflows/riscv-sail-formal.yml",
    ".github/workflows/riscv-team-b-refinement.yml",
    "scripts/riscv_refinement.py",
    "scripts/riscv_opcode_coverage.py",
    "scripts/riscv_team_a.py",
    "scripts/riscv_team_b.py",
    "scripts/riscv_team_b_inventory.py",
    "scripts/riscv_team_b_refresh.py",
    "scripts/riscv_team_b_witnesses.py",
    "scripts/riscv_refinement_lib/model.py",
    "scripts/riscv_refinement_lib/codec.py",
    "scripts/riscv_refinement_lib/air.py",
    "scripts/riscv_refinement_lib/air_program.py",
    "scripts/riscv_refinement_lib/air_program_contract.py",
    "scripts/riscv_refinement_lib/air_program_lean.py",
    "scripts/riscv_refinement_lib/air_program_registry_lean.py",
    "scripts/riscv_refinement_lib/sail.py",
    "scripts/riscv_refinement_lib/sail_lean_bridge.py",
    "scripts/riscv_refinement_lib/sail_translation.py",
    "scripts/riscv_refinement_lib/negative.py",
    "scripts/riscv_refinement_lib/render.py",
    "scripts/riscv_refinement_lib/render_paths.py",
    "scripts/riscv_refinement_lib/render_validation.py",
    "scripts/tests/test_riscv_refinement.py",
    "scripts/tests/test_sail_air_composition_contract.py",
    "scripts/tests/test_sail_translation.py",
    "scripts/tests/test_riscv_team_a.py",
    "scripts/tests/test_riscv_team_b.py",
    "scripts/tests/test_riscv_team_b_inventory.py",
    "scripts/tests/test_riscv_team_b_refresh.py",
    "scripts/tests/test_riscv_team_b_witnesses.py",
)
GENERATOR_GLOBS = (
    "scripts/riscv_refinement_*.py",
    "scripts/riscv_team_a_*.py",
    "scripts/riscv_team_b_*.py",
    "scripts/riscv_refinement_lib/*.py",
    "scripts/riscv_team_b_witnesses_lib/*.py",
    "scripts/tests/_riscv_team_b_witnesses_*.py",
    "scripts/tests/riscv_refinement_test_support.py",
    "scripts/tests/test_riscv_refinement_*.py",
)

PROOF_PATHS = (
    "formal/riscv-refinement/README.md",
    "formal/riscv-refinement/TEAM_B.md",
    "formal/riscv-refinement/lean-toolchain",
    "formal/riscv-refinement/lake-manifest.json",
    "formal/riscv-refinement/lakefile.toml",
    "formal/riscv-refinement/RiscvRefinement.lean",
    "conformance/riscv/sail-lean-riscv-extras.patch",
    "soundness/AIR_IR_V2_CONTRACT.md",
    "soundness/SAIL_AIR_COMPOSITION.md",
    "soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md",
    "soundness/air-ir-v2.schema.json",
)
PROOF_TREES = (
    "formal/riscv-refinement/RiscvRefinement",
    "formal/riscv-refinement/generated-sail-bridge",
)
PROOF_TREE_EXCLUDES = (
    "formal/riscv-refinement/RiscvRefinement/Air/Generated",
    "formal/riscv-refinement/RiscvRefinement/Sail/Generated",
)
PROOF_GLOBS = (
    "formal/riscv-refinement/*-coverage.json",
)

EXPORTED_FAMILIES = frozenset(
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
MANIFEST_ARTIFACTS = frozenset(
    {
        "RiscvRefinement/Air/Generated/Pilot.lean",
        "RiscvRefinement/Air/Generated/LuiProgram.lean",
        "RiscvRefinement/Air/Generated/Programs.lean",
        "RiscvRefinement/Sail/Generated/Pilot.lean",
        "generated/air/addi.json",
        "generated/air/lui.json",
        "generated/sail/rv32im-zkvm-v1.json",
        "generated/sail/definitions/execute_ITYPE.lean",
        "generated/sail/definitions/execute_RTYPE.lean",
        "generated/sail/definitions/execute_UTYPE.lean",
        "generated/sail/generated-monad-bridge-receipt-v1.json",
        "generated/sail/translation-receipt-v1.json",
        *(
            f"generated/air/{mnemonic}.air-ir-v2.json"
            for _, mnemonic, _ in air_program.OPCODES
        ),
    }
)
