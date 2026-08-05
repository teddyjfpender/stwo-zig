//! Every test-bearing file in this package, named once so the test binary
//! contains all of them.
//!
//! ## Why this file exists
//!
//! Zig collects a `test` declaration only from a file the compiler was made to
//! analyse. A `pub const x = @import("x.zig")` at the top of a `mod.zig` does
//! not do that, and neither does `std.testing.refAllDecls` or
//! `refAllDeclsRecursive` -- both reference decls from *inside* a test body,
//! which is after the runner's test list is fixed. The only thing that works is
//! a literal `_ = @import("...")` in a `test` block reachable from the module
//! root, which is why `air/mod.zig` already carries two of them with that
//! comment attached.
//!
//! Relying on that per directory left 142 named tests in this package compiled
//! by nothing at all -- not by this package's own `test` step, and not by any
//! product gate. Measured before this file existed: 458 named `test` blocks in
//! the tree, 316 of them in the binary. Among the missing were every pin in
//! `air/diagnostic_hints.zig` (now `air/diagnostic_hints_test.zig`),
//! `air/interaction.zig` and `prover/statement_validation.zig`.
//!
//! ## The rule
//!
//! A new test-bearing file in this package must be named below. A file already
//! reachable some other way may be listed anyway -- a duplicate import is free,
//! and a complete list is what makes "is my test compiled?" answerable by
//! reading one file.
//!
//! `test_inventory_test.zig` walks this directory tree and fails if a file
//! holding a `test` block is missing from the list, so the list cannot silently
//! fall behind the tree. The test-count floors in
//! `src/frontends/riscv/build.zig` and `build_support/products/riscv_cpu.zig`
//! fail if a rewiring drops the tests back out of a binary.
//!
//! Deliberately excluded: `refinement_ir_export_test.zig`, whose single test
//! demands `RISCV_AIR_IR_DIR` and is driven by the `riscv-refinement-ir` step
//! with that variable set; and `mod.zig`, the module root, whose tests are
//! always collected.

test {
    // Package root.
    _ = @import("access_clock.zig");
    _ = @import("air_semantics_test_root.zig");
    _ = @import("infra_trace.zig");
    _ = @import("isa_test_root.zig");
    _ = @import("opcode_coverage_test.zig");
    _ = @import("opcode_manifest.zig");
    _ = @import("owned_statement.zig");
    _ = @import("proof_transcript.zig");
    _ = @import("runner_test_root.zig");
    _ = @import("testing.zig");
    _ = @import("witness_layout.zig");

    // Host interface.
    _ = @import("host/hint_oracle.zig");
    _ = @import("host/mod.zig");
    _ = @import("host/runtime.zig");

    // Instruction decode and profile authority.
    _ = @import("isa/authority.zig");
    _ = @import("isa/decode.zig");
    _ = @import("isa/mod.zig");
    _ = @import("isa/profile.zig");

    // Sail-authoritative execution and trace capture.
    _ = @import("runner/access_witness.zig");
    _ = @import("runner/cpu.zig");
    _ = @import("runner/decode.zig");
    _ = @import("runner/decode_cache.zig");
    _ = @import("runner/elf_loader.zig");
    _ = @import("runner/execute.zig");
    _ = @import("runner/memory.zig");
    _ = @import("runner/memory_state.zig");
    _ = @import("runner/mod.zig");
    _ = @import("runner/sail_oracle.zig");
    _ = @import("runner/state_chain.zig");
    _ = @import("runner/trace.zig");
    _ = @import("runner/trace_dump.zig");

    // Per-family witness derivation.
    _ = @import("runner/witness/load_store.zig");
    _ = @import("runner/witness/m_extension.zig");
    _ = @import("runner/witness/shift.zig");

    // AIR: claims, components, relations and diagnostics.
    _ = @import("air/claims.zig");
    _ = @import("air/clock_update_component_test.zig");
    _ = @import("air/component.zig");
    _ = @import("air/component_order.zig");
    _ = @import("air/diagnostic_hints_test.zig");
    _ = @import("air/interaction.zig");
    _ = @import("air/interaction_gen.zig");
    _ = @import("air/logup.zig");
    _ = @import("air/memory_logup.zig");
    _ = @import("air/mod.zig");
    _ = @import("air/opcode_memory.zig");
    _ = @import("air/public_data.zig");
    _ = @import("air/public_logup.zig");
    _ = @import("air/relation_challenges.zig");
    _ = @import("air/relation_evidence.zig");
    _ = @import("air/relation_export_components_test.zig");
    _ = @import("air/relation_export_test.zig");
    _ = @import("air/relations.zig");
    _ = @import("air/semantic_component_test.zig");
    _ = @import("air/semantic_eval.zig");
    _ = @import("air/trace_columns.zig");

    // AIR: isolated typed authoring kernel.
    _ = @import("air/lang/authoring_test.zig");
    _ = @import("air/lang/compat_layout_test.zig");
    _ = @import("air/lang/compat_manifest_diff_test.zig");
    _ = @import("air/lang/compat_manifest_test.zig");
    _ = @import("air/lang/degree_test.zig");
    _ = @import("air/lang/diagnostic_test.zig");
    _ = @import("air/lang/digest_test.zig");
    _ = @import("air/lang/finalization_test.zig");
    _ = @import("air/lang/hint_recipe_test.zig");
    _ = @import("air/lang/hints_test.zig");
    _ = @import("air/lang/kernel_test.zig");
    _ = @import("air/lang/lower_air_ir_test.zig");
    _ = @import("air/lang/lower_constraint_test.zig");
    _ = @import("air/lang/lower_lookup_test.zig");
    _ = @import("air/lang/lower_runtime_test.zig");
    _ = @import("air/lang/manifest_test.zig");
    _ = @import("air/lang/mod.zig");
    _ = @import("air/lang/program_test.zig");
    _ = @import("air/lang/protocol_degree_test.zig");
    _ = @import("air/lang/protocol_report_test.zig");
    _ = @import("air/lang/relation_test.zig");
    _ = @import("air/lang/shadow_import_test.zig");
    _ = @import("air/lang/shadow_program_test.zig");
    _ = @import("air/lang/static_collections_test.zig");
    _ = @import("air/lang/typed_poseidon2_test.zig");
    _ = @import("air/lang/validate_test.zig");

    // AIR: relation wiring.
    _ = @import("air/lookups/entry.zig");
    _ = @import("air/lookups/mod.zig");
    _ = @import("air/lookups/opcode_component.zig");
    _ = @import("air/lookups/opcode_entries.zig");
    _ = @import("air/lookups/opcode_interaction_test.zig");

    // AIR: preprocessed lookup tables.
    _ = @import("air/lookups/tables/component.zig");
    _ = @import("air/lookups/tables/counter.zig");
    _ = @import("air/lookups/tables/interaction.zig");
    _ = @import("air/lookups/tables/mod.zig");
    _ = @import("air/lookups/tables/schema.zig");
    _ = @import("air/lookups/tables/source_ingest.zig");

    // AIR: memory commitment.
    _ = @import("air/memory_commitment/boundary.zig");
    _ = @import("air/memory_commitment/hash_component.zig");
    _ = @import("air/memory_commitment/interaction.zig");
    _ = @import("air/memory_commitment/merkle_node.zig");
    _ = @import("air/memory_commitment/mod.zig");
    _ = @import("air/memory_commitment/poseidon2.zig");
    _ = @import("air/memory_commitment/poseidon2_air.zig");
    _ = @import("air/memory_commitment/sparse_merkle.zig");
    _ = @import("air/memory_commitment/trace.zig");

    // AIR: transcript protocol.
    _ = @import("air/transcript/claims.zig");
    _ = @import("air/transcript/mod.zig");
    _ = @import("air/transcript/protocol.zig");

    // AIR: preprocessed range and bitwise tables.
    _ = @import("air/preprocessed/bitwise.zig");
    _ = @import("air/preprocessed/mod.zig");
    _ = @import("air/preprocessed/range_check.zig");

    // AIR: per-family opcode semantics.
    _ = @import("air/semantics/auipc.zig");
    _ = @import("air/semantics/base_alu_imm.zig");
    _ = @import("air/semantics/base_alu_reg.zig");
    _ = @import("air/semantics/branch_eq.zig");
    _ = @import("air/semantics/branch_lt.zig");
    _ = @import("air/semantics/common.zig");
    _ = @import("air/semantics/control_common.zig");
    _ = @import("air/semantics/div.zig");
    _ = @import("air/semantics/fence.zig");
    _ = @import("air/semantics/jal.zig");
    _ = @import("air/semantics/jalr.zig");
    _ = @import("air/semantics/load_store.zig");
    _ = @import("air/semantics/lt_imm.zig");
    _ = @import("air/semantics/lt_reg.zig");
    _ = @import("air/semantics/lui.zig");
    _ = @import("air/semantics/mod.zig");
    _ = @import("air/semantics/mul.zig");
    _ = @import("air/semantics/mulh.zig");
    _ = @import("air/semantics/shift_common.zig");
    _ = @import("air/semantics/shifts_imm.zig");
    _ = @import("air/semantics/shifts_reg.zig");

    // AIR: committed column layout.
    _ = @import("air/trace_columns/m_extension.zig");

    // AIR: program commitment.
    _ = @import("air/program/commitment.zig");
    _ = @import("air/program/decode.zig");
    _ = @import("air/program/interaction.zig");
    _ = @import("air/program/mod.zig");
    _ = @import("air/program/opcode.zig");
    _ = @import("air/program/table.zig");

    // AIR: symbolic extraction for the uniqueness model.
    _ = @import("air/extract/mod.zig");
    _ = @import("air/extract/runtime_program.zig");
    _ = @import("air/extract/symbolic.zig");

    // Shared primitives.
    _ = @import("common/poseidon2.zig");

    // Diagnostic dumps.
    _ = @import("diagnostics/mod.zig");
    _ = @import("diagnostics/public_values.zig");

    // Proof orchestration.
    _ = @import("prover/lookup_sources.zig");
    _ = @import("prover/opcode_trace.zig");
    _ = @import("prover/preprocessed.zig");
    _ = @import("prover/proof_workspace.zig");
    _ = @import("prover/statement_validation.zig");
    _ = @import("prover/test_witness_hook.zig");
    _ = @import("prover/trace_arena.zig");
    _ = @import("prover/verifier_test.zig");
    _ = @import("air/constraint_program.zig");
    _ = @import("air/extract/program.zig");
    _ = @import("air/extract/program_json.zig");
    _ = @import("sail_oracle_test_root.zig");
}
