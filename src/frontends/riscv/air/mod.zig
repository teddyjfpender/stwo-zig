//! RISC-V AIR (Algebraic Intermediate Representation) module.
//!
//! Provides the constraint definitions, trace column layouts, claim types,
//! and relation definitions for the RV32IM zkVM.
//!
//! Opcode AIR has one ownership path: `semantic_component` owns the family
//! constraints and `lookups` owns their relation wiring. Keep that split
//! explicit rather than introducing a second per-family component facade whose
//! layouts can drift from the committed trace.

pub const claims = @import("claims.zig");
pub const clock_update_component = @import("clock_update_component.zig");
pub const clock_update_interaction = @import("clock_update_interaction.zig");
pub const component_order = @import("component_order.zig");
pub const composition_work_support = @import("composition_work_support.zig");
pub const constraint_program = @import("constraint_program.zig");
pub const diagnostic_hints = @import("diagnostic_hints.zig");
pub const extract = @import("extract/mod.zig");
pub const guest_precompile = @import("guest_precompile/mod.zig");
pub const interaction = @import("interaction.zig");
pub const interaction_gen = @import("interaction_gen.zig");
pub const logup = @import("logup.zig");
pub const lookups = @import("lookups/mod.zig");
pub const lookup_physical_manifest_v2 =
    @import("lang/lookup_physical_manifest_v2.zig");
pub const lookup_batch_execution = @import("lang/lookup_batch_execution.zig");
pub const lookup_polynomial_program_v2 =
    @import("lang/lookup_polynomial_program_v2.zig");
pub const memory_commitment = @import("memory_commitment/mod.zig");
pub const typed_poseidon2_authority = @import("lang/typed_poseidon2_authority.zig");
pub const memory_logup = @import("memory_logup.zig");
pub const opcode_memory = @import("opcode_memory.zig");
pub const public_data = @import("public_data.zig");
pub const public_data_v2 = @import("public_data_v2.zig");
pub const public_logup = @import("public_logup.zig");
pub const public_logup_v2 = @import("public_logup_v2.zig");
pub const program = @import("program/mod.zig");
pub const relation_challenges = @import("relation_challenges.zig");
pub const relation_evidence = @import("relation_evidence.zig");
pub const relation_export = @import("relation_export.zig");
pub const relation_export_components = @import("relation_export_components.zig");
pub const relations = @import("relations.zig");
pub const semantic_component = @import("semantic_component.zig");
pub const semantic_eval = @import("semantic_eval.zig");
pub const semantics = @import("semantics/mod.zig");
pub const statement = @import("statement.zig");
pub const statement_v2 = @import("statement_v2.zig");
pub const transcript = @import("transcript/mod.zig");
pub const trace_columns = @import("trace_columns.zig");
pub const preprocessed = @import("preprocessed/mod.zig");
pub const profiling = @import("profiling.zig");

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
    // `refAllDecls` references these lazily from inside a test body, which is
    // too late for the test runner to collect the tests they contain.
    _ = @import("constraint_program.zig");
    _ = @import("extract/mod.zig");
    _ = @import("semantic_eval.zig");
}
