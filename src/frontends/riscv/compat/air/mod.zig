//! RISC-V AIR (Algebraic Intermediate Representation) module.
//!
//! Provides the constraint definitions, trace column layouts, claim types,
//! and relation definitions for the RV32IM zkVM.
//!
//! Opcode AIR has one ownership path: `semantic_component` owns the family
//! constraints and `lookups` owns their relation wiring. Keep that split
//! explicit rather than introducing a second per-family component facade whose
//! layouts can drift from the committed trace.

pub const claims = @import("stwo_riscv_rv32").air_claims;
pub const clock_update_component = @import("stwo_riscv_rv32").air_clock_update_component;
pub const clock_update_interaction = @import("stwo_riscv_rv32").air_clock_update_interaction;
pub const component_order = @import("stwo_riscv_rv32").air_component_order;
pub const composition_work_support = @import("stwo_riscv_air_lang").shared_air_composition_work_support;
pub const constraint_program = @import("stwo_riscv_rv32").air_constraint_program;
pub const diagnostic_hints = @import("stwo_riscv_rv32").air_diagnostic_hints;
pub const extract = @import("stwo_riscv_rv32").air_extract_mod;
pub const guest_precompile = @import("stwo_riscv_precompiles").air_mod;
pub const interaction = @import("stwo_riscv_rv32").air_interaction;
pub const logup = @import("stwo_riscv_air_lang").shared_air_logup;
pub const lookups = @import("stwo_riscv_rv32").air_lookups_mod;
pub const lookup_physical_manifest_v2 =
    @import("stwo_riscv_rv32").air_lang_lookup_physical_manifest;
pub const lookup_batch_execution = @import("stwo_riscv_rv32").air_lang_lookup_batch_execution;
pub const memory_commitment = @import("stwo_riscv_memory").air_mod;
pub const typed_poseidon2_authority = @import("stwo_riscv_memory").typed_typed_poseidon2_authority;
pub const typed_poseidon2_degree_bounded_candidate =
    @import("stwo_riscv_memory").typed_typed_poseidon2_degree_bounded_candidate;
pub const typed_poseidon2_degree_bounded_component =
    @import("stwo_riscv_memory").typed_typed_poseidon2_degree_bounded_component;
pub const typed_poseidon2_degree_bounded_trace =
    @import("stwo_riscv_memory").typed_typed_poseidon2_degree_bounded_trace;
pub const typed_poseidon2_degree5_component =
    @import("stwo_riscv_memory").typed_typed_poseidon2_degree5_component;
pub const typed_poseidon2_degree5_backend =
    @import("stwo_riscv_rv32").air_lang_typed_poseidon2_degree5_backend;
pub const typed_poseidon2_degree5_trace =
    @import("stwo_riscv_memory").typed_typed_poseidon2_degree5_trace;
pub const memory_logup = @import("stwo_riscv_rv32").air_memory_logup;
pub const opcode_memory = @import("stwo_riscv_rv32").air_opcode_memory;
pub const public_data = @import("stwo_riscv_rv32").air_public_data;
pub const public_data_v2 = @import("stwo_riscv_rv32").air_public_data_v2;
pub const public_logup = @import("stwo_riscv_rv32").air_public_logup;
pub const public_logup_v2 = @import("stwo_riscv_rv32").air_public_logup_v2;
pub const program = @import("stwo_riscv_rv32").air_program_mod;
pub const relation_challenges = @import("stwo_riscv_air_lang").shared_air_relation_challenges;
pub const relation = @import("stwo_riscv_air_lang").relation;
pub const relation_evidence = @import("stwo_riscv_rv32").air_relation_evidence;
pub const relation_export = @import("stwo_riscv_rv32").air_relation_export;
pub const relation_export_components = @import("stwo_riscv_rv32").air_relation_export_components;
pub const relations = @import("stwo_riscv_rv32").air_relations;
pub const semantic_component = @import("stwo_riscv_rv32").air_semantic_component;
pub const semantic_eval = @import("stwo_riscv_rv32").air_semantic_eval;
pub const semantics = @import("stwo_riscv_rv32").air_semantics_mod;
pub const statement = @import("stwo_riscv_rv32").air_statement;
pub const statement_v2 = @import("stwo_riscv_rv32").air_statement_v2;
pub const transcript = @import("stwo_riscv_rv32").air_transcript_mod;
pub const trace_columns = @import("stwo_riscv_rv32").air_trace_columns;
pub const preprocessed = @import("stwo_riscv_rv32").air_preprocessed_mod;
pub const profiling = @import("stwo_riscv_rv32").air_profiling;

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
    // `refAllDecls` references these lazily from inside a test body, which is
    // too late for the test runner to collect the tests they contain.
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
}

/// Source-only authenticated inventory; its backend emitter is supplied by the caller.
pub const native_polynomial_inventory_v1 = @import("stwo_riscv_rv32").air_native_polynomial_inventory;
