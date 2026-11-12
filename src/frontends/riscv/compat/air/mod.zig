//! RISC-V AIR (Algebraic Intermediate Representation) module.
//!
//! Provides the constraint definitions, trace column layouts, claim types,
//! and relation definitions for the RV32IM zkVM.
//!
//! Opcode AIR has one ownership path: `semantic_component` owns the family
//! constraints and `lookups` owns their relation wiring. Keep that split
//! explicit rather than introducing a second per-family component facade whose
//! layouts can drift from the committed trace.

pub const claims = @import("stwo_riscv_rv32").air.claims;
pub const clock_update_component = @import("stwo_riscv_rv32").air.clock_update_component;
pub const clock_update_interaction = @import("stwo_riscv_rv32").air.clock_update_interaction;
pub const component_order = @import("stwo_riscv_rv32").air.component_order;
pub const composition_work_support = @import("stwo_riscv_air_lang").evaluation.composition_work_support;
pub const constraint_program = @import("stwo_riscv_rv32").air.constraint_program;
pub const diagnostic_hints = @import("stwo_riscv_rv32").air.diagnostic_hints;
pub const extract = @import("stwo_riscv_rv32").air.extract.api;
pub const guest_precompile = @import("../assembly/precompiles/air/mod.zig");
pub const interaction = @import("stwo_riscv_rv32").air.interaction;
pub const logup = @import("stwo_riscv_air_lang").evaluation.logup;
pub const lookups = @import("stwo_riscv_rv32").air.lookups.api;
pub const lookup_physical_manifest_v2 =
    @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
pub const lookup_batch_execution = @import("stwo_riscv_rv32").air.lang.lookup_batch_execution;
pub const memory_commitment = @import("../assembly/memory/air/mod.zig");
pub const typed_poseidon2_authority = @import("stwo_riscv_memory").typed.typed_poseidon2_authority;
pub const typed_poseidon2_degree_bounded_candidate =
    @import("stwo_riscv_memory").typed.typed_poseidon2_degree_bounded_candidate;
pub const typed_poseidon2_degree_bounded_component =
    @import("stwo_riscv_memory").typed.typed_poseidon2_degree_bounded_component;
pub const typed_poseidon2_degree_bounded_trace =
    @import("stwo_riscv_memory").typed.typed_poseidon2_degree_bounded_trace;
pub const typed_poseidon2_degree5_component =
    @import("stwo_riscv_memory").typed.typed_poseidon2_degree5_component;
pub const typed_poseidon2_degree5_backend =
    @import("stwo_riscv_rv32").air.lang.typed_poseidon2_degree5_backend;
pub const typed_poseidon2_degree5_trace =
    @import("stwo_riscv_memory").typed.typed_poseidon2_degree5_trace;
pub const memory_logup = @import("stwo_riscv_rv32").air.memory_logup;
pub const opcode_memory = @import("stwo_riscv_rv32").air.opcode_memory;
pub const public_data = @import("stwo_riscv_rv32").air.public_data;
pub const public_data_v2 = @import("stwo_riscv_rv32").air.public_data_v2;
pub const public_logup = @import("stwo_riscv_rv32").air.public_logup;
pub const public_logup_v2 = @import("stwo_riscv_rv32").air.public_logup_v2;
pub const program = @import("stwo_riscv_rv32").air.program.api;
pub const relation_challenges = @import("stwo_riscv_air_lang").evaluation.relation_challenges;
pub const relation = @import("stwo_riscv_air_lang").relation;
pub const relation_evidence = @import("stwo_riscv_rv32").air.relation_evidence;
pub const relation_export = @import("stwo_riscv_rv32").air.relation_export;
pub const relation_export_components = @import("stwo_riscv_rv32").air.relation_export_components;
pub const relations = @import("stwo_riscv_rv32").air.relations;
pub const semantic_component = @import("stwo_riscv_rv32").air.semantic_component;
pub const semantic_eval = @import("stwo_riscv_rv32").air.semantic_eval;
pub const semantics = @import("stwo_riscv_rv32").air.semantics.api;
pub const statement = @import("stwo_riscv_rv32").air.statement;
pub const statement_v2 = @import("stwo_riscv_rv32").air.statement_v2;
pub const transcript = @import("stwo_riscv_rv32").air.transcript.api;
pub const trace_columns = @import("stwo_riscv_rv32").air.trace_columns.api;
pub const preprocessed = @import("stwo_riscv_rv32").air.preprocessed.api;
pub const profiling = @import("stwo_riscv_rv32").air.profiling;

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
pub const native_polynomial_inventory_v1 = @import("stwo_riscv_rv32").air.native_polynomial_inventory;
