//! Typed AIR authoring kernel.
//!
//! Typed constraints remain compatibility-checked against production AIR.
//! Reviewed witness recipes become production authorities one family at a
//! time through `runner/trace.zig`, only after exact row, relation, proof,
//! adversarial, allocation, and performance gates. Definitions not selected
//! by that dispatch remain shadow-only regardless of being exported here.

const std = @import("std");

pub const types = @import("stwo_riscv_air_lang").modules.types;
pub const source = @import("stwo_riscv_air_lang").modules.source;
pub const expr = @import("stwo_riscv_air_lang").modules.expr;
pub const capabilities = @import("stwo_riscv_air_lang").modules.capabilities;
pub const static_collections = @import("stwo_riscv_air_lang").modules.static_collections;
pub const typed_poseidon2 = @import("stwo_riscv_memory").modules.typed_typed_poseidon2;
pub const typed_poseidon2_witness = @import("stwo_riscv_memory").modules.typed_typed_poseidon2_witness;
pub const typed_poseidon2_authority = @import("stwo_riscv_memory").modules.typed_typed_poseidon2_authority;
/// Experimental, non-admitted lower-width compiler candidates. These use a
/// distinct identity domain and are not production `HashComponent` aliases.
pub const typed_poseidon2_degree_bounded_candidate =
    @import("stwo_riscv_memory").modules.typed_typed_poseidon2_degree_bounded_candidate;
pub const typed_poseidon2_degree_bounded_component =
    @import("stwo_riscv_memory").modules.typed_typed_poseidon2_degree_bounded_component;
pub const typed_poseidon2_degree_bounded_trace =
    @import("stwo_riscv_memory").modules.typed_typed_poseidon2_degree_bounded_trace;
pub const typed_poseidon2_degree5_component =
    @import("stwo_riscv_memory").modules.typed_typed_poseidon2_degree5_component;
pub const typed_poseidon2_degree5_backend =
    @import("stwo_riscv_rv32").modules.air_lang_typed_poseidon2_degree5_backend;
pub const typed_poseidon2_degree5_trace =
    @import("stwo_riscv_memory").modules.typed_typed_poseidon2_degree5_trace;
pub const typed_lui = @import("stwo_riscv_air_lang").modules.typed_lui;
pub const typed_lui_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_lui_authority;
pub const typed_lui_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_lui_witness;
pub const typed_addi = @import("stwo_riscv_air_lang").modules.typed_addi;
pub const typed_base_alu_imm_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_base_alu_imm_witness;
pub const typed_base_alu_imm_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_base_alu_imm_authority;
pub const typed_base_alu_reg = @import("stwo_riscv_air_lang").modules.typed_base_alu_reg;
pub const typed_base_alu_reg_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_base_alu_reg_witness;
pub const typed_auipc = @import("stwo_riscv_air_lang").modules.typed_auipc;
pub const typed_auipc_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_auipc_witness;
pub const typed_branch_eq = @import("stwo_riscv_air_lang").modules.typed_branch_eq;
pub const typed_branch_eq_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_branch_eq_authority;
pub const typed_branch_eq_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_branch_eq_witness;
pub const typed_branch_lt = @import("stwo_riscv_air_lang").modules.typed_branch_lt;
pub const typed_branch_lt_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_branch_lt_authority;
pub const typed_branch_lt_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_branch_lt_witness;
pub const typed_div = @import("stwo_riscv_air_lang").modules.typed_div;
pub const typed_div_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_div_authority;
pub const typed_div_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_div_witness;
pub const typed_fence = @import("stwo_riscv_air_lang").modules.typed_fence;
pub const typed_fence_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_fence_witness;
pub const typed_jal = @import("stwo_riscv_air_lang").modules.typed_jal;
pub const typed_jal_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_jal_authority;
pub const typed_jal_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_jal_witness;
pub const typed_jalr = @import("stwo_riscv_air_lang").modules.typed_jalr;
pub const typed_jalr_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_jalr_authority;
pub const typed_jalr_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_jalr_witness;
pub const typed_load_store = @import("stwo_riscv_air_lang").modules.typed_load_store;
pub const typed_load_store_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_load_store_authority;
pub const typed_load_store_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_load_store_witness;
pub const typed_lt_imm = @import("stwo_riscv_air_lang").modules.typed_lt_imm;
pub const typed_lt_imm_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_imm_authority;
pub const typed_lt_imm_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_imm_witness;
pub const typed_lt_reg = @import("stwo_riscv_air_lang").modules.typed_lt_reg;
pub const typed_lt_reg_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_reg_authority;
pub const typed_lt_reg_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_reg_witness;
pub const typed_mul = @import("stwo_riscv_air_lang").modules.typed_mul;
pub const typed_mul_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_mul_authority;
pub const typed_mul_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_mul_witness;
pub const typed_mulh = @import("stwo_riscv_air_lang").modules.typed_mulh;
pub const typed_mulh_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_mulh_authority;
pub const typed_mulh_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_mulh_witness;
pub const typed_shifts_imm = @import("stwo_riscv_air_lang").modules.typed_shifts_imm;
pub const typed_shifts_imm_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_imm_authority;
pub const typed_shifts_imm_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_imm_witness;
pub const typed_shifts_reg = @import("stwo_riscv_air_lang").modules.typed_shifts_reg;
pub const typed_shifts_reg_authority = @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_reg_authority;
pub const typed_shifts_reg_witness = @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_reg_witness;
pub const direct_witness_executor = @import("stwo_riscv_air_lang").modules.direct_witness_executor;
pub const program = @import("stwo_riscv_air_lang").modules.program;
pub const ir = @import("stwo_riscv_air_lang").modules.ir;
pub const effects = @import("stwo_riscv_air_lang").modules.effects;
pub const instruction_effects = @import("stwo_riscv_air_lang").modules.instruction_effects;
pub const validate = @import("stwo_riscv_air_lang").modules.validate;
pub const manifest = @import("stwo_riscv_air_lang").modules.manifest;
pub const relation = @import("stwo_riscv_air_lang").modules.relation;
pub const functions = @import("stwo_riscv_air_lang").modules.functions;
pub const function_activation_logup = @import("stwo_riscv_rv32").modules.air_lang_function_activation_logup;
pub const hint_recipe = @import("stwo_riscv_air_lang").modules.hint_recipe;
pub const hints = @import("stwo_riscv_air_lang").modules.hints;
pub const digest = @import("stwo_riscv_air_lang").modules.digest;
pub const degree = @import("stwo_riscv_air_lang").modules.degree;
pub const static_profile = @import("stwo_riscv_rv32").modules.air_lang_static_profile;
pub const runtime_profile = @import("stwo_riscv_rv32").modules.air_lang_runtime_profile;
pub const degree3_materializer = @import("stwo_riscv_air_lang").modules.degree3_materializer;
pub const compat_layout = @import("stwo_riscv_rv32").modules.air_lang_compat_layout;
pub const compat_manifest = @import("stwo_riscv_rv32").modules.air_lang_compat_manifest;
pub const compat_manifest_diff = @import("stwo_riscv_air_lang").modules.compat_manifest_diff;
pub const lower_constraint = @import("stwo_riscv_rv32").modules.air_lang_lower_constraint;
pub const lower_effects = @import("stwo_riscv_air_lang").modules.lower_effects;
pub const lower_air_ir = @import("stwo_riscv_rv32").modules.air_lang_lower_air_ir;
pub const lower_lookup = @import("stwo_riscv_rv32").modules.air_lang_lower_lookup;
pub const lower_runtime = @import("stwo_riscv_rv32").modules.air_lang_lower_runtime;
pub const lookup_batch_execution = @import("stwo_riscv_rv32").modules.air_lang_lookup_batch_execution;
pub const lookup_physical_manifest_v2 = @import("stwo_riscv_rv32").modules.air_lang_lookup_physical_manifest;
pub const protocol_degree = @import("stwo_riscv_rv32").modules.air_lang_protocol_degree;
pub const row_window = @import("stwo_riscv_rv32").modules.air_lang_row_window;
pub const window_ir_v2 = @import("stwo_riscv_air_lang").modules.window_ir;
pub const access_transaction = @import("stwo_riscv_rv32").modules.air_lang_access_transaction;
pub const protocol_report = @import("stwo_riscv_rv32").modules.air_lang_protocol_report;
pub const diagnostic = @import("stwo_riscv_air_lang").modules.diagnostic;
pub const shadow_import = @import("stwo_riscv_air_lang").modules.shadow_import;
pub const shadow_program = @import("stwo_riscv_rv32").modules.air_lang_shadow_program;

/// Logical schema version for the pre-production authoring kernel.
///
/// This is not an artifact or proof-protocol version. It lets focused tests
/// reject accidental reuse of a future incompatible logical representation.
pub const LOGICAL_SCHEMA_VERSION = manifest.logical_schema_version;
pub const TYPED_EFFECT_LOGICAL_SCHEMA_VERSION =
    manifest.typed_effect_logical_schema_version;
pub const REGISTER_GROUP_LOGICAL_SCHEMA_VERSION =
    manifest.register_group_logical_schema_version;
pub const MEMORY_ACCESS_LOGICAL_SCHEMA_VERSION =
    manifest.memory_access_logical_schema_version;
pub const SEQUENTIAL_RETIREMENT_LOGICAL_SCHEMA_VERSION =
    manifest.sequential_retirement_logical_schema_version;
pub const TYPED_LOOKUP_REQUEST_LOGICAL_SCHEMA_VERSION =
    manifest.typed_lookup_request_logical_schema_version;
pub const RANGE_REFINEMENT_LOGICAL_SCHEMA_VERSION =
    manifest.range_refinement_logical_schema_version;
pub const CONDITIONAL_ACCESS_LOGICAL_SCHEMA_VERSION =
    manifest.conditional_access_logical_schema_version;
pub const PROGRAM_CONTROL_TARGET_LOGICAL_SCHEMA_VERSION =
    manifest.program_control_target_logical_schema_version;
pub const COMMITTED_PROGRAM_CONTROL_TARGET_LOGICAL_SCHEMA_VERSION =
    manifest.committed_program_control_target_logical_schema_version;

test "typed AIR language: isolated kernel has an explicit logical version" {
    try std.testing.expectEqual(@as(u16, 2), LOGICAL_SCHEMA_VERSION);
    try std.testing.expectEqual(
        @as(u16, 3),
        TYPED_EFFECT_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 4),
        REGISTER_GROUP_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 5),
        MEMORY_ACCESS_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 6),
        SEQUENTIAL_RETIREMENT_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 7),
        TYPED_LOOKUP_REQUEST_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 8),
        RANGE_REFINEMENT_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 9),
        CONDITIONAL_ACCESS_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 10),
        PROGRAM_CONTROL_TARGET_LOGICAL_SCHEMA_VERSION,
    );
    try std.testing.expectEqual(
        @as(u16, 11),
        COMMITTED_PROGRAM_CONTROL_TARGET_LOGICAL_SCHEMA_VERSION,
    );
}
