//! Typed AIR authoring kernel.
//!
//! Typed constraints remain compatibility-checked against production AIR.
//! Reviewed witness recipes become production authorities one family at a
//! time through `runner/trace.zig`, only after exact row, relation, proof,
//! adversarial, allocation, and performance gates. Definitions not selected
//! by that dispatch remain shadow-only regardless of being exported here.

const std = @import("std");

pub const types = @import("types.zig");
pub const source = @import("source.zig");
pub const expr = @import("expr.zig");
pub const capabilities = @import("capabilities.zig");
pub const static_collections = @import("static_collections.zig");
pub const typed_poseidon2 = @import("typed_poseidon2.zig");
pub const typed_poseidon2_compat = @import("typed_poseidon2_compat.zig");
pub const typed_poseidon2_identity = @import("typed_poseidon2_identity.zig");
pub const typed_poseidon2_relations = @import("typed_poseidon2_relations.zig");
pub const typed_poseidon2_witness = @import("typed_poseidon2_witness.zig");
pub const typed_poseidon2_authority = @import("typed_poseidon2_authority.zig");
/// Experimental, non-admitted lower-width compiler candidates. These use a
/// distinct identity domain and are not production `HashComponent` aliases.
pub const typed_poseidon2_degree_bounded_candidate =
    @import("typed_poseidon2_degree_bounded_candidate.zig");
pub const typed_poseidon2_degree_bounded_component =
    @import("typed_poseidon2_degree_bounded_component.zig");
pub const typed_poseidon2_degree_bounded_backend =
    @import("typed_poseidon2_degree_bounded_backend.zig");
pub const typed_poseidon2_degree_bounded_trace =
    @import("typed_poseidon2_degree_bounded_trace.zig");
pub const typed_poseidon2_degree5_component =
    @import("typed_poseidon2_degree5_component.zig");
pub const typed_poseidon2_degree5_backend =
    @import("typed_poseidon2_degree5_backend.zig");
pub const typed_poseidon2_degree5_trace =
    @import("typed_poseidon2_degree5_trace.zig");
pub const typed_poseidon2_degree_bounded_residency =
    @import("typed_poseidon2_degree_bounded_residency.zig");
pub const typed_lui = @import("typed_lui.zig");
pub const typed_lui_authority = @import("typed_lui_authority.zig");
pub const typed_lui_witness = @import("typed_lui_witness.zig");
pub const typed_addi = @import("typed_addi.zig");
pub const typed_addi_witness = @import("typed_addi_witness.zig");
pub const typed_base_alu_imm_witness = @import("typed_base_alu_imm_witness.zig");
pub const typed_base_alu_imm_authority = @import("typed_base_alu_imm_authority.zig");
pub const typed_base_alu_reg = @import("typed_base_alu_reg.zig");
pub const typed_base_alu_reg_witness = @import("typed_base_alu_reg_witness.zig");
pub const typed_auipc = @import("typed_auipc.zig");
pub const typed_auipc_witness = @import("typed_auipc_witness.zig");
pub const typed_branch_eq = @import("typed_branch_eq.zig");
pub const typed_branch_eq_authority = @import("typed_branch_eq_authority.zig");
pub const typed_branch_eq_witness = @import("typed_branch_eq_witness.zig");
pub const typed_branch_lt = @import("typed_branch_lt.zig");
pub const typed_branch_lt_authority = @import("typed_branch_lt_authority.zig");
pub const typed_branch_lt_witness = @import("typed_branch_lt_witness.zig");
pub const typed_div = @import("typed_div.zig");
pub const typed_div_authority = @import("typed_div_authority.zig");
pub const typed_div_witness = @import("typed_div_witness.zig");
pub const typed_fence = @import("typed_fence.zig");
pub const typed_fence_witness = @import("typed_fence_witness.zig");
pub const typed_jal = @import("typed_jal.zig");
pub const typed_jal_authority = @import("typed_jal_authority.zig");
pub const typed_jal_witness = @import("typed_jal_witness.zig");
pub const typed_jalr = @import("typed_jalr.zig");
pub const typed_jalr_authority = @import("typed_jalr_authority.zig");
pub const typed_jalr_witness = @import("typed_jalr_witness.zig");
pub const typed_load_store = @import("typed_load_store.zig");
pub const typed_load_store_authority = @import("typed_load_store_authority.zig");
pub const typed_load_store_witness = @import("typed_load_store_witness.zig");
pub const typed_lt_imm = @import("typed_lt_imm.zig");
pub const typed_lt_imm_authority = @import("typed_lt_imm_authority.zig");
pub const typed_lt_imm_witness = @import("typed_lt_imm_witness.zig");
pub const typed_lt_reg = @import("typed_lt_reg.zig");
pub const typed_lt_reg_authority = @import("typed_lt_reg_authority.zig");
pub const typed_lt_reg_witness = @import("typed_lt_reg_witness.zig");
pub const typed_mul = @import("typed_mul.zig");
pub const typed_mul_authority = @import("typed_mul_authority.zig");
pub const typed_mul_witness = @import("typed_mul_witness.zig");
pub const typed_mulh = @import("typed_mulh.zig");
pub const typed_mulh_authority = @import("typed_mulh_authority.zig");
pub const typed_mulh_witness = @import("typed_mulh_witness.zig");
pub const typed_shifts_imm = @import("typed_shifts_imm.zig");
pub const typed_shifts_imm_authority = @import("typed_shifts_imm_authority.zig");
pub const typed_shifts_imm_witness = @import("typed_shifts_imm_witness.zig");
pub const typed_shifts_reg = @import("typed_shifts_reg.zig");
pub const typed_shifts_reg_authority = @import("typed_shifts_reg_authority.zig");
pub const typed_shifts_reg_witness = @import("typed_shifts_reg_witness.zig");
pub const direct_witness_executor = @import("direct_witness_executor.zig");
pub const program = @import("program.zig");
pub const ir = @import("ir.zig");
pub const effects = @import("effects.zig");
pub const instruction_effects = @import("instruction_effects.zig");
pub const validate = @import("validate.zig");
pub const manifest = @import("manifest.zig");
pub const relation = @import("relation.zig");
pub const functions = @import("functions.zig");
pub const function_frames = @import("function_frames.zig");
pub const function_body_lowering = @import("function_body_lowering.zig");
pub const function_activation_logup = @import("function_activation_logup.zig");
pub const hint_recipe = @import("hint_recipe.zig");
pub const hints = @import("hints.zig");
pub const digest = @import("digest.zig");
pub const degree = @import("degree.zig");
pub const static_profile = @import("static_profile.zig");
pub const static_profile_registry = @import("static_profile_registry.zig");
pub const static_profile_registry_artifact =
    @import("static_profile_registry_artifact.zig");
pub const runtime_profile = @import("runtime_profile.zig");
pub const degree3_materializer = @import("degree3_materializer.zig");
pub const materialization_diagnostics = @import("materialization_diagnostics.zig");
pub const compat_layout = @import("compat_layout.zig");
pub const compat_manifest = @import("compat_manifest.zig");
pub const compat_manifest_diff = @import("compat_manifest_diff.zig");
pub const lower_constraint = @import("lower_constraint.zig");
pub const lower_effects = @import("lower_effects.zig");
pub const lower_air_ir = @import("lower_air_ir.zig");
pub const lower_lookup = @import("lower_lookup.zig");
pub const lower_runtime = @import("lower_runtime.zig");
pub const lookup_batch_execution = @import("lookup_batch_execution.zig");
pub const lookup_batch_planner = @import("lookup_batch_planner.zig");
pub const lookup_physical_manifest_v2 = @import("lookup_physical_manifest_v2.zig");
pub const protocol_degree = @import("protocol_degree.zig");
pub const row_window = @import("row_window.zig");
pub const row_window_expression_v2 = @import("row_window_expression_v2.zig");
pub const window_ir_v2 = @import("window_ir_v2.zig");
pub const access_transaction = @import("access_transaction.zig");
pub const protocol_report = @import("protocol_report.zig");
pub const diagnostic = @import("diagnostic.zig");
pub const shadow_import = @import("shadow_import.zig");
pub const shadow_program = @import("shadow_program.zig");

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
