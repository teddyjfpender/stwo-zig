//! Canonical cost-model identity carried by `STWAIRM` search receipts.

const std = @import("std");
const frontier_digest = @import("materialization_frontier_digest.zig");
const fixed_direct = @import("materialization_fixed_direct.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");

pub const Digest = frontier_digest.Digest;
pub const EvaluationSchedule = frontier_digest.EvaluationSchedule;
pub const Error = error{ InvalidCostModel, DigestMismatch };

pub const Scope = enum(u8) {
    semantic_equalities_only = 0,
    poseidon2_permutation_direct_v1 = 1,

    pub fn id(self: Scope) []const u8 {
        return switch (self) {
            .semantic_equalities_only => "stwo.typed-air.cost.semantic-equalities-only",
            .poseidon2_permutation_direct_v1 => poseidon_fixed.cost_scope_id,
        };
    }
};

pub const Identity = struct {
    scope: Scope,
    scope_version: u16,
    fixed_program_format_version: u16,
    fixed_program_digest: Digest,
    fixed_column_count: u32,
    fixed_node_count: u32,
    fixed_root_count: u32,
    evaluation_schedule: EvaluationSchedule,
    cost_model_digest: Digest,

    pub fn digestView(self: Identity) frontier_digest.CostModelIdentity {
        return .{
            .scope_id = self.scope.id(),
            .scope_version = self.scope_version,
            .fixed_program_format_version = self.fixed_program_format_version,
            .fixed_program_digest = self.fixed_program_digest,
            .fixed_column_count = self.fixed_column_count,
            .fixed_node_count = self.fixed_node_count,
            .fixed_root_count = self.fixed_root_count,
            .evaluation_schedule = self.evaluation_schedule,
        };
    }
};

pub fn semanticOnly() Identity {
    var result = Identity{
        .scope = .semantic_equalities_only,
        .scope_version = 1,
        .fixed_program_format_version = 0,
        .fixed_program_digest = .{0} ** 32,
        .fixed_column_count = 0,
        .fixed_node_count = 0,
        .fixed_root_count = 0,
        .evaluation_schedule = .candidate_equalities_only,
        .cost_model_digest = undefined,
    };
    result.cost_model_digest = frontier_digest.computeCostModel(result.digestView());
    return result;
}

pub fn poseidon2PermutationDirect() Identity {
    var result = Identity{
        .scope = .poseidon2_permutation_direct_v1,
        .scope_version = poseidon_fixed.cost_scope_version,
        .fixed_program_format_version = fixed_direct.format_version,
        .fixed_program_digest = poseidon_fixed.canonical_digest,
        .fixed_column_count = @intCast(poseidon_fixed.columns.len),
        .fixed_node_count = @intCast(poseidon_fixed.nodes.len),
        .fixed_root_count = poseidon_fixed.fixed_root_count,
        .evaluation_schedule = .fixed_prefix_candidate_equalities_fixed_suffix,
        .cost_model_digest = undefined,
    };
    result.cost_model_digest = frontier_digest.computeCostModel(result.digestView());
    return result;
}

pub fn validate(model: Identity, geometry_fixed_roots: u64) Error!void {
    if (model.scope_version == 0 or model.fixed_root_count != geometry_fixed_roots)
        return error.InvalidCostModel;
    switch (model.scope) {
        .semantic_equalities_only => {
            if (model.scope_version != 1 or model.fixed_program_format_version != 0 or
                model.fixed_column_count != 0 or model.fixed_node_count != 0 or
                model.fixed_root_count != 0 or
                model.evaluation_schedule != .candidate_equalities_only or
                !std.mem.allEqual(u8, &model.fixed_program_digest, 0))
                return error.InvalidCostModel;
        },
        .poseidon2_permutation_direct_v1 => {
            if (model.scope_version != poseidon_fixed.cost_scope_version or
                model.fixed_program_format_version != fixed_direct.format_version or
                model.fixed_column_count != @as(u32, @intCast(poseidon_fixed.columns.len)) or
                model.fixed_node_count != @as(u32, @intCast(poseidon_fixed.nodes.len)) or
                model.fixed_root_count != poseidon_fixed.fixed_root_count or
                model.evaluation_schedule !=
                    .fixed_prefix_candidate_equalities_fixed_suffix or
                !std.mem.eql(
                    u8,
                    &model.fixed_program_digest,
                    &poseidon_fixed.canonical_digest,
                ))
                return error.InvalidCostModel;
        },
    }
    if (!std.mem.eql(
        u8,
        &model.cost_model_digest,
        &frontier_digest.computeCostModel(model.digestView()),
    )) return error.DigestMismatch;
}
