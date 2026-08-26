//! Internal authentication helpers for the benchmark-only proposal executor.
//!
//! Kept separate from row execution so review can distinguish immutable
//! H-005/H-009 construction and digest checks from the hot witness path.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat = @import("typed_poseidon2_compat.zig");
const cut_set = @import("materialization_cut_set.zig");
const digest = @import("digest.zig");
const fixed_cost = @import("typed_poseidon2_fixed_direct.zig");
const frontier = @import("materialization_frontier_manifest.zig");
const ir = @import("ir.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const search = @import("cost_aware_materializer.zig");
const types = @import("types.zig");
const witness = @import("typed_poseidon2_witness.zig");

pub const WIDTH = compat.WIDTH;
pub const N_MATERIALIZATIONS = compat.N_MATERIALIZATIONS;
pub const N_MAIN_COLUMNS = compat.N_MAIN_COLUMNS;
pub const LAYOUT_DIGEST_FORMAT_VERSION: u16 = 1;
pub const LAYOUT_DIGEST_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/poseidon2-proposal-layout-executor/v1";
pub const ROOT_RESIDUAL_DIGEST_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/poseidon2-proposal-root-residuals/v1";

pub const ConstructionError = std.mem.Allocator.Error || error{
    GeometryMismatch,
    InstructionClosureMismatch,
    ProposalMismatch,
    SemanticIdentityMismatch,
    UnsupportedCostModel,
};

pub const IntegrityError = error{
    CutDigestMismatch,
    IdentityDigestMismatch,
    LayoutDigestMismatch,
};

pub fn validateGeometry(
    manifest: frontier.Manifest,
    proposal: frontier.Proposal,
) ConstructionError!void {
    const expected_model = frontier.poseidon2PermutationDirectCostModel();
    if (!std.meta.eql(manifest.cost_model, expected_model))
        return error.UnsupportedCostModel;
    const expected_geometry = frontier.Geometry{
        .preprocessed_columns = 0,
        .base_main_columns = 1 + WIDTH + 2,
        .fixed_direct_roots = fixed_cost.fixed_root_count,
        .interaction_columns = production.N_INTERACTION_COLUMNS,
        .field_element_bytes = @sizeOf(M31),
    };
    if (!std.meta.eql(manifest.geometry, expected_geometry) or
        proposal.selected_values.len != N_MATERIALIZATIONS or
        proposal.cost.materialization_count != N_MATERIALIZATIONS or
        proposal.cost.candidate_main_columns != N_MAIN_COLUMNS)
    {
        return error.GeometryMismatch;
    }
}

pub fn validateProposalCut(
    proposal_cut: *const cut_set.CutSet,
    manifest: frontier.Manifest,
    proposal: frontier.Proposal,
) ConstructionError!void {
    if (proposal_cut.values.len != N_MATERIALIZATIONS or
        proposal.selected_values.len != proposal_cut.values.len or
        proposal_cut.program_digest_format != digest.format_version or
        !std.mem.eql(u8, &proposal_cut.program_digest, &manifest.identity.semantic_digest) or
        manifest.identity.gate != (if (proposal_cut.gate) |gate|
            @intFromEnum(gate)
        else
            null) or
        manifest.identity.maximum_constraint_degree !=
            proposal_cut.policy.maximum_constraint_degree or
        manifest.identity.row_mask_degree != proposal_cut.policy.row_mask_degree or
        manifest.identity.roots.len != proposal_cut.roots.len)
    {
        return error.ProposalMismatch;
    }
    for (proposal_cut.roots, manifest.identity.roots) |root, raw| {
        if (@intFromEnum(root) != raw) return error.ProposalMismatch;
    }
    for (proposal_cut.values, proposal.selected_values) |value, raw| {
        if (@intFromEnum(value) != raw) return error.ProposalMismatch;
    }
    const canonical_cut_digest = search.cutDigest(proposal_cut) catch
        return error.ProposalMismatch;
    if (!std.mem.eql(u8, &canonical_cut_digest, &proposal.cut_digest))
        return error.ProposalMismatch;
}

pub fn validateSemanticIdentity(
    semantic: witness.Identity,
    identity: frontier.Identity,
) ConstructionError!void {
    if (!std.mem.eql(u8, &semantic.program_digest, &identity.semantic_digest) or
        identity.gate != @as(?u32, @intFromEnum(semantic.gate)) or
        identity.seed_policy_version != semantic.materializer_policy_version or
        identity.maximum_constraint_degree != semantic.policy.maximum_constraint_degree or
        identity.row_mask_degree != semantic.policy.row_mask_degree or
        identity.roots.len != WIDTH)
    {
        return error.SemanticIdentityMismatch;
    }
    for (semantic.outputs, identity.roots) |root, raw| {
        if (@intFromEnum(root) != raw) return error.SemanticIdentityMismatch;
    }
}

pub fn compileSelectedSlots(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    roots: [WIDTH]types.ValueId,
    selected_values: *const [N_MATERIALIZATIONS]u32,
    instruction_count: usize,
) ConstructionError![N_MATERIALIZATIONS]u32 {
    const reachable = try allocator.alloc(bool, arena.nodeCount());
    defer allocator.free(reachable);
    @memset(reachable, false);
    for (roots) |root| {
        const index = types.idIndex(root);
        if (index >= reachable.len) return error.InstructionClosureMismatch;
        reachable[index] = true;
    }
    var reverse = reachable.len;
    while (reverse != 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        switch (arena.nodesView()[reverse].key.op) {
            .constant, .input => {},
            .add, .sub, .mul => |binary| {
                try markReachable(reachable, reverse, binary.lhs);
                try markReachable(reachable, reverse, binary.rhs);
            },
            .neg => |operand| try markReachable(reachable, reverse, operand),
            .select => |selection| {
                try markReachable(reachable, reverse, selection.selector);
                try markReachable(reachable, reverse, selection.when_true);
                try markReachable(reachable, reverse, selection.when_false);
            },
            .hint_output, .call_output, .machine_derived => return error.InstructionClosureMismatch,
        }
    }

    var result: [N_MATERIALIZATIONS]u32 = undefined;
    var local_slot: usize = 0;
    var selected: usize = 0;
    for (reachable, 0..) |is_reachable, node_index| {
        if (!is_reachable) continue;
        if (selected < N_MATERIALIZATIONS and selected_values[selected] == node_index) {
            result[selected] = std.math.cast(u32, local_slot) orelse
                return error.InstructionClosureMismatch;
            selected += 1;
        } else if (selected < N_MATERIALIZATIONS and
            selected_values[selected] < node_index)
        {
            return error.InstructionClosureMismatch;
        }
        local_slot += 1;
    }
    if (selected != N_MATERIALIZATIONS or local_slot != instruction_count)
        return error.InstructionClosureMismatch;
    return result;
}

fn markReachable(reachable: []bool, parent: usize, child: types.ValueId) ConstructionError!void {
    const index = types.idIndex(child);
    if (index >= parent or index >= reachable.len)
        return error.InstructionClosureMismatch;
    reachable[index] = true;
}

pub fn validateIntegrity(
    semantic: witness.Identity,
    semantic_execution_digest: frontier.Digest,
    frontier_identity_digest: frontier.Digest,
    cost_model_digest: frontier.Digest,
    cut_digest: frontier.Digest,
    proposal_digest: frontier.Digest,
    layout_digest: frontier.Digest,
    selected_values: *const [N_MATERIALIZATIONS]u32,
    selected_slots: *const [N_MATERIALIZATIONS]u32,
    root_ordinals: *const [WIDTH]u16,
    instruction_count: usize,
) IntegrityError!void {
    var roots: [WIDTH]u32 = undefined;
    for (semantic.outputs, &roots) |root, *raw| raw.* = @intFromEnum(root);
    const h009_identity = frontier.Identity{
        .semantic_digest = semantic.program_digest,
        .roots = &roots,
        .gate = @intFromEnum(semantic.gate),
        .seed_policy_version = semantic.materializer_policy_version,
        .maximum_constraint_degree = semantic.policy.maximum_constraint_degree,
        .row_mask_degree = semantic.policy.row_mask_degree,
        .identity_digest = frontier_identity_digest,
    };
    if (!std.mem.eql(
        u8,
        &frontier_identity_digest,
        &frontier.computeIdentityDigest(h009_identity),
    )) return error.IdentityDigestMismatch;
    if (!strictlyIncreasing(selected_values)) return error.CutDigestMismatch;
    const expected_cut = frontier.computeCutDigest(h009_identity, selected_values);
    if (!std.mem.eql(u8, &cut_digest, &expected_cut)) return error.CutDigestMismatch;
    for (selected_slots, 0..) |slot, index| {
        if (slot >= instruction_count or
            (index != 0 and selected_slots[index - 1] >= slot))
        {
            return error.LayoutDigestMismatch;
        }
    }
    for (semantic.outputs, root_ordinals) |root, ordinal| {
        if (ordinal >= N_MATERIALIZATIONS or
            selected_values[ordinal] != @intFromEnum(root))
        {
            return error.LayoutDigestMismatch;
        }
    }
    const actual_layout = computeLayoutDigest(
        semantic_execution_digest,
        frontier_identity_digest,
        cost_model_digest,
        cut_digest,
        proposal_digest,
        selected_values,
        selected_slots,
        root_ordinals,
    );
    if (!std.mem.eql(u8, &layout_digest, &actual_layout))
        return error.LayoutDigestMismatch;
}

pub fn computeLayoutDigest(
    semantic_execution_digest: frontier.Digest,
    frontier_identity_digest: frontier.Digest,
    cost_model_digest: frontier.Digest,
    cut_digest: frontier.Digest,
    proposal_digest: frontier.Digest,
    selected_values: *const [N_MATERIALIZATIONS]u32,
    selected_slots: *const [N_MATERIALIZATIONS]u32,
    root_ordinals: *const [WIDTH]u16,
) frontier.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(LAYOUT_DIGEST_DOMAIN_SEPARATOR);
    hashInt(&hash, u16, LAYOUT_DIGEST_FORMAT_VERSION);
    hashInt(&hash, u16, WIDTH);
    hashInt(&hash, u16, N_MATERIALIZATIONS);
    hashInt(&hash, u16, N_MAIN_COLUMNS);
    hash.update(&semantic_execution_digest);
    hash.update(&frontier_identity_digest);
    hash.update(&cost_model_digest);
    hash.update(&cut_digest);
    hash.update(&proposal_digest);
    for (selected_values) |value| hashInt(&hash, u32, value);
    for (selected_slots) |slot| hashInt(&hash, u32, slot);
    for (root_ordinals) |ordinal| hashInt(&hash, u16, ordinal);
    return hash.finalResult();
}

pub fn computeRootResidualDigest(
    layout_digest: frontier.Digest,
    residuals: [WIDTH]M31,
) frontier.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROOT_RESIDUAL_DIGEST_DOMAIN_SEPARATOR);
    hash.update(&layout_digest);
    for (residuals) |value| hashInt(&hash, u32, value.toU32());
    return hash.finalResult();
}

pub fn indexOf(values: *const [N_MATERIALIZATIONS]u32, wanted: u32) ?usize {
    var low: usize = 0;
    var high: usize = values.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (values[middle] < wanted) low = middle + 1 else high = middle;
    }
    if (low == values.len or values[low] != wanted) return null;
    return low;
}

fn strictlyIncreasing(values: *const [N_MATERIALIZATIONS]u32) bool {
    for (values[1..], values[0 .. values.len - 1]) |value, previous| {
        if (previous >= value) return false;
    }
    return true;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (N_MAIN_COLUMNS != production.N_MAIN_COLUMNS or
        N_MATERIALIZATIONS != production.N_TEMPORARIES or WIDTH != production.WIDTH)
    {
        @compileError("Poseidon proposal validation geometry drifted");
    }
}
