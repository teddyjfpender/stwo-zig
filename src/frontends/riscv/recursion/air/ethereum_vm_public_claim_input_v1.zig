//! Ethereum row 12 retains canonical claim semantics, I/O projections,
//! and byte range checks. Exact admitted use counts enable only the canonical
//! claim words and bytes consumed by the role-source arithmetic graph.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("vm_public_claim_input.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");

pub const PROFILE_VERSION: u16 = 2;
pub const STABLE_NAME = "recursion.ethereum_vm_public_claim_input.v2";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 3;
pub const PARAMETER_COUNT = legacy.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 3;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = legacy.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = legacy.INTERACTION_COLUMN_COUNT;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "064801f229b955638e49c848d704cc91691e493038d6461898936e3f0b989bc6";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
const event_ids: [RELATION_EVENT_COUNT]types.EffectId = .{
    @enumFromInt(0), @enumFromInt(1), @enumFromInt(2), @enumFromInt(3),
    @enumFromInt(4), @enumFromInt(5), @enumFromInt(6), @enumFromInt(7),
};

pub const Definition = struct {
    arena: ir.Arena,
    events: [RELATION_EVENT_COUNT]types.EffectId = event_ids,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try @import("../../air/lang/validate.zig").validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.typed_effect_format_version or
            !std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            !std.meta.eql(self.events, event_ids))
            return error.InvalidEthereumClaimRoutingDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildEthereumRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildEthereumRoutingArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}

pub fn logicalRow(row: [legacy.LOGICAL_INPUT_COUNT]M31, uses: [3]u32) Relation.Row {
    const at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    return row[0..at].* ++ .{ M31.fromCanonical(uses[0]), M31.fromCanonical(uses[1]), M31.fromCanonical(uses[2]) } ++ row[at..].*;
}
