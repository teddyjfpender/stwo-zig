//! Ethereum role-input routing: one constrained value supplies arithmetic and publication hashing.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("vm_public_logup_input.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
pub const STABLE_NAME = "recursion.ethereum_public_logup_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 6;
pub const PARAMETER_COUNT = legacy.PROOF_KIND_PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 6;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT + 2;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = legacy.INTERACTION_BATCH_COUNT + 1;
pub const INTERACTION_COLUMN_COUNT = legacy.INTERACTION_COLUMN_COUNT + 4;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "fdeacd0daf651b507d28664714d131fa9837e4a701bcb00e41cf84b9c815b8fd";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
const event_ids: [RELATION_EVENT_COUNT]types.EffectId = blk: {
    var result: [RELATION_EVENT_COUNT]types.EffectId = undefined;
    for (&result, 0..) |*value, index| value.* = @enumFromInt(index);
    break :blk result;
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
        const actual = try digest.computeIdentity(&self.arena);
        if (!std.meta.eql(actual.bytes, SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            !std.meta.eql(self.events, event_ids)) return error.InvalidEthereumPublicLogupInput;
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildRoleRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildRoleRoutingArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}
pub fn logicalRow(row: [legacy.LOGICAL_INPUT_COUNT]M31, hash_scope: u32, hash_index: ?u32, source_scope: u32, source_header_index: ?u32) Relation.Row {
    const at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    return row[0..at].* ++ .{ M31.fromCanonical(@intFromBool(hash_index != null)), M31.fromCanonical(hash_scope), M31.fromCanonical(hash_index orelse 0), M31.fromCanonical(source_scope), M31.fromCanonical(@intFromBool(source_header_index != null)), M31.fromCanonical(source_header_index orelse 0) } ++ row[at..].*;
}
