//! Ethereum terminal digest routing from the final native draw's input state.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("transcript_state.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
pub const STABLE_NAME = "recursion.ethereum_transcript_state.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 1;
pub const PARAMETER_COUNT = legacy.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 1;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT + 8;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = legacy.INTERACTION_BATCH_COUNT + 4;
pub const INTERACTION_COLUMN_COUNT = legacy.INTERACTION_COLUMN_COUNT + 16;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "450fe2b9364468383ad2bc1e6c50ac1b2a5dee33fb2ca47f8d39b3b08224995f";
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
            !std.meta.eql(self.events, event_ids)) return error.InvalidEthereumTranscriptState;
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildPublicationRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildPublicationRoutingArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}
pub fn logicalRow(row: [legacy.LOGICAL_INPUT_COUNT]M31, terminal: bool) Relation.Row {
    const at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    return row[0..at].* ++ .{M31.fromCanonical(@intFromBool(terminal))} ++ row[at..].*;
}
