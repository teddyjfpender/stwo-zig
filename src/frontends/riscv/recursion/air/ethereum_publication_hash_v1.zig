//! Shared claim/publication hash AIR with fixed per-row phase preprocessing.
//! Physical order is main, legacy preprocessing, domain/scope/verifier/kind,
//! then the sole segment-active parameter. CSP retains its original ordering.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("vm_public_claim_hash.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");

pub const STABLE_NAME = "recursion.ethereum_publication_hash.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 4;
pub const PARAMETER_COUNT = 1;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = legacy.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = legacy.INTERACTION_COLUMN_COUNT;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "5ca22b7fd0a6e08537c18b391a148900182a827aca4ec8056251dabce6f483c3";
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
        if (actual.format_version != digest.typed_effect_format_version or
            !std.meta.eql(actual.bytes, SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            !std.meta.eql(self.events, event_ids))
            return error.InvalidEthereumPublicationHashDefinition;
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

pub fn fromLegacy(row: [legacy.LOGICAL_INPUT_COUNT]M31) Relation.Row {
    const parameters_at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    return row[0..parameters_at].* ++ row[parameters_at + 1 ..].* ++ .{row[parameters_at]};
}
