//! Ethereum statement-word and byte fan-out. The V1 builder supplies all
//! constraints, including byte decomposition and the (8,8) range lookup.
//! Four extra preprocessing columns route those authenticated bytes to the
//! admitted graph. No byte value or use count enters circuit construction.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("statement_semantics_input.zig");
const witness = @import("statement_semantics_input_witness.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");

pub const STABLE_NAME = "recursion.statement_semantics.bytes.v2";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 4;
pub const PARAMETER_COUNT = legacy.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 4;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT + 2;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = legacy.INTERACTION_BATCH_COUNT + 1;
pub const INTERACTION_COLUMN_COUNT = legacy.INTERACTION_COLUMN_COUNT + 4;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "7b551728773dfd558dfbb81a91937e95e71ec48a74c1bc952cf41993eb8bd389";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
const event_ids: [RELATION_EVENT_COUNT]types.EffectId = .{
    @enumFromInt(0), @enumFromInt(1), @enumFromInt(2), @enumFromInt(3), @enumFromInt(4),
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
            !std.meta.eql(self.events, event_ids))
            return error.InvalidStatementByteRoutingDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildByteRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildByteRoutingArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}

/// Exact physical order: four main columns, seventeen preprocessing columns,
/// four parameters. The source owner admits the fixed byte destinations.
pub fn logicalRow(row: witness.Row, value: M31, kind: witness.ProofKind, byte_routes: [4]M31) !Relation.Row {
    if ((!byte_routes[1].isZero() or !byte_routes[3].isZero()) and
        (row.source != .statement or !row.integer or !row.active_kinds.segment))
        return error.InvalidStatementByteRoutingDefinition;
    const original = try witness.logicalRowForEthereum(row, value, kind);
    const parameters_at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    return original[0..parameters_at].* ++ byte_routes ++ original[parameters_at..].*;
}
