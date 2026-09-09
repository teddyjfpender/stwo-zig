//! Ethereum row 5: export clocks and publication words from the recorded transcript
//! into the admitted statement routing plan, without adding witness columns.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("transcript_payload.zig");
const witness = @import("transcript_payload_witness.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
pub const clocks = @import("../ethereum_clock_routing_v1.zig");
const publication = @import("../ethereum_publication_routing_v1.zig");

pub const STABLE_NAME = "recursion.transcript_payload.clocks.v2";
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
pub const SEMANTIC_DIGEST_HEX = "95a72779d509cbf9b844a662e220e000d6cd88f0a45b7351f50bf7654567f79d";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
const event_ids: [RELATION_EVENT_COUNT]types.EffectId = .{ @enumFromInt(0), @enumFromInt(1), @enumFromInt(2), @enumFromInt(3) };

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
            !std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or !std.meta.eql(self.events, event_ids))
            return error.InvalidTranscriptClockRoutingDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildClockRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildClockRoutingArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}

pub fn logicalRow(row: witness.Row, value: M31) !Relation.Row {
    return logicalRowForProfile(row, value, false);
}

pub fn logicalRowForFieldFrame(row: witness.Row, value: M31) !Relation.Row {
    return logicalRowForProfile(row, value, true);
}

fn logicalRowForProfile(row: witness.Row, value: M31, field_frame: bool) !Relation.Row {
    const original = if (field_frame)
        try witness.logicalRowForEthereumFieldFrame(row, value, .segment_leaf)
    else if (row.segment_mask == 1)
        try witness.logicalRowForEthereumRecordedFrame(row, value, .segment_leaf)
    else
        try witness.logicalRow(row, value, .segment_leaf);
    var uses: u32 = 0;
    var scope: u32 = 0;
    var index: u32 = 0;
    if (row.segment_mask == 1 and row.source_kind == .statement) {
        if (row.item_index == clocks.STATEMENT_SCOPE) {
            uses = clocks.sourceUses(row.limb_index);
            scope = clocks.STATEMENT_SCOPE;
            index = row.limb_index;
        } else if (row.item_index == publication.STATEMENT_SCOPE) {
            uses = 1;
            scope = publication.STATEMENT_SCOPE;
            index = row.limb_index;
        }
    } else if (row.segment_mask == 1 and row.source_kind == .commitment) {
        index = publication.commitmentIndex(row.item_index, row.limb_index) orelse return error.InvalidTranscriptClockRoutingDefinition;
        uses = 1;
        scope = publication.STATEMENT_SCOPE;
    }
    const parameters_at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    const native_uses = if (scope == publication.STATEMENT_SCOPE) uses else 0;
    const clock_uses = if (scope == clocks.STATEMENT_SCOPE) uses else 0;
    return original[0..parameters_at].* ++ .{ M31.fromCanonical(clock_uses), M31.fromCanonical(scope), M31.fromCanonical(index), M31.fromCanonical(native_uses) } ++ original[parameters_at..].*;
}
