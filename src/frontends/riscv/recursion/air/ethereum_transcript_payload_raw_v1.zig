//! Opt-in schema4 raw-V2 export. One recorded payload value feeds both its
//! existing transcript/source relations and the complete raw-wire hash.
//! This proves byte custody, not auxiliary V2 document or namespace semantics.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("transcript_payload.zig");
const clocks = @import("transcript_payload_clocks_v2.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const routing = @import("../ethereum_publication_routing_v1.zig");

pub const STABLE_NAME = "recursion.ethereum_transcript_payload_raw.v1";
pub const RAW_WIRE_SCOPE = routing.RAW_WIRE_HASH_SCOPE;
pub const ROOT_SOURCE_SCOPE = routing.STATEMENT_SCOPE;
pub const ROOT_SOURCE_BASE = routing.RAW_V2_SOURCE_BASE;
pub const PHYSICAL_MAIN_COLUMN_COUNT = clocks.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = clocks.PREPROCESSED_COLUMN_COUNT + 2;
pub const PARAMETER_COUNT = clocks.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = clocks.LOGICAL_INPUT_COUNT + 2;
pub const RELATION_EVENT_COUNT = clocks.RELATION_EVENT_COUNT + 1;
pub const DIRECT_CONSTRAINT_COUNT = clocks.DIRECT_CONSTRAINT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = clocks.MAXIMUM_CONSTRAINT_DEGREE;
pub const LOOKUP_BATCH_SIZE = clocks.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = clocks.INTERACTION_BATCH_COUNT + 1;
pub const INTERACTION_COLUMN_COUNT = clocks.INTERACTION_COLUMN_COUNT + 4;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
// Pinned by the isolated frontend semantic-identity gate before selection.
pub const SEMANTIC_DIGEST_HEX = "991e77a54fc6e135eba0d8a2776a687d344675b3e307c61303e2624e387bdc74";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
const event_ids: [RELATION_EVENT_COUNT]types.EffectId = blk: {
    var result: [RELATION_EVENT_COUNT]types.EffectId = undefined;
    for (&result, 0..) |*event, index| event.* = @enumFromInt(index);
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
            !std.meta.eql(self.events, event_ids))
            return error.InvalidEthereumRawPayloadDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildRawWireRoutingArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildRawWireRoutingArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}

/// The frame-plan owner selects raw_wire only for native_statement_words.
/// Each root limb exports twice to the existing raw bus (hash source + root
/// join). Every other word exports once directly to its hash input. There is
/// no caller-selected multiplicity or coordinate.
/// This conversion does not itself admit source metadata or private fields.
pub fn logicalRow(row: clocks.Relation.Row, raw_wire: bool) Relation.Row {
    const at = clocks.PHYSICAL_MAIN_COLUMN_COUNT + clocks.PREPROCESSED_COLUMN_COUNT;
    const root = !rawHashProvidedDirectly(row[clocks.PHYSICAL_MAIN_COLUMN_COUNT + 10].toU32());
    return row[0..at].* ++ .{ M31.fromCanonical(@intFromBool(raw_wire)), M31.fromCanonical(@intFromBool(raw_wire and root)) } ++ row[at..].*;
}

pub const Export = routing.RawExport;

/// Activation uses this to select exactly one raw hash publisher. Skip the old
/// sourceRow for every direct word, including statement/clocks; retain its four
/// root rows and the two rootJoinRows. Native-authority phase rows are separate.
pub const rawHashProvidedDirectly = routing.rawHashProvidedDirectly;
pub const exportForRawWord = routing.exportForRawWord;
