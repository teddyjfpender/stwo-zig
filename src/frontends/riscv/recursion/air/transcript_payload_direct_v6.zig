//! Versioned native row-5 payload AIR for the direct SegmentV2 wrapper.
//! The extra key-owned mask emits the eight wire-ID words read by ProgramV2.
//! It reads the same committed payload value already used by Fiat–Shamir.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("transcript_payload.zig");
const old_relation = @import("transcript_payload_relation.zig");
const compiler = @import("relation_interaction.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");

pub const STABLE_NAME = "recursion.transcript_payload.direct.v6";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 1;
pub const PARAMETER_COUNT = legacy.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 1;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT + 3;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT + 1;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 4 * INTERACTION_BATCH_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const SEMANTIC_DIGEST_HEX = "2d1d3a4ee6ff22271bc42b7fa06ab18ec0ac31516ba471b6d203808562ee5c96";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk result;
};
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const Runtime = compiler.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Row = Runtime.Row;
pub const Plan = Runtime.Plan;
const events: [RELATION_EVENT_COUNT]types.EffectId = .{ @enumFromInt(0), @enumFromInt(1), @enumFromInt(2) };

pub const Definition = struct {
    arena: ir.Arena,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try @import("../../air/lang/validate.zig").validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (!std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidDirectPayloadDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = Definition{ .arena = try legacy.buildDirectNpv2WireExportArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildDirectNpv2WireExportArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, events);
}

/// Physical order: original main, original fixed, NPV2 mask, two public
/// activation parameters. The mask is never inferred from child-selected data.
pub fn logicalRow(original: old_relation.Row, wire_mask: bool) !Row {
    const fixed_at = PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    if (wire_mask) {
        if (original[0].toU32() != 1 or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 11].toU32() != @intFromEnum(legacy.VerifierInputKind.statement) or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 12].toU32() != 1 or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 13].toU32() >= legacy.NPV2_WIRE_WORD_COUNT or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 14].toU32() != 0 or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 15].toU32() != 1)
            return error.InvalidDirectNpv2WireRow;
    }
    return original[0..fixed_at].* ++ .{M31.fromCanonical(@intFromBool(wire_mask))} ++ original[fixed_at..].*;
}

test "V6 direct row5 semantic identity" {
    const identity = try semanticIdentity(std.testing.allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, identity.bytes);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    _ = try authenticate(&definition);
}

comptime {
    if (Runtime.BATCH_COUNT != INTERACTION_BATCH_COUNT or
        Runtime.INTERACTION_COLUMN_COUNT != INTERACTION_COLUMN_COUNT or
        legacy.NPV2_SCOPE != 0x4e50_5632)
        @compileError("direct row5 relation profile drifted");
}
