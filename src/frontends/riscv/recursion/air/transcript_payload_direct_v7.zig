//! Versioned native row-5 payload AIR for the direct SegmentV2 wrapper.
//! Its key-owned mask emits all sixteen u16 wire-ID transcript halves under
//! NPH2; row42 must prove bounds and recomposition before using a field word.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("transcript_payload.zig");
const old_relation = @import("transcript_payload_relation.zig");
const compiler = @import("relation_interaction.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");

pub const STABLE_NAME = "recursion.transcript_payload.direct.v7.halves";
pub const PHYSICAL_MAIN_COLUMN_COUNT = legacy.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = legacy.PREPROCESSED_COLUMN_COUNT + 1;
pub const PARAMETER_COUNT = legacy.PARAMETER_COUNT;
pub const LOGICAL_INPUT_COUNT = legacy.LOGICAL_INPUT_COUNT + 1;
pub const DIRECT_CONSTRAINT_COUNT = legacy.DIRECT_CONSTRAINT_COUNT + 4;
pub const RELATION_EVENT_COUNT = legacy.RELATION_EVENT_COUNT + 1;
pub const LOOKUP_BATCH_SIZE = legacy.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 4 * INTERACTION_BATCH_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = legacy.MAXIMUM_CONSTRAINT_DEGREE;
pub const SEMANTIC_DIGEST_HEX = "b4dce005c6eb300e2e598f6dc90bf51c170d1b2090ca6a0e3e424aa77553ccf3";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk result;
};
pub const Runtime = compiler.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Row = Runtime.Row;
pub const Plan = Runtime.Plan;
pub const events: [RELATION_EVENT_COUNT]types.EffectId = .{ @enumFromInt(0), @enumFromInt(1), @enumFromInt(2) };

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
    var result = Definition{ .arena = try legacy.buildDirectWireHalfExportArena(allocator) };
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var arena = try legacy.buildDirectWireHalfExportArena(allocator);
    defer arena.deinit();
    return digest.computeIdentity(&arena);
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, events);
}

/// Physical order: original main, original fixed, NPH2 mask, two public
/// activation parameters. The mask is compiled from the sixteen wire limbs.
pub fn logicalRow(original: old_relation.Row, half_mask: bool) !Row {
    const fixed_at = PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    if (half_mask) {
        if (original[0].toU32() != 1 or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 11].toU32() != @intFromEnum(legacy.VerifierInputKind.statement) or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 12].toU32() != 1 or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 13].toU32() >= 2 * legacy.NPV2_WIRE_WORD_COUNT or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 14].toU32() != 0 or
            original[PHYSICAL_MAIN_COLUMN_COUNT + 15].toU32() != 1)
            return error.InvalidDirectWireHalfRow;
    }
    return original[0..fixed_at].* ++ .{M31.fromCanonical(@intFromBool(half_mask))} ++ original[fixed_at..].*;
}

test "V7 direct row5 half-tuple semantic identity" {
    const identity = try semanticIdentity(std.testing.allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, identity.bytes);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    _ = try authenticate(&definition);
    var original = [_]M31{M31.zero()} ** legacy.LOGICAL_INPUT_COUNT;
    original[0] = M31.one();
    original[1] = M31.fromCanonical(17);
    original[PHYSICAL_MAIN_COLUMN_COUNT] = M31.one();
    original[PHYSICAL_MAIN_COLUMN_COUNT + 1] = M31.one();
    original[PHYSICAL_MAIN_COLUMN_COUNT + 11] = M31.fromCanonical(@intFromEnum(legacy.VerifierInputKind.statement));
    original[PHYSICAL_MAIN_COLUMN_COUNT + 12] = M31.one();
    original[PHYSICAL_MAIN_COLUMN_COUNT + 15] = M31.one();
    original[legacy.LOGICAL_INPUT_COUNT - 2] = M31.one();
    var row = try logicalRow(original, true);
    const support = @import("test_support.zig");
    const good = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(good);
    for (definition.arena.constraintsView()) |constraint|
        try std.testing.expect(good[types.idIndex(constraint.root)].isZero());
    row[PHYSICAL_MAIN_COLUMN_COUNT + 14] = M31.one();
    const forged = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(forged);
    try std.testing.expect(!forged[types.idIndex(definition.arena.constraintsView()[6].root)].isZero());
}

comptime {
    if (Runtime.BATCH_COUNT != INTERACTION_BATCH_COUNT or
        Runtime.INTERACTION_COLUMN_COUNT != INTERACTION_COLUMN_COUNT or
        legacy.WIRE_HALF_SCOPE != 0x4e50_4832)
        @compileError("direct row5 relation profile drifted");
}
