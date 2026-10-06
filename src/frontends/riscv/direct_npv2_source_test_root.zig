const std = @import("std");
const payload = @import("recursion/air/transcript_payload.zig");
const field = @import("recursion/transcript_program_v2_field_authority_v1.zig");
const transcript = @import("recursion/transcript_program_v2.zig");
const protocol = @import("recursion/segment_leaf_wrapper_protocol_direct_v4.zig");
const support = @import("recursion/air/test_support.zig");
const types = @import("air/lang/types.zig");
const relation = @import("air/lang/relation.zig");
const M31 = @import("stwo_core").fields.m31.M31;

test {
    _ = payload;
}

test "NPV2 base payload export maps canonical ProgramV2 wire ID indices" {
    const instructions = try std.testing.allocator.alloc(transcript.Instruction, 0);
    defer std.testing.allocator.free(instructions);
    var program = transcript.Program{
        .allocator = std.testing.allocator,
        .plan_id = .{0} ** 8,
        .wire_id = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .statement_authority_id = .{0} ** 8,
        .wire_word_count = 0,
        .pcs_config = protocol.PCS_CONFIG,
        .instructions = instructions,
        .identity = .{0} ** 8,
    };
    const words = try field.canonicalWords(std.testing.allocator, &program);
    defer std.testing.allocator.free(words);
    for (program.wire_id, 0..) |limb, index|
        try std.testing.expectEqual(limb, words[payload.NPV2_WIRE_WORD_BASE + index].toU32());
    const original = words[payload.NPV2_WIRE_WORD_BASE + 3].toU32();
    program.wire_id[3] += 1;
    const changed = try field.canonicalWords(std.testing.allocator, &program);
    defer std.testing.allocator.free(changed);
    try std.testing.expectEqual(original + 1, changed[payload.NPV2_WIRE_WORD_BASE + 3].toU32());
    for (words, changed, 0..) |before, after, index|
        if (index != payload.NPV2_WIRE_WORD_BASE + 3)
            try std.testing.expect(before.eql(after));
}

test "NPV2 base payload export rejects wrong row-5 source and multiplicity" {
    var arena = try payload.buildNpv2WireExportArena(std.testing.allocator);
    defer arena.deinit();
    var row = [_]M31{M31.zero()} ** 28;
    row[0] = M31.one(); // main enabler
    row[1] = M31.fromCanonical(5); // actual row-5 payload value
    row[2] = M31.one(); // row mask
    row[3] = M31.one(); // segment mask
    row[13] = M31.fromCanonical(@intFromEnum(payload.VerifierInputKind.statement));
    row[14] = M31.one(); // wire-ID statement item
    row[15] = M31.fromCanonical(3); // digest limb
    row[17] = M31.one(); // original verifier-input use only
    row[25] = M31.one(); // NPV2 wire export mask
    row[26] = M31.one(); // segment-active parameter
    try expectAllConstraints(&arena, &row, true);
    const values = try support.evaluateArena(std.testing.allocator, &arena, &row);
    defer std.testing.allocator.free(values);
    const event_id: types.EffectId = @enumFromInt(arena.effectsView().len - 1);
    const event = arena.effect(event_id).?;
    try std.testing.expectEqual(relation.get(.recursion_vm_public_claim_word).id, event.binding.?.schema);
    try std.testing.expectEqual(types.RelationRole.emit, event.binding.?.role);
    const tuple = arena.effectValues(event_id).?;
    try std.testing.expectEqual(@as(usize, 3), tuple.len);
    try std.testing.expectEqual(payload.NPV2_SCOPE, values[types.idIndex(tuple[0])].toU32());
    try std.testing.expectEqual(@as(u32, payload.NPV2_WIRE_WORD_BASE + 3), values[types.idIndex(tuple[1])].toU32());
    try std.testing.expectEqual(@as(u32, 5), values[types.idIndex(tuple[2])].toU32());
    try std.testing.expectEqual(@as(u32, 1), values[types.idIndex(event.liveness.?)].toU32());

    row[13] = M31.fromCanonical(@intFromEnum(payload.VerifierInputKind.protocol));
    try expectAllConstraints(&arena, &row, false);
    row[13] = M31.fromCanonical(@intFromEnum(payload.VerifierInputKind.statement));
    row[14] = M31.fromCanonical(2);
    try expectAllConstraints(&arena, &row, false);
    row[14] = M31.one();
    row[17] = M31.fromCanonical(2);
    try expectAllConstraints(&arena, &row, false);
}

fn expectAllConstraints(arena: anytype, row: []const M31, expected: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, arena, row);
    defer std.testing.allocator.free(values);
    var all_zero = true;
    for (arena.constraintsView()) |constraint| {
        if (!values[types.idIndex(constraint.root)].isZero()) all_zero = false;
    }
    try std.testing.expectEqual(expected, all_zero);
}
