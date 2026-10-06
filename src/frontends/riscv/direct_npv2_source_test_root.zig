const std = @import("std");
const payload = @import("recursion/air/transcript_payload.zig");
const field = @import("recursion/transcript_program_v2_field_authority_v1.zig");
const origins = @import("recursion/transcript_program_v2_word_origins_v4.zig");
const transcript = @import("recursion/transcript_program_v2.zig");
const protocol = @import("recursion/segment_leaf_wrapper_protocol_direct_v4.zig");
const support = @import("recursion/air/test_support.zig");
const types = @import("air/lang/types.zig");
const relation = @import("air/lang/relation.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const row5_schedule = @import("recursion/transcript_program_v2_row5_npv2_schedule_v4.zig");
const native_source = @import("recursion/segment_transcript_outer_source_v2.zig");

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

test "NPV2 canonical index map covers fixed PCS and instruction descriptors" {
    const instructions = try std.testing.allocator.alloc(transcript.Instruction, 2);
    defer std.testing.allocator.free(instructions);
    instructions[0] = .{ .kind = .pcs_config, .verifier_sequence = 1, .sub_index = 2, .args = .{ 3, 4, 5, 6 } };
    instructions[1] = .{ .kind = .statement_wire_id, .verifier_sequence = 7, .sub_index = 8, .args = .{ 9, 10, 11, 12 } };
    const program = transcript.Program{
        .allocator = std.testing.allocator,
        .plan_id = .{0} ** 8,
        .wire_id = .{0} ** 8,
        .statement_authority_id = .{0} ** 8,
        .wire_word_count = 0,
        .pcs_config = protocol.PCS_CONFIG,
        .instructions = instructions,
        .identity = .{0} ** 8,
    };
    var map = try origins.Map.init(std.testing.allocator, &program);
    defer map.deinit();
    try std.testing.expectEqual(@as(usize, 69), map.origins.len);
    try std.testing.expectEqual(@as(usize, 8), map.count(.wire_id));
    try std.testing.expectEqual(@as(usize, 13), map.count(.pcs_parameter));
    try std.testing.expectEqual(@as(usize, 2), map.count(.instruction_kind));
    try std.testing.expectEqual(@as(usize, 4), map.count(.instruction_sequence));
    try std.testing.expectEqual(@as(usize, 16), map.count(.instruction_arg));
    try std.testing.expectEqual(origins.Kind.pcs_parameter, map.origins[28].kind);
    try std.testing.expectEqual(origins.Kind.instruction_kind, map.origins[43].kind);
    try std.testing.expectEqual(@as(u32, 0), map.origins[43].ordinal);
    try std.testing.expectEqual(origins.Kind.instruction_kind, map.origins[56].kind);
    try std.testing.expectEqual(@as(u32, 1), map.origins[56].ordinal);
    const coverage = map.coverage();
    try std.testing.expectEqual(@as(usize, 14), coverage.native_row5);
    try std.testing.expectEqual(@as(usize, 9), coverage.fixed_row42_required);
    try std.testing.expectEqual(@as(usize, 46), coverage.unlinked);
    try std.testing.expect(!coverage.complete());

    const Preprocessed = struct {
        row_mask: u32 = 1,
        segment_mask: u32 = 1,
        verifier_id: u32 = 0,
        sequence: u32,
        tag: u32,
        args: [4]u32,
    };
    const Row = struct { preprocessing: Preprocessed };
    var rows = [_]Row{
        .{ .preprocessing = .{ .sequence = 0, .tag = @import("recursion/segment_transcript_outer_source_v2_contract.zig").typedTag(instructions[0].kind), .args = instructions[0].args } },
        .{ .preprocessing = .{ .sequence = 1, .tag = @import("recursion/segment_transcript_outer_source_v2_contract.zig").typedTag(instructions[1].kind), .args = instructions[1].args } },
    };
    var row4 = try origins.Row4Audit.init(std.testing.allocator, &program, &rows);
    defer row4.deinit();
    try row4.requireAllPresent();
    rows[1].preprocessing.row_mask = 0;
    var missing = try origins.Row4Audit.init(std.testing.allocator, &program, &rows);
    defer missing.deinit();
    try std.testing.expectError(error.MissingNpv2Row4Instruction, missing.requireAllPresent());
    rows[1].preprocessing.row_mask = 1;
    rows[1].preprocessing.args[0] += 1;
    try std.testing.expectError(error.InvalidNpv2Row4Descriptor, origins.Row4Audit.init(std.testing.allocator, &program, &rows));
}

test "NPV2 PCS payload coordinates equal six canonical ProgramV2 words" {
    const instructions = try std.testing.allocator.alloc(transcript.Instruction, 0);
    defer std.testing.allocator.free(instructions);
    const program = transcript.Program{
        .allocator = std.testing.allocator,
        .plan_id = .{0} ** 8,
        .wire_id = .{0} ** 8,
        .statement_authority_id = .{0} ** 8,
        .wire_word_count = 0,
        .pcs_config = protocol.PCS_CONFIG,
        .instructions = instructions,
        .identity = .{0} ** 8,
    };
    const words = try field.canonicalWords(std.testing.allocator, &program);
    defer std.testing.allocator.free(words);
    var mixed: [8]M31 = undefined;
    @import("recursion/transcript_program_v2_program.zig").writePcsFelts(&mixed, program.pcs_config);
    for (payload.NPV2_PCS_CANONICAL_INDICES, 0..) |canonical_index, payload_index|
        try std.testing.expectEqual(words[canonical_index].toU32(), mixed[payload_index].toU32());
}

test "NPV2 PCS row-5 export rejects wrong source and preserves payload value" {
    var arena = try payload.buildNpv2WirePcsExportArena(std.testing.allocator);
    defer arena.deinit();
    var row = [_]M31{M31.zero()} ** 30;
    row[0] = M31.one();
    row[1] = M31.fromCanonical(protocol.PCS_CONFIG.pow_bits);
    row[2] = M31.one();
    row[3] = M31.one();
    row[13] = M31.fromCanonical(@intFromEnum(payload.VerifierInputKind.pcs_parameters));
    row[16] = M31.one(); // constant payload
    row[18] = row[1]; // base row-5 constant equals the value Fiat--Shamir mixes
    row[26] = M31.one(); // PCS NPV2 emitter
    row[27] = M31.fromCanonical(payload.NPV2_PCS_CANONICAL_INDICES[0]);
    row[28] = M31.one(); // segment active
    try expectAllConstraints(&arena, &row, true);
    const values = try support.evaluateArena(std.testing.allocator, &arena, &row);
    defer std.testing.allocator.free(values);
    const event_id: types.EffectId = @enumFromInt(arena.effectsView().len - 1);
    const tuple = arena.effectValues(event_id).?;
    try std.testing.expectEqual(payload.NPV2_SCOPE, values[types.idIndex(tuple[0])].toU32());
    try std.testing.expectEqual(@as(u32, 28), values[types.idIndex(tuple[1])].toU32());
    try std.testing.expectEqual(protocol.PCS_CONFIG.pow_bits, values[types.idIndex(tuple[2])].toU32());

    row[13] = M31.fromCanonical(@intFromEnum(payload.VerifierInputKind.statement));
    try expectAllConstraints(&arena, &row, false);
    row[13] = M31.fromCanonical(@intFromEnum(payload.VerifierInputKind.pcs_parameters));
    row[14] = M31.one();
    try expectAllConstraints(&arena, &row, false);
    row[14] = M31.zero();
    row[16] = M31.zero();
    try expectAllConstraints(&arena, &row, false);
    row[16] = M31.one();
    row[17] = M31.one();
    try expectAllConstraints(&arena, &row, false);
    row[17] = M31.zero();
    row[1] = M31.fromCanonical(protocol.PCS_CONFIG.pow_bits + 1);
    try expectAllConstraints(&arena, &row, false);
}

test "NPV2 row-5 fixed schedule rejects omitted duplicate and changed native words" {
    const instructions = try std.testing.allocator.alloc(transcript.Instruction, 0);
    defer std.testing.allocator.free(instructions);
    const program = transcript.Program{
        .allocator = std.testing.allocator,
        .plan_id = .{0} ** 8,
        .wire_id = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .statement_authority_id = .{0} ** 8,
        .wire_word_count = 0,
        .pcs_config = protocol.PCS_CONFIG,
        .instructions = instructions,
        .identity = .{0} ** 8,
    };
    const Row = struct {
        source_kind: native_source.PayloadSourceKindV2,
        item_index: u32,
        limb_index: u32,
        constant_mask: u32,
        input_use_count: u32,
        value: M31,
    };
    var rows: [14]Row = undefined;
    var mixed: [8]M31 = undefined;
    @import("recursion/transcript_program_v2_program.zig").writePcsFelts(&mixed, program.pcs_config);
    for (0..6) |index| rows[index] = .{
        .source_kind = .pcs_parameters,
        .item_index = 0,
        .limb_index = @intCast(index),
        .constant_mask = 1,
        .input_use_count = 0,
        .value = mixed[index],
    };
    for (0..8) |index| rows[6 + index] = .{
        .source_kind = .statement,
        .item_index = 1,
        .limb_index = @intCast(index),
        .constant_mask = 0,
        .input_use_count = 1,
        .value = M31.fromCanonical(program.wire_id[index]),
    };
    var schedule = try row5_schedule.Schedule.init(std.testing.allocator, &program, &rows);
    defer schedule.deinit();
    for (schedule.entries[0..6], 0..) |entry, index| {
        try std.testing.expectEqual(@as(u32, 1), entry.pcs_mask);
        try std.testing.expectEqual(payload.NPV2_PCS_CANONICAL_INDICES[index], entry.pcs_canonical_index);
    }
    for (schedule.entries[6..]) |entry| try std.testing.expectEqual(@as(u32, 1), entry.wire_mask);
    rows[6].value = M31.fromCanonical(9);
    try std.testing.expectError(error.InvalidNpv2Row5WireSource, row5_schedule.Schedule.init(std.testing.allocator, &program, &rows));
    rows[6].value = M31.fromCanonical(program.wire_id[0]);
    rows[7].limb_index = 0;
    try std.testing.expectError(error.InvalidNpv2Row5WireSource, row5_schedule.Schedule.init(std.testing.allocator, &program, &rows));
    rows[7].limb_index = 1;
    rows[0].source_kind = .protocol;
    try std.testing.expectError(error.IncompleteNpv2Row5PcsSource, row5_schedule.Schedule.init(std.testing.allocator, &program, &rows));
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
