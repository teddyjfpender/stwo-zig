const std = @import("std");
const payload = @import("recursion/air/transcript_payload.zig");
const fixed_bridge = @import("recursion/air/transcript_program_v2_field_bridge_v5.zig");
const descriptor_export = @import("recursion/air/transcript_word_descriptor_export_v4.zig");
const descriptor_schedule = @import("recursion/transcript_program_v2_row4_descriptor_schedule_v4.zig");
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
const native_contract = @import("recursion/segment_transcript_outer_source_v2_contract.zig");

test {
    _ = payload;
    _ = fixed_bridge;
    _ = descriptor_export;
    _ = descriptor_schedule;
}

test "NPV2 row4 descriptor variant pins semantic identity" {
    const digest = try descriptor_export.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualDeep(descriptor_export.SEMANTIC_DIGEST, digest);
}

test "NPV2 row4 descriptor export uses native tag and canonical arg limbs" {
    var definition = try descriptor_export.build(std.testing.allocator);
    defer definition.deinit();
    var row = [_]M31{M31.zero()} ** descriptor_export.LOGICAL_INPUT_COUNT;
    row[0] = M31.one(); // native row4 enabler
    row[1] = M31.fromCanonical(9); // executed payload
    row[2] = M31.one(); // row mask
    row[3] = M31.one(); // segment mask
    row[7] = M31.fromCanonical(native_contract.typedTag(.statement_header));
    row[8] = M31.fromCanonical(0x12345); // native row4 arg0
    row[13] = M31.fromCanonical(8); // word index
    row[14] = M31.one(); // payload row
    row[17] = M31.one(); // segment active
    const extra = 19;
    row[extra] = M31.one(); // selected
    row[extra + 1] = M31.fromCanonical(native_contract.typedTag(.statement_header) - @intFromEnum(transcript.Kind.statement_header));
    row[extra + 2] = M31.fromCanonical(43); // canonical instruction base
    row[extra + 3] = M31.fromCanonical(0x2345);
    row[extra + 4] = M31.one();
    try expectAllConstraints(&definition.base.arena, &row, true);
    const values = try support.evaluateArena(std.testing.allocator, &definition.base.arena, &row);
    defer std.testing.allocator.free(values);
    const kind_tuple = definition.base.arena.effectValues(definition.events[0]).?;
    const native_tuple = definition.base.arena.effectValues(definition.base.events.payload_word_consume).?;
    try std.testing.expectEqual(values[types.idIndex(native_tuple[2])].toU32(), row[7].toU32());
    try std.testing.expectEqual(values[types.idIndex(native_tuple[3])].toU32(), row[8].toU32());
    try std.testing.expectEqual(payload.NPV2_SCOPE, values[types.idIndex(kind_tuple[0])].toU32());
    try std.testing.expectEqual(@as(u32, 43), values[types.idIndex(kind_tuple[1])].toU32());
    try std.testing.expectEqual(@as(u32, @intFromEnum(transcript.Kind.statement_header)), values[types.idIndex(kind_tuple[2])].toU32());
    const arg_tuple = definition.base.arena.effectValues(definition.events[1]).?;
    try std.testing.expectEqual(@as(u32, 48), values[types.idIndex(arg_tuple[1])].toU32());
    try std.testing.expectEqual(@as(u32, 0x2345), values[types.idIndex(arg_tuple[2])].toU32());
    row[extra + 3] = row[extra + 3].add(M31.one());
    try expectAllConstraints(&definition.base.arena, &row, false);
    row[extra + 3] = row[extra + 3].sub(M31.one());
    row[14] = M31.zero();
    try expectAllConstraints(&definition.base.arena, &row, false);
    row[14] = M31.one();
    row[extra] = M31.fromCanonical(2);
    try expectAllConstraints(&definition.base.arena, &row, false);
}

test "NPV2 row4 schedule reports zero-payload instruction and absent descriptor fields" {
    const instructions = try std.testing.allocator.alloc(transcript.Instruction, 2);
    defer std.testing.allocator.free(instructions);
    instructions[0] = .{ .kind = .statement_header, .verifier_sequence = 2, .sub_index = 3, .args = .{ 0x12345, 0, 0, 0 } };
    instructions[1] = .{ .kind = .relation_draw, .verifier_sequence = 4, .sub_index = 5, .args = .{ 7, 8, 9, 10 } };
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
    const Preprocessed = struct {
        row_mask: u32 = 1,
        segment_mask: u32 = 1,
        binary_mask: u32 = 0,
        verifier_id: u32 = 0,
        sequence: u32 = 0,
        tag: u32 = native_contract.typedTag(.statement_header),
        args: [4]u32 = .{ 0x12345, 0, 0, 0 },
        word_index: u32 = 8,
        is_payload: u32 = 1,
        payload_index: u32 = 0,
    };
    const NativeRow = struct { preprocessing: Preprocessed };
    var rows = [_]NativeRow{.{ .preprocessing = .{} }};
    var schedule = try descriptor_schedule.Schedule.init(std.testing.allocator, &program, &rows);
    defer schedule.deinit();
    const coverage = schedule.coverage();
    try std.testing.expectEqual(@as(usize, 2), coverage.total_instructions);
    try std.testing.expectEqual(@as(usize, 1), coverage.selected_kind_arg_sources);
    try std.testing.expectEqual(@as(usize, 1), coverage.missing_row4_payload);
    try std.testing.expectEqual(@as(usize, 2), coverage.missing_verifier_sequence_source);
    try std.testing.expectEqual(@as(usize, 2), coverage.missing_sub_index_source);
    try std.testing.expectError(error.IncompleteInstructionDescriptorSource, coverage.requireComplete());
    const draw_tag = M31.fromCanonical(native_contract.typedTag(.relation_draw));
    const draw_kind = M31.fromCanonical(@intFromEnum(transcript.Kind.relation_draw));
    try std.testing.expect(draw_tag.sub(M31.fromCanonical(schedule.entries[1].tag_offset)).eql(draw_kind));
    const extra = schedule.extraRow(0);
    try std.testing.expectEqual(@as(u32, 1), extra[0].toU32());
    try std.testing.expectEqual(@as(u32, 43), extra[2].toU32());
    try std.testing.expectEqual(@as(u32, 0x2345), extra[3].toU32());
    try std.testing.expectEqual(@as(u32, 1), extra[4].toU32());
    try schedule.validateExtraRow(0, extra);
    var wrong_extra = extra;
    wrong_extra[4] = wrong_extra[4].add(M31.one());
    try std.testing.expectError(error.IncorrectNativeDescriptorPreprocessing, schedule.validateExtraRow(0, wrong_extra));
    wrong_extra = extra;
    wrong_extra[1] = wrong_extra[1].add(M31.one());
    try std.testing.expectError(error.IncorrectNativeDescriptorPreprocessing, schedule.validateExtraRow(0, wrong_extra));
    rows[0].preprocessing.args[0] += 1;
    try std.testing.expectError(error.NativeInstructionDescriptorMismatch, descriptor_schedule.Schedule.init(std.testing.allocator, &program, &rows));
    rows[0].preprocessing.args[0] -= 1;
    rows[0].preprocessing.tag += 1;
    try std.testing.expectError(error.NativeInstructionDescriptorMismatch, descriptor_schedule.Schedule.init(std.testing.allocator, &program, &rows));
    rows[0].preprocessing.tag -= 1;
    rows[0].preprocessing.word_index = 9;
    try std.testing.expectError(error.InvalidNativeInstructionPayloadRow, descriptor_schedule.Schedule.init(std.testing.allocator, &program, &rows));
    rows[0].preprocessing.word_index = 8;
    const duplicated = [_]NativeRow{ rows[0], rows[0] };
    try std.testing.expectError(error.DuplicateNativeInstructionPayloadOrigin, descriptor_schedule.Schedule.init(std.testing.allocator, &program, &duplicated));
    rows[0].preprocessing.is_payload = 0;
    var missing = try descriptor_schedule.Schedule.init(std.testing.allocator, &program, &rows);
    defer missing.deinit();
    try std.testing.expectEqual(@as(usize, 2), missing.coverage().missing_row4_payload);
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
    try std.testing.expectError(error.IncompleteNpv2ProgramCoverage, coverage.requireComplete());

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

test "NPV2 V5 fixed-word schedule exactly covers format schema and PCS high limbs" {
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
    var map = try origins.Map.init(std.testing.allocator, &program);
    defer map.deinit();
    const schedule = try fixed_bridge.FixedSchedule.init(words.len);
    var fixed_count: usize = 0;
    for (map.origins, words, 0..) |origin, word, index| {
        const fixed = fixed_bridge.fixedValue(@intCast(index));
        try std.testing.expectEqual(origin.kind == .format or origin.kind == .schema or
            (origin.kind == .pcs_parameter and origins.route(origin) == .fixed_row42_required), fixed != null);
        if (fixed) |expected| {
            fixed_count += 1;
            try std.testing.expectEqual(expected, word.toU32());
            const pp = try schedule.preprocessedRow(index);
            try std.testing.expectEqual(@as(u32, 1), pp[3].toU32());
            try std.testing.expectEqual(expected, pp[4].toU32());
        }
    }
    try std.testing.expectEqual(@as(usize, 9), fixed_count);
    try std.testing.expect(!map.coverage().complete());
    var wrong_profile = program;
    wrong_profile.pcs_config.fri_config.n_queries += 1;
    try std.testing.expectError(error.UnexpectedNpv2PcsProfile, origins.Map.init(std.testing.allocator, &wrong_profile));
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
