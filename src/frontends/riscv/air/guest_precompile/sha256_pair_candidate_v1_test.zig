const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const sha = @import("sha256_pair_candidate_v1.zig");
const direct = @import("sha256_pair_direct_candidate_v1.zig");
const caller = @import("sha256_pair_caller_candidate_v1.zig");
const projection = @import("sha256_pair_observer_projection_v1.zig");

test "fixed SHA-256 pair owns exact two-block semantics" {
    const zeros = [_]u8{0} ** sha.input_bytes;
    var patterned: [sha.input_bytes]u8 = undefined;
    fillPattern(&patterned);
    try expectStandardHash(zeros);
    try expectStandardHash(patterned);

    const zero_hash = sha.hashPair(zeros);
    const expected_zero = try hexDigest(
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
    );
    try std.testing.expectEqualSlices(u8, &expected_zero, &zero_hash);

    const witness = sha.buildWitness(patterned);
    try witness.validate();
    try std.testing.expectEqualSlices(u8, &patterned, &witness.blocks[0].input);
    const padding = sha.paddingBlock();
    try std.testing.expectEqualSlices(u8, &padding, &witness.blocks[1].input);
    try std.testing.expectEqual(@as(u8, 0x80), padding[0]);
    try std.testing.expectEqual(@as(u8, 0x02), padding[62]);
    try std.testing.expectEqual(@as(u8, 0x00), padding[63]);
    for (padding[1..62]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expectEqual(@as(u32, 0x8000_0000), witness.blocks[1].schedule[0]);
    try std.testing.expectEqual(@as(u32, 512), witness.blocks[1].schedule[15]);
    try std.testing.expectEqualSlices(
        u32,
        &witness.blocks[0].output_state,
        &witness.blocks[1].states[0],
    );
    try std.testing.expect(!sha.production_active);
    try std.testing.expect(!sha.opcode_registry_ready);
    try std.testing.expect(!sha.air_ready);
}

test "fixed SHA-256 pair rejects semantic trace and identity mutations" {
    var input: [sha.input_bytes]u8 = undefined;
    fillPattern(&input);
    const clean = sha.buildWitness(input);

    var malformed = clean;
    malformed.blocks[0].schedule[16] ^= 1;
    try std.testing.expectError(error.InvalidSchedule, malformed.validate());
    malformed = clean;
    malformed.blocks[0].states[19][3] ^= 1;
    try std.testing.expectError(error.InvalidBlockState, malformed.validate());
    malformed = clean;
    malformed.blocks[1].input[0] ^= 1;
    try std.testing.expectError(error.InvalidPadding, malformed.validate());
    malformed = clean;
    malformed.output[7] ^= 1;
    try std.testing.expectError(error.InvalidOutput, malformed.validate());
    malformed = clean;
    malformed.verifier_program_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidProgramIdentity, malformed.validate());
    malformed = clean;
    malformed.instance_identity[31] ^= 1;
    try std.testing.expectError(error.InvalidInstanceIdentity, malformed.validate());
}

test "round AIR closes every two-block row and boundary relation" {
    var input: [sha.input_bytes]u8 = undefined;
    fillPattern(&input);
    const witness = sha.buildWitness(input);
    for (0..sha.block_count) |block| {
        for (0..sha.round_count) |round| {
            const position = try direct.Position.init(block, round);
            const row = direct.fill(9, &witness, position);
            const next = if (position.isCallLast())
                direct.zeroRow(M31)
            else if (position.isBlockLast())
                direct.fill(9, &witness, try direct.Position.init(block + 1, 0))
            else
                direct.fill(9, &witness, try direct.Position.init(block, round + 1));
            var sink = RootSink{};
            direct.evaluateGeneric(M31, &row, &next, position, M31.one(), &sink);
            try std.testing.expectEqual(direct.constraint_count, sink.count);
            try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
        }
    }

    const first = direct.fill(9, &witness, try direct.Position.init(0, 0));
    const input_tuple = direct.inputRelationTuple(M31, &first);
    for (input, 0..) |byte, index|
        try std.testing.expectEqual(@as(u32, byte), input_tuple[2 + index].toU32());
    const last = direct.fill(9, &witness, try direct.Position.init(1, 63));
    const output_tuple = direct.outputRelationTuple(M31, &last);
    for (witness.output, 0..) |byte, index|
        try std.testing.expectEqual(@as(u32, byte), output_tuple[2 + index].toU32());
}

test "round AIR rejects arithmetic transition boundary and padding mutations" {
    var input: [sha.input_bytes]u8 = undefined;
    fillPattern(&input);
    const witness = sha.buildWitness(input);
    const position = try direct.Position.init(0, 17);
    const clean = direct.fill(4, &witness, position);
    const next = direct.fill(4, &witness, try direct.Position.init(0, 18));

    var malformed = clean;
    malformed.state_before[4][7] = toggle(malformed.state_before[4][7]);
    try expectNonzero(malformed, next, position, M31.one());
    malformed = clean;
    malformed.schedule_append[11] = toggle(malformed.schedule_append[11]);
    try expectNonzero(malformed, next, position, M31.one());
    malformed = clean;
    malformed.t1_carry[8][0] = toggle(malformed.t1_carry[8][0]);
    try expectNonzero(malformed, next, position, M31.one());

    var malformed_next = next;
    malformed_next.schedule_ring[5][3] = toggle(malformed_next.schedule_ring[5][3]);
    try expectNonzero(clean, malformed_next, position, M31.one());

    const final_position = try direct.Position.init(1, 63);
    var final = direct.fill(4, &witness, final_position);
    const zero = direct.zeroRow(M31);
    final.digest[2][9] = toggle(final.digest[2][9]);
    try expectNonzero(final, zero, final_position, M31.one());

    var padding = direct.zeroRow(M31);
    padding.call_index = M31.one();
    try expectNonzero(padding, zero, position, M31.zero());
    const clean_padding = direct.zeroRow(M31);
    var sink = RootSink{};
    direct.evaluateGeneric(
        M31,
        &clean_padding,
        &zero,
        position,
        M31.zero(),
        &sink,
    );
    try std.testing.expectEqual(direct.constraint_count, sink.count);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
}

test "caller binds fixed input output and all memory chains" {
    const record = sampleRecord();
    try record.validate();
    const witness = sha.buildWitness(record.input);
    const first = direct.fill(
        record.call_index,
        &witness,
        try direct.Position.init(0, 0),
    );
    const last = direct.fill(
        record.call_index,
        &witness,
        try direct.Position.init(1, 63),
    );
    try caller.validateAgainstAir(record, &first, &last);
    const events = try record.relationEvents();
    try std.testing.expectEqual(@as(u32, record.pc + 4), events.state_after[0]);
    try std.testing.expectEqual(@as(u32, record.execution_clock + 1), events.state_after[1]);
    try std.testing.expectEqual(@as(u32, record.record_ptr / 4), events.memory[0].before.address);
    try std.testing.expectEqualSlices(
        u8,
        record.input[0..4],
        &events.memory[0].after.bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        record.output_before[0..4],
        &events.memory[caller.input_word_count].before.bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        record.output[0..4],
        &events.memory[caller.input_word_count].after.bytes,
    );
    try std.testing.expect(!caller.production_active);
    try std.testing.expect(!caller.opcode_allocated);
    try std.testing.expect(!caller.program_relation_ready);
}

test "caller rejects output clock pointer and relation mutations" {
    const clean = sampleRecord();
    var malformed = clean;
    malformed.output[0] ^= 1;
    try std.testing.expectError(error.InvalidOutput, malformed.validate());
    malformed = clean;
    malformed.record_ptr += 1;
    try std.testing.expectError(error.InvalidCall, malformed.validate());
    malformed = clean;
    malformed.memory_previous_clocks[3] = access_clock.encode(
        clean.execution_clock,
        .second,
    );
    try std.testing.expectError(error.InvalidCall, malformed.validate());

    const witness = sha.buildWitness(clean.input);
    var first = direct.fill(clean.call_index, &witness, try direct.Position.init(0, 0));
    const last = direct.fill(clean.call_index, &witness, try direct.Position.init(1, 63));
    first.schedule_ring[0][31] = toggle(first.schedule_ring[0][31]);
    try std.testing.expectError(
        error.RelationMismatch,
        caller.validateAgainstAir(clean, &first, &last),
    );
    first = direct.fill(clean.call_index, &witness, try direct.Position.init(0, 0));
    var wrong_index = clean;
    wrong_index.call_index += 1;
    try std.testing.expectError(
        error.RelationMismatch,
        caller.validateAgainstAir(wrong_index, &first, &last),
    );
}

test "retained prefix projection isolates 1385 fixed pairs and keeps variable SHA" {
    const retained = projection.prefix64();
    try retained.validate();
    try std.testing.expectEqual(@as(u64, 2_771), retained.compression_calls);
    try std.testing.expectEqual(@as(u64, 1_385), retained.fixed_pair_calls);
    try std.testing.expectEqual(@as(u64, 2_770), retained.fixed_pair_compressions);
    try std.testing.expectEqual(@as(u64, 11_869_450), retained.fixed_pair_core_rows);
    try std.testing.expectEqual(@as(u64, 1), retained.variable_hash_calls);
    try std.testing.expectEqual(@as(u64, 4_285), retained.variable_hash_core_rows_kept_software);
    try std.testing.expectEqual(@as(u64, 11_868_065), retained.projected_net_core_rows_removed);
    try std.testing.expectEqual(@as(u64, 177_280), retained.projected_round_air_rows);
    try std.testing.expectEqual(
        @as(u64, 262_144),
        retained.aggregate_round_air_padded_rows_lower_bound,
    );
    try std.testing.expectEqual(
        @as(u64, 383_279_360),
        retained.round_air_active_main_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 566_755_328),
        retained.aggregate_round_air_padded_main_cells_lower_bound,
    );
    try std.testing.expectEqual(
        @as(u64, 498_904_700),
        retained.removed_typed_logical_main_cells_upper_bound,
    );
    try std.testing.expectEqual(
        @as(u64, 67_850_628),
        retained.round_air_main_cell_overhead_lower_bound,
    );
    try std.testing.expectEqual(
        @as(u64, 11_869_450),
        fixedPairFamilyRows(),
    );
    try std.testing.expect(!retained.main_cell_reduction);
    try std.testing.expect(!retained.caller_component_cells_included);
    try std.testing.expect(!retained.interaction_cells_included);
    try std.testing.expect(retained.variable_hash_stays_software);
    try std.testing.expect(retained.no_extrapolation);
    try std.testing.expect(!projection.production_active);

    var malformed = retained;
    malformed.fixed_pair_calls += 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.variable_hash_stays_software = false;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.round_air_main_cell_overhead_lower_bound -= 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.execution_journal_sha256[0] ^= 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.round_air_program_identity[31] ^= 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.projection_identity[0] ^= 1;
    try expectInvalidProjection(malformed);
}

fn fixedPairFamilyRows() u64 {
    var result: u64 = 0;
    for (projection.fixed_pair_rows_by_family) |item| result += item.rows;
    return result;
}

fn expectStandardHash(input: [sha.input_bytes]u8) !void {
    var expected: [sha.output_bytes]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &expected, .{});
    const actual = sha.hashPair(input);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
    const witness = sha.buildWitness(input);
    try witness.validate();
}

fn expectNonzero(
    row: direct.Row(M31),
    next: direct.Row(M31),
    position: direct.Position,
    expected_active: M31,
) !void {
    var sink = RootSink{};
    direct.evaluateGeneric(M31, &row, &next, position, expected_active, &sink);
    try std.testing.expectEqual(direct.constraint_count, sink.count);
    try std.testing.expect(sink.nonzero != 0);
}

fn sampleRecord() caller.RecordV1 {
    var input: [sha.input_bytes]u8 = undefined;
    fillPattern(&input);
    var output_before: [sha.output_bytes]u8 = undefined;
    for (&output_before, 0..) |*byte, index| byte.* = @truncate(index *% 11 +% 3);
    return .{
        .execution_clock = 17,
        .pc = 0x2000,
        .pointer_register = 10,
        .pointer_previous_clock = 1,
        .record_ptr = 0x4000,
        .memory_previous_clocks = @splat(1),
        .output_before = output_before,
        .input = input,
        .output = sha.hashPair(input),
        .call_index = 7,
    };
}

fn fillPattern(output: []u8) void {
    for (output, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% 19);
}

fn toggle(value: M31) M31 {
    return M31.one().sub(value);
}

fn hexDigest(encoded: []const u8) ![sha.output_bytes]u8 {
    var result: [sha.output_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}

fn expectInvalidProjection(value: projection.ProjectionV1) !void {
    try std.testing.expectError(error.InvalidObserverProjection, value.validate());
}

const RootSink = struct {
    count: usize = 0,
    nonzero: usize = 0,

    pub fn add(self: *RootSink, value: M31, degree: u8) void {
        std.debug.assert(degree <= direct.maximum_constraint_degree);
        self.count += 1;
        if (!value.isZero()) self.nonzero += 1;
    }
};
