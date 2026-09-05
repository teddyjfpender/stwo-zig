const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const candidate = @import("keccak256_sponge_candidate_v1.zig");
const direct = @import("keccak256_sponge_direct_candidate_v1.zig");
const relations = @import("keccakf_relations.zig");
const projection = @import("keccak256_sponge_observer_projection_v1.zig");

test "Keccak-256 sponge matches independent standard vectors and boundaries" {
    const empty = [_]u8{};
    const abc = "abc";
    var rate_minus_one: [candidate.rate_bytes - 1]u8 = undefined;
    var exact_rate: [candidate.rate_bytes]u8 = undefined;
    var rate_plus_one: [candidate.rate_bytes + 1]u8 = undefined;
    fillPattern(&rate_minus_one);
    fillPattern(&exact_rate);
    fillPattern(&rate_plus_one);

    try expectStandardHash(&empty);
    try expectStandardHash(abc);
    try expectStandardHash(&rate_minus_one);
    try expectStandardHash(&exact_rate);
    try expectStandardHash(&rate_plus_one);

    const empty_hash = try candidate.hash(&empty);
    const expected_empty = try hexDigest(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
    try std.testing.expectEqualSlices(u8, &expected_empty, &empty_hash);
    const abc_hash = try candidate.hash(abc);
    const expected_abc = try hexDigest(
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    );
    try std.testing.expectEqualSlices(u8, &expected_abc, &abc_hash);
}

test "Keccak-256 sponge owns exact legacy padding and permutation chain" {
    var exact_rate: [candidate.rate_bytes]u8 = undefined;
    fillPattern(&exact_rate);
    var witness = try candidate.buildWitness(std.testing.allocator, &exact_rate);
    defer witness.deinit();
    try witness.validate(&exact_rate);
    try std.testing.expectEqual(@as(u32, 2), witness.plan.block_count);
    try std.testing.expectEqual(@as(usize, 2), witness.blocks.len);
    try std.testing.expectEqual(@as(u8, candidate.rate_bytes), witness.blocks[0].input_count);
    try std.testing.expect(!witness.blocks[0].is_final);
    try std.testing.expectEqual(@as(u8, 0), witness.blocks[0].padded_rate[0] ^ exact_rate[0]);
    try std.testing.expect(witness.blocks[1].is_final);
    try std.testing.expectEqual(@as(u8, 0), witness.blocks[1].input_count);
    try std.testing.expectEqual(candidate.legacy_keccak_suffix, witness.blocks[1].padded_rate[0]);
    try std.testing.expectEqual(candidate.terminal_padding_bit, witness.blocks[1].padded_rate[candidate.rate_bytes - 1]);
    try std.testing.expectEqualSlices(
        u64,
        &witness.blocks[0].permutation_output,
        &witness.blocks[1].state_before,
    );

    const original_padding = witness.blocks[1].padded_rate[0];
    witness.blocks[1].padded_rate[0] ^= 1;
    try std.testing.expectError(error.InvalidPadding, witness.validate(&exact_rate));
    witness.blocks[1].padded_rate[0] = original_padding;

    witness.blocks[1].state_before[0] ^= 1;
    try std.testing.expectError(error.InvalidSpongeChain, witness.validate(&exact_rate));
    witness.blocks[1].state_before[0] ^= 1;

    witness.blocks[1].permutation_input[0] ^= 1;
    try std.testing.expectError(error.InvalidPermutationInput, witness.validate(&exact_rate));
    witness.blocks[1].permutation_input[0] ^= 1;

    witness.blocks[1].permutation_output[0] ^= 1;
    try std.testing.expectError(error.InvalidPermutationOutput, witness.validate(&exact_rate));
    witness.blocks[1].permutation_output[0] ^= 1;

    witness.output[31] ^= 1;
    try std.testing.expectError(error.InvalidSpongeOutput, witness.validate(&exact_rate));
    witness.output[31] ^= 1;
    try witness.validate(&exact_rate);
}

test "Keccak-256 sponge plans separate verifier program and call instance" {
    const empty = try candidate.compile(0);
    const rate_minus_one = try candidate.compile(candidate.rate_bytes - 1);
    const exact_rate = try candidate.compile(candidate.rate_bytes);
    try empty.validate();
    try rate_minus_one.validate();
    try exact_rate.validate();
    try std.testing.expect(!candidate.production_active);
    try std.testing.expect(!candidate.air_ready);
    try std.testing.expectEqual(@as(u32, 1), empty.block_count);
    try std.testing.expectEqual(@as(u32, 1), rate_minus_one.block_count);
    try std.testing.expectEqual(@as(u32, 2), exact_rate.block_count);
    try std.testing.expectEqualSlices(
        u8,
        &empty.verifier_program_identity,
        &exact_rate.verifier_program_identity,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &empty.instance_identity,
        &exact_rate.instance_identity,
    ));

    var malformed = exact_rate;
    malformed.block_count -= 1;
    try std.testing.expectError(error.InvalidPlan, malformed.validate());
    malformed = exact_rate;
    malformed.verifier_program_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidPlan, malformed.validate());
    malformed = exact_rate;
    malformed.instance_identity[31] ^= 1;
    try std.testing.expectError(error.InvalidPlan, malformed.validate());
}

test "prefix-64 sponge projection is exact and explicitly not extrapolated" {
    const retained = projection.prefix64();
    try retained.validate();
    try std.testing.expect(!projection.production_active);
    try std.testing.expect(retained.no_extrapolation);
    try std.testing.expectEqual(@as(u64, 4_314), retained.native_invocations);
    try std.testing.expectEqual(@as(u64, 21_826), retained.retained_permutation_calls);
    try std.testing.expectEqual(@as(u64, 19_658_986), retained.projected_core_rows_removed);
    try std.testing.expectEqual(@as(u64, 19_654_672), retained.projected_net_execution_retirements_removed);
    try std.testing.expectEqual(@as(u64, 4_314), retained.semantic_call_rows);
    try std.testing.expectEqual(@as(u64, 21_826), retained.semantic_block_rows);

    var malformed = retained;
    malformed.native_invocations += 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.retained_permutation_calls -= 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.no_extrapolation = false;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.execution_journal_sha256[0] ^= 1;
    try expectInvalidProjection(malformed);
    malformed = retained;
    malformed.projection_identity[31] ^= 1;
    try expectInvalidProjection(malformed);
}

test "sponge block AIR derives exact permutation tuples and output bytes" {
    var input: [candidate.rate_bytes]u8 = undefined;
    fillPattern(&input);
    var witness = try candidate.buildWitness(std.testing.allocator, &input);
    defer witness.deinit();

    const first = direct.fill(7, 19, witness.blocks[0]);
    const second = direct.fill(7, 20, witness.blocks[1]);
    var first_sink = RootSink{};
    direct.evaluateGeneric(
        M31,
        &first,
        &second.state_before,
        M31.one(),
        &first_sink,
    );
    try std.testing.expectEqual(direct.constraint_count, first_sink.count);
    try std.testing.expectEqual(@as(usize, 0), first_sink.nonzero);

    var second_sink = RootSink{};
    const zero_state = [_]M31{M31.zero()} ** direct.state_bits;
    direct.evaluateGeneric(
        M31,
        &second,
        &zero_state,
        M31.one(),
        &second_sink,
    );
    try std.testing.expectEqual(direct.constraint_count, second_sink.count);
    try std.testing.expectEqual(@as(usize, 0), second_sink.nonzero);

    const first_tuple = direct.permutationIoTuple(M31, &first);
    const expected_first = try relations.ioTuple(
        19,
        witness.blocks[0].permutation_input,
        witness.blocks[0].permutation_output,
    );
    try expectM31SlicesEqual(&expected_first, &first_tuple);
    const second_tuple = direct.permutationIoTuple(M31, &second);
    const expected_second = try relations.ioTuple(
        20,
        witness.blocks[1].permutation_input,
        witness.blocks[1].permutation_output,
    );
    try expectM31SlicesEqual(&expected_second, &second_tuple);
    const actual_output = direct.outputBytes(M31, &second);
    for (actual_output, witness.output) |actual, expected|
        try std.testing.expectEqual(@as(u32, expected), actual.toU32());
}

test "sponge block AIR rejects mask chain state and inactive-row mutations" {
    var input: [candidate.rate_bytes]u8 = undefined;
    fillPattern(&input);
    var witness = try candidate.buildWitness(std.testing.allocator, &input);
    defer witness.deinit();
    const second = direct.fill(0, 1, witness.blocks[1]);
    const zero_state = [_]M31{M31.zero()} ** direct.state_bits;

    var malformed = direct.fill(0, 0, witness.blocks[0]);
    malformed.input_mask[9] = M31.zero();
    var sink = RootSink{};
    direct.evaluateGeneric(M31, &malformed, &second.state_before, M31.one(), &sink);
    try std.testing.expect(sink.nonzero != 0);

    malformed = direct.fill(0, 0, witness.blocks[0]);
    malformed.state_after[17] = malformed.state_after[17].sub(M31.one());
    sink = .{};
    direct.evaluateGeneric(M31, &malformed, &second.state_before, M31.one(), &sink);
    try std.testing.expect(sink.nonzero != 0);

    malformed = direct.zeroRow(M31);
    malformed.call_index = M31.one();
    sink = .{};
    direct.evaluateGeneric(M31, &malformed, &zero_state, M31.zero(), &sink);
    try std.testing.expect(sink.nonzero != 0);

    const clean = direct.zeroRow(M31);
    sink = .{};
    direct.evaluateGeneric(M31, &clean, &zero_state, M31.zero(), &sink);
    try std.testing.expectEqual(direct.constraint_count, sink.count);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
    try std.testing.expect(!direct.production_active);
    try std.testing.expect(!direct.memory_relation_ready);
    const program_identity = direct.airProgramIdentity();
    try std.testing.expect(!std.mem.allEqual(u8, &program_identity, 0));
}

fn expectStandardHash(input: []const u8) !void {
    var expected: [candidate.output_bytes]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(input, &expected, .{});
    const actual = try candidate.hash(input);
    try std.testing.expectEqualSlices(u8, &expected, &actual);

    var witness = try candidate.buildWitness(std.testing.allocator, input);
    defer witness.deinit();
    try witness.validate(input);
    try std.testing.expectEqualSlices(u8, &expected, &witness.output);
}

fn expectInvalidProjection(value: projection.ProjectionV1) !void {
    try std.testing.expectError(error.InvalidObserverProjection, value.validate());
}

fn fillPattern(output: []u8) void {
    for (output, 0..) |*byte, index|
        byte.* = @truncate(index *% 73 +% 19);
}

fn hexDigest(encoded: []const u8) ![candidate.output_bytes]u8 {
    var result: [candidate.output_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
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

fn expectM31SlicesEqual(expected: []const M31, actual: []const M31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try std.testing.expectEqual(want, got);
}
