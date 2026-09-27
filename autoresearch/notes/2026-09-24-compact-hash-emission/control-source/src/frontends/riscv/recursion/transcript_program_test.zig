//! Exact schedule, backend-parity, mutation, and allocation gates for the
//! production recursive transcript driver.

const std = @import("std");
const stwo_core = @import("stwo_core");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const transcript = @import("transcript_program.zig");
const schedule = @import("air/verifier_schedule.zig");

const M31 = stwo_core.fields.m31.M31;

const DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 2,
    .sampled_value_count = 3,
    .queried_value_count = 12,
    .trace_path_count = 12,
    .fri_layer_count = 1,
    .query_count = 3,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};
const Wire = fixed_wire.FixedStarkProofWire(DIMENSIONS);

test "R-012 PoW nonce wire is four disjoint little-endian u16 limbs" {
    const payload = transcript.powPayload(0xfedc_ba98_7654_3210);
    const expected = [_]u32{ 0x3210, 0x7654, 0xba98, 0xfedc };
    for (payload, expected) |actual, word|
        try std.testing.expectEqual(word, actual.toU32());
}

test "R-012 schedule-driven transcript records one exact authoritative trace" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try fixture.execution.validateAgainst(&fixture.plan);
    try fixture.execution.replayNative(&fixture.plan);
    const trace = fixture.execution.trace();
    try trace.validate();
    try std.testing.expectEqual(
        fixture.execution.operations.len,
        transcriptOperationCount(&fixture.plan),
    );
    try std.testing.expectEqual(@as(usize, 3), fixture.execution.relationChallengeCount());
    try std.testing.expectEqual(@as(usize, 2), trace.pow_checks.len);
    try std.testing.expectEqual(@as(u32, 1), fixture.execution.final_draw_count);

    const first = trace.hash_frames[0];
    try std.testing.expectEqual(transcript.HashPurpose.mix, first.purpose);
    try std.testing.expectEqual(@as(u32, 0), first.hash_id);
    try std.testing.expectEqual(@as(u32, transcript.TRANSCRIPT_OPERATION_TAG), first.words[8].toU32());
    try std.testing.expectEqual(@as(u32, 0), first.words[9].toU32());
    try std.testing.expectEqual(@as(u32, 1), first.words[10].toU32());
    try std.testing.expectEqual(@as(u32, 0), first.words[11].toU32());
    try std.testing.expectEqual(
        @as(usize, transcript.RATE + transcript.HEADER_WORD_COUNT +
            transcript.PROTOCOL_BINDING_WORD_COUNT),
        first.words.len,
    );
    for (fixture.plan.protocol_id, 0..) |expected, index| {
        try std.testing.expectEqual(
            expected,
            first.words[transcript.RATE + transcript.HEADER_WORD_COUNT + index].toU32(),
        );
    }
    for (fixture.plan.shape_id, 0..) |expected, index| {
        try std.testing.expectEqual(
            expected,
            first.words[
                transcript.RATE + transcript.HEADER_WORD_COUNT +
                    transcript.RATE + index
            ].toU32(),
        );
    }

    var relation_draws: [3]transcript.Draw = undefined;
    try fixture.execution.writeRelationChallenges(&relation_draws);
    var relation_at: usize = 0;
    for (fixture.execution.operations) |operation| switch (operation.step) {
        .draw_relation_challenge => {
            try std.testing.expectEqual(
                operation.draw.?,
                relation_draws[relation_at],
            );
            relation_at += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(relation_draws.len, relation_at);
}

test "R-012 transcript trace and receipt mutations fail closed" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const original_input = fixture.execution.poseidon_calls[0].input[0];
    fixture.execution.poseidon_calls[0].input[0] = original_input.add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        fixture.execution.validateAgainst(&fixture.plan),
    );
    fixture.execution.poseidon_calls[0].input[0] = original_input;
    try fixture.execution.validateAgainst(&fixture.plan);

    fixture.execution.identity_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixture.execution.validateAgainst(&fixture.plan),
    );
}

test "R-012 transcript input changes alter verifier randomness" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const original = fixture.execution.final_digest;

    fixture.wire.commitments[0][0] = 19;
    var changed = try transcript.executeFixedTranscript(
        DIMENSIONS,
        std.testing.allocator,
        &fixture.plan,
        &fixture.statement,
        fixture.public_claim,
        &fixture.wire,
    );
    defer changed.deinit();
    try changed.replayNative(&fixture.plan);
    try std.testing.expect(!std.meta.eql(original, changed.final_digest));
}

test "R-012 transcript shape identity changes verifier randomness" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var changed_plan = try testPlan(std.testing.allocator);
    defer changed_plan.deinit();
    changed_plan.shape_id[0] +%= 1;
    // Recompute through the public constructor so the plan seal remains
    // verifier-authoritative rather than mutating an admitted plan in place.
    const changed_shape = schedule.ScheduleShape{
        .protocol_id = changed_plan.protocol_id,
        .shape_id = changed_plan.shape_id,
        .interaction_pow_bits = 0,
        .pcs_pow_bits = 0,
        .query_count = DIMENSIONS.query_count,
        .table_count = 4,
        .claimed_sum_count = DIMENSIONS.claimed_sum_count,
        .sampled_value_count = DIMENSIONS.sampled_value_count,
        .tree_heights = .{ 5, 5, 5, 5 },
        .fri = try fixed_profile.FriSchedule.init(4, protocol.PCS_CONFIG.fri_config),
    };
    changed_plan.deinit();
    changed_plan = try schedule.Plan.initShape(
        std.testing.allocator,
        try schedule.ProgramSpec.init(.vm, 3, 1, 2, 3),
        changed_shape,
    );
    var changed = try transcript.executeFixedTranscript(
        DIMENSIONS,
        std.testing.allocator,
        &changed_plan,
        &fixture.statement,
        fixture.public_claim,
        &fixture.wire,
    );
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(
        fixture.execution.final_digest,
        changed.final_digest,
    ));
}

test "R-012 transcript rejects a public-claim schema substitution" {
    var plan = try testPlan(std.testing.allocator);
    defer plan.deinit();
    var statement = testStatement();
    var wire = testWire();
    try std.testing.expectError(
        error.PublicClaimSchemaMismatch,
        transcript.executeFixedTranscript(
            DIMENSIONS,
            std.testing.allocator,
            &plan,
            &statement,
            .recursion,
            &wire,
        ),
    );
}

test "R-012 transcript releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const Fixture = struct {
    plan: schedule.Plan,
    statement: transcript.StatementWords,
    public_claim: transcript.PublicClaim,
    wire: Wire,
    execution: transcript.Execution,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var plan = try testPlan(allocator);
        errdefer plan.deinit();
        const statement = testStatement();
        const public_claim = testPublicClaim();
        const wire = testWire();
        const execution = try transcript.executeFixedTranscript(
            DIMENSIONS,
            allocator,
            &plan,
            &statement,
            public_claim,
            &wire,
        );
        return .{
            .plan = plan,
            .statement = statement,
            .public_claim = public_claim,
            .wire = wire,
            .execution = execution,
        };
    }

    fn deinit(self: *Fixture) void {
        self.execution.deinit();
        self.plan.deinit();
        self.* = undefined;
    }
};

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    try fixture.execution.replayNative(&fixture.plan);
}

fn testPlan(allocator: std.mem.Allocator) !schedule.Plan {
    const fri = try fixed_profile.FriSchedule.init(
        4,
        protocol.PCS_CONFIG.fri_config,
    );
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(.vm, 3, 1, 2, 3),
        .{
            .protocol_id = channel.hashBytes("transcript-test-protocol", 0x5450),
            .shape_id = channel.hashBytes("transcript-test-shape", 0x5453),
            .interaction_pow_bits = 0,
            .pcs_pow_bits = 0,
            .query_count = DIMENSIONS.query_count,
            .table_count = 4,
            .claimed_sum_count = DIMENSIONS.claimed_sum_count,
            .sampled_value_count = DIMENSIONS.sampled_value_count,
            .tree_heights = .{ 5, 5, 5, 5 },
            .fri = fri,
        },
    );
}

fn testStatement() transcript.StatementWords {
    var words: transcript.StatementWords = undefined;
    for (&words, 0..) |*word, index| {
        word.* = M31.fromCanonical(@intCast((17 * index + 3) % 65_521));
    }
    return words;
}

fn testPublicClaim() transcript.PublicClaim {
    var digest: [transcript.RATE]M31 = undefined;
    for (&digest, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast(101 + index));
    return .{ .vm = digest };
}

fn testWire() Wire {
    var wire = std.mem.zeroes(Wire);
    for (&wire.commitments, 0..) |*digest, digest_index| {
        for (digest, 0..) |*word, word_index|
            word.* = @intCast(1 + 17 * digest_index + word_index);
    }
    for (&wire.claimed_sums, 0..) |*value, index| {
        for (value, 0..) |*word, limb| word.* = @intCast(200 + 4 * index + limb);
    }
    for (&wire.sampled_values, 0..) |*value, index| {
        for (value, 0..) |*word, limb| word.* = @intCast(300 + 4 * index + limb);
    }
    for (&wire.fri_layers[0].commitment, 0..) |*word, index|
        word.* = @intCast(400 + index);
    for (&wire.last_layer_coefficients[0], 0..) |*word, index|
        word.* = @intCast(500 + index);
    wire.interaction_pow = 0;
    wire.pcs_pow = 0;
    return wire;
}

fn transcriptOperationCount(plan: *const schedule.Plan) usize {
    var count: usize = 0;
    for (plan.steps) |step| count += @intFromBool(transcript.effect(step) != null);
    return count;
}
