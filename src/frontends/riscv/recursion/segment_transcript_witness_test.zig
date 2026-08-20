//! End-to-end and adversarial gates for the production rows 1--9 owner.

const std = @import("std");
const stwo_core = @import("stwo_core");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const transcript = @import("transcript_program.zig");
const owner = @import("segment_transcript_witness.zig");
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
const Prepared = owner.Prepared(DIMENSIONS);

test "R-012 segment transcript owner derives rows 1 through 9 from one execution" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.prepared.validateAgainst(
        &fixture.preprocessing,
        &fixture.vm_plan,
        &fixture.recursion_plan,
    );
    try fixture.prepared.execution.replayNative(&fixture.vm_plan);
    try std.testing.expectEqual(
        fixture.prepared.execution.poseidon_calls.len,
        fixture.prepared.transcript_air.rows.len,
    );
    try std.testing.expectEqual(@as(usize, 3), fixture.prepared.execution.relationChallengeCount());
    try std.testing.expectEqual(@as(usize, 2), fixture.prepared.pow_check.invocations.len);
    try std.testing.expectEqual(
        fixture.prepared.pow_check.invocations.len,
        fixture.prepared.pow_frame.invocations.len,
    );

    var query_words: [DIMENSIONS.query_count]M31 = undefined;
    try fixture.prepared.writeRawQueryWords(
        &fixture.preprocessing,
        &query_words,
    );
    var expected: [DIMENSIONS.query_count]M31 = undefined;
    var cursor: usize = 0;
    for (fixture.prepared.execution.operations) |operation| switch (operation.step) {
        .draw_query_block => |draw| {
            const words = operation.draw.?;
            for (words[0..draw.query_count]) |word| {
                expected[cursor] = word;
                cursor += 1;
            }
        },
        else => {},
    };
    try std.testing.expectEqual(expected.len, cursor);
    try std.testing.expectEqualSlices(M31, &expected, &query_words);
}

test "R-012 raw query extraction rejects shape mismatch without mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var destination = [_]M31{M31.fromCanonical(0x5a5a)} **
        (DIMENSIONS.query_count - 1);
    const before = destination;
    try std.testing.expectError(
        error.DrawCountMismatch,
        fixture.prepared.writeRawQueryWords(
            &fixture.preprocessing,
            &destination,
        ),
    );
    try std.testing.expectEqualSlices(M31, &before, &destination);
}

test "R-012 segment transcript owner rejects detached row snapshots" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const relation_row = &fixture.prepared.relation_challenge.rows[0];
    const original = relation_row.outputs[0];
    relation_row.outputs[0] = original.add(M31.one());
    try std.testing.expectError(
        error.TranscriptSnapshotMismatch,
        fixture.prepared.validateAgainst(
            &fixture.preprocessing,
            &fixture.vm_plan,
            &fixture.recursion_plan,
        ),
    );
    relation_row.outputs[0] = original;

    fixture.prepared.pow_check.invocations[0].check.bits +%= 1;
    try std.testing.expectError(
        error.TranscriptSnapshotMismatch,
        fixture.prepared.validateAgainst(
            &fixture.preprocessing,
            &fixture.vm_plan,
            &fixture.recursion_plan,
        ),
    );
}

test "R-012 segment transcript owner releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const Fixture = struct {
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    preprocessing: owner.Preprocessing,
    prepared: Prepared,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var vm_plan = try testPlan(allocator, .vm);
        errdefer vm_plan.deinit();
        var recursion_plan = try testPlan(allocator, .recursion);
        errdefer recursion_plan.deinit();
        var preprocessing = try owner.Preprocessing.init(
            allocator,
            &vm_plan,
            &recursion_plan,
        );
        errdefer preprocessing.deinit();
        const statement = testStatement();
        const public_claim = testPublicClaim();
        const wire = testWire();
        const prepared = try Prepared.init(
            allocator,
            &preprocessing,
            &vm_plan,
            &recursion_plan,
            &statement,
            public_claim,
            &wire,
        );
        return .{
            .vm_plan = vm_plan,
            .recursion_plan = recursion_plan,
            .preprocessing = preprocessing,
            .prepared = prepared,
        };
    }

    fn deinit(self: *Fixture) void {
        self.prepared.deinit();
        self.preprocessing.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }
};

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    try fixture.prepared.validateAgainst(
        &fixture.preprocessing,
        &fixture.vm_plan,
        &fixture.recursion_plan,
    );
}

fn testPlan(allocator: std.mem.Allocator, schema: schedule.Schema) !schedule.Plan {
    const fri = try fixed_profile.FriSchedule.init(4, protocol.PCS_CONFIG.fri_config);
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            schema,
            3,
            if (schema == .vm) 1 else 0,
            2,
            3,
        ),
        .{
            .protocol_id = protocol.protocolId(),
            .shape_id = channel.hashBytes("segment-owner-test-shape", 0x4f53),
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
    for (&words, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast((19 * index + 5) % 65_521));
    return words;
}

fn testPublicClaim() transcript.PublicClaim {
    var digest: [transcript.RATE]M31 = undefined;
    for (&digest, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast(151 + index));
    return .{ .vm = digest };
}

fn testWire() Wire {
    var wire = std.mem.zeroes(Wire);
    for (&wire.commitments, 0..) |*digest, digest_index| {
        for (digest, 0..) |*value, index|
            value.* = @intCast(1 + 17 * digest_index + index);
    }
    for (&wire.claimed_sums, 0..) |*value, index| {
        for (value, 0..) |*limb, limb_index|
            limb.* = @intCast(200 + 4 * index + limb_index);
    }
    for (&wire.sampled_values, 0..) |*value, index| {
        for (value, 0..) |*limb, limb_index|
            limb.* = @intCast(300 + 4 * index + limb_index);
    }
    for (&wire.fri_layers[0].commitment, 0..) |*value, index|
        value.* = @intCast(400 + index);
    for (&wire.last_layer_coefficients[0], 0..) |*value, index|
        value.* = @intCast(500 + index);
    return wire;
}
