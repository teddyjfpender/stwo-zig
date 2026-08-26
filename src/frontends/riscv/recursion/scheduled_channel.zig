//! Allocation-free native channel driven by an authenticated verifier plan.
//!
//! This adapter is intentionally strict: the caller must present every
//! transcript-bearing operation in plan order, with its exact payload width.
//! Ordinary channel methods are not exposed, so native proving and recursive
//! trace construction cannot silently disagree about framing.

const std = @import("std");
const stwo_core = @import("stwo_core");
const channel_mod = @import("poseidon2_channel.zig");
const transcript = @import("transcript_program.zig");
const schedule = @import("air/verifier_schedule.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const Draw = transcript.Draw;
pub const Error = transcript.Error || schedule.Error || error{
    IncompleteSchedule,
    UnexpectedStep,
};

pub const Channel = struct {
    plan: *const schedule.Plan,
    inner: channel_mod.Channel = .{},
    next_sequence: usize = 0,

    const Self = @This();

    pub fn init(plan: *const schedule.Plan) Error!Self {
        try plan.validate();
        return .{ .plan = plan };
    }

    pub fn digestWords(self: Self) channel_mod.Digest {
        return self.inner.digestWords();
    }

    pub fn drawCount(self: Self) u32 {
        return self.inner.n_draws;
    }

    pub fn complete(self: *const Self) Error!void {
        if (self.nextTranscriptIndex() != self.plan.steps.len)
            return error.IncompleteSchedule;
    }

    pub fn mix(self: *Self, expected: schedule.VerifierStep, payload: []const M31) Error!void {
        if (transcript.effect(expected) != .mix) return error.UnexpectedStep;
        const sequence = try self.peek(expected);
        try transcript.applyOperationForPlan(
            &self.inner,
            self.plan,
            sequence,
            expected,
            payload,
        );
        self.advance(sequence);
    }

    /// Absorbs a secure-field payload directly as canonical M31 limbs. This
    /// preserves the plan-owned flat encoding without allocating or staging a
    /// payload-sized word buffer.
    pub fn mixSecureFelts(
        self: *Self,
        expected: schedule.VerifierStep,
        payload: []const QM31,
    ) Error!void {
        if (transcript.effect(expected) != .mix) return error.UnexpectedStep;
        const sequence = try self.peek(expected);
        try transcript.applySecureFeltOperationForPlan(
            &self.inner,
            self.plan,
            sequence,
            expected,
            payload,
        );
        self.advance(sequence);
    }

    pub fn draw(self: *Self, expected: schedule.VerifierStep) Error!Draw {
        if (transcript.effect(expected) != .draw) return error.UnexpectedStep;
        const sequence = try self.peek(expected);
        const result = try transcript.applyDrawOperation(
            &self.inner,
            sequence,
            expected,
        );
        self.advance(sequence);
        return result;
    }

    pub fn drawSecureFelt(self: *Self, expected: schedule.VerifierStep) Error!QM31 {
        const words = try self.draw(expected);
        return QM31.fromU32Unchecked(
            words[0].toU32(),
            words[1].toU32(),
            words[2].toU32(),
            words[3].toU32(),
        );
    }

    pub fn drawRelationPair(
        self: *Self,
        challenge: u32,
    ) Error![2]QM31 {
        const words = try self.draw(.{ .draw_relation_challenge = .{
            .challenge = challenge,
        } });
        return .{
            QM31.fromU32Unchecked(
                words[0].toU32(),
                words[1].toU32(),
                words[2].toU32(),
                words[3].toU32(),
            ),
            QM31.fromU32Unchecked(
                words[4].toU32(),
                words[5].toU32(),
                words[6].toU32(),
                words[7].toU32(),
            ),
        };
    }

    pub fn verifyPow(
        self: *Self,
        expected: schedule.VerifierStep,
        nonce: u64,
    ) Error!bool {
        if (transcript.effect(expected) != .pow) return error.UnexpectedStep;
        const sequence = try self.peek(expected);
        return transcript.verifyPowOperation(
            self.inner,
            sequence,
            expected,
            nonce,
        );
    }

    pub fn absorbPow(
        self: *Self,
        expected: schedule.VerifierStep,
        nonce: u64,
    ) Error!void {
        if (transcript.effect(expected) != .pow) return error.UnexpectedStep;
        const sequence = try self.peek(expected);
        try transcript.absorbPowOperation(
            &self.inner,
            sequence,
            expected,
            nonce,
        );
        self.advance(sequence);
    }

    pub fn grindPow(
        self: *Self,
        expected: schedule.VerifierStep,
    ) Error!u64 {
        if (transcript.effect(expected) != .pow) return error.UnexpectedStep;
        const sequence = try self.peek(expected);
        return transcript.grindPowOperation(self.inner, sequence, expected);
    }

    fn peek(self: *const Self, expected: schedule.VerifierStep) Error!u32 {
        const sequence = self.nextTranscriptIndex();
        if (sequence >= self.plan.steps.len or
            !std.meta.eql(self.plan.steps[sequence], expected))
        {
            return error.UnexpectedStep;
        }
        return @intCast(sequence);
    }

    fn nextTranscriptIndex(self: *const Self) usize {
        var sequence = self.next_sequence;
        while (sequence < self.plan.steps.len and
            transcript.effect(self.plan.steps[sequence]) == null)
        {
            sequence += 1;
        }
        return sequence;
    }

    fn advance(self: *Self, sequence: u32) void {
        self.next_sequence = @as(usize, sequence) + 1;
    }
};

test "scheduled channel rejects out-of-order operations without advancing" {
    var plan = try testPlan(std.testing.allocator, .vm);
    defer plan.deinit();
    var channel = try Channel.init(&plan);
    var binding: [transcript.PROTOCOL_BINDING_WORD_COUNT]M31 = undefined;
    for (&binding, 0..) |*word, index| {
        const raw = if (index < channel_mod.RATE)
            plan.protocol_id[index]
        else
            plan.shape_id[index - channel_mod.RATE];
        word.* = M31.fromCanonical(raw);
    }
    try channel.mix(.bind_protocol, &binding);
    const digest_before = channel.digestWords();
    const sequence_before = channel.next_sequence;
    try std.testing.expectError(
        error.UnexpectedStep,
        channel.mix(.bind_pcs_parameters, &.{}),
    );
    try std.testing.expectEqual(digest_before, channel.digestWords());
    try std.testing.expectEqual(sequence_before, channel.next_sequence);
}

test "scheduled channel differentially executes the full schedule for both schemas" {
    try runFullScheduleDifferential(.vm);
    try runFullScheduleDifferential(.recursion);
}

const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const protocol = @import("protocol.zig");

const TEST_DIMENSIONS = fixed_wire.Dimensions{
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
const TestWire = fixed_wire.FixedStarkProofWire(TEST_DIMENSIONS);

fn runFullScheduleDifferential(schema: schedule.Schema) !void {
    var plan = try testPlan(std.testing.allocator, schema);
    defer plan.deinit();
    var statement = testStatement();
    var wire = testWire();
    const public_claim: transcript.PublicClaim = switch (schema) {
        .vm => testPublicClaim(),
        .recursion => .recursion,
    };
    var execution = try transcript.executeFixedTranscript(
        TEST_DIMENSIONS,
        std.testing.allocator,
        &plan,
        &statement,
        public_claim,
        &wire,
    );
    defer execution.deinit();
    try execution.replayNative(&plan);

    var scheduled = try Channel.init(&plan);
    var skipped_steps: usize = 0;
    var checked_secure_width_rejection = false;
    for (execution.operations) |operation| {
        const sequence: usize = @intCast(operation.sequence);
        try std.testing.expect(sequence >= scheduled.next_sequence);
        skipped_steps += sequence - scheduled.next_sequence;
        const mix_frame = execution.hash_frames[operation.first_hash_id];
        const payload = mix_frame.words[transcript.RATE + transcript.HEADER_WORD_COUNT ..];
        switch (transcript.effect(operation.step).?) {
            .mix => switch (operation.step) {
                .absorb_claimed_sums,
                .absorb_sampled_values,
                .absorb_last_layer_coefficients,
                => {
                    var secure: [TEST_DIMENSIONS.sampled_value_count]QM31 = undefined;
                    const count = payload.len / 4;
                    try std.testing.expectEqual(@as(usize, 0), payload.len % 4);
                    try std.testing.expect(count <= secure.len);
                    for (secure[0..count], 0..) |*felt, index| {
                        const start = index * 4;
                        felt.* = QM31.fromM31Array(payload[start..][0..4].*);
                    }
                    if (!checked_secure_width_rejection) {
                        const digest_before = scheduled.digestWords();
                        const sequence_before = scheduled.next_sequence;
                        try std.testing.expectError(
                            error.AuthorityMismatch,
                            scheduled.mixSecureFelts(
                                operation.step,
                                secure[0 .. count - 1],
                            ),
                        );
                        try std.testing.expectEqual(
                            digest_before,
                            scheduled.digestWords(),
                        );
                        try std.testing.expectEqual(
                            sequence_before,
                            scheduled.next_sequence,
                        );
                        checked_secure_width_rejection = true;
                    }
                    try scheduled.mixSecureFelts(
                        operation.step,
                        secure[0..count],
                    );
                },
                else => try scheduled.mix(operation.step, payload),
            },
            .draw => {
                const actual = try scheduled.draw(operation.step);
                try std.testing.expectEqual(operation.draw.?, actual);
            },
            .pow => {
                const nonce = switch (operation.step) {
                    .verify_and_absorb_interaction_pow => wire.interaction_pow,
                    .verify_and_absorb_pcs_pow => wire.pcs_pow,
                    else => unreachable,
                };
                try std.testing.expect(try scheduled.verifyPow(
                    operation.step,
                    nonce,
                ));
                try std.testing.expectEqual(
                    nonce,
                    try scheduled.grindPow(operation.step),
                );
                try scheduled.absorbPow(operation.step, nonce);
            },
        }
        try std.testing.expectEqual(sequence + 1, scheduled.next_sequence);
        for (scheduled.digestWords(), mix_frame.output[0..transcript.RATE]) |
            actual,
            expected,
        | try std.testing.expectEqual(expected.toU32(), actual);
    }
    skipped_steps += plan.steps.len - scheduled.next_sequence;
    try std.testing.expectEqual(
        plan.steps.len - execution.operations.len,
        skipped_steps,
    );
    try std.testing.expect(checked_secure_width_rejection);
    try scheduled.complete();
    try std.testing.expectEqual(execution.final_digest, scheduledDigest(&scheduled));
    try std.testing.expectEqual(execution.final_draw_count, scheduled.drawCount());
}

fn scheduledDigest(scheduled: *const Channel) transcript.Draw {
    var result: transcript.Draw = undefined;
    for (&result, scheduled.digestWords()) |*word, raw|
        word.* = M31.fromCanonical(raw);
    return result;
}

fn testPlan(
    allocator: std.mem.Allocator,
    schema: schedule.Schema,
) !schedule.Plan {
    const public_logup_term_count: u32 = if (schema == .vm) 1 else 0;
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            schema,
            3,
            public_logup_term_count,
            2,
            3,
        ),
        .{
            .protocol_id = channel_mod.hashBytes(
                "scheduled-channel-test-protocol",
                0x5343,
            ),
            .shape_id = channel_mod.hashBytes(
                "scheduled-channel-test-shape",
                0x5348,
            ),
            .interaction_pow_bits = 0,
            .pcs_pow_bits = 0,
            .query_count = TEST_DIMENSIONS.query_count,
            .table_count = 4,
            .claimed_sum_count = TEST_DIMENSIONS.claimed_sum_count,
            .sampled_value_count = TEST_DIMENSIONS.sampled_value_count,
            .tree_heights = .{ 5, 5, 5, 5 },
            .fri = try fixed_profile.FriSchedule.init(
                4,
                protocol.PCS_CONFIG.fri_config,
            ),
        },
    );
}

fn testStatement() transcript.StatementWords {
    var words: transcript.StatementWords = undefined;
    for (&words, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast((17 * index + 3) % 65_521));
    return words;
}

fn testPublicClaim() transcript.PublicClaim {
    var digest: [transcript.RATE]M31 = undefined;
    for (&digest, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast(101 + index));
    return .{ .vm = digest };
}

fn testWire() TestWire {
    var wire = std.mem.zeroes(TestWire);
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
