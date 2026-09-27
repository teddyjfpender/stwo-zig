//! Production owner for universal recursion rows 1--9 on a VM segment leaf.
//!
//! The fixed proof wire enters exactly once, through `transcript_program`.
//! Every row-specific witness below is then snapshotted from that one checked
//! execution.  This removes the independent fixture construction that used to
//! make transcript integration both slow and easy to disconnect.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const fixed_wire = @import("fixed_wire.zig");
const transcript_program = @import("transcript_program.zig");
const schedule = @import("air/verifier_schedule.zig");
const binding = @import("air/transcript_binding_witness.zig");
const state = @import("air/transcript_state_witness.zig");
const word = @import("air/transcript_word_witness.zig");
const payload = @import("air/transcript_payload_witness.zig");
const transcript_air = @import("air/transcript_air_witness.zig");
const pow_check = @import("air/pow_check_witness.zig");
const pow_frame = @import("air/pow_frame_witness.zig");
const relation_challenge = @import("air/relation_challenge_witness.zig");
const verifier_randomness = @import("air/verifier_randomness_witness.zig");

pub const FORMAT_VERSION: u16 = 1;

pub const Error = transcript_program.Error || binding.Error || state.Error ||
    word.Error || payload.Error || transcript_air.Error || pow_check.Error ||
    pow_frame.Error || relation_challenge.Error || verifier_randomness.Error ||
    std.mem.Allocator.Error || error{
    DrawCountMismatch,
    TranscriptSnapshotMismatch,
};

/// Proof-independent verifier-key material shared by segment and binary modes.
/// Each row schedule has one owner and is validated against the two admitted
/// verifier plans before a proof-derived snapshot may be constructed.
pub const Preprocessing = struct {
    transcript_binding: binding.Preprocessed,
    transcript_state: state.Preprocessed,
    transcript_word: word.Preprocessed,
    transcript_payload: payload.Preprocessed,
    relation_challenge: relation_challenge.Preprocessed,
    verifier_randomness: verifier_randomness.Preprocessed,

    pub fn init(
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) Error!Preprocessing {
        var transcript_binding = try binding.Preprocessed.init(
            allocator,
            vm_plan,
            recursion_plan,
        );
        errdefer transcript_binding.deinit();
        var transcript_state = try state.Preprocessed.init(
            allocator,
            &transcript_binding,
        );
        errdefer transcript_state.deinit();
        var transcript_word = try word.Preprocessed.init(
            allocator,
            vm_plan,
            recursion_plan,
        );
        errdefer transcript_word.deinit();
        var transcript_payload = try payload.Preprocessed.init(
            allocator,
            vm_plan,
            recursion_plan,
        );
        errdefer transcript_payload.deinit();
        var relation_challenge_value = try relation_challenge.Preprocessed.init(
            allocator,
            vm_plan,
            recursion_plan,
        );
        errdefer relation_challenge_value.deinit();
        var verifier_randomness_value = try verifier_randomness.Preprocessed.init(
            allocator,
            vm_plan,
            recursion_plan,
        );
        errdefer verifier_randomness_value.deinit();
        const result = Preprocessing{
            .transcript_binding = transcript_binding,
            .transcript_state = transcript_state,
            .transcript_word = transcript_word,
            .transcript_payload = transcript_payload,
            .relation_challenge = relation_challenge_value,
            .verifier_randomness = verifier_randomness_value,
        };
        try result.validateAgainst(vm_plan, recursion_plan);
        return result;
    }

    pub fn deinit(self: *Preprocessing) void {
        self.verifier_randomness.deinit();
        self.relation_challenge.deinit();
        self.transcript_payload.deinit();
        self.transcript_word.deinit();
        self.transcript_state.deinit();
        self.transcript_binding.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Preprocessing,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) Error!void {
        try self.transcript_binding.validateAgainst(vm_plan, recursion_plan);
        try self.transcript_state.validateAgainst(&self.transcript_binding);
        try self.transcript_word.validateAgainst(vm_plan, recursion_plan);
        try self.transcript_payload.validateAgainst(vm_plan, recursion_plan);
        try self.relation_challenge.validateAgainst(vm_plan, recursion_plan);
        try self.verifier_randomness.validateAgainst(vm_plan, recursion_plan);
    }
};

/// Failure-atomic, immutable segment-leaf snapshot for rows 1--9.
pub fn Prepared(comptime dimensions: fixed_wire.Dimensions) type {
    return struct {
        execution: transcript_program.Execution,
        transcript_air: transcript_air.PreparedBatch,
        transcript_binding: binding.MainWitness,
        transcript_state: state.MainWitness,
        transcript_word: word.PreparedBatch,
        transcript_payload: payload.PreparedBatch,
        pow_check: pow_check.PreparedBatch,
        pow_frame: pow_frame.PreparedBatch,
        relation_challenge: relation_challenge.MainWitness,
        verifier_randomness: verifier_randomness.MainWitness,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            preprocessing: *const Preprocessing,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            statement_words: *const transcript_program.StatementWords,
            public_claim: transcript_program.PublicClaim,
            proof: *const fixed_wire.FixedStarkProofWire(dimensions),
        ) Error!Self {
            try preprocessing.validateAgainst(vm_plan, recursion_plan);
            var execution = try transcript_program.executeFixedTranscript(
                dimensions,
                allocator,
                vm_plan,
                statement_words,
                public_claim,
                proof,
            );
            errdefer execution.deinit();
            const trace = execution.trace();
            const transcript_lane = transcript_air.Lane{
                .plan = vm_plan,
                .trace = &trace,
            };
            var transcript_air_value = try transcript_air.PreparedBatch.init(
                allocator,
                .{ .segment_leaf = transcript_lane },
            );
            errdefer transcript_air_value.deinit();
            var transcript_binding_value = try binding.MainWitness.init(
                allocator,
                &preprocessing.transcript_binding,
                .{ .segment_leaf = .{ .plan = vm_plan, .trace = &trace } },
            );
            errdefer transcript_binding_value.deinit();
            var transcript_state_value = try state.MainWitness.init(
                allocator,
                &preprocessing.transcript_state,
                .{ .segment_leaf = .{ .plan = vm_plan, .trace = &trace } },
            );
            errdefer transcript_state_value.deinit();
            var transcript_word_value = try word.PreparedBatch.init(
                allocator,
                &preprocessing.transcript_word,
                vm_plan,
                recursion_plan,
                .{ .segment_leaf = &trace },
            );
            errdefer transcript_word_value.deinit();
            var transcript_payload_value = try payload.PreparedBatch.init(
                allocator,
                &preprocessing.transcript_payload,
                vm_plan,
                recursion_plan,
                .{ .segment_leaf = &trace },
            );
            errdefer transcript_payload_value.deinit();
            var pow_frame_value = try pow_frame.PreparedBatch.init(
                allocator,
                .{ .segment_leaf = .{ .plan = vm_plan, .trace = &trace } },
            );
            errdefer pow_frame_value.deinit();

            const pow_invocations = try allocator.alloc(
                pow_check.Invocation,
                pow_frame_value.invocations.len,
            );
            defer allocator.free(pow_invocations);
            for (pow_invocations, pow_frame_value.invocations) |*target, source| {
                target.* = .{
                    .verifier_id = source.verifier_id,
                    .kind = source.kind,
                    .check = source.check,
                };
            }
            var pow_check_value = try pow_check.PreparedBatch.init(
                allocator,
                pow_invocations,
            );
            errdefer pow_check_value.deinit();

            const relation_draws = try allocator.alloc(
                relation_challenge.Draw,
                execution.relationChallengeCount(),
            );
            defer allocator.free(relation_draws);
            try execution.writeRelationChallenges(relation_draws);
            var relation_challenge_value = try relation_challenge.MainWitness.init(
                allocator,
                &preprocessing.relation_challenge,
                .{ .segment_leaf = relation_draws },
            );
            errdefer relation_challenge_value.deinit();

            const randomness_count = verifierRandomnessCount(&execution);
            const randomness_draws = try allocator.alloc(
                verifier_randomness.Draw,
                randomness_count,
            );
            defer allocator.free(randomness_draws);
            try writeVerifierRandomness(&execution, randomness_draws);
            var verifier_randomness_value = try verifier_randomness.MainWitness.init(
                allocator,
                &preprocessing.verifier_randomness,
                .{ .segment_leaf = randomness_draws },
            );
            errdefer verifier_randomness_value.deinit();

            const result = Self{
                .execution = execution,
                .transcript_air = transcript_air_value,
                .transcript_binding = transcript_binding_value,
                .transcript_state = transcript_state_value,
                .transcript_word = transcript_word_value,
                .transcript_payload = transcript_payload_value,
                .pow_check = pow_check_value,
                .pow_frame = pow_frame_value,
                .relation_challenge = relation_challenge_value,
                .verifier_randomness = verifier_randomness_value,
            };
            try result.validateAgainst(preprocessing, vm_plan, recursion_plan);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.verifier_randomness.deinit();
            self.relation_challenge.deinit();
            self.pow_frame.deinit();
            self.pow_check.deinit();
            self.transcript_payload.deinit();
            self.transcript_word.deinit();
            self.transcript_state.deinit();
            self.transcript_binding.deinit();
            self.transcript_air.deinit();
            self.execution.deinit();
            self.* = undefined;
        }

        /// Allocation-free validation of every snapshot against the one
        /// execution and the proof-independent verifier-key schedules.
        pub fn validateAgainst(
            self: *const Self,
            preprocessing: *const Preprocessing,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
        ) Error!void {
            try preprocessing.validateAgainst(vm_plan, recursion_plan);
            try self.execution.validateAgainst(vm_plan);
            const trace = self.execution.trace();
            try self.transcript_air.validateAgainstSource(.{
                .segment_leaf = .{ .plan = vm_plan, .trace = &trace },
            });
            try self.transcript_binding.validateAgainstSource(
                &preprocessing.transcript_binding,
                .{ .segment_leaf = .{ .plan = vm_plan, .trace = &trace } },
            );
            try self.transcript_state.validateAgainstSource(
                &preprocessing.transcript_state,
                .{ .segment_leaf = .{ .plan = vm_plan, .trace = &trace } },
            );
            try self.transcript_word.validateAgainstSource(
                &preprocessing.transcript_word,
                vm_plan,
                recursion_plan,
                .{ .segment_leaf = &trace },
            );
            try self.transcript_payload.validateAgainstSource(
                &preprocessing.transcript_payload,
                vm_plan,
                recursion_plan,
                .{ .segment_leaf = &trace },
            );
            try self.pow_frame.validateAgainstSource(.{
                .segment_leaf = .{ .plan = vm_plan, .trace = &trace },
            });
            if (self.pow_check.invocations.len != self.pow_frame.invocations.len)
                return error.TranscriptSnapshotMismatch;
            for (self.pow_check.invocations, self.pow_frame.invocations) |check, frame| {
                if (!std.meta.eql(check, pow_check.Invocation{
                    .verifier_id = frame.verifier_id,
                    .kind = frame.kind,
                    .check = frame.check,
                })) return error.TranscriptSnapshotMismatch;
            }
            try self.pow_check.validate();
            try validateRelationSnapshot(
                &self.execution,
                &preprocessing.relation_challenge,
                &self.relation_challenge,
            );
            try validateRandomnessSnapshot(
                &self.execution,
                &preprocessing.verifier_randomness,
                &self.verifier_randomness,
            );
        }

        /// Copies the unmasked Fiat--Shamir query words authenticated by row 9.
        ///
        /// Native FRI stores `word & ((1 << lifting_log_size) - 1)` as each
        /// Merkle position.  Row 9, however, publishes the complete canonical
        /// M31 word drawn from the transcript.  Query decomposition must start
        /// from this complete word and let the verifier-owned mapping rows
        /// select the low position bits; feeding the already-masked capture back
        /// into row 20 would disconnect the query positions from Fiat--Shamir.
        ///
        /// The first pass authenticates the snapshot and proves that the fixed
        /// schedule covers every destination exactly once and in order.  No
        /// destination byte is touched on failure.  The second pass is a small,
        /// allocation-free copy over the admitted query blocks.
        pub fn writeRawQueryWords(
            self: *const Self,
            preprocessing: *const Preprocessing,
            destination: []M31,
        ) Error!void {
            if (destination.len != dimensions.query_count)
                return error.DrawCountMismatch;
            try validateRandomnessSnapshot(
                &self.execution,
                &preprocessing.verifier_randomness,
                &self.verifier_randomness,
            );

            var expected_item: usize = 0;
            for (
                preprocessing.verifier_randomness.rows,
                self.verifier_randomness.rows,
            ) |metadata, row| {
                if (metadata.verifier_id != verifier_randomness.SEGMENT_VERIFIER_ID or
                    metadata.kind != .raw_query)
                {
                    continue;
                }
                if (metadata.query_items != 1 or row.enabler != 1)
                    return error.TranscriptSnapshotMismatch;
                for (metadata.multiplicities, 0..) |multiplicity, word_index| {
                    if (multiplicity == 0) continue;
                    const item = std.math.add(
                        usize,
                        metadata.item_base,
                        word_index,
                    ) catch return error.DrawCountMismatch;
                    if (multiplicity != 1 or item != expected_item or
                        item >= destination.len)
                    {
                        return error.DrawCountMismatch;
                    }
                    expected_item += 1;
                }
            }
            if (expected_item != destination.len) return error.DrawCountMismatch;

            for (
                preprocessing.verifier_randomness.rows,
                self.verifier_randomness.rows,
            ) |metadata, row| {
                if (metadata.verifier_id != verifier_randomness.SEGMENT_VERIFIER_ID or
                    metadata.kind != .raw_query)
                {
                    continue;
                }
                for (metadata.multiplicities, row.outputs, 0..) |
                    multiplicity,
                    output,
                    word_index,
                | {
                    if (multiplicity == 0) continue;
                    const item: usize = @as(usize, metadata.item_base) + word_index;
                    destination[item] = output;
                }
            }
        }
    };
}

fn verifierRandomnessCount(execution: *const transcript_program.Execution) usize {
    var count: usize = 0;
    for (execution.operations) |operation| {
        count += @intFromBool(isVerifierRandomness(operation.step));
    }
    return count;
}

fn writeVerifierRandomness(
    execution: *const transcript_program.Execution,
    destination: []verifier_randomness.Draw,
) Error!void {
    if (destination.len != verifierRandomnessCount(execution))
        return error.DrawCountMismatch;
    var at: usize = 0;
    for (execution.operations) |operation| {
        if (!isVerifierRandomness(operation.step)) continue;
        destination[at] = operation.draw orelse return error.DrawCountMismatch;
        at += 1;
    }
}

fn isVerifierRandomness(step: schedule.VerifierStep) bool {
    return switch (step) {
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => true,
        else => false,
    };
}

fn validateRelationSnapshot(
    execution: *const transcript_program.Execution,
    preprocessing: *const relation_challenge.Preprocessed,
    witness: *const relation_challenge.MainWitness,
) Error!void {
    try witness.validateAgainst(preprocessing);
    for (preprocessing.rows, witness.rows) |metadata, row| {
        if (metadata.verifier_id != relation_challenge.SEGMENT_VERIFIER_ID) continue;
        const operation = findOperation(execution, metadata.sequence) orelse
            return error.TranscriptSnapshotMismatch;
        const expected = operation.draw orelse return error.TranscriptSnapshotMismatch;
        if (operation.step != .draw_relation_challenge or
            operation.step.draw_relation_challenge.challenge != metadata.challenge or
            !std.meta.eql(row.outputs, expected))
        {
            return error.TranscriptSnapshotMismatch;
        }
    }
}

fn validateRandomnessSnapshot(
    execution: *const transcript_program.Execution,
    preprocessing: *const verifier_randomness.Preprocessed,
    witness: *const verifier_randomness.MainWitness,
) Error!void {
    try witness.validateAgainst(preprocessing);
    for (preprocessing.rows, witness.rows) |metadata, row| {
        if (metadata.verifier_id != verifier_randomness.SEGMENT_VERIFIER_ID) continue;
        const operation = findOperation(execution, metadata.sequence) orelse
            return error.TranscriptSnapshotMismatch;
        const expected = operation.draw orelse return error.TranscriptSnapshotMismatch;
        if (!isVerifierRandomness(operation.step) or
            !std.meta.eql(row.outputs, expected))
        {
            return error.TranscriptSnapshotMismatch;
        }
    }
}

fn findOperation(
    execution: *const transcript_program.Execution,
    sequence: u32,
) ?transcript_program.Operation {
    for (execution.operations) |operation| {
        if (operation.sequence == sequence) return operation;
    }
    return null;
}
