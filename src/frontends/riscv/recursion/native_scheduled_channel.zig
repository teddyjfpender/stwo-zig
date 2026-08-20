//! Production-channel facade for the recursion verifier transcript.
//!
//! Generic STWO proving code speaks in roots, secure-field values, draws, and
//! PoW nonces.  The recursive verifier speaks in authenticated verifier-plan
//! operations.  This adapter is the deliberately small seam between them: it
//! recognizes only the generic calls that correspond to the next
//! transcript-bearing plan step and frames them through `scheduled_channel`.
//!
//! A channel is initialized from one admitted segment authority.  Proving and
//! verification then revalidate the actual `PublicData` before opening the
//! transcript, so a detached statement or public-claim digest cannot be used
//! to seed an otherwise valid proof.

const std = @import("std");
const stwo_core = @import("stwo_core");
const public_data_mod = @import("../air/public_data.zig");
const protocol = @import("protocol.zig");
const segment_authority = @import("segment_leaf_authority.zig");
const channel_mod = @import("poseidon2_channel.zig");
const scheduled = @import("scheduled_channel.zig");
const transcript = @import("transcript_program.zig");
const schedule = @import("air/verifier_schedule.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const Error = segment_authority.Error || scheduled.Error || error{
    ChannelNotInitialized,
    InvalidPcsConfiguration,
    InvalidProofSchema,
    TranscriptAlreadyStarted,
    TranscriptFault,
    UnexpectedChannelOperation,
};

pub const Channel = struct {
    driver: ?scheduled.Channel = null,
    leaf: ?*const segment_authority.Prepared = null,
    started: bool = false,
    finished: bool = false,
    first_fault: ?anyerror = null,

    /// Compatibility mirror for existing transcript diagnostics.  The owner
    /// is `driver.inner.n_draws`; this field is updated after every draw or mix
    /// that resets the counter.
    n_draws: u32 = 0,

    const Self = @This();

    pub fn init(
        plan: *const schedule.Plan,
        leaf: *const segment_authority.Prepared,
    ) Error!Self {
        if (plan.schema != .vm) return error.InvalidProofSchema;
        return .{
            .driver = try scheduled.Channel.init(plan),
            .leaf = leaf,
        };
    }

    /// Opens the transcript from verifier-owned protocol material.  This is
    /// invoked by the production frontend in place of its legacy unframed PCS
    /// and public-data prefix.
    pub fn bindRiscVTranscript(
        self: *Self,
        pcs_config: stwo_core.pcs.PcsConfig,
        data: *const public_data_mod.PublicData,
    ) Error!void {
        try self.checkHealthy();
        if (self.started) return error.TranscriptAlreadyStarted;
        try validatePcsConfig(pcs_config);

        const leaf = self.leaf orelse return error.ChannelNotInitialized;
        try leaf.claim.validateAgainst(data);
        try leaf.statement.validateAgainst(data, &leaf.claim);

        const driver = self.driverPtr() catch |err| return err;
        var protocol_words: [transcript.PROTOCOL_BINDING_WORD_COUNT]M31 = undefined;
        for (&protocol_words, 0..) |*destination, index| {
            const raw = if (index < channel_mod.RATE)
                driver.plan.protocol_id[index]
            else
                driver.plan.shape_id[index - channel_mod.RATE];
            destination.* = try canonical(raw);
        }
        try driver.mix(.bind_protocol, &protocol_words);
        try driver.mix(.bind_statement, &leaf.statement.words);

        var pcs_words: [schedule.PCS_PARAMETER_WORDS.len]M31 = undefined;
        for (&pcs_words, schedule.PCS_PARAMETER_WORDS) |*destination, raw|
            destination.* = try canonical(raw);
        try driver.mix(.bind_pcs_parameters, &pcs_words);
        self.started = true;
        self.syncDrawCount();
    }

    /// Replaces the legacy main-claim/shard-manifest prefix with the digest of
    /// the complete canonical VM public claim.
    pub fn absorbRiscVPublicClaim(self: *Self) Error!void {
        try self.checkStarted();
        const leaf = self.leaf orelse return error.ChannelNotInitialized;
        var words: [channel_mod.RATE]M31 = undefined;
        for (&words, leaf.claim.digest) |*destination, raw|
            destination.* = try canonical(raw);
        try (try self.driverPtr()).mix(.absorb_public_claim, &words);
        self.syncDrawCount();
    }

    /// The recursive protocol binds exactly the canonical component sums.  It
    /// does not inherit the native implementation's auxiliary interaction
    /// column-log list, whose shape is already verifier-owned.
    pub fn absorbRiscVClaimedSums(
        self: *Self,
        values: []const QM31,
    ) Error!void {
        try self.checkStarted();
        try self.mixSecurePayload(values);
    }

    pub fn completeRiscVTranscript(self: *Self) Error!void {
        try self.checkStarted();
        if (self.first_fault != null) return error.TranscriptFault;
        try (try self.driverPtr()).complete();
        self.finished = true;
        self.syncDrawCount();
    }

    pub fn digestWords(self: Self) channel_mod.Digest {
        const driver = self.driver orelse return [_]u32{0} ** channel_mod.RATE;
        return driver.digestWords();
    }

    pub fn digestBytes(self: Self) [channel_mod.RATE * @sizeOf(u32)]u8 {
        var result: [channel_mod.RATE * @sizeOf(u32)]u8 = undefined;
        for (self.digestWords(), 0..) |word, index| {
            std.mem.writeInt(
                u32,
                result[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
                word,
                .little,
            );
        }
        return result;
    }

    /// Generic commitment hook used by the paired Merkle channel below.
    fn mixRoot(self: *Self, root: channel_mod.Digest) void {
        const step = self.nextTranscriptStep() catch |err| {
            self.recordFault(err);
            return;
        };
        switch (step) {
            .absorb_trace_commitment, .absorb_fri_commitment => {},
            else => {
                self.recordFault(error.UnexpectedChannelOperation);
                return;
            },
        }
        var words: [channel_mod.RATE]M31 = undefined;
        for (&words, root) |*destination, raw| {
            destination.* = canonical(raw) catch |err| {
                self.recordFault(err);
                return;
            };
        }
        const driver = self.driverPtr() catch |err| {
            self.recordFault(err);
            return;
        };
        driver.mix(step, &words) catch |err| self.recordFault(err);
        self.syncDrawCount();
    }

    /// Every unrestricted-u32 absorption in the native proof must be lifted to
    /// a typed protocol operation before reaching this adapter.  Keeping this
    /// method fail-closed makes a future generic call-site addition visible.
    pub fn mixU32s(self: *Self, _: []const u32) void {
        self.recordFault(error.UnexpectedChannelOperation);
    }

    pub fn mixU64(self: *Self, nonce: u64) void {
        const step = self.nextTranscriptStep() catch |err| {
            self.recordFault(err);
            return;
        };
        switch (step) {
            .verify_and_absorb_interaction_pow,
            .verify_and_absorb_pcs_pow,
            => {
                const driver = self.driverPtr() catch |err| {
                    self.recordFault(err);
                    return;
                };
                driver.absorbPow(step, nonce) catch |err|
                    self.recordFault(err);
            },
            else => self.recordFault(error.UnexpectedChannelOperation),
        }
        self.syncDrawCount();
    }

    pub fn mixFelts(self: *Self, values: []const QM31) void {
        self.mixSecurePayload(values) catch |err| self.recordFault(err);
    }

    pub fn drawU32s(self: *Self) channel_mod.Digest {
        const step = self.nextTranscriptStep() catch |err| {
            self.recordFault(err);
            return [_]u32{0} ** channel_mod.RATE;
        };
        switch (step) {
            .draw_query_block => {},
            else => {
                self.recordFault(error.UnexpectedChannelOperation);
                return [_]u32{0} ** channel_mod.RATE;
            },
        }
        const driver = self.driverPtr() catch |err| {
            self.recordFault(err);
            return [_]u32{0} ** channel_mod.RATE;
        };
        const words = driver.draw(step) catch |err| {
            self.recordFault(err);
            return [_]u32{0} ** channel_mod.RATE;
        };
        var result: channel_mod.Digest = undefined;
        for (&result, words) |*destination, word| destination.* = word.toU32();
        self.syncDrawCount();
        return result;
    }

    pub fn drawSecureFelt(self: *Self) QM31 {
        const step = self.nextTranscriptStep() catch |err| {
            self.recordFault(err);
            return QM31.zero();
        };
        switch (step) {
            .draw_composition_randomness,
            .draw_oods_point,
            .draw_deep_randomness,
            .draw_fri_alpha,
            => {},
            else => {
                self.recordFault(error.UnexpectedChannelOperation);
                return QM31.zero();
            },
        }
        const driver = self.driverPtr() catch |err| {
            self.recordFault(err);
            return QM31.zero();
        };
        const result = driver.drawSecureFelt(step) catch |err| {
            self.recordFault(err);
            return QM31.zero();
        };
        self.syncDrawCount();
        return result;
    }

    pub fn drawSecureFelts(
        self: *Self,
        allocator: std.mem.Allocator,
        count: usize,
    ) ![]QM31 {
        try self.checkStarted();
        if (count % 2 != 0) return error.UnexpectedChannelOperation;
        const result = try allocator.alloc(QM31, count);
        errdefer allocator.free(result);
        var at: usize = 0;
        while (at < count) : (at += 2) {
            const step = try self.nextTranscriptStep();
            if (step != .draw_relation_challenge)
                return error.UnexpectedChannelOperation;
            const pair = try (try self.driverPtr()).drawRelationPair(
                step.draw_relation_challenge.challenge,
            );
            result[at] = pair[0];
            result[at + 1] = pair[1];
        }
        self.syncDrawCount();
        return result;
    }

    pub fn verifyPowNonce(self: *Self, bits: u32, nonce: u64) bool {
        const step = self.nextTranscriptStep() catch |err| {
            self.recordFault(err);
            return false;
        };
        if (powBits(step) != bits) {
            self.recordFault(error.UnexpectedChannelOperation);
            return false;
        }
        const driver = self.driverPtr() catch |err| {
            self.recordFault(err);
            return false;
        };
        return driver.verifyPow(step, nonce) catch |err| {
            self.recordFault(err);
            return false;
        };
    }

    pub fn grind(self: *Self, bits: u32) u64 {
        const step = self.nextTranscriptStep() catch |err| {
            self.recordFault(err);
            return 0;
        };
        if (powBits(step) != bits) {
            self.recordFault(error.UnexpectedChannelOperation);
            return 0;
        }
        const driver = self.driverPtr() catch |err| {
            self.recordFault(err);
            return 0;
        };
        return driver.grindPow(step) catch |err| {
            self.recordFault(err);
            return 0;
        };
    }

    fn mixSecurePayload(self: *Self, values: []const QM31) Error!void {
        try self.checkStarted();
        const step = try self.nextTranscriptStep();
        switch (step) {
            .absorb_claimed_sums,
            .absorb_sampled_values,
            .absorb_last_layer_coefficients,
            => {},
            else => return error.UnexpectedChannelOperation,
        }
        // `scheduled_channel` owns the allocation-free flattening primitive.
        try (try self.driverPtr()).mixSecureFelts(step, values);
        self.syncDrawCount();
    }

    fn nextTranscriptStep(self: *Self) Error!schedule.VerifierStep {
        try self.checkStarted();
        const driver = self.driverPtr() catch |err| return err;
        var cursor = driver.next_sequence;
        while (cursor < driver.plan.steps.len) : (cursor += 1) {
            const step = driver.plan.steps[cursor];
            if (transcript.effect(step) != null) return step;
        }
        return error.IncompleteSchedule;
    }

    fn driverPtr(self: *Self) Error!*scheduled.Channel {
        return if (self.driver) |*driver| driver else error.ChannelNotInitialized;
    }

    fn checkHealthy(self: *const Self) Error!void {
        if (self.first_fault != null) return error.TranscriptFault;
        if (self.finished) return error.IncompleteSchedule;
        if (self.driver == null or self.leaf == null)
            return error.ChannelNotInitialized;
    }

    fn checkStarted(self: *const Self) Error!void {
        try self.checkHealthy();
        if (!self.started) return error.ChannelNotInitialized;
    }

    fn recordFault(self: *Self, err: anyerror) void {
        if (self.first_fault == null) self.first_fault = err;
    }

    fn syncDrawCount(self: *Self) void {
        if (self.driver) |driver| self.n_draws = driver.drawCount();
    }
};

/// Merkle/channel coupling for the framed native transcript.  Hashing remains
/// exactly the recursion suite's Poseidon2 Merkle construction; only root
/// absorption is lifted into its verifier-plan operation.
pub const MerkleChannel = struct {
    pub fn mixRoot(channel: *Channel, root: channel_mod.Digest) void {
        channel.mixRoot(root);
    }
};

fn validatePcsConfig(actual: stwo_core.pcs.PcsConfig) Error!void {
    const expected = protocol.PCS_CONFIG;
    if (actual.pow_bits != expected.pow_bits or
        actual.fri_config.log_blowup_factor != expected.fri_config.log_blowup_factor or
        actual.fri_config.n_queries != expected.fri_config.n_queries or
        actual.fri_config.log_last_layer_degree_bound !=
            expected.fri_config.log_last_layer_degree_bound or
        actual.fri_config.fold_step != expected.fri_config.fold_step or
        actual.lifting_log_size != expected.lifting_log_size)
    {
        return error.InvalidPcsConfiguration;
    }
}

fn powBits(step: schedule.VerifierStep) ?u32 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| item.bits,
        .verify_and_absorb_pcs_pow => |item| item.bits,
        else => null,
    };
}

fn canonical(value: u32) Error!M31 {
    if (value >= stwo_core.fields.m31.Modulus)
        return error.InvalidFieldElement;
    return M31.fromCanonical(value);
}

comptime {
    if (channel_mod.RATE != 8 or schedule.PCS_PARAMETER_WORDS.len != 16)
        @compileError("native scheduled channel geometry drifted");
}
