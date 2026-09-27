//! Internal transcript program authority shard; use transcript_program.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const permutation = @import("../air/memory_commitment/poseidon2.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const channel_mod = @import("poseidon2_channel.zig");
pub const schedule = @import("air/verifier_schedule.zig");
pub const statement_input = @import("air/statement_input.zig");
pub const trace_mod = @import("air/pow_frame_witness.zig");
pub const pow_check = @import("air/pow_check_witness.zig");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const SECURE_EXTENSION_DEGREE = stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE;
pub const m31 = stwo_core.fields.m31;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const RATE: usize = channel_mod.RATE;
pub const WIDTH: usize = permutation.WIDTH;
pub const STATEMENT_WORD_COUNT: usize = statement_input.CANONICAL_WORD_COUNT;
/// The first transcript operation binds both the cryptographic suite and the
/// verifier-owned proof shape.  Keeping the two digests in one frame prevents
/// two admitted geometries from sharing a Fiat--Shamir prefix.
pub const PROTOCOL_BINDING_WORD_COUNT: usize = 2 * RATE;
pub const HEADER_WORD_COUNT: usize = 8;
pub const DRAW_WORD_COUNT: usize = RATE + 2;
pub const TRANSCRIPT_OPERATION_TAG: u32 = 0x5452;
pub const FORMAT_VERSION: u16 = 1;
pub const IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-program/v1\x00";

pub const TranscriptTrace = trace_mod.TranscriptTrace;
pub const PoseidonCall = trace_mod.PoseidonCall;
pub const HashFrame = trace_mod.HashFrame;
pub const HashPurpose = trace_mod.HashPurpose;
pub const Check = pow_check.Check;
pub const StatementWords = [STATEMENT_WORD_COUNT]M31;
pub const Draw = [RATE]M31;

pub const Error = schedule.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    CallCountOutOfRange,
    ControlWordOutOfRange,
    DrawCountOverflow,
    FrameCountOutOfRange,
    IndexOutOfRange,
    InvalidFieldElement,
    InvalidInputCount,
    InvalidProofOfWork,
    InvalidTranscriptTrace,
    MissingDraw,
    OperationCountOutOfRange,
    PublicClaimSchemaMismatch,
    WordCountOutOfRange,
};

pub const Effect = enum(u8) {
    mix,
    draw,
    pow,

    pub fn hashCount(self: Effect) u32 {
        return if (self == .mix) 1 else 2;
    }
};

/// Schema-specific material absorbed at `absorb_public_claim`.
pub const PublicClaim = union(schedule.Schema) {
    vm: [RATE]M31,
    recursion: void,

    pub fn schema(self: PublicClaim) schedule.Schema {
        return std.meta.activeTag(self);
    }

    pub fn words(self: *const PublicClaim) []const M31 {
        return switch (self.*) {
            .vm => |*digest| digest,
            .recursion => &.{},
        };
    }
};

/// Exact frame/call coordinates and optional semantic draw produced by one
/// transcript-bearing verifier step. PoW's temporary draw is intentionally
/// represented by `pow_checks`, not as verifier randomness.
pub const Operation = struct {
    sequence: u32,
    step: schedule.VerifierStep,
    first_hash_id: u32,
    hash_count: u32,
    first_call_id: u32,
    call_count: u32,
    draw: ?Draw,
};

/// One compact owner for all trace arrays and every frame-word slice.
/// Construction performs exactly five retained allocations regardless of the
/// number of transcript operations.
pub const Execution = struct {
    allocator: std.mem.Allocator,
    plan_digest: channel_mod.Digest,
    schema: schedule.Schema,
    poseidon_calls: []PoseidonCall,
    hash_frames: []HashFrame,
    pow_checks: []Check,
    word_storage: []M31,
    operations: []Operation,
    final_digest: Draw,
    final_draw_count: u32,
    identity_digest: [Sha256.digest_length]u8,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.operations);
        self.allocator.free(self.word_storage);
        self.allocator.free(self.pow_checks);
        self.allocator.free(self.hash_frames);
        self.allocator.free(self.poseidon_calls);
        self.* = undefined;
    }

    pub fn trace(self: *const Execution) TranscriptTrace {
        return .{
            .poseidon_calls = self.poseidon_calls,
            .hash_frames = self.hash_frames,
            .pow_checks = self.pow_checks,
        };
    }

    /// Allocation-free validation at the prepared-witness boundary.
    pub fn validateAgainst(
        self: *const Execution,
        plan: *const schedule.Plan,
    ) Error!void {
        try plan.validate();
        if (self.schema != plan.schema or
            !std.meta.eql(self.plan_digest, plan.authority_digest))
        {
            return error.AuthorityMismatch;
        }
        self.trace().validate() catch return error.InvalidTranscriptTrace;
        try validateWordOwnership(self);
        try validateOperations(self, plan);
        for (self.final_digest) |word| try validateM31(word);
        const actual = identityDigest(self);
        if (!std.mem.eql(u8, &actual, &self.identity_digest))
            return error.AuthorityMismatch;
    }

    /// Replays every recorded frame through the production channel primitive.
    /// This checks that the AIR-facing recording backend and the native digest
    /// implementation have exactly the same mix/draw/PoW behavior.
    pub fn replayNative(
        self: *const Execution,
        plan: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(plan);
        var channel = channel_mod.Channel{};
        var pow_at: usize = 0;
        for (self.operations) |operation| {
            const effect_value = effect(operation.step) orelse
                return error.AuthorityMismatch;
            const mix_frame = self.hash_frames[operation.first_hash_id];
            try expectDigestPrefix(channel.digestWords(), mix_frame.words);
            channel.mixCanonicalM31Words(mix_frame.words[RATE..]);
            try expectDigest(channel.digestWords(), mix_frame.output[0..RATE].*);

            if (effect_value == .mix) continue;
            const draw_frame = self.hash_frames[operation.first_hash_id + 1];
            try expectDigestPrefix(channel.digestWords(), draw_frame.words);
            const native_draw = channel.drawU32s();
            try expectDigest(native_draw, draw_frame.output[0..RATE].*);
            if (effect_value == .draw) {
                const recorded = operation.draw orelse return error.MissingDraw;
                try expectDigest(native_draw, recorded);
            } else {
                if (pow_at >= self.pow_checks.len)
                    return error.AuthorityMismatch;
                const check = self.pow_checks[pow_at];
                if (check.call_id != draw_frame.finalCallId() or
                    check.word.toU32() != native_draw[0] or
                    @ctz(native_draw[0]) < check.bits)
                {
                    return error.InvalidProofOfWork;
                }
                // PoW draws run on a temporary clone. The nonce-bearing mix is
                // persistent, while its draw counter returns to zero.
                channel.n_draws = 0;
                pow_at += 1;
            }
        }
        if (pow_at != self.pow_checks.len or
            channel.n_draws != self.final_draw_count)
        {
            return error.AuthorityMismatch;
        }
        try expectDigest(channel.digestWords(), self.final_digest);
    }

    pub fn relationChallengeCount(self: *const Execution) usize {
        var count: usize = 0;
        for (self.operations) |operation| switch (operation.step) {
            .draw_relation_challenge => count += 1,
            else => {},
        };
        return count;
    }

    pub fn writeRelationChallenges(
        self: *const Execution,
        destination: []Draw,
    ) Error!void {
        if (destination.len != self.relationChallengeCount())
            return error.InvalidInputCount;
        var at: usize = 0;
        for (self.operations) |operation| switch (operation.step) {
            .draw_relation_challenge => {
                destination[at] = operation.draw orelse return error.MissingDraw;
                at += 1;
            },
            else => {},
        };
    }
};

pub fn effect(step: schedule.VerifierStep) ?Effect {
    return switch (step) {
        .bind_protocol,
        .bind_statement,
        .bind_pcs_parameters,
        .absorb_trace_commitment,
        .absorb_public_claim,
        .absorb_claimed_sums,
        .absorb_sampled_values,
        .absorb_fri_commitment,
        .absorb_last_layer_coefficients,
        => .mix,
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => .draw,
        .verify_and_absorb_interaction_pow,
        .verify_and_absorb_pcs_pow,
        => .pow,
        else => null,
    };
}

pub fn payloadWordCount(
    schema: schedule.Schema,
    step: schedule.VerifierStep,
) Error!usize {
    return switch (step) {
        .bind_protocol => PROTOCOL_BINDING_WORD_COUNT,
        .bind_statement => STATEMENT_WORD_COUNT,
        .bind_pcs_parameters => schedule.PCS_PARAMETER_WORDS.len,
        .absorb_trace_commitment, .absorb_fri_commitment => RATE,
        .absorb_public_claim => if (schema == .vm) RATE else 0,
        .verify_and_absorb_interaction_pow,
        .verify_and_absorb_pcs_pow,
        => 4,
        .absorb_claimed_sums => |item| try timesFour(item.count),
        .absorb_sampled_values => |item| try timesFour(item.count),
        .absorb_last_layer_coefficients => |item| try timesFour(item.count),
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => 0,
        else => error.AuthorityMismatch,
    };
}

pub const Layout = struct {
    call_count: usize = 0,
    frame_count: usize = 0,
    pow_count: usize = 0,
    word_count: usize = 0,
    operation_count: usize = 0,

    pub fn init(plan: *const schedule.Plan) Error!Layout {
        var result = Layout{};
        for (plan.steps) |step| {
            const effect_value = effect(step) orelse continue;
            const payload_count = try payloadWordCount(plan.schema, step);
            const mix_words = try add3(RATE, HEADER_WORD_COUNT, payload_count);
            result.call_count = try add(
                result.call_count,
                try frameCallCount(mix_words),
            );
            result.frame_count = try add(result.frame_count, 1);
            result.word_count = try add(result.word_count, mix_words);
            result.operation_count = try add(result.operation_count, 1);
            if (effect_value != .mix) {
                result.call_count = try add(
                    result.call_count,
                    try frameCallCount(DRAW_WORD_COUNT),
                );
                result.frame_count = try add(result.frame_count, 1);
                result.word_count = try add(result.word_count, DRAW_WORD_COUNT);
            }
            result.pow_count = try add(
                result.pow_count,
                @intFromBool(effect_value == .pow),
            );
        }
        if (result.call_count >= m31.Modulus)
            return error.CallCountOutOfRange;
        if (result.frame_count >= m31.Modulus)
            return error.FrameCountOutOfRange;
        if (result.operation_count >= m31.Modulus)
            return error.OperationCountOutOfRange;
        if (result.word_count >= std.math.maxInt(u32))
            return error.WordCountOutOfRange;
        return result;
    }
};

pub fn writeHeader(
    destination: []M31,
    sequence: u32,
    step: schedule.VerifierStep,
) Error!void {
    if (destination.len != HEADER_WORD_COUNT) return error.AuthorityMismatch;
    const encoded = step.encode();
    const words = [_]u32{
        TRANSCRIPT_OPERATION_TAG,
        sequence,
        encoded.tag,
        encoded.arity,
        encoded.args[0],
        encoded.args[1],
        encoded.args[2],
        encoded.args[3],
    };
    for (destination, words) |*target, word| target.* = try canonical(word);
}

pub fn writePayload(
    destination: []M31,
    step: schedule.VerifierStep,
    plan: *const schedule.Plan,
    statement_words: *const StatementWords,
    public_claim: *const PublicClaim,
    proof: anytype,
) Error!void {
    const expected = try payloadWordCount(plan.schema, step);
    if (destination.len != expected) return error.AuthorityMismatch;
    switch (step) {
        .bind_protocol => {
            try copyCanonicalU32(destination[0..RATE], &plan.protocol_id);
            try copyCanonicalU32(destination[RATE..][0..RATE], &plan.shape_id);
        },
        .bind_statement => @memcpy(destination, statement_words),
        .bind_pcs_parameters => try copyCanonicalU32(
            destination,
            &schedule.PCS_PARAMETER_WORDS,
        ),
        .absorb_trace_commitment => |item| {
            const index: usize = @intCast(item.tree);
            if (index >= proof.commitments.len) return error.IndexOutOfRange;
            try copyCanonicalU32(destination, &proof.commitments[index]);
        },
        .absorb_public_claim => @memcpy(destination, public_claim.words()),
        .verify_and_absorb_interaction_pow => writeNonce(
            destination,
            proof.interaction_pow,
        ),
        .verify_and_absorb_pcs_pow => writeNonce(destination, proof.pcs_pow),
        .absorb_claimed_sums => try copyQm31Wires(destination, &proof.claimed_sums),
        .absorb_sampled_values => try copyQm31Wires(destination, &proof.sampled_values),
        .absorb_fri_commitment => |item| {
            const index: usize = @intCast(item.layer);
            if (index >= proof.fri_layers.len) return error.IndexOutOfRange;
            try copyCanonicalU32(destination, &proof.fri_layers[index].commitment);
        },
        .absorb_last_layer_coefficients => try copyQm31Wires(
            destination,
            &proof.last_layer_coefficients,
        ),
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => {},
        else => return error.AuthorityMismatch,
    }
}

pub fn validateWordOwnership(execution: *const Execution) Error!void {
    var word_at: usize = 0;
    for (execution.hash_frames) |frame| {
        const end = try add(word_at, frame.words.len);
        if (end > execution.word_storage.len or
            frame.words.ptr != execution.word_storage[word_at..end].ptr)
        {
            return error.AuthorityMismatch;
        }
        word_at = end;
    }
    if (word_at != execution.word_storage.len) return error.AuthorityMismatch;
}

pub fn validateOperations(
    execution: *const Execution,
    plan: *const schedule.Plan,
) Error!void {
    var operation_at: usize = 0;
    var hash_at: usize = 0;
    var call_at: usize = 0;
    var final_digest = [_]M31{M31.zero()} ** RATE;
    var final_draw_count: u32 = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect_value = effect(step) orelse continue;
        if (operation_at >= execution.operations.len)
            return error.AuthorityMismatch;
        const operation = execution.operations[operation_at];
        if (operation.sequence != sequence or
            !std.meta.eql(operation.step, step) or
            operation.first_hash_id != hash_at or
            operation.first_call_id != call_at or
            operation.hash_count != effect_value.hashCount() or
            (operation.draw != null) != (effect_value == .draw))
        {
            return error.AuthorityMismatch;
        }
        var expected_calls: usize = 0;
        for (execution.hash_frames[hash_at .. hash_at + operation.hash_count]) |frame| {
            expected_calls = try add(expected_calls, frame.call_count);
        }
        if (operation.call_count != expected_calls)
            return error.AuthorityMismatch;
        final_digest = execution.hash_frames[hash_at].output[0..RATE].*;
        final_draw_count = @intFromBool(effect_value == .draw);
        hash_at += operation.hash_count;
        call_at += operation.call_count;
        operation_at += 1;
    }
    if (operation_at != execution.operations.len or
        hash_at != execution.hash_frames.len or
        call_at != execution.poseidon_calls.len or
        !fieldArrayEql(RATE, final_digest, execution.final_digest) or
        final_draw_count != execution.final_draw_count)
    {
        return error.AuthorityMismatch;
    }
}

pub fn identityDigest(execution: *const Execution) [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    for (execution.plan_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u16, @intFromEnum(execution.schema));
    const trace_receipt = execution.trace().receiptDigest();
    hash.update(&trace_receipt);
    hashInt(&hash, u64, execution.operations.len);
    for (execution.operations) |operation| {
        hashInt(&hash, u32, operation.sequence);
        const encoded = operation.step.encode();
        hashInt(&hash, u32, encoded.tag);
        hashInt(&hash, u8, encoded.arity);
        for (encoded.args) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u32, operation.first_hash_id);
        hashInt(&hash, u32, operation.hash_count);
        hashInt(&hash, u32, operation.first_call_id);
        hashInt(&hash, u32, operation.call_count);
        hashInt(&hash, u8, @intFromBool(operation.draw != null));
        if (operation.draw) |draw_words| for (draw_words) |word|
            hashInt(&hash, u32, word.toU32());
    }
    for (execution.final_digest) |word| hashInt(&hash, u32, word.toU32());
    hashInt(&hash, u32, execution.final_draw_count);
    return hash.finalResult();
}

pub fn addChunk(
    previous: [WIDTH]M31,
    words: []const M31,
    step: usize,
) [WIDTH]M31 {
    var input = previous;
    for (0..RATE) |lane| {
        const index = step * RATE + lane;
        const word = if (index < words.len)
            words[index]
        else if (index == words.len)
            M31.one()
        else
            M31.zero();
        input[lane] = input[lane].add(word);
    }
    return input;
}

pub fn copyCanonicalU32(destination: []M31, source: []const u32) Error!void {
    if (destination.len != source.len) return error.InvalidInputCount;
    for (destination, source) |*target, word| target.* = try canonical(word);
}

pub fn copyQm31Wires(destination: []M31, source: anytype) Error!void {
    if (destination.len != source.len * 4) return error.InvalidInputCount;
    var at: usize = 0;
    for (source) |value| for (value) |word| {
        destination[at] = try canonical(word);
        at += 1;
    };
}

pub fn writeNonce(destination: []M31, nonce: u64) void {
    std.debug.assert(destination.len == 4);
    for (destination, 0..) |*word, limb| {
        const shift: u6 = @intCast(16 * limb);
        const limb_value: u16 = @truncate(nonce >> shift);
        word.* = M31.fromCanonical(limb_value);
    }
}

pub fn frameCallCount(word_count: usize) Error!usize {
    const with_marker = try add(word_count, 1);
    return std.math.divCeil(usize, with_marker, RATE) catch
        return error.ArithmeticOverflow;
}

pub fn timesFour(value: u32) Error!usize {
    return std.math.mul(usize, @as(usize, value), 4) catch
        return error.ArithmeticOverflow;
}

pub fn add(left: usize, right: anytype) Error!usize {
    return std.math.add(usize, left, @intCast(right)) catch
        return error.ArithmeticOverflow;
}

pub fn add3(a: usize, b: usize, c: usize) Error!usize {
    return add(try add(a, b), c);
}

pub fn canonical(value: u32) Error!M31 {
    try validateU32(value);
    return M31.fromCanonical(value);
}

pub fn validateU32(value: u32) Error!void {
    if (value >= m31.Modulus) return error.InvalidFieldElement;
}

pub fn validateM31(value: M31) Error!void {
    try validateU32(value.toU32());
}

pub fn expectDigestPrefix(expected: channel_mod.Digest, words: []const M31) Error!void {
    if (words.len < RATE) return error.InvalidTranscriptTrace;
    try expectDigest(expected, words[0..RATE].*);
}

pub fn expectDigest(expected: channel_mod.Digest, actual: Draw) Error!void {
    for (expected, actual) |left, right| {
        if (left != right.toU32()) return error.InvalidTranscriptTrace;
    }
}

pub fn fieldArrayEql(
    comptime count: usize,
    left: [count]M31,
    right: [count]M31,
) bool {
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
