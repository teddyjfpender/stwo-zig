//! Internal transcript program authority shard; use transcript_program.zig publicly.

const dependency_0 = @import("transcript_program_contract.zig");

const Check = dependency_0.Check;
const DRAW_WORD_COUNT = dependency_0.DRAW_WORD_COUNT;
const Draw = dependency_0.Draw;
const Error = dependency_0.Error;
const Execution = dependency_0.Execution;
const HEADER_WORD_COUNT = dependency_0.HEADER_WORD_COUNT;
const HashFrame = dependency_0.HashFrame;
const HashPurpose = dependency_0.HashPurpose;
const Layout = dependency_0.Layout;
const M31 = dependency_0.M31;
const Operation = dependency_0.Operation;
const PROTOCOL_BINDING_WORD_COUNT = dependency_0.PROTOCOL_BINDING_WORD_COUNT;
const PoseidonCall = dependency_0.PoseidonCall;
const PublicClaim = dependency_0.PublicClaim;
const QM31 = dependency_0.QM31;
const RATE = dependency_0.RATE;
const SECURE_EXTENSION_DEGREE = dependency_0.SECURE_EXTENSION_DEGREE;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const StatementWords = dependency_0.StatementWords;
const WIDTH = dependency_0.WIDTH;
const add = dependency_0.add;
const add3 = dependency_0.add3;
const addChunk = dependency_0.addChunk;
const canonical = dependency_0.canonical;
const channel_mod = dependency_0.channel_mod;
const effect = dependency_0.effect;
const fixed_wire = dependency_0.fixed_wire;
const frameCallCount = dependency_0.frameCallCount;
const identityDigest = dependency_0.identityDigest;
const payloadWordCount = dependency_0.payloadWordCount;
const permutation = dependency_0.permutation;
const schedule = dependency_0.schedule;
const std = dependency_0.std;
const timesFour = dependency_0.timesFour;
const validateM31 = dependency_0.validateM31;
const validateU32 = dependency_0.validateU32;
const writeHeader = dependency_0.writeHeader;
const writeNonce = dependency_0.writeNonce;
const writePayload = dependency_0.writePayload;

/// Executes the complete fixed transcript and publishes no partial owner on
/// failure. The proof wire should already have passed its shape-specific
/// canonicity gate; this function nevertheless rechecks every consumed word.
pub fn executeFixedTranscript(
    comptime dimensions: fixed_wire.Dimensions,
    allocator: std.mem.Allocator,
    plan: *const schedule.Plan,
    statement_words: *const StatementWords,
    public_claim: PublicClaim,
    proof: *const fixed_wire.FixedStarkProofWire(dimensions),
) Error!Execution {
    try plan.validate();
    if (public_claim.schema() != plan.schema)
        return error.PublicClaimSchemaMismatch;
    try validateInputs(dimensions, plan, statement_words, &public_claim, proof);
    const layout = try Layout.init(plan);

    const calls = try allocator.alloc(PoseidonCall, layout.call_count);
    errdefer allocator.free(calls);
    const frames = try allocator.alloc(HashFrame, layout.frame_count);
    errdefer allocator.free(frames);
    const checks = try allocator.alloc(Check, layout.pow_count);
    errdefer allocator.free(checks);
    const words = try allocator.alloc(M31, layout.word_count);
    errdefer allocator.free(words);
    const operations = try allocator.alloc(Operation, layout.operation_count);
    errdefer allocator.free(operations);

    var kernel = Kernel{
        .calls = calls,
        .frames = frames,
        .checks = checks,
        .words = words,
    };
    for (plan.steps, 0..) |step, sequence| {
        const effect_value = effect(step) orelse continue;
        const before_hash = kernel.frame_at;
        const before_call = kernel.call_at;
        try kernel.absorbOperation(
            @intCast(sequence),
            step,
            plan,
            statement_words,
            &public_claim,
            proof,
        );
        const semantic_draw: ?Draw = switch (effect_value) {
            .mix => null,
            .draw => try kernel.draw(),
            .pow => blk: {
                const bits = powBits(step) orelse return error.AuthorityMismatch;
                const nonce = powNonce(step, proof);
                try kernel.verifyPow(nonce, bits);
                break :blk null;
            },
        };
        const frame_delta = kernel.frame_at - before_hash;
        const expected_hashes = effect_value.hashCount();
        if (frame_delta != expected_hashes)
            return error.AuthorityMismatch;
        operations[kernel.operation_at] = .{
            .sequence = @intCast(sequence),
            .step = step,
            .first_hash_id = @intCast(before_hash),
            .hash_count = @intCast(frame_delta),
            .first_call_id = @intCast(before_call),
            .call_count = @intCast(kernel.call_at - before_call),
            .draw = semantic_draw,
        };
        kernel.operation_at += 1;
    }
    if (!kernel.complete(layout)) return error.AuthorityMismatch;

    var result = Execution{
        .allocator = allocator,
        .plan_digest = plan.authority_digest,
        .schema = plan.schema,
        .poseidon_calls = calls,
        .hash_frames = frames,
        .pow_checks = checks,
        .word_storage = words,
        .operations = operations,
        .final_digest = kernel.digest,
        .final_draw_count = kernel.draw_count,
        .identity_digest = undefined,
    };
    result.identity_digest = identityDigest(&result);
    try result.validateAgainst(plan);
    return result;
}

/// Applies one verifier-scheduled transcript operation without recording an
/// AIR trace. This is the allocation-free production seam used by a native
/// prover/verifier channel; `executeFixedTranscript` records the same operation
/// into rows 1--9 and differential tests require the two paths to agree.
pub fn applyOperation(
    channel: *channel_mod.Channel,
    sequence: u32,
    step: schedule.VerifierStep,
    payload: []const M31,
) Error!void {
    try applyOperationWithWordCount(
        channel,
        sequence,
        step,
        payload,
        try payloadWordCountForStep(step),
    );
}

pub fn applyOperationWithWordCount(
    channel: *channel_mod.Channel,
    sequence: u32,
    step: schedule.VerifierStep,
    payload: []const M31,
    expected_word_count: usize,
) Error!void {
    if (effect(step) == null or payload.len != expected_word_count)
        return error.AuthorityMismatch;
    var header: [HEADER_WORD_COUNT]M31 = undefined;
    try writeHeader(&header, sequence, step);
    for (payload) |word| try validateM31(word);
    channel.mixCanonicalM31Slices(&.{ &header, payload });
}

pub fn applyOperationForPlan(
    channel: *channel_mod.Channel,
    plan: *const schedule.Plan,
    sequence: u32,
    step: schedule.VerifierStep,
    payload: []const M31,
) Error!void {
    try applyOperationWithWordCount(
        channel,
        sequence,
        step,
        payload,
        try payloadWordCount(plan.schema, step),
    );
}

/// Allocation-free secure-field payload absorption for the three transcript
/// operations whose wire representation is a flat sequence of QM31 limbs.
/// The header and limbs share one sponge frame; there is no staging buffer and
/// therefore no payload-size-dependent stack use.
pub fn applySecureFeltOperationForPlan(
    channel: *channel_mod.Channel,
    plan: *const schedule.Plan,
    sequence: u32,
    step: schedule.VerifierStep,
    payload: []const QM31,
) Error!void {
    switch (step) {
        .absorb_claimed_sums,
        .absorb_sampled_values,
        .absorb_last_layer_coefficients,
        => {},
        else => return error.AuthorityMismatch,
    }
    const actual_word_count = std.math.mul(
        usize,
        payload.len,
        SECURE_EXTENSION_DEGREE,
    ) catch return error.ArithmeticOverflow;
    if (effect(step) != .mix or
        actual_word_count != try payloadWordCount(plan.schema, step))
    {
        return error.AuthorityMismatch;
    }

    var header: [HEADER_WORD_COUNT]M31 = undefined;
    try writeHeader(&header, sequence, step);
    // Validate the complete payload before touching the channel so rejection
    // is failure-atomic even for values constructed outside safe field APIs.
    for (payload) |felt| for (felt.toM31Array()) |word| try validateM31(word);
    mixHeaderAndSecureFelts(channel, &header, payload);
}

pub fn mixHeaderAndSecureFelts(
    channel: *channel_mod.Channel,
    header: *const [HEADER_WORD_COUNT]M31,
    payload: []const QM31,
) void {
    comptime {
        std.debug.assert(WIDTH == 2 * RATE);
        std.debug.assert(HEADER_WORD_COUNT == RATE);
        std.debug.assert(SECURE_EXTENSION_DEGREE == 4);
    }

    // This is the streaming form of Channel.mixCanonicalM31Slices for a
    // header followed by flattened QM31 limbs. The initial digest occupies a
    // full rate block, as does the fixed transcript header.
    var state = [_]M31{M31.zero()} ** WIDTH;
    for (channel.digestWords(), 0..) |word, lane|
        state[lane] = M31.fromCanonical(word);
    permutation.permute(&state);
    for (header, 0..) |word, lane| state[lane] = state[lane].add(word);
    permutation.permute(&state);

    var filled: usize = 0;
    for (payload) |felt| {
        for (felt.toM31Array()) |word| {
            state[filled] = state[filled].add(word);
            filled += 1;
            if (filled == RATE) {
                permutation.permute(&state);
                filled = 0;
            }
        }
    }
    // Canonical-word sponge termination is one additive word followed by the
    // final permutation, including when the marker closes a full rate block.
    state[filled] = state[filled].add(M31.one());
    permutation.permute(&state);
    for (channel.digest[0..RATE], state[0..RATE]) |*word, value|
        word.* = value.toU32();
    channel.n_draws = 0;
}

/// Applies a zero-payload draw operation and returns the exact two-QM31 draw
/// block used by relation and verifier-randomness consumers.
pub fn applyDrawOperation(
    channel: *channel_mod.Channel,
    sequence: u32,
    step: schedule.VerifierStep,
) Error!Draw {
    if (effect(step) != .draw) return error.AuthorityMismatch;
    try applyOperation(channel, sequence, step, &.{});
    const words = channel.drawU32s();
    var result: Draw = undefined;
    for (&result, words) |*target, value| target.* = try canonical(value);
    return result;
}

pub fn powPayload(nonce: u64) [4]M31 {
    var result: [4]M31 = undefined;
    writeNonce(&result, nonce);
    return result;
}

/// Checks the schedule-framed PoW candidate on a clone. The nonce operation
/// itself is persistent only when the caller later invokes
/// `absorbPowOperation`, matching STWO's verify-then-mix channel contract.
pub fn verifyPowOperation(
    channel: channel_mod.Channel,
    sequence: u32,
    step: schedule.VerifierStep,
    nonce: u64,
) Error!bool {
    const bits = powBits(step) orelse return error.AuthorityMismatch;
    if (bits > 31) return error.InvalidProofOfWork;
    var candidate = channel;
    const payload = powPayload(nonce);
    try applyOperation(&candidate, sequence, step, &payload);
    return @ctz(candidate.drawU32s()[0]) >= bits;
}

pub fn absorbPowOperation(
    channel: *channel_mod.Channel,
    sequence: u32,
    step: schedule.VerifierStep,
    nonce: u64,
) Error!void {
    if (effect(step) != .pow) return error.AuthorityMismatch;
    const payload = powPayload(nonce);
    try applyOperation(channel, sequence, step, &payload);
}

pub fn grindPowOperation(
    channel: channel_mod.Channel,
    sequence: u32,
    step: schedule.VerifierStep,
) Error!u64 {
    _ = powBits(step) orelse return error.AuthorityMismatch;
    var nonce: u64 = 0;
    while (!try verifyPowOperation(channel, sequence, step, nonce)) nonce +%= 1;
    return nonce;
}

pub fn payloadWordCountForStep(step: schedule.VerifierStep) Error!usize {
    return switch (step) {
        .bind_protocol => PROTOCOL_BINDING_WORD_COUNT,
        .bind_statement => STATEMENT_WORD_COUNT,
        .bind_pcs_parameters => schedule.PCS_PARAMETER_WORDS.len,
        .absorb_trace_commitment, .absorb_fri_commitment => RATE,
        .absorb_public_claim => RATE,
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

pub const Kernel = struct {
    calls: []PoseidonCall,
    frames: []HashFrame,
    checks: []Check,
    words: []M31,
    digest: Draw = .{M31.zero()} ** RATE,
    draw_count: u32 = 0,
    call_at: usize = 0,
    frame_at: usize = 0,
    check_at: usize = 0,
    word_at: usize = 0,
    operation_at: usize = 0,

    fn absorbOperation(
        self: *Kernel,
        sequence: u32,
        step: schedule.VerifierStep,
        plan: *const schedule.Plan,
        statement_words: *const StatementWords,
        public_claim: *const PublicClaim,
        proof: anytype,
    ) Error!void {
        const payload_count = try payloadWordCount(plan.schema, step);
        const word_count = try add3(RATE, HEADER_WORD_COUNT, payload_count);
        const words = try self.claimWords(word_count);
        @memcpy(words[0..RATE], &self.digest);
        try writeHeader(words[RATE..][0..HEADER_WORD_COUNT], sequence, step);
        const payload = words[RATE + HEADER_WORD_COUNT ..];
        try writePayload(
            payload,
            step,
            plan,
            statement_words,
            public_claim,
            proof,
        );
        const output = try self.hashFrame(.mix, words);
        self.digest = output[0..RATE].*;
        self.draw_count = 0;
    }

    fn draw(self: *Kernel) Error!Draw {
        const words = try self.claimWords(DRAW_WORD_COUNT);
        @memcpy(words[0..RATE], &self.digest);
        words[RATE] = try canonical(self.draw_count);
        words[RATE + 1] = M31.fromCanonical(channel_mod.DRAW_TAG);
        const output = try self.hashFrame(.draw, words);
        self.draw_count = std.math.add(u32, self.draw_count, 1) catch
            return error.DrawCountOverflow;
        return output[0..RATE].*;
    }

    fn verifyPow(self: *Kernel, nonce: u64, bits: u32) Error!void {
        if (bits > 31) return error.InvalidProofOfWork;
        const draw_words = try self.draw();
        const call_id: u32 = @intCast(self.call_at - 1);
        const word = draw_words[0];
        if (@ctz(word.toU32()) < bits) return error.InvalidProofOfWork;
        if (self.check_at >= self.checks.len) return error.AuthorityMismatch;
        self.checks[self.check_at] = .{
            .call_id = call_id,
            .nonce = nonce,
            .bits = bits,
            .word = word,
        };
        self.check_at += 1;
        self.draw_count = 0;
    }

    fn claimWords(self: *Kernel, count: usize) Error![]M31 {
        const end = try add(self.word_at, count);
        if (end > self.words.len) return error.AuthorityMismatch;
        const result = self.words[self.word_at..end];
        self.word_at = end;
        return result;
    }

    fn hashFrame(
        self: *Kernel,
        purpose: HashPurpose,
        words: []const M31,
    ) Error![WIDTH]M31 {
        if (self.frame_at >= self.frames.len) return error.AuthorityMismatch;
        const call_count = try frameCallCount(words.len);
        const first_call = self.call_at;
        var state = [_]M31{M31.zero()} ** WIDTH;
        for (0..call_count) |step| {
            if (self.call_at >= self.calls.len) return error.AuthorityMismatch;
            const input = addChunk(state, words, step);
            var output = input;
            permutation.permute(&output);
            self.calls[self.call_at] = .{
                .id = .{
                    .call_id = @intCast(self.call_at),
                    .hash_id = @intCast(self.frame_at),
                    .step = @intCast(step),
                },
                .input = input,
                .output = output,
            };
            state = output;
            self.call_at += 1;
        }
        self.frames[self.frame_at] = .{
            .hash_id = @intCast(self.frame_at),
            .first_call_id = @intCast(first_call),
            .call_count = @intCast(call_count),
            .purpose = purpose,
            .words = words,
            .output = state,
        };
        self.frame_at += 1;
        return state;
    }

    fn complete(self: Kernel, layout: Layout) bool {
        return self.call_at == layout.call_count and
            self.frame_at == layout.frame_count and
            self.check_at == layout.pow_count and
            self.word_at == layout.word_count and
            self.operation_at == layout.operation_count;
    }
};

pub fn validateInputs(
    comptime dimensions: fixed_wire.Dimensions,
    plan: *const schedule.Plan,
    statement_words: *const StatementWords,
    public_claim: *const PublicClaim,
    proof: *const fixed_wire.FixedStarkProofWire(dimensions),
) Error!void {
    for (statement_words) |word| try validateM31(word);
    for (public_claim.words()) |word| try validateM31(word);

    var commitments: usize = 0;
    var fri_layers: usize = 0;
    var raw_queries: usize = 0;
    var claimed_sums: ?usize = null;
    var sampled_values: ?usize = null;
    var terminal: ?usize = null;
    for (plan.steps) |step| switch (step) {
        .absorb_trace_commitment => commitments += 1,
        .absorb_fri_commitment => fri_layers += 1,
        .draw_query_block => |item| raw_queries = try add(
            raw_queries,
            @as(usize, @intCast(item.query_count)),
        ),
        .absorb_claimed_sums => |item| claimed_sums = @intCast(item.count),
        .absorb_sampled_values => |item| sampled_values = @intCast(item.count),
        .absorb_last_layer_coefficients => |item| terminal = @intCast(item.count),
        else => {},
    };
    if (commitments != dimensions.commitment_count or
        fri_layers != dimensions.fri_layer_count or
        raw_queries != dimensions.query_count or
        claimed_sums != dimensions.claimed_sum_count or
        sampled_values != dimensions.sampled_value_count or
        terminal != dimensions.last_layer_coefficient_count)
    {
        return error.InvalidInputCount;
    }
    for (proof.commitments) |digest_value| for (digest_value) |word|
        try validateU32(word);
    for (proof.claimed_sums) |value| for (value) |word| try validateU32(word);
    for (proof.sampled_values) |value| for (value) |word| try validateU32(word);
    for (proof.fri_layers) |layer| for (layer.commitment) |word|
        try validateU32(word);
    for (proof.last_layer_coefficients) |value| for (value) |word|
        try validateU32(word);
}

pub fn powBits(step: schedule.VerifierStep) ?u32 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| item.bits,
        .verify_and_absorb_pcs_pow => |item| item.bits,
        else => null,
    };
}

pub fn powNonce(step: schedule.VerifierStep, proof: anytype) u64 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => proof.interaction_pow,
        .verify_and_absorb_pcs_pow => proof.pcs_pow,
        else => unreachable,
    };
}

comptime {
    if (RATE != 8 or WIDTH != 16 or PROTOCOL_BINDING_WORD_COUNT != 16 or
        STATEMENT_WORD_COUNT != 412 or
        schedule.PCS_PARAMETER_WORDS.len != 16)
    {
        @compileError("recursive transcript-program geometry drifted");
    }
}
