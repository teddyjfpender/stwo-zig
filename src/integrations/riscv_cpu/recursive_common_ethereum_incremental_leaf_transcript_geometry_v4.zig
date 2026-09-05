//! Verifier-derived geometry for role-0 universal transcript rows 0--9.
//!
//! The stage-101 cold verifier records every native Poseidon channel
//! operation. This module derives the ten logical row counts directly from
//! that live replay, checks the full 17-context order, and seals the result to
//! the replay identity and terminal transcript checkpoint. It deliberately
//! owns no AIR program or row writer: the role-0 payload router must still
//! authenticate the variable V4 statement preimage before these logs can enter
//! a proof manifest.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const transcript_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_v4.zig");

const recording = frontend.recursion.recording_poseidon_channel_v4;
const air = frontend.recursion.air;
const schedule = air.verifier_schedule;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 0;
pub const LAST_ROW: usize = 9;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const CONTEXT_COUNT: usize = 17;
pub const EXPECTED_RELATION_DRAW_COUNT: u32 =
    transcript_mod.RELATION_DRAW_COUNT;
pub const EXPECTED_RELATION_CHALLENGE_COUNT: u32 =
    EXPECTED_RELATION_DRAW_COUNT / 2;
pub const EXPECTED_QUERY_WORD_COUNT: u32 = transcript_mod.QUERY_WORD_COUNT;
pub const EXPECTED_POW_CHECK_COUNT: u32 = 2;
pub const TRANSCRIPT_GEOMETRY_AVAILABLE = true;
pub const ROW_MATERIALIZERS_AVAILABLE = true;
pub const CALLER_AUTHORED_COUNTS_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-transcript-geometry/v4-schema3\x00";

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalTranscriptGeometryMismatchV4,
};

pub const CountsV4 = struct {
    control: u32,
    transcript_air: u32,
    transcript_binding: u32,
    transcript_state: u32,
    transcript_word: u32,
    transcript_payload: u32,
    pow_check: u32,
    pow_frame: u32,
    relation_challenge: u32,
    verifier_randomness: u32,

    pub fn rows(self: CountsV4) [ROW_COUNT]u32 {
        return .{
            self.control,
            self.transcript_air,
            self.transcript_binding,
            self.transcript_state,
            self.transcript_word,
            self.transcript_payload,
            self.pow_check,
            self.pow_frame,
            self.relation_challenge,
            self.verifier_randomness,
        };
    }
};

/// Pointer-free receipt. It is comparison evidence only; `validateAgainst`
/// always re-derives every count from the live verifier-owned replay.
pub const AuthorityV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    counts: CountsV4,
    log_sizes: [ROW_COUNT]u32,
    context_operation_counts: [CONTEXT_COUNT]u32,
    poseidon_request_count: u32,
    relation_draw_count: u32,
    query_word_count: u32,
    query_draw_count: u32,
    replay_identity_sha256: [32]u8,
    execution_identity_sha256: [32]u8,
    vm_plan_identity: recording.Digest,
    recursion_plan_identity: recording.Digest,
    final_digest: recording.Digest,
    final_draw_count: u32,
    identity_sha256: [32]u8,

    pub fn mint(
        replay: *const transcript_mod.ReplayV4,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !AuthorityV4 {
        try replay.validate();
        const derived = try derive(replay, vm_plan, recursion_plan);
        var result = AuthorityV4{
            .counts = derived.counts,
            .log_sizes = logsFor(derived.counts),
            .context_operation_counts = derived.context_operation_counts,
            .poseidon_request_count = derived.counts.transcript_air,
            .relation_draw_count = EXPECTED_RELATION_DRAW_COUNT,
            .query_word_count = EXPECTED_QUERY_WORD_COUNT,
            .query_draw_count = derived.query_draw_count,
            .replay_identity_sha256 = replay.identity_sha256,
            .execution_identity_sha256 = replay.execution.identity_sha256,
            .vm_plan_identity = vm_plan.authority_digest,
            .recursion_plan_identity = recursion_plan.authority_digest,
            .final_digest = replay.final_digest,
            .final_draw_count = replay.final_draw_count,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAgainst(replay, vm_plan, recursion_plan);
        return result;
    }

    pub fn validateAgainst(
        self: *const AuthorityV4,
        replay: *const transcript_mod.ReplayV4,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !void {
        try replay.validate();
        const derived = try derive(replay, vm_plan, recursion_plan);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.counts, derived.counts) or
            !std.meta.eql(self.log_sizes, logsFor(derived.counts)) or
            !std.meta.eql(
                self.context_operation_counts,
                derived.context_operation_counts,
            ) or
            self.poseidon_request_count != derived.counts.transcript_air or
            self.relation_draw_count != EXPECTED_RELATION_DRAW_COUNT or
            self.query_word_count != EXPECTED_QUERY_WORD_COUNT or
            self.query_draw_count != derived.query_draw_count or
            !std.mem.eql(
                u8,
                &self.replay_identity_sha256,
                &replay.identity_sha256,
            ) or
            !std.mem.eql(
                u8,
                &self.execution_identity_sha256,
                &replay.execution.identity_sha256,
            ) or !std.meta.eql(
            self.vm_plan_identity,
            vm_plan.authority_digest,
        ) or !std.meta.eql(
            self.recursion_plan_identity,
            recursion_plan.authority_digest,
        ) or
            !std.meta.eql(self.final_digest, replay.final_digest) or
            self.final_draw_count != replay.final_draw_count or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.EthereumIncrementalTranscriptGeometryMismatchV4;
        }
    }
};

const Derived = struct {
    counts: CountsV4,
    context_operation_counts: [CONTEXT_COUNT]u32,
    query_draw_count: u32,
};

fn derive(
    replay: *const transcript_mod.ReplayV4,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
) !Derived {
    try vm_plan.validate();
    try recursion_plan.validate();
    if (vm_plan.schema != .vm or recursion_plan.schema != .recursion)
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    const execution = &replay.execution;
    var contexts = [_]u32{0} ** CONTEXT_COUNT;
    var last_context: u32 = 0;
    var relation_draws: u32 = 0;
    var randomness_draws: u32 = 0;
    var query_draws: u32 = 0;
    var pow_checks: u32 = 0;

    for (execution.operations) |operation| {
        if (operation.context_tag == 0 or
            operation.context_tag > CONTEXT_COUNT or
            operation.context_tag < last_context)
        {
            return error.EthereumIncrementalTranscriptGeometryMismatchV4;
        }
        last_context = operation.context_tag;
        const context_index: usize = operation.context_tag - 1;
        contexts[context_index] = try add(
            contexts[context_index],
            1,
        );
        const context: transcript_mod.ContextV4 =
            @enumFromInt(operation.context_tag);
        try validateEffect(context, operation.effect);
        switch (operation.effect) {
            .pow => pow_checks = try add(pow_checks, 1),
            .draw => if (context == .relation_draws) {
                relation_draws = try add(relation_draws, 1);
            } else {
                randomness_draws = try add(randomness_draws, 1);
                if (context == .queries)
                    query_draws = try add(query_draws, 1);
            },
            .mix => {},
        }
    }
    for (contexts) |count| if (count == 0)
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    const expected_query_draws = std.math.divCeil(
        u32,
        EXPECTED_QUERY_WORD_COUNT,
        @as(u32, recording.RATE),
    ) catch return error.ArithmeticOverflow;
    if (relation_draws != EXPECTED_RELATION_DRAW_COUNT or
        query_draws != expected_query_draws or
        pow_checks != EXPECTED_POW_CHECK_COUNT or
        execution.pow_checks.len != pow_checks)
    {
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    }
    const vm_relation_count = try planRelationCount(vm_plan);
    const recursion_relation_count = try planRelationCount(recursion_plan);
    const vm_randomness_count = try planRandomnessCount(vm_plan);
    const recursion_randomness_count = try planRandomnessCount(recursion_plan);
    if (vm_relation_count != EXPECTED_RELATION_CHALLENGE_COUNT or
        vm_randomness_count != randomness_draws)
    {
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    }
    const relation_row_count = try add(
        vm_relation_count,
        try mul(recursion_relation_count, 2),
    );
    const randomness_row_count = try add(
        vm_randomness_count,
        try mul(recursion_randomness_count, 2),
    );
    const recursion_transcript_counts = try canonicalTranscriptCounts(
        recursion_plan,
    );

    var transcript_words: u32 = 0;
    var payload_words: u32 = 0;
    for (execution.hash_frames) |frame| {
        const padded = try mul(frame.call_count, recording.RATE);
        if (padded < recording.RATE or frame.words.len < recording.RATE)
            return error.EthereumIncrementalTranscriptGeometryMismatchV4;
        transcript_words = try add(
            transcript_words,
            padded - recording.RATE,
        );
        if (frame.purpose == .mix) {
            const payload = std.math.cast(
                u32,
                frame.words.len - recording.RATE,
            ) orelse return error.ArithmeticOverflow;
            payload_words = try add(payload_words, payload);
        }
    }
    const operation_count = std.math.cast(
        u32,
        execution.operations.len,
    ) orelse return error.ArithmeticOverflow;
    const vm_step_count = std.math.cast(
        u32,
        vm_plan.steps.len,
    ) orelse return error.ArithmeticOverflow;
    const control_count = try add(
        vm_step_count,
        try mul(recursion_plan.steps.len, 2),
    );
    const call_count = std.math.cast(
        u32,
        execution.poseidon_calls.len,
    ) orelse return error.ArithmeticOverflow;
    const frame_count = std.math.cast(
        u32,
        execution.hash_frames.len,
    ) orelse return error.ArithmeticOverflow;
    if (operation_count == 0 or control_count == 0 or call_count == 0 or
        frame_count == 0 or
        transcript_words == 0 or payload_words == 0)
    {
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    }
    return .{
        .counts = .{
            .control = control_count,
            .transcript_air = call_count,
            .transcript_binding = try add(
                call_count,
                try mul(recursion_transcript_counts.binding, 2),
            ),
            .transcript_state = try add(
                frame_count,
                try mul(recursion_transcript_counts.state, 2),
            ),
            .transcript_word = try add(
                transcript_words,
                try mul(recursion_transcript_counts.word, 2),
            ),
            .transcript_payload = try add(
                payload_words,
                try mul(recursion_transcript_counts.payload, 2),
            ),
            .pow_check = pow_checks,
            .pow_frame = pow_checks,
            .relation_challenge = relation_row_count,
            .verifier_randomness = randomness_row_count,
        },
        .context_operation_counts = contexts,
        .query_draw_count = query_draws,
    };
}

const CanonicalTranscriptCounts = struct {
    binding: u32,
    state: u32,
    word: u32,
    payload: u32,
};

/// Mirrors the verifier-schedule preprocessing geometry for one inactive
/// recursion lane. The row owner additionally constructs and validates the
/// canonical preprocessing objects before admitting these counts.
fn canonicalTranscriptCounts(
    plan: *const schedule.Plan,
) Error!CanonicalTranscriptCounts {
    var result = CanonicalTranscriptCounts{
        .binding = 0,
        .state = 0,
        .word = 0,
        .payload = 0,
    };
    for (plan.steps) |step| {
        const effect = canonicalTranscriptEffect(step) orelse continue;
        const payload = try canonicalPayloadWordCount(plan.schema, step);
        const raw_mix = try add(
            2 * recording.RATE,
            payload,
        );
        const padded_mix = try paddedWordCount(raw_mix);
        const mix_calls = padded_mix / recording.RATE;
        result.binding = try add(result.binding, mix_calls);
        result.state = try add(result.state, 1);
        result.word = try add(
            result.word,
            padded_mix - recording.RATE,
        );
        result.payload = try add(result.payload, payload);
        if (effect != .mix) {
            const draw_calls = try paddedWordCount(recording.RATE + 2) /
                recording.RATE;
            result.binding = try add(result.binding, draw_calls);
            result.state = try add(result.state, 1);
            result.word = try add(result.word, recording.RATE);
        }
    }
    if (result.binding == 0 or result.state == 0 or result.word == 0)
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    return result;
}

const CanonicalTranscriptEffect = enum { mix, draw, pow };

fn canonicalTranscriptEffect(
    step: schedule.VerifierStep,
) ?CanonicalTranscriptEffect {
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

fn canonicalPayloadWordCount(
    schema: schedule.Schema,
    step: schedule.VerifierStep,
) Error!u32 {
    return switch (step) {
        .bind_protocol => 2 * recording.RATE,
        .bind_statement => air.statement_input.CANONICAL_WORD_COUNT,
        .bind_pcs_parameters => air.transcript_payload.PCS_PARAMETER_WORD_COUNT,
        .absorb_trace_commitment,
        .absorb_fri_commitment,
        => recording.RATE,
        .absorb_public_claim => if (schema == .vm) recording.RATE else 0,
        .verify_and_absorb_interaction_pow,
        .verify_and_absorb_pcs_pow,
        => 4,
        .absorb_claimed_sums => |item| try mul(item.count, 4),
        .absorb_sampled_values => |item| try mul(item.count, 4),
        .absorb_last_layer_coefficients => |item| try mul(item.count, 4),
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => 0,
        else => error.EthereumIncrementalTranscriptGeometryMismatchV4,
    };
}

fn paddedWordCount(raw_count: u32) Error!u32 {
    const with_marker = try add(raw_count, 1);
    const calls = std.math.divCeil(
        u32,
        with_marker,
        recording.RATE,
    ) catch return error.ArithmeticOverflow;
    return mul(calls, recording.RATE);
}

fn planRelationCount(plan: *const schedule.Plan) Error!u32 {
    var count: u32 = 0;
    for (plan.steps) |step| switch (step) {
        .draw_relation_challenge => count = try add(count, 1),
        else => {},
    };
    if (count == 0)
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    return count;
}

fn planRandomnessCount(plan: *const schedule.Plan) Error!u32 {
    var count: u32 = 0;
    for (plan.steps) |step| switch (step) {
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => count = try add(count, 1),
        else => {},
    };
    if (count == 0)
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
    return count;
}

fn validateEffect(
    context: transcript_mod.ContextV4,
    effect: recording.Effect,
) Error!void {
    const valid = switch (context) {
        .profile_pre_tree0,
        .tree0_commitment,
        .tree1_commitment,
        .profile_post_tree1,
        .interaction_claims,
        .tree2_commitment,
        .sampled_values,
        .tree3_commitment,
        .last_layer,
        => effect == .mix,
        .interaction_pow, .pcs_pow => effect == .pow,
        .relation_draws,
        .composition_draw,
        .oods_draw,
        .deep_draw,
        .queries,
        => effect == .draw,
        .fri => effect == .mix or effect == .draw,
    };
    if (!valid)
        return error.EthereumIncrementalTranscriptGeometryMismatchV4;
}

fn logsFor(counts: CountsV4) [ROW_COUNT]u32 {
    var result: [ROW_COUNT]u32 = undefined;
    for (&result, counts.rows()) |*log_size, count| {
        log_size.* = @max(
            MIN_LOG_SIZE,
            @as(u32, @intCast(std.math.log2_int_ceil(
                u32,
                @max(count, 1),
            ))),
        );
    }
    return result;
}

fn identity(value: *const AuthorityV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    for (value.counts.rows()) |count| hashInt(&hash, u32, count);
    for (value.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    for (value.context_operation_counts) |count| hashInt(&hash, u32, count);
    hashInt(&hash, u32, value.poseidon_request_count);
    hashInt(&hash, u32, value.relation_draw_count);
    hashInt(&hash, u32, value.query_word_count);
    hashInt(&hash, u32, value.query_draw_count);
    hash.update(&value.replay_identity_sha256);
    hash.update(&value.execution_identity_sha256);
    for (value.vm_plan_identity) |word| hashInt(&hash, u32, word);
    for (value.recursion_plan_identity) |word| hashInt(&hash, u32, word);
    for (value.final_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.final_draw_count);
    return hash.finalResult();
}

fn add(left: u32, right: anytype) Error!u32 {
    const narrowed = std.math.cast(u32, right) orelse
        return error.ArithmeticOverflow;
    return std.math.add(u32, left, narrowed) catch
        error.ArithmeticOverflow;
}

fn mul(left: anytype, right: anytype) Error!u32 {
    const lhs = std.math.cast(u32, left) orelse
        return error.ArithmeticOverflow;
    const rhs = std.math.cast(u32, right) orelse
        return error.ArithmeticOverflow;
    return std.math.mul(u32, lhs, rhs) catch
        error.ArithmeticOverflow;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 0 or
        LAST_ROW != 9 or ROW_COUNT != 10 or MIN_LOG_SIZE != 4 or
        MAX_LOG_SIZE != 30 or CONTEXT_COUNT != 17 or
        EXPECTED_RELATION_DRAW_COUNT != 50 or
        EXPECTED_RELATION_CHALLENGE_COUNT != 25 or
        EXPECTED_QUERY_WORD_COUNT != 193 or EXPECTED_POW_CHECK_COUNT != 2 or
        !TRANSCRIPT_GEOMETRY_AVAILABLE or !ROW_MATERIALIZERS_AVAILABLE or
        CALLER_AUTHORED_COUNTS_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental transcript geometry V4 drifted");
    }
}
