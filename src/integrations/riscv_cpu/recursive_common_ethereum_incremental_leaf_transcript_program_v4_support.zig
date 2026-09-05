//! Derivation support for the verifier-owned role-0 Stage101 Poseidon program.
//!
//! The ordinary SegmentV2 transcript program cannot describe the joined
//! Ethereum+incremental transcript: its profile frames, fifty relation draws,
//! and forty-three aggregate claims are different protocol operations.  This
//! owner classifies every operation recorded by the successful Stage101 cold
//! verifier and binds it to the exact VM verifier-plan step.  Only proof
//! values which are also supplied by a typed recursion input row are dynamic;
//! all remaining verifier-derived words are committed preprocessing.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const transcript_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_v4.zig");
const types =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_types_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const recording = recursion.recording_poseidon_channel_v4;
const schedule = recursion.air.verifier_schedule;
const transcript_program = recursion.transcript_program_v2;
const CONSTANT_TAG_BASE: u32 = 0x400;
const CONTEXT_COUNT = types.CONTEXT_COUNT;
const BASE_STATEMENT_WIRE_OFFSET = types.BASE_STATEMENT_WIRE_OFFSET;
const BASE_STATEMENT_WORD_COUNT = types.BASE_STATEMENT_WORD_COUNT;
const RELATION_DRAW_COUNT = types.RELATION_DRAW_COUNT;
const QUERY_WORD_COUNT = types.QUERY_WORD_COUNT;
const ContextRangeV4 = types.ContextRangeV4;
const OperationV4 = types.OperationV4;
const PayloadMetadataV4 = types.PayloadMetadataV4;
const InputKindV4 = types.InputKindV4;
const Error = types.Error;

pub const DerivedV4 = struct {
    contexts: [CONTEXT_COUNT]ContextRangeV4,
    operations: []OperationV4,
};

pub fn derive(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    captured: *const campaign_materializer.PreparedOwnedCampaignCaptureV4(
        Engine,
    ),
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
) !DerivedV4 {
    try vm_plan.validate();
    try recursion_plan.validate();
    if (vm_plan.schema != .vm or recursion_plan.schema != .recursion)
        return mismatch();
    const replay = &captured.base.transcript;
    try replay.validateAgainst(Engine, &captured.base.input);
    const execution = &replay.execution;
    const contexts = try contextRanges(execution);
    const operations = try allocator.alloc(OperationV4, execution.operations.len);
    errdefer allocator.free(operations);

    for (contexts, 0..) |range, context_index| {
        const context: transcript_mod.ContextV4 = @enumFromInt(context_index + 1);
        for (0..range.count) |local| {
            const index: usize = @as(usize, range.first) + local;
            const native = execution.operations[index];
            operations[index] = .{
                .recording_index = @intCast(index),
                .context = context,
                .context_ordinal = @intCast(local),
                .effect = native.effect,
                .verifier_sequence = try defaultSequence(vm_plan, context),
                .tag = CONSTANT_TAG_BASE + @intFromEnum(context),
                .args = .{ @intCast(local), 0, 0, 0 },
                .payload = if (native.effect == .draw) .none else .constant,
                .draw = .none,
            };
        }
    }

    try classifyPreTree0(captured, vm_plan, contexts[0], operations);
    try classifyCommitment(execution, vm_plan, contexts[1], operations, 0);
    try classifyCommitment(execution, vm_plan, contexts[2], operations, 1);
    try requireSingleContext(execution, contexts[3], .mix);
    try classifyPow(execution, vm_plan, contexts[4], operations, true);
    try classifyRelations(replay, vm_plan, contexts[5], operations);
    try classifyInteractionClaims(captured, vm_plan, contexts[6], operations);
    try classifyCommitment(execution, vm_plan, contexts[7], operations, 2);
    try classifyDraw(execution, captured, vm_plan, contexts[8], operations, .composition);
    try classifyCommitment(execution, vm_plan, contexts[9], operations, 3);
    try classifyDraw(execution, captured, vm_plan, contexts[10], operations, .oods);
    try classifySampled(execution, captured, vm_plan, contexts[11], operations);
    try classifyDraw(execution, captured, vm_plan, contexts[12], operations, .deep);
    try classifyFri(execution, captured, vm_plan, contexts[13], operations);
    try classifyLastLayer(execution, captured, vm_plan, contexts[14], operations);
    try classifyPow(execution, vm_plan, contexts[15], operations, false);
    try classifyQueries(replay, vm_plan, contexts[16], operations);

    return .{ .contexts = contexts, .operations = operations };
}

fn contextRanges(execution: *const recording.ExecutionV4) ![CONTEXT_COUNT]ContextRangeV4 {
    var result = [_]ContextRangeV4{.{ .first = 0, .count = 0 }} ** CONTEXT_COUNT;
    var prior: u32 = 0;
    for (execution.operations, 0..) |operation, index| {
        if (operation.context_tag == 0 or operation.context_tag > CONTEXT_COUNT or
            operation.context_tag < prior)
        {
            return mismatch();
        }
        const slot: usize = operation.context_tag - 1;
        if (result[slot].count == 0) result[slot].first = @intCast(index);
        result[slot].count = add(result[slot].count, 1) catch return mismatch();
        prior = operation.context_tag;
    }
    for (result) |range| if (range.count == 0) return mismatch();
    return result;
}

fn classifyPreTree0(
    captured: anytype,
    vm_plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    if (range.count < 8) return mismatch();
    const pcs_sequence = try sequenceForSimple(vm_plan, .bind_pcs_parameters);
    const statement_sequence = try sequenceForSimple(vm_plan, .bind_statement);
    operations[@as(usize, range.first)].verifier_sequence = pcs_sequence;
    operations[@as(usize, range.first)].tag = typedTag(.pcs_config);
    operations[@as(usize, range.first)].payload = .constant;
    for (1..8) |local| operations[@as(usize, range.first) + local].verifier_sequence =
        statement_sequence;

    const raw_index: usize = @as(usize, range.first) + 3;
    const words = captured.base.input.stage101.public_data.data.words();
    const payload = try operationPayload(&captured.base.transcript.execution, raw_index);
    if (!m31SlicesEql(payload, words)) return mismatch();
    const offset: usize = BASE_STATEMENT_WIRE_OFFSET;
    const end = std.math.add(usize, offset, BASE_STATEMENT_WORD_COUNT) catch
        return mismatch();
    if (end > payload.len) return mismatch();
    for (payload[offset..end], captured.base.input.statement_words) |felt, word|
        if (felt.toU32() != word) return mismatch();
    operations[raw_index].tag = typedTag(.statement_words);
    operations[raw_index].args = .{
        @intCast(words.len),
        BASE_STATEMENT_WIRE_OFFSET,
        BASE_STATEMENT_WORD_COUNT,
        0,
    };
    operations[raw_index].payload = .{ .statement_span = .{
        .wire_offset = BASE_STATEMENT_WIRE_OFFSET,
        .word_count = BASE_STATEMENT_WORD_COUNT,
    } };
}

fn classifyCommitment(
    execution: *const recording.ExecutionV4,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
    tree: u32,
) !void {
    try requireSingleContext(execution, range, .mix);
    const index: usize = range.first;
    if ((try operationPayload(execution, index)).len != recording.RATE)
        return mismatch();
    operations[index].verifier_sequence = try sequenceForCommitment(plan, tree);
    operations[index].tag = typedTag(.trace_commitment);
    operations[index].args = .{ tree, 0, 0, 0 };
    operations[index].payload = .{ .commitment = tree };
}

fn classifyPow(
    execution: *const recording.ExecutionV4,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
    interaction: bool,
) !void {
    try requireSingleContext(execution, range, .pow);
    const index: usize = range.first;
    const sequence = try sequenceForPow(plan, interaction);
    const bits = switch (plan.steps[sequence]) {
        .verify_and_absorb_interaction_pow => |value| if (interaction)
            value.bits
        else
            return mismatch(),
        .verify_and_absorb_pcs_pow => |value| if (!interaction)
            value.bits
        else
            return mismatch(),
        else => return mismatch(),
    };
    if ((try operationPayload(execution, index)).len != 4) return mismatch();
    operations[index].verifier_sequence = sequence;
    operations[index].tag = if (interaction) 6 else 20;
    operations[index].args = .{ bits, 0, 0, 0 };
    operations[index].payload = if (interaction)
        .interaction_pow_nonce
    else
        .pcs_pow_nonce;
}

fn classifyRelations(
    replay: *const transcript_mod.ReplayV4,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    if (range.count != RELATION_DRAW_COUNT) return mismatch();
    for (0..range.count) |local| {
        const index: usize = @as(usize, range.first) + local;
        const native = replay.execution.operations[index];
        if (native.effect != .draw) return mismatch();
        const challenge: u32 = @intCast(local / 2);
        const half: u32 = @intCast(local % 2);
        const drawn = try operationDraw(&replay.execution, index);
        const expected = replay.relation_draws[local].toM31Array();
        if (!m31SlicesEql(drawn[0..4], &expected)) return mismatch();
        operations[index].verifier_sequence = try sequenceForRelation(
            plan,
            challenge,
        );
        operations[index].tag = 7;
        operations[index].args = .{ challenge, half, 0, 0 };
        operations[index].draw = .{ .relation_limb = .{
            .challenge = challenge,
            .half = half,
        } };
    }
}

fn classifyInteractionClaims(
    captured: anytype,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    const sequence = try sequenceForSimple(plan, .absorb_claimed_sums);
    var local: usize = 0;
    try consumeConstant(range, &local, operations, sequence);
    const capture = &captured.base.input.stage101;
    const canonical = try capture.base_claim.canonical(&capture.statement.core);
    for (canonical.claimed_sums, 0..) |claim, claim_index|
        try consumeClaim(
            &captured.base.transcript.execution,
            range,
            &local,
            operations,
            sequence,
            @intCast(claim_index),
            claim,
        );
    try consumeConstant(range, &local, operations, sequence);
    for (canonical.log_sizes) |_|
        try consumeConstant(range, &local, operations, sequence);

    const extension = &capture.extension_claim;
    try consumeComponent(
        &captured.base.transcript.execution,
        range,
        &local,
        operations,
        sequence,
        28,
        extension.keccak_shard.component_sum,
    );
    try consumeClaim(
        &captured.base.transcript.execution,
        range,
        &local,
        operations,
        sequence,
        29,
        extension.keccak_chi_table,
    );
    try consumeClaim(
        &captured.base.transcript.execution,
        range,
        &local,
        operations,
        sequence,
        30,
        extension.keccak_xor5_table,
    );
    inline for (.{
        extension.product_base.component_sum,
        extension.product_scalar.component_sum,
        extension.linear_base.component_sum,
        extension.linear_scalar.component_sum,
        extension.point.component_sum,
        extension.split.component_sum,
        extension.scalar.component_sum,
        extension.table.component_sum,
        extension.recovery.component_sum,
        extension.byte.component_sum,
        extension.recovery_caller.component_sum,
    }, 31..) |claim, claim_index| try consumeComponent(
        &captured.base.transcript.execution,
        range,
        &local,
        operations,
        sequence,
        @intCast(claim_index),
        claim,
    );
    try consumeClaim(
        &captured.base.transcript.execution,
        range,
        &local,
        operations,
        sequence,
        42,
        capture.bridge_claim,
    );
    if (local != range.count) return mismatch();
}

fn consumeComponent(
    execution: *const recording.ExecutionV4,
    range: ContextRangeV4,
    local: *usize,
    operations: []OperationV4,
    sequence: u32,
    claim_index: u32,
    claim: QM31,
) !void {
    try consumeConstant(range, local, operations, sequence);
    try consumeConstant(range, local, operations, sequence);
    try consumeClaim(
        execution,
        range,
        local,
        operations,
        sequence,
        claim_index,
        claim,
    );
}

fn consumeConstant(
    range: ContextRangeV4,
    local: *usize,
    operations: []OperationV4,
    sequence: u32,
) !void {
    if (local.* >= range.count) return mismatch();
    const index: usize = @as(usize, range.first) + local.*;
    operations[index].verifier_sequence = sequence;
    operations[index].payload = .constant;
    local.* += 1;
}

fn consumeClaim(
    execution: *const recording.ExecutionV4,
    range: ContextRangeV4,
    local: *usize,
    operations: []OperationV4,
    sequence: u32,
    claim_index: u32,
    claim: QM31,
) !void {
    if (local.* >= range.count) return mismatch();
    const index: usize = @as(usize, range.first) + local.*;
    const payload = try operationPayload(execution, index);
    const expected = claim.toM31Array();
    if (!m31SlicesEql(payload, &expected))
        return mismatch();
    operations[index].verifier_sequence = sequence;
    operations[index].tag = typedTag(.claimed_sum);
    operations[index].args = .{ claim_index, 0, 0, 0 };
    operations[index].payload = .{ .transcript_claimed_sum = claim_index };
    local.* += 1;
}

const SimpleStepV4 = enum {
    bind_protocol,
    bind_statement,
    bind_pcs_parameters,
    absorb_public_claim,
    absorb_claimed_sums,
    draw_composition_randomness,
    draw_oods_point,
    absorb_sampled_values,
    draw_deep_randomness,
    absorb_last_layer_coefficients,
};

fn defaultSequence(
    plan: *const schedule.Plan,
    context: transcript_mod.ContextV4,
) !u32 {
    return switch (context) {
        .profile_pre_tree0 => sequenceForSimple(plan, .bind_protocol),
        .tree0_commitment => sequenceForCommitment(plan, 0),
        .tree1_commitment => sequenceForCommitment(plan, 1),
        .profile_post_tree1 => sequenceForSimple(plan, .absorb_public_claim),
        .interaction_pow => sequenceForPow(plan, true),
        .relation_draws => sequenceForRelation(plan, 0),
        .interaction_claims => sequenceForSimple(plan, .absorb_claimed_sums),
        .tree2_commitment => sequenceForCommitment(plan, 2),
        .composition_draw => sequenceForSimple(plan, .draw_composition_randomness),
        .tree3_commitment => sequenceForCommitment(plan, 3),
        .oods_draw => sequenceForSimple(plan, .draw_oods_point),
        .sampled_values => sequenceForSimple(plan, .absorb_sampled_values),
        .deep_draw => sequenceForSimple(plan, .draw_deep_randomness),
        .fri => sequenceForFriCommitment(plan, 0),
        .last_layer => sequenceForSimple(plan, .absorb_last_layer_coefficients),
        .pcs_pow => sequenceForPow(plan, false),
        .queries => sequenceForQuery(plan, 0),
    };
}

fn sequenceForSimple(plan: *const schedule.Plan, wanted: SimpleStepV4) !u32 {
    var found: ?u32 = null;
    for (plan.steps, 0..) |step, index| {
        const matches = switch (wanted) {
            .bind_protocol => step == .bind_protocol,
            .bind_statement => step == .bind_statement,
            .bind_pcs_parameters => step == .bind_pcs_parameters,
            .absorb_public_claim => step == .absorb_public_claim,
            .absorb_claimed_sums => step == .absorb_claimed_sums,
            .draw_composition_randomness => step == .draw_composition_randomness,
            .draw_oods_point => step == .draw_oods_point,
            .absorb_sampled_values => step == .absorb_sampled_values,
            .draw_deep_randomness => step == .draw_deep_randomness,
            .absorb_last_layer_coefficients => step == .absorb_last_layer_coefficients,
        };
        if (!matches) continue;
        if (found != null) return mismatch();
        found = std.math.cast(u32, index) orelse return mismatch();
    }
    return found orelse return mismatch();
}

fn sequenceForCommitment(plan: *const schedule.Plan, tree: u32) !u32 {
    for (plan.steps, 0..) |step, index| switch (step) {
        .absorb_trace_commitment => |value| if (value.tree == tree)
            return std.math.cast(u32, index) orelse return mismatch(),
        else => {},
    };
    return mismatch();
}

fn sequenceForPow(plan: *const schedule.Plan, interaction: bool) !u32 {
    for (plan.steps, 0..) |step, index| switch (step) {
        .verify_and_absorb_interaction_pow => if (interaction)
            return std.math.cast(u32, index) orelse return mismatch(),
        .verify_and_absorb_pcs_pow => if (!interaction)
            return std.math.cast(u32, index) orelse return mismatch(),
        else => {},
    };
    return mismatch();
}

fn sequenceForRelation(plan: *const schedule.Plan, challenge: u32) !u32 {
    for (plan.steps, 0..) |step, index| switch (step) {
        .draw_relation_challenge => |value| if (value.challenge == challenge)
            return std.math.cast(u32, index) orelse return mismatch(),
        else => {},
    };
    return mismatch();
}

fn sequenceForFriCommitment(plan: *const schedule.Plan, layer: u32) !u32 {
    for (plan.steps, 0..) |step, index| switch (step) {
        .absorb_fri_commitment => |value| if (value.layer == layer)
            return std.math.cast(u32, index) orelse return mismatch(),
        else => {},
    };
    return mismatch();
}

fn sequenceForFriAlpha(plan: *const schedule.Plan, layer: u32) !u32 {
    for (plan.steps, 0..) |step, index| switch (step) {
        .draw_fri_alpha => |value| if (value.layer == layer)
            return std.math.cast(u32, index) orelse return mismatch(),
        else => {},
    };
    return mismatch();
}

fn sequenceForQuery(plan: *const schedule.Plan, block: u32) !u32 {
    for (plan.steps, 0..) |step, index| switch (step) {
        .draw_query_block => |value| if (value.block == block)
            return std.math.cast(u32, index) orelse mismatch(),
        else => {},
    };
    return mismatch();
}

fn classifyDraw(
    execution: *const recording.ExecutionV4,
    captured: anytype,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
    comptime kind: enum { composition, oods, deep },
) !void {
    try requireSingleContext(execution, range, .draw);
    const index: usize = range.first;
    const expected = switch (kind) {
        .composition => captured.base.input.stage101.proof.composition_randomness,
        .oods => captured.base.input.stage101.proof.oods_seed,
        .deep => captured.base.input.stage101.proof.deep_randomness,
    }.toM31Array();
    if (!m31SlicesEql((try operationDraw(execution, index))[0..4], &expected))
        return mismatch();
    const simple: SimpleStepV4 = switch (kind) {
        .composition => .draw_composition_randomness,
        .oods => .draw_oods_point,
        .deep => .draw_deep_randomness,
    };
    operations[index].verifier_sequence = try sequenceForSimple(plan, simple);
    operations[index].tag = switch (kind) {
        .composition => 9,
        .oods => 10,
        .deep => 16,
    };
    operations[index].draw = switch (kind) {
        .composition => .composition,
        .oods => .oods,
        .deep => .deep,
    };
}

fn m31SlicesEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_value, right_value|
        if (!left_value.eql(right_value)) return false;
    return true;
}

fn classifySampled(
    execution: *const recording.ExecutionV4,
    captured: anytype,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    try requireSingleContext(execution, range, .mix);
    const index: usize = range.first;
    const count = std.math.cast(
        u32,
        captured.base.input.stage101.proof.sampled_values.len,
    ) orelse return mismatch();
    if ((try operationPayload(execution, index)).len !=
        @as(usize, count) * 4) return mismatch();
    operations[index].verifier_sequence = try sequenceForSimple(
        plan,
        .absorb_sampled_values,
    );
    operations[index].tag = typedTag(.sampled_values);
    operations[index].args = .{ count, 0, 0, 0 };
    operations[index].payload = .{ .sampled_values = count };
}

fn classifyFri(
    execution: *const recording.ExecutionV4,
    captured: anytype,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    const layers = captured.base.input.stage101.proof.fri.layers;
    if (range.count != 2 * layers.len) return mismatch();
    for (layers, 0..) |layer, layer_index| {
        const layer_u32 = std.math.cast(u32, layer_index) orelse return mismatch();
        const commitment_index: usize = @as(usize, range.first) + 2 * layer_index;
        const alpha_index = commitment_index + 1;
        if (execution.operations[commitment_index].effect != .mix or
            execution.operations[alpha_index].effect != .draw or
            (try operationPayload(execution, commitment_index)).len !=
                recording.RATE)
        {
            return mismatch();
        }
        const alpha = layer.folding_alpha.toM31Array();
        if (!m31SlicesEql(
            (try operationDraw(execution, alpha_index))[0..4],
            &alpha,
        )) return mismatch();
        operations[commitment_index].verifier_sequence =
            try sequenceForFriCommitment(plan, layer_u32);
        operations[commitment_index].tag = typedTag(.fri_commitment);
        operations[commitment_index].args = .{ layer_u32, 0, 0, 0 };
        operations[commitment_index].payload = .{ .fri_commitment = layer_u32 };
        operations[alpha_index].verifier_sequence =
            try sequenceForFriAlpha(plan, layer_u32);
        operations[alpha_index].tag = 18;
        operations[alpha_index].args = .{ layer_u32, 0, 0, 0 };
        operations[alpha_index].draw = .{ .fri_alpha = layer_u32 };
    }
}

fn classifyLastLayer(
    execution: *const recording.ExecutionV4,
    captured: anytype,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    try requireSingleContext(execution, range, .mix);
    const index: usize = range.first;
    const count = std.math.cast(
        u32,
        captured.base.input.stage101.proof.last_layer_coefficients.len,
    ) orelse return mismatch();
    if ((try operationPayload(execution, index)).len !=
        @as(usize, count) * 4) return mismatch();
    operations[index].verifier_sequence = try sequenceForSimple(
        plan,
        .absorb_last_layer_coefficients,
    );
    operations[index].tag = typedTag(.last_layer_coefficients);
    operations[index].args = .{ count, 0, 0, 0 };
    operations[index].payload = .{ .last_layer_coefficients = count };
}

fn classifyQueries(
    replay: *const transcript_mod.ReplayV4,
    plan: *const schedule.Plan,
    range: ContextRangeV4,
    operations: []OperationV4,
) !void {
    var first_word: u32 = 0;
    for (0..range.count) |local| {
        const index: usize = @as(usize, range.first) + local;
        const block = std.math.cast(u32, local) orelse return mismatch();
        const sequence = try sequenceForQuery(plan, block);
        const query = plan.steps[sequence].draw_query_block;
        if (query.first_query != first_word or query.query_count == 0 or
            query.query_count > recording.RATE)
        {
            return mismatch();
        }
        const draw = try operationDraw(&replay.execution, index);
        const end = add(first_word, query.query_count) catch return mismatch();
        if (end > replay.query_words.len or
            !m31SlicesEql(
                draw[0..@as(usize, query.query_count)],
                replay.query_words[@as(usize, first_word)..@as(usize, end)],
            ))
        {
            return mismatch();
        }
        operations[index].verifier_sequence = sequence;
        operations[index].tag = 21;
        operations[index].args = .{
            block,
            first_word,
            query.query_count,
            0,
        };
        operations[index].draw = .{ .query_block = .{
            .block = block,
            .first_word = first_word,
            .word_count = query.query_count,
        } };
        first_word = end;
    }
    if (first_word != QUERY_WORD_COUNT) return mismatch();
}

fn requireSingleContext(
    execution: *const recording.ExecutionV4,
    range: ContextRangeV4,
    effect: recording.Effect,
) !void {
    if (range.count != 1 or
        execution.operations[@as(usize, range.first)].effect != effect)
        return mismatch();
}

fn operationPayload(
    execution: *const recording.ExecutionV4,
    operation_index: usize,
) ![]const M31 {
    if (operation_index >= execution.operations.len) return mismatch();
    const operation = execution.operations[operation_index];
    if (operation.effect == .draw or operation.hash_count == 0)
        return mismatch();
    const frame_index: usize = operation.first_hash_id;
    if (frame_index >= execution.hash_frames.len) return mismatch();
    const frame = execution.hash_frames[frame_index];
    if (frame.purpose != .mix or frame.words.len < recording.RATE)
        return mismatch();
    return frame.words[recording.RATE..];
}

fn operationDraw(
    execution: *const recording.ExecutionV4,
    operation_index: usize,
) ![recording.RATE]M31 {
    if (operation_index >= execution.operations.len) return mismatch();
    const operation = execution.operations[operation_index];
    if (operation.effect == .mix or operation.hash_count == 0)
        return mismatch();
    const frame_index: usize = operation.first_hash_id + operation.hash_count - 1;
    if (frame_index >= execution.hash_frames.len) return mismatch();
    const frame = execution.hash_frames[frame_index];
    if (frame.purpose != .draw) return mismatch();
    return frame.output[0..recording.RATE].*;
}

pub fn metadata(
    operation: OperationV4,
    payload_index: u32,
) Error!PayloadMetadataV4 {
    return switch (operation.payload) {
        .none => mismatch(),
        .constant => constantMetadata(payload_index),
        .statement_span => |span| if (payload_index >= span.wire_offset and
            payload_index - span.wire_offset < span.word_count)
            .{
                .source_kind = .statement,
                .item_index = 2,
                .limb_index = payload_index - span.wire_offset,
                .constant_mask = 0,
                .input_use_count = 1,
            }
        else
            constantMetadata(payload_index),
        .commitment => |tree| dynamicMetadata(.commitment, tree, payload_index, 1),
        .interaction_pow_nonce => dynamicMetadata(
            .interaction_pow_nonce,
            0,
            payload_index,
            0,
        ),
        .transcript_claimed_sum => |item| dynamicMetadata(
            .claimed_sum,
            item,
            payload_index,
            1,
        ),
        .sampled_values => dynamicMetadata(
            .sampled_value,
            payload_index / 4,
            payload_index % 4,
            2,
        ),
        .fri_commitment => |layer| dynamicMetadata(
            .fri_commitment,
            layer,
            payload_index,
            1,
        ),
        .last_layer_coefficients => dynamicMetadata(
            .last_layer_coefficient,
            payload_index / 4,
            payload_index % 4,
            1,
        ),
        .pcs_pow_nonce => dynamicMetadata(
            .pcs_pow_nonce,
            0,
            payload_index,
            0,
        ),
    };
}

fn constantMetadata(payload_index: u32) PayloadMetadataV4 {
    return .{
        .source_kind = .protocol,
        .item_index = 0,
        .limb_index = payload_index,
        .constant_mask = 1,
        .input_use_count = 0,
    };
}

fn dynamicMetadata(
    kind: InputKindV4,
    item: u32,
    limb: u32,
    use_count: u32,
) PayloadMetadataV4 {
    return .{
        .source_kind = kind,
        .item_index = item,
        .limb_index = limb,
        .constant_mask = 0,
        .input_use_count = use_count,
    };
}

fn typedTag(kind: transcript_program.Kind) u32 {
    return switch (kind) {
        .interaction_pow => 6,
        .relation_draw => 7,
        .composition_draw => 9,
        .oods_draw => 10,
        .deep_draw => 16,
        .fri_alpha_draw => 18,
        .pcs_pow => 20,
        .query_draw => 21,
        else => @as(u32, 0x200) + @intFromEnum(kind),
    };
}

fn add(left: anytype, right: anytype) !u32 {
    const lhs = std.math.cast(u32, left) orelse return error.ArithmeticOverflow;
    const rhs = std.math.cast(u32, right) orelse return error.ArithmeticOverflow;
    return std.math.add(u32, lhs, rhs) catch error.ArithmeticOverflow;
}

fn mismatch() Error {
    return error.EthereumIncrementalTranscriptProgramMismatchV4;
}
