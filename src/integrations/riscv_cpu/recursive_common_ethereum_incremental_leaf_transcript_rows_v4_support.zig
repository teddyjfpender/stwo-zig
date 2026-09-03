//! Row writer support for the schema-3 role-0 Stage101 transcript source.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const program_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const air = recursion.air;
const recording = recursion.recording_poseidon_channel_v4;
const schedule = air.verifier_schedule;
const source_rows = recursion.segment_transcript_outer_source_v2;

pub const Error = program_mod.Error || recording.Error ||
    air.transcript_binding_witness.Error ||
    air.transcript_state_witness.Error ||
    air.transcript_word_witness.Error ||
    air.transcript_payload_witness.Error || error{
    EthereumIncrementalTranscriptRowsMismatchV4,
};

pub const TranscriptPayloadRowV4 = struct {
    preprocessing: air.transcript_payload_witness.Row,
    value: M31,
};

pub const CanonicalSuffixesV4 = struct {
    binding: *const air.transcript_binding_witness.Preprocessed,
    state: *const air.transcript_state_witness.Preprocessed,
    word: *const air.transcript_word_witness.Preprocessed,
    payload: *const air.transcript_payload_witness.Preprocessed,
};

pub const BuffersV4 = struct {
    transcript_air: []source_rows.TranscriptAirRowV2,
    transcript_binding: []source_rows.TranscriptBindingRowV2,
    transcript_state: []source_rows.TranscriptStateRowV2,
    transcript_word: []source_rows.TranscriptWordRowV2,
    transcript_payload: []TranscriptPayloadRowV4,
    pow_check: []source_rows.PowCheckRowV2,
    pow_frame: []source_rows.PowFrameRowV2,
    provider_calls: []source_rows.ProviderCall,
};

pub fn populateOrValidate(
    execution: *const recording.ExecutionV4,
    program: *const program_mod.ProgramAuthorityV4,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
    suffixes: CanonicalSuffixesV4,
    buffers: BuffersV4,
    comptime validate_only: bool,
) Error!void {
    try execution.validate();
    try vm_plan.validate();
    try recursion_plan.validate();
    try suffixes.binding.validateAgainst(vm_plan, recursion_plan);
    try suffixes.state.validateAgainst(suffixes.binding);
    try suffixes.word.validateAgainst(vm_plan, recursion_plan);
    try suffixes.payload.validateAgainst(vm_plan, recursion_plan);
    if (vm_plan.schema != .vm or recursion_plan.schema != .recursion or
        program.operations.len != execution.operations.len)
        return mismatch();

    var call_at: usize = 0;
    var binding_at: usize = 0;
    var state_at: usize = 0;
    var word_at: usize = 0;
    var payload_at: usize = 0;
    var pow_at: usize = 0;
    var pow_frame_at: usize = 0;
    var mix_ordinal: u32 = 0;

    for (program.operations, execution.operations, 0..) |
        instruction,
        operation,
        instruction_index,
    | {
        if (instruction.recording_index != instruction_index or
            instruction.effect != operation.effect or
            @intFromEnum(instruction.context) != operation.context_tag or
            @as(usize, instruction.verifier_sequence) >= vm_plan.steps.len)
        {
            return mismatch();
        }
        const verifier_sequence: usize = instruction.verifier_sequence;
        const encoded_step = vm_plan.steps[verifier_sequence].encode();
        const operation_first = instruction_index == 0 or
            program.operations[instruction_index - 1].verifier_sequence !=
                instruction.verifier_sequence;
        const first_frame: usize = operation.first_hash_id;
        const frame_count: usize = operation.hash_count;
        const frame_end = std.math.add(usize, first_frame, frame_count) catch
            return mismatch();
        if (frame_count == 0 or frame_end > execution.hash_frames.len)
            return mismatch();

        for (execution.hash_frames[first_frame..frame_end], 0..) |
            frame,
            local_frame,
        | {
            const is_mix = frame.purpose == .mix;
            const pow_draw = instruction.effect == .pow and
                local_frame + 1 == frame_count;
            const state_key = mix_ordinal + @intFromBool(is_mix);
            try emit(
                source_rows.TranscriptStateRowV2,
                buffers.transcript_state,
                &state_at,
                .{
                    .preprocessing = .{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = 0,
                        .sequence = instruction.verifier_sequence,
                        .tag = encoded_step.tag,
                        .args = encoded_step.args,
                        .hash_id = frame.hash_id,
                        .input_state_key = if (is_mix)
                            mix_ordinal
                        else
                            state_key,
                        .output_state_key = state_key,
                        .initial_mask = @intFromBool(
                            is_mix and mix_ordinal == 0,
                        ),
                        .state_consume_mask = @intFromBool(
                            !is_mix or mix_ordinal > 0,
                        ),
                        .state_produce_multiplicity = if (is_mix)
                            stateConsumerCount(
                                execution.hash_frames,
                                first_frame + local_frame,
                            )
                        else
                            0,
                        .draw_output_mask = @intFromBool(
                            !is_mix and !pow_draw,
                        ),
                    },
                    .main = .{
                        .enabler = 1,
                        .inputs = frame.words[0..recording.RATE].*,
                        .outputs = frame.output[0..recording.RATE].*,
                    },
                },
                validate_only,
            );
            mix_ordinal += @intFromBool(is_mix);

            const first_call: usize = frame.first_call_id;
            const call_count: usize = frame.call_count;
            const call_end = std.math.add(usize, first_call, call_count) catch
                return mismatch();
            if (call_end > execution.poseidon_calls.len) return mismatch();
            for (first_call..call_end) |call_index| {
                const call = execution.poseidon_calls[call_index];
                const call_row = try transcriptCallRow(
                    execution,
                    call_index,
                    frame,
                );
                try emit(
                    source_rows.TranscriptAirRowV2,
                    buffers.transcript_air,
                    &call_at,
                    call_row,
                    validate_only,
                );
                try emit(
                    source_rows.TranscriptBindingRowV2,
                    buffers.transcript_binding,
                    &binding_at,
                    .{
                        .preprocessing = .{
                            .row_mask = 1,
                            .segment_mask = 1,
                            .binary_mask = 0,
                            .verifier_id = 0,
                            .sequence = instruction.verifier_sequence,
                            .tag = encoded_step.tag,
                            .args = encoded_step.args,
                            .call_id = @intCast(call_index),
                            .hash_id = frame.hash_id,
                            .hash_step = call.id.step,
                            .is_first = call_row.is_first,
                            .is_last = call_row.is_last,
                            .is_draw = call_row.is_draw,
                            .is_operation_first = @intFromBool(
                                operation_first and local_frame == 0 and
                                    call.id.step == 0,
                            ),
                            .pow_final_mask = @intFromBool(
                                pow_draw and call_row.is_last == 1,
                            ),
                        },
                        .main = .{
                            .enabler = 1,
                            .chunks = call_row.chunk,
                            .outputs = if (call_row.is_last == 1)
                                call.output[0..recording.RATE].*
                            else
                                [_]M31{M31.zero()} ** recording.RATE,
                        },
                    },
                    validate_only,
                );
            }

            const padded_words = std.math.mul(
                usize,
                call_count,
                recording.RATE,
            ) catch return mismatch();
            for (recording.RATE..padded_words) |frame_word_index| {
                const is_payload = is_mix and frame_word_index < frame.words.len;
                const constant_value: u32 = if (is_payload)
                    0
                else if (frame_word_index < frame.words.len)
                    frame.words[frame_word_index].toU32()
                else if (frame_word_index == frame.words.len)
                    1
                else
                    0;
                const value = if (is_payload)
                    frame.words[frame_word_index]
                else
                    M31.zero();
                try emit(
                    source_rows.TranscriptWordRowV2,
                    buffers.transcript_word,
                    &word_at,
                    .{
                        .preprocessing = .{
                            .row_mask = 1,
                            .segment_mask = 1,
                            .binary_mask = 0,
                            .verifier_id = 0,
                            .sequence = @intCast(instruction_index),
                            .tag = instruction.tag,
                            .args = instruction.args,
                            .hash_id = frame.hash_id,
                            .word_index = @intCast(frame_word_index),
                            .is_payload = @intFromBool(is_payload),
                            .payload_index = if (is_payload)
                                @intCast(frame_word_index - recording.RATE)
                            else
                                0,
                            .constant_value = constant_value,
                        },
                        .value = value,
                    },
                    validate_only,
                );
                if (is_payload) {
                    const payload_index: u32 = @intCast(
                        frame_word_index - recording.RATE,
                    );
                    const metadata = try program.payloadMetadata(
                        instruction_index,
                        payload_index,
                    );
                    try emit(
                        TranscriptPayloadRowV4,
                        buffers.transcript_payload,
                        &payload_at,
                        .{
                            .preprocessing = .{
                                .row_mask = 1,
                                .segment_mask = 1,
                                .binary_mask = 0,
                                .verifier_id = 0,
                                .sequence = @intCast(instruction_index),
                                .tag = instruction.tag,
                                .args = instruction.args,
                                .payload_index = payload_index,
                                .source_kind = @enumFromInt(
                                    @intFromEnum(metadata.source_kind),
                                ),
                                .item_index = metadata.item_index,
                                .limb_index = metadata.limb_index,
                                .constant_mask = metadata.constant_mask,
                                .input_use_count = metadata.input_use_count,
                                .constant_value = if (metadata.constant_mask == 1) value.toU32() else 0,
                                .source_hash_id = frame.hash_id,
                                .source_word_index = @intCast(frame_word_index),
                            },
                            .value = value,
                        },
                        validate_only,
                    );
                }
            }
        }

        if (instruction.effect == .pow) {
            const check_index = operation.pow_check_index orelse
                return mismatch();
            if (@as(usize, check_index) != pow_at or
                pow_at >= execution.pow_checks.len)
                return mismatch();
            const check = execution.pow_checks[pow_at];
            const interaction = switch (instruction.payload) {
                .interaction_pow_nonce => true,
                else => false,
            };
            const pow_kind: air.pow_check.PowKind = if (interaction)
                .interaction
            else
                .pcs;
            const bits = try powBits(vm_plan.steps[verifier_sequence], interaction);
            if (check.bits != bits) return mismatch();
            var word_bits: [31]u32 = undefined;
            var active_bits: [31]u32 = undefined;
            for (&word_bits, &active_bits, 0..) |*word_bit, *active, bit| {
                word_bit.* = (check.word.toU32() >> @intCast(bit)) & 1;
                active.* = @intFromBool(bit < bits);
            }
            const draw_frame = execution.hash_frames[frame_end - 1];
            try emit(
                source_rows.PowCheckRowV2,
                buffers.pow_check,
                &pow_at,
                .{
                    .pow_kind = pow_kind,
                    .call_id = check.call_id,
                    .bits = bits,
                    .word = check.word,
                    .word_bits = word_bits,
                    .active_bits = active_bits,
                },
                validate_only,
            );
            try emit(
                source_rows.PowFrameRowV2,
                buffers.pow_frame,
                &pow_frame_at,
                .{
                    .instruction_index = instruction.verifier_sequence,
                    .pow_kind = pow_kind,
                    .hash_id = draw_frame.hash_id,
                    .call_id = check.call_id,
                    .bits = bits,
                    .words = draw_frame.output[0..recording.RATE].*,
                },
                validate_only,
            );
        } else if (operation.pow_check_index != null) return mismatch();
    }

    if (call_at != buffers.transcript_air.len or
        binding_at != execution.poseidon_calls.len or
        state_at != execution.hash_frames.len or
        pow_at != buffers.pow_check.len or
        pow_frame_at != buffers.pow_frame.len or
        buffers.provider_calls.len != execution.poseidon_calls.len)
    {
        return mismatch();
    }
    try appendCanonicalSuffixes(
        suffixes,
        buffers,
        &binding_at,
        &state_at,
        &word_at,
        &payload_at,
        validate_only,
    );
    if (binding_at != buffers.transcript_binding.len or
        state_at != buffers.transcript_state.len or
        word_at != buffers.transcript_word.len or
        payload_at != buffers.transcript_payload.len)
    {
        return mismatch();
    }
    if (validate_only) {
        for (buffers.provider_calls, execution.poseidon_calls) |actual, expected|
            if (!std.meta.eql(actual, providerCall(expected))) return mismatch();
    } else {
        for (buffers.provider_calls, execution.poseidon_calls) |*actual, expected|
            actual.* = providerCall(expected);
    }
}

fn providerCall(source: recording.PoseidonCall) source_rows.ProviderCall {
    var input: [recording.WIDTH]u32 = undefined;
    for (&input, source.input) |*destination, value|
        destination.* = value.toU32();
    return .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
}

fn appendCanonicalSuffixes(
    suffixes: CanonicalSuffixesV4,
    buffers: BuffersV4,
    binding_at: *usize,
    state_at: *usize,
    word_at: *usize,
    payload_at: *usize,
    comptime validate_only: bool,
) Error!void {
    for (suffixes.binding.rows[suffixes.binding.vm_call_count..]) |row| {
        try emit(
            source_rows.TranscriptBindingRowV2,
            buffers.transcript_binding,
            binding_at,
            .{
                .preprocessing = row,
                .main = .{
                    .enabler = 1,
                    .chunks = [_]M31{M31.zero()} ** recording.RATE,
                    .outputs = [_]M31{M31.zero()} ** recording.RATE,
                },
            },
            validate_only,
        );
    }
    for (suffixes.state.rows[suffixes.state.vm_frame_count..]) |row| {
        try emit(
            source_rows.TranscriptStateRowV2,
            buffers.transcript_state,
            state_at,
            .{
                .preprocessing = row,
                .main = .{
                    .enabler = 1,
                    .inputs = [_]M31{M31.zero()} ** recording.RATE,
                    .outputs = [_]M31{M31.zero()} ** recording.RATE,
                },
            },
            validate_only,
        );
    }
    for (suffixes.word.rows[suffixes.word.vm_row_count..]) |row| {
        try emit(
            source_rows.TranscriptWordRowV2,
            buffers.transcript_word,
            word_at,
            .{ .preprocessing = row, .value = M31.zero() },
            validate_only,
        );
    }
    for (suffixes.payload.rows[suffixes.payload.vm_row_count..]) |row| {
        try emit(
            TranscriptPayloadRowV4,
            buffers.transcript_payload,
            payload_at,
            .{ .preprocessing = row, .value = M31.zero() },
            validate_only,
        );
    }
}

pub fn relationDrawsAlloc(
    allocator: std.mem.Allocator,
    execution: *const recording.ExecutionV4,
    program: *const program_mod.ProgramAuthorityV4,
) Error![]air.relation_challenge_witness.Draw {
    const count: usize = @intCast(program_mod.RELATION_DRAW_COUNT / 2);
    const result = try allocator.alloc(air.relation_challenge_witness.Draw, count);
    errdefer allocator.free(result);
    var seen = [_][2]bool{.{ false, false }} ** count;
    for (program.operations, 0..) |operation, index| switch (operation.draw) {
        .relation_limb => |binding| {
            if (@as(usize, binding.challenge) >= result.len or
                binding.half >= 2 or
                seen[binding.challenge][binding.half])
            {
                return mismatch();
            }
            const draw = try operationDraw(execution, index);
            const offset: usize = 4 * binding.half;
            @memcpy(result[binding.challenge][offset..][0..4], draw[0..4]);
            seen[binding.challenge][binding.half] = true;
        },
        else => {},
    };
    for (seen) |complete| if (!complete[0] or !complete[1]) return mismatch();
    return result;
}

pub fn randomnessDrawsAlloc(
    allocator: std.mem.Allocator,
    execution: *const recording.ExecutionV4,
    program: *const program_mod.ProgramAuthorityV4,
) Error![]air.verifier_randomness_witness.Draw {
    var count: usize = 0;
    for (program.operations) |operation| switch (operation.draw) {
        .composition, .oods, .deep, .fri_alpha, .query_block => count += 1,
        else => {},
    };
    const result = try allocator.alloc(air.verifier_randomness_witness.Draw, count);
    errdefer allocator.free(result);
    var at: usize = 0;
    for (program.operations, 0..) |operation, index| switch (operation.draw) {
        .composition, .oods, .deep, .fri_alpha, .query_block => {
            result[at] = try operationDraw(execution, index);
            at += 1;
        },
        else => {},
    };
    if (at != result.len) return mismatch();
    return result;
}

fn transcriptCallRow(
    execution: *const recording.ExecutionV4,
    call_index: usize,
    frame: recording.HashFrame,
) Error!source_rows.TranscriptAirRowV2 {
    if (call_index >= execution.poseidon_calls.len) return mismatch();
    const call = execution.poseidon_calls[call_index];
    const previous = if (call.id.step == 0)
        [_]M31{M31.zero()} ** recording.WIDTH
    else blk: {
        if (call_index == 0) return mismatch();
        break :blk execution.poseidon_calls[call_index - 1].output;
    };
    var chunk: [recording.RATE]M31 = undefined;
    for (&chunk, call.input[0..recording.RATE], previous[0..recording.RATE]) |
        *target,
        input,
        prior,
    | target.* = input.sub(prior);
    return .{
        .enabler = 1,
        .verifier_id = 0,
        .call_id = @intCast(call_index),
        .hash_id = frame.hash_id,
        .step = call.id.step,
        .is_first = @intFromBool(call.id.step == 0),
        .is_last = @intFromBool(call.id.step + 1 == frame.call_count),
        .is_draw = @intFromBool(frame.purpose == .draw),
        .previous = previous,
        .chunk = chunk,
        .output = call.output,
    };
}

fn stateConsumerCount(
    frames: []const recording.HashFrame,
    mix_index: usize,
) u32 {
    std.debug.assert(mix_index < frames.len);
    std.debug.assert(frames[mix_index].purpose == .mix);
    var result: u32 = 0;
    for (frames[mix_index + 1 ..]) |frame| {
        result += 1;
        if (frame.purpose == .mix) break;
    }
    return result;
}

fn operationDraw(
    execution: *const recording.ExecutionV4,
    operation_index: usize,
) Error![recording.RATE]M31 {
    if (operation_index >= execution.operations.len) return mismatch();
    const operation = execution.operations[operation_index];
    if (operation.effect == .mix or operation.hash_count == 0)
        return mismatch();
    const frame_index = std.math.add(
        usize,
        operation.first_hash_id,
        operation.hash_count - 1,
    ) catch return mismatch();
    if (frame_index >= execution.hash_frames.len) return mismatch();
    const frame = execution.hash_frames[frame_index];
    if (frame.purpose != .draw) return mismatch();
    return frame.output[0..recording.RATE].*;
}

fn powBits(step: schedule.VerifierStep, interaction: bool) Error!u32 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |value| if (interaction)
            value.bits
        else
            mismatch(),
        .verify_and_absorb_pcs_pow => |value| if (!interaction)
            value.bits
        else
            mismatch(),
        else => mismatch(),
    };
}

fn emit(
    comptime T: type,
    destination: []T,
    cursor: *usize,
    value: T,
    comptime validate_only: bool,
) Error!void {
    if (cursor.* >= destination.len) return mismatch();
    if (validate_only) {
        if (!std.meta.eql(destination[cursor.*], value)) return mismatch();
    } else destination[cursor.*] = value;
    cursor.* += 1;
}

fn mismatch() Error {
    return error.EthereumIncrementalTranscriptRowsMismatchV4;
}
