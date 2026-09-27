//! Internal segment transcript outer source v2 authority shard; use segment_transcript_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_transcript_outer_source_v2_contract.zig");
const dependency_1 = @import("segment_transcript_outer_source_v2_prepared_v2.zig");

const DestinationsV2 = dependency_1.DestinationsV2;
const M31 = dependency_0.M31;
const PowCheckRowV2 = dependency_1.PowCheckRowV2;
const PowFrameRowV2 = dependency_1.PowFrameRowV2;
const RelationChallengeRowV2 = dependency_1.RelationChallengeRowV2;
const RelationEventV2 = dependency_1.RelationEventV2;
const TranscriptAirRowV2 = dependency_0.TranscriptAirRowV2;
const TranscriptBindingRowV2 = dependency_1.TranscriptBindingRowV2;
const TranscriptPayloadRowV2 = dependency_1.TranscriptPayloadRowV2;
const TranscriptStateRowV2 = dependency_1.TranscriptStateRowV2;
const TranscriptWordRowV2 = dependency_1.TranscriptWordRowV2;
const VERIFIER_ID = dependency_0.VERIFIER_ID;
const channel = dependency_0.channel;
const felt = dependency_0.felt;
const payloadRow = dependency_1.payloadRow;
const pow_check_air = dependency_0.pow_check_air;
const randomness_witness = dependency_0.randomness_witness;
const relation = dependency_0.relation;
const relation_witness = dependency_0.relation_witness;
const roster = dependency_0.roster;
const schedule = dependency_0.schedule;
const stateConsumerCount = dependency_1.stateConsumerCount;
const std = dependency_0.std;
const transcript = dependency_0.transcript;
const transcriptCallRow = dependency_1.transcriptCallRow;
const typedTag = dependency_0.typedTag;
const universal = dependency_0.universal;

pub fn writeRowsAssumeValid(
    destinations: DestinationsV2,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    plan: *const schedule.Plan,
) void {
    var control_at: usize = 0;
    for (plan.steps, 0..) |step, sequence| {
        const encoded = step.encode();
        destinations.control[control_at] = .{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = VERIFIER_ID,
            .sequence = @intCast(sequence),
            .tag = encoded.tag,
            .args = encoded.args,
            .terminal_mask = @intFromBool(step.terminal()),
        };
        control_at += 1;
    }

    var call_at: usize = 0;
    var state_at: usize = 0;
    var word_at: usize = 0;
    var payload_at: usize = 0;
    var pow_at: usize = 0;
    var relation_at: usize = 0;
    var randomness_at: usize = 0;
    var mix_ordinal: u32 = 0;

    for (program.instructions, execution.operations, 0..) |
        instruction,
        operation,
        instruction_index,
    | {
        const instruction_tag = typedTag(instruction.kind);
        const verifier_sequence = instruction.verifier_sequence;
        const encoded_step = plan.steps[verifier_sequence].encode();
        const operation_first = instruction_index == 0 or
            program.instructions[instruction_index - 1].verifier_sequence !=
                verifier_sequence;
        for (0..operation.hash_count) |local_frame| {
            const frame_index: usize = operation.first_hash_id + local_frame;
            const frame = execution.hash_frames[frame_index];
            const is_mix = frame.purpose == .mix;
            const pow_draw = instruction.effect() == .pow and local_frame == 1;
            const state_key = mix_ordinal + @intFromBool(is_mix);

            destinations.transcript_state[state_at] = .{
                .preprocessing = .{
                    .row_mask = 1,
                    .segment_mask = 1,
                    .binary_mask = 0,
                    .verifier_id = VERIFIER_ID,
                    .sequence = verifier_sequence,
                    .tag = encoded_step.tag,
                    .args = encoded_step.args,
                    .hash_id = @intCast(frame_index),
                    .input_state_key = if (is_mix) mix_ordinal else state_key,
                    .output_state_key = state_key,
                    .initial_mask = @intFromBool(is_mix and mix_ordinal == 0),
                    .state_consume_mask = @intFromBool(!is_mix or mix_ordinal > 0),
                    .state_produce_multiplicity = if (is_mix)
                        stateConsumerCount(execution.hash_frames, frame_index)
                    else
                        0,
                    .draw_output_mask = @intFromBool(!is_mix and !pow_draw),
                },
                .main = .{
                    .enabler = 1,
                    .inputs = frame.words[0..channel.RATE].*,
                    .outputs = frame.output[0..channel.RATE].*,
                },
            };
            state_at += 1;
            mix_ordinal += @intFromBool(is_mix);

            const frame_call_end: usize = frame.first_call_id + frame.call_count;
            for (frame.first_call_id..frame_call_end) |call_index| {
                const call = execution.poseidon_calls[call_index];
                const call_row = transcriptCallRow(execution, call_index, frame);
                destinations.transcript_air[call_at] = call_row;
                destinations.transcript_binding[call_at] = .{
                    .preprocessing = .{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = VERIFIER_ID,
                        .sequence = verifier_sequence,
                        .tag = encoded_step.tag,
                        .args = encoded_step.args,
                        .call_id = @intCast(call_index),
                        .hash_id = @intCast(frame_index),
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
                            call.output[0..channel.RATE].*
                        else
                            [_]M31{M31.zero()} ** channel.RATE,
                    },
                };
                call_at += 1;
            }

            const padded_words: usize = frame.call_count * channel.RATE;
            for (channel.RATE..padded_words) |frame_word_index| {
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
                destinations.transcript_word[word_at] = .{
                    .preprocessing = .{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = VERIFIER_ID,
                        .sequence = @intCast(instruction_index),
                        .tag = instruction_tag,
                        .args = instruction.args,
                        .hash_id = @intCast(frame_index),
                        .word_index = @intCast(frame_word_index),
                        .is_payload = @intFromBool(is_payload),
                        .payload_index = if (is_payload)
                            @intCast(frame_word_index - channel.RATE)
                        else
                            0,
                        .constant_value = constant_value,
                    },
                    .value = value,
                };
                word_at += 1;

                if (is_payload) {
                    destinations.transcript_payload[payload_at] = payloadRow(
                        instruction,
                        @intCast(instruction_index),
                        @intCast(frame_index),
                        @intCast(frame_word_index - channel.RATE),
                        @intCast(frame_word_index),
                        value,
                    );
                    payload_at += 1;
                }
            }
        }

        switch (instruction.kind) {
            .interaction_pow, .pcs_pow => {
                const check = execution.pow_checks[pow_at];
                const pow_kind: pow_check_air.PowKind = if (instruction.kind == .interaction_pow) .interaction else .pcs;
                var word_bits: [31]u32 = undefined;
                var active_bits: [31]u32 = undefined;
                for (&word_bits, &active_bits, 0..) |*word_bit, *active, bit| {
                    word_bit.* = (check.word.toU32() >> @intCast(bit)) & 1;
                    active.* = @intFromBool(bit < check.bits);
                }
                const draw_frame = execution.hash_frames[
                    operation.first_hash_id + operation.hash_count - 1
                ];
                destinations.pow_check[pow_at] = .{
                    .pow_kind = pow_kind,
                    .call_id = check.call_id,
                    .bits = check.bits,
                    .word = check.word,
                    .word_bits = word_bits,
                    .active_bits = active_bits,
                };
                destinations.pow_frame[pow_at] = .{
                    .instruction_index = verifier_sequence,
                    .pow_kind = pow_kind,
                    .hash_id = draw_frame.hash_id,
                    .call_id = check.call_id,
                    .bits = check.bits,
                    .words = draw_frame.output[0..channel.RATE].*,
                };
                pow_at += 1;
            },
            .relation_draw => {
                const draw = operation.draw.?;
                destinations.relation_challenge[relation_at] = .{
                    .preprocessing = .{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .public_logup_mask = @intFromBool(instruction.args[0] < 4),
                        .verifier_id = VERIFIER_ID,
                        .sequence = verifier_sequence,
                        .tag = encoded_step.tag,
                        .args = encoded_step.args,
                        .challenge = instruction.args[0],
                    },
                    .main = .{ .enabler = 1, .outputs = draw },
                };
                relation_at += 1;
            },
            .composition_draw,
            .oods_draw,
            .deep_draw,
            .fri_alpha_draw,
            .query_draw,
            => {
                const descriptor = randomnessDescriptor(instruction);
                var multiplicities: [channel.RATE]u32 = .{0} ** channel.RATE;
                for (0..descriptor.word_count) |word|
                    multiplicities[word] = descriptor.semantic_use_count;
                destinations.verifier_randomness[randomness_at] = .{
                    .preprocessing = .{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = VERIFIER_ID,
                        .sequence = verifier_sequence,
                        .tag = encoded_step.tag,
                        .args = encoded_step.args,
                        .kind = descriptor.kind,
                        .item_base = descriptor.item_base,
                        .query_items = @intFromBool(descriptor.query_items),
                        .multiplicities = multiplicities,
                        .draw_index = @intCast(randomness_at),
                    },
                    .main = .{ .enabler = 1, .outputs = operation.draw.? },
                };
                randomness_at += 1;
            },
            else => {},
        }
    }

    std.debug.assert(control_at == destinations.control.len);
    std.debug.assert(call_at == destinations.transcript_air.len);
    std.debug.assert(call_at == destinations.transcript_binding.len);
    std.debug.assert(state_at == destinations.transcript_state.len);
    std.debug.assert(word_at == destinations.transcript_word.len);
    std.debug.assert(payload_at == destinations.transcript_payload.len);
    std.debug.assert(pow_at == destinations.pow_check.len);
    std.debug.assert(pow_at == destinations.pow_frame.len);
    std.debug.assert(relation_at == destinations.relation_challenge.len);
    std.debug.assert(randomness_at == destinations.verifier_randomness.len);
}

pub const RandomnessDescriptor = struct {
    kind: randomness_witness.Kind,
    item_base: u32,
    query_items: bool,
    word_count: usize,
    semantic_use_count: u32,
};

pub fn randomnessDescriptor(instruction: transcript.Instruction) RandomnessDescriptor {
    return switch (instruction.kind) {
        .composition_draw => .{
            .kind = .composition_randomness,
            .item_base = 0,
            .query_items = false,
            .word_count = 4,
            .semantic_use_count = 1,
        },
        .oods_draw => .{
            .kind = .oods_point,
            .item_base = 0,
            .query_items = false,
            .word_count = 4,
            .semantic_use_count = 2,
        },
        .deep_draw => .{
            .kind = .deep_randomness,
            .item_base = 0,
            .query_items = false,
            .word_count = 4,
            .semantic_use_count = 1,
        },
        .fri_alpha_draw => .{
            .kind = .fri_alpha,
            .item_base = instruction.args[0],
            .query_items = false,
            .word_count = 4,
            .semantic_use_count = 1,
        },
        .query_draw => .{
            .kind = .raw_query,
            .item_base = instruction.args[1],
            .query_items = true,
            .word_count = instruction.args[2],
            .semantic_use_count = 1,
        },
        else => unreachable,
    };
}

pub const EventSink = struct {
    events: []RelationEventV2,
    at: usize = 0,

    pub fn put(
        self: *EventSink,
        row: roster.Component,
        logical_row: usize,
        ordinal: u8,
        domain: relation.Domain,
        role: relation.Role,
        multiplicity: u32,
        values: []const M31,
    ) void {
        std.debug.assert(self.at < self.events.len);
        std.debug.assert(values.len == relation.universalDescriptor(domain).arity);
        var tuple = [_]M31{M31.zero()} ** universal.MAX_ARITY;
        @memcpy(tuple[0..values.len], values);
        self.events[self.at] = .{
            .roster_row = @intFromEnum(row),
            .logical_row = @intCast(logical_row),
            .event_ordinal = ordinal,
            .domain = domain,
            .role = role,
            .multiplicity = multiplicity,
            .arity = @intCast(values.len),
            .tuple = tuple,
        };
        self.at += 1;
    }
};

pub fn writeTranscriptAirEvents(
    sink: *EventSink,
    logical_row: usize,
    row: TranscriptAirRowV2,
) void {
    var poseidon_input = row.previous;
    for (poseidon_input[0..channel.RATE], row.chunk) |*target, chunk|
        target.* = target.add(chunk);
    const poseidon_tuple = poseidon_input ++ row.output;
    const control_tuple = [_]M31{
        felt(row.verifier_id), felt(row.call_id), felt(row.hash_id), felt(row.step),
        felt(row.is_first),    felt(row.is_last), felt(row.is_draw),
    };
    const data_tuple = [_]M31{
        felt(row.verifier_id), felt(row.hash_id), felt(row.step),
    } ++ row.chunk;
    const state_input_tuple = [_]M31{
        felt(row.verifier_id), felt(row.hash_id), felt(row.step),
    } ++ row.previous;
    const state_output_tuple = [_]M31{
        felt(row.verifier_id), felt(row.hash_id), felt(row.step + 1),
    } ++ row.output;
    const output_tuple = [_]M31{
        felt(row.verifier_id), felt(row.hash_id), felt(row.call_id), felt(row.is_draw),
    } ++ row.output[0..channel.RATE].*;

    sink.put(.transcript_air, logical_row, 0, .poseidon2_io, .request, 1, &poseidon_tuple);
    sink.put(.transcript_air, logical_row, 1, .recursion_hash_call_control, .consume, 1, &control_tuple);
    sink.put(.transcript_air, logical_row, 2, .recursion_hash_data, .consume, 1, &data_tuple);
    sink.put(.transcript_air, logical_row, 3, .recursion_hash_state, .consume, 1 - row.is_first, &state_input_tuple);
    sink.put(.transcript_air, logical_row, 4, .recursion_hash_state, .emit, 1 - row.is_last, &state_output_tuple);
    sink.put(.transcript_air, logical_row, 5, .recursion_hash_output, .emit, row.is_last, &output_tuple);
}

pub fn writeBindingEvents(
    sink: *EventSink,
    logical_row: usize,
    row: TranscriptBindingRowV2,
) void {
    const pp = row.preprocessing;
    const main = row.main;
    const control_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.call_id), felt(pp.hash_id), felt(pp.hash_step),
        felt(pp.is_first),    felt(pp.is_last), felt(pp.is_draw),
    };
    const data_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.hash_id), felt(pp.hash_step),
    } ++ main.chunks;
    const output_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.hash_id), felt(pp.call_id), felt(pp.is_draw),
    } ++ main.outputs;
    const frame_output_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.hash_id),
    } ++ main.outputs;
    const pow_frame_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.sequence), felt(pp.tag), felt(pp.hash_id),
        felt(pp.call_id),     felt(pp.args[0]),
    } ++ main.outputs;
    const step_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.sequence), felt(pp.tag),
    } ++ feltArgs(pp.args);

    sink.put(.transcript_binding, logical_row, 0, .recursion_hash_call_control, .emit, 1, &control_tuple);
    sink.put(.transcript_binding, logical_row, 1, .recursion_hash_data, .emit, 1, &data_tuple);
    sink.put(.transcript_binding, logical_row, 2, .recursion_hash_output, .consume, pp.is_last, &output_tuple);
    sink.put(.transcript_binding, logical_row, 3, .recursion_transcript_frame_output, .emit, pp.is_last, &frame_output_tuple);
    sink.put(.transcript_binding, logical_row, 4, .recursion_transcript_pow_frame, .emit, pp.pow_final_mask, &pow_frame_tuple);
    sink.put(.transcript_binding, logical_row, 5, .recursion_step, .consume, pp.is_operation_first, &step_tuple);
    for (main.chunks, 0..) |chunk, word| {
        const word_index = pp.hash_step * channel.RATE + word;
        const tuple = [_]M31{
            felt(pp.verifier_id), felt(pp.hash_id), felt(@intCast(word_index)), chunk,
        };
        sink.put(
            .transcript_binding,
            logical_row,
            @intCast(6 + word),
            .recursion_transcript_frame_word,
            .consume,
            1,
            &tuple,
        );
    }
}

pub fn writeStateEvents(
    sink: *EventSink,
    logical_row: usize,
    row: TranscriptStateRowV2,
) void {
    const pp = row.preprocessing;
    const main = row.main;
    const frame_output_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.hash_id),
    } ++ main.outputs;
    const draw_output_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.sequence), felt(pp.tag),
    } ++ feltArgs(pp.args) ++ main.outputs;
    const input_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.input_state_key),
    } ++ main.inputs;
    const output_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.output_state_key),
    } ++ main.outputs;
    sink.put(.transcript_state, logical_row, 0, .recursion_transcript_frame_output, .consume, 1, &frame_output_tuple);
    sink.put(.transcript_state, logical_row, 1, .recursion_transcript_draw_output, .emit, pp.draw_output_mask, &draw_output_tuple);
    sink.put(.transcript_state, logical_row, 2, .recursion_transcript_digest_state, .consume, pp.state_consume_mask, &input_tuple);
    sink.put(.transcript_state, logical_row, 3, .recursion_transcript_digest_state, .emit, pp.state_produce_multiplicity, &output_tuple);
    for (main.inputs, 0..) |value, word| {
        const tuple = [_]M31{
            felt(pp.verifier_id), felt(pp.hash_id), felt(@intCast(word)), value,
        };
        sink.put(
            .transcript_state,
            logical_row,
            @intCast(4 + word),
            .recursion_transcript_frame_word,
            .emit,
            1,
            &tuple,
        );
    }
}

pub fn writeWordEvents(
    sink: *EventSink,
    logical_row: usize,
    row: TranscriptWordRowV2,
) void {
    const pp = row.preprocessing;
    const frame_value = row.value.add(felt(pp.constant_value));
    const frame_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.hash_id), felt(pp.word_index), frame_value,
    };
    const payload_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.sequence), felt(pp.tag),
    } ++ feltArgs(pp.args) ++ .{ felt(pp.payload_index), row.value };
    sink.put(.transcript_word, logical_row, 0, .recursion_transcript_frame_word, .emit, 1, &frame_tuple);
    sink.put(.transcript_word, logical_row, 1, .recursion_transcript_payload_word, .consume, pp.is_payload, &payload_tuple);
}

pub fn writePayloadEvents(
    sink: *EventSink,
    logical_row: usize,
    row: TranscriptPayloadRowV2,
) void {
    const payload_tuple = [_]M31{
        felt(row.verifier_id), felt(row.instruction_index), felt(row.tag),
    } ++ feltArgs(row.args) ++ .{ felt(row.payload_index), row.value };
    const input_tuple = [_]M31{
        felt(row.verifier_id),
        felt(@intFromEnum(row.source_kind)),
        felt(row.item_index),
        felt(row.limb_index),
        row.value,
    };
    sink.put(.transcript_payload, logical_row, 0, .recursion_transcript_payload_word, .emit, 1, &payload_tuple);
    sink.put(.transcript_payload, logical_row, 1, .recursion_verifier_input_word, .emit, row.input_use_count, &input_tuple);
}

pub fn writePowCheckEvents(
    sink: *EventSink,
    logical_row: usize,
    row: PowCheckRowV2,
) void {
    const tuple = [_]M31{
        felt(row.verifier_id),
        felt(@intFromEnum(row.pow_kind)),
        felt(row.call_id),
        felt(row.bits),
        row.word,
    };
    sink.put(.pow_check, logical_row, 0, .recursion_pow_check, .consume, row.enabler, &tuple);
}

pub fn writePowFrameEvents(
    sink: *EventSink,
    logical_row: usize,
    row: PowFrameRowV2,
) void {
    const pow_tag = @intFromEnum(row.pow_kind) * 14 - 8;
    const frame_tuple = [_]M31{
        felt(row.verifier_id), felt(row.instruction_index), felt(pow_tag),
        felt(row.hash_id),     felt(row.call_id),           felt(row.bits),
    } ++ row.words;
    const check_tuple = [_]M31{
        felt(row.verifier_id),
        felt(@intFromEnum(row.pow_kind)),
        felt(row.call_id),
        felt(row.bits),
        row.words[0],
    };
    sink.put(.pow_frame, logical_row, 0, .recursion_transcript_pow_frame, .consume, row.enabler, &frame_tuple);
    sink.put(.pow_frame, logical_row, 1, .recursion_pow_check, .emit, row.enabler, &check_tuple);
}

pub fn writeRelationChallengeEvents(
    sink: *EventSink,
    logical_row: usize,
    row: RelationChallengeRowV2,
) void {
    const pp = row.preprocessing;
    const draw_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.sequence), felt(pp.tag),
    } ++ feltArgs(pp.args) ++ row.main.outputs;
    sink.put(.relation_challenge, logical_row, 0, .recursion_transcript_draw_output, .consume, row.main.enabler, &draw_tuple);
    for (row.main.outputs, 0..) |value, word| {
        const air_tuple = [_]M31{
            felt(pp.verifier_id),
            felt(relation_witness.AIR_EVALUATION_CHALLENGE_SCOPE),
            felt(pp.challenge),
            felt(@intCast(word)),
            value,
        };
        const public_tuple = [_]M31{
            felt(pp.verifier_id),
            felt(relation_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE),
            felt(pp.challenge),
            felt(@intCast(word)),
            value,
        };
        sink.put(
            .relation_challenge,
            logical_row,
            @intCast(1 + 2 * word),
            .recursion_relation_challenge_word,
            .emit,
            row.main.enabler,
            &air_tuple,
        );
        sink.put(
            .relation_challenge,
            logical_row,
            @intCast(2 + 2 * word),
            .recursion_relation_challenge_word,
            .emit,
            row.main.enabler * pp.public_logup_mask,
            &public_tuple,
        );
    }
}

pub fn feltArgs(values: [4]u32) [4]M31 {
    return .{
        felt(values[0]),
        felt(values[1]),
        felt(values[2]),
        felt(values[3]),
    };
}
