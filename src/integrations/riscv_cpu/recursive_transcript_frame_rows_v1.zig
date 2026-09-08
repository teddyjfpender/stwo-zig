//! Shared native-sponge row construction. Callers own schedule admission and
//! validate the recording before supplying frame/call coordinates.
const frontend = @import("stwo_riscv_frontend");
const M31 = @import("stwo_core").fields.m31.M31;
const recursion = frontend.recursion;
const air = recursion.air;
const recording = recursion.recording_poseidon_channel_v4;
const rows = recursion.segment_transcript_outer_source_v2;

pub const Step = struct {
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,

    fn segment(self: Step) u32 {
        return @intFromBool(self.verifier_id == 0);
    }
    fn binary(self: Step) u32 {
        return @intFromBool(self.verifier_id != 0);
    }
};

pub fn callRow(execution: *const recording.ExecutionV4, index: usize, frame: recording.HashFrame, verifier_id: u32) !rows.TranscriptAirRowV2 {
    const call = execution.poseidon_calls[index];
    const previous = if (call.id.step == 0)
        [_]M31{M31.zero()} ** recording.WIDTH
    else
        execution.poseidon_calls[index - 1].output;
    return air.transcript_air_witness.rowFromCall(verifier_id, frame, call, previous);
}

pub fn binding(step: Step, call_index: u32, frame: recording.HashFrame, call: recording.PoseidonCall, row: rows.TranscriptAirRowV2, operation_first: bool, pow_draw: bool) rows.TranscriptBindingRowV2 {
    return .{
        .preprocessing = .{
            .row_mask = 1,
            .segment_mask = step.segment(),
            .binary_mask = step.binary(),
            .verifier_id = step.verifier_id,
            .sequence = step.sequence,
            .tag = step.tag,
            .args = step.args,
            .call_id = call_index,
            .hash_id = frame.hash_id,
            .hash_step = call.id.step,
            .is_first = row.is_first,
            .is_last = row.is_last,
            .is_draw = row.is_draw,
            .is_operation_first = @intFromBool(operation_first and call.id.step == 0),
            .pow_final_mask = @intFromBool(pow_draw and row.is_last == 1),
        },
        .main = .{
            .enabler = 1,
            .chunks = row.chunk,
            .outputs = if (row.is_last == 1) call.output[0..recording.RATE].* else [_]M31{M31.zero()} ** recording.RATE,
        },
    };
}

pub fn state(step: Step, frames: []const recording.HashFrame, frame_index: usize, mix_ordinal: u32, pow_draw: bool) rows.TranscriptStateRowV2 {
    const frame = frames[frame_index];
    const is_mix = frame.purpose == .mix;
    const state_key = mix_ordinal + @intFromBool(is_mix);
    var consumers: u32 = 0;
    if (is_mix) for (frames[frame_index + 1 ..]) |next| {
        consumers += 1;
        if (next.purpose == .mix) break;
    };
    return .{
        .preprocessing = .{
            .row_mask = 1,
            .segment_mask = step.segment(),
            .binary_mask = step.binary(),
            .verifier_id = step.verifier_id,
            .sequence = step.sequence,
            .tag = step.tag,
            .args = step.args,
            .hash_id = frame.hash_id,
            .input_state_key = if (is_mix) mix_ordinal else state_key,
            .output_state_key = state_key,
            .initial_mask = @intFromBool(is_mix and mix_ordinal == 0),
            .state_consume_mask = @intFromBool(!is_mix or mix_ordinal > 0),
            .state_produce_multiplicity = consumers,
            .draw_output_mask = @intFromBool(!is_mix and !pow_draw),
        },
        .main = .{ .enabler = 1, .inputs = frame.words[0..recording.RATE].*, .outputs = frame.output[0..recording.RATE].* },
    };
}

pub fn word(step: Step, frame: recording.HashFrame, index: u32) rows.TranscriptWordRowV2 {
    const is_payload = frame.purpose == .mix and index < frame.words.len;
    return .{
        .preprocessing = .{
            .row_mask = 1,
            .segment_mask = step.segment(),
            .binary_mask = step.binary(),
            .verifier_id = step.verifier_id,
            .sequence = step.sequence,
            .tag = step.tag,
            .args = step.args,
            .hash_id = frame.hash_id,
            .word_index = index,
            .is_payload = @intFromBool(is_payload),
            .payload_index = if (is_payload) @intCast(index - recording.RATE) else 0,
            .constant_value = if (is_payload) 0 else if (index < frame.words.len)
                frame.words[index].toU32()
            else
                @intFromBool(index == frame.words.len),
        },
        .value = if (is_payload) frame.words[index] else M31.zero(),
    };
}

pub fn providerCall(source: recording.PoseidonCall) rows.ProviderCall {
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
