//! Proof-free reconstruction of the transcript's call, state, and draw shape.
//! The schedule is compiled from admitted key geometry; no execution, captured
//! transcript frame, or proof word is consumed.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const native_geometry = @import("detached_native_column_geometry_v1.zig");
const schedule = @import("air/verifier_schedule.zig");
const program_contract = @import("transcript_program_v2_contract.zig");
const program = @import("transcript_program_v2_program.zig");
const source_contract = @import("segment_transcript_outer_source_v2_contract.zig");
const source_writer = @import("segment_transcript_outer_source_v2_write_rows_assume_valid.zig");
const source_rows = @import("segment_transcript_outer_source_v2_prepared_v2.zig");
const framework = @import("air/framework_interaction.zig");
const statement = @import("../air/statement.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const binding = @import("air/transcript_binding_witness.zig");
const state = @import("air/transcript_state_witness.zig");
const word_witness = @import("air/transcript_word_witness.zig");
const payload_witness = @import("air/transcript_payload_witness.zig");
const relation = @import("air/relation_challenge_witness.zig");
const randomness = @import("air/verifier_randomness_witness.zig");

const Frame = struct {
    instruction_index: usize,
    local_frame: usize,
    first_call: usize,
    call_count: usize,
    word_count: usize,
    purpose: program_contract.HashPurpose,
};

const Shape = struct {
    allocator: std.mem.Allocator,
    vm_plan: schedule.Plan,
    instructions: []program_contract.Instruction,
    frames: []Frame,
    call_count: usize,
    lookup_activation: lookup.AuthenticatedStatement,

    fn init(allocator: std.mem.Allocator, key: *const KeyV1) !Shape {
        var geometry = try native_geometry.init(
            allocator,
            key.native_descriptors,
            key.profile.nativePcsConfig().fri_config.log_blowup_factor,
        );
        defer geometry.deinit();
        const schedule_shape = try geometry.q193ScheduleShape(key.native_descriptors);
        var vm_plan = try schedule.Plan.initShape(
            allocator,
            try schedule.vmProgramSpec(0, 0),
            schedule_shape,
        );
        errdefer vm_plan.deinit();

        var core: statement.RiscVStatement = undefined;
        core.n_components = @intCast(key.native_descriptors.components.len);
        @memcpy(core.component_descs[0..core.n_components], key.native_descriptors.components);
        core.n_infra = @intCast(key.native_descriptors.infrastructure.len);
        @memcpy(core.infra_descs[0..core.n_infra], key.native_descriptors.infrastructure);
        var lookup_manifest = lookup.Manifest.native();
        const activation = try lookup.AuthenticatedStatement.init(&core, &lookup_manifest);
        var instruction_list: std.ArrayList(program_contract.Instruction) = .empty;
        errdefer instruction_list.deinit(allocator);
        try program_contract.buildInstructions(
            allocator,
            &instruction_list,
            &vm_plan,
            key.profile.nativePcsConfig(),
            key.source_manifest.wire_word_count,
            key.native_descriptors.components,
            key.native_descriptors.infrastructure,
            activation,
            &lookup_manifest,
        );
        const instructions = try instruction_list.toOwnedSlice(allocator);
        errdefer allocator.free(instructions);

        var frame_list: std.ArrayList(Frame) = .empty;
        errdefer frame_list.deinit(allocator);
        var call_count: usize = 0;
        for (instructions, 0..) |instruction, instruction_index| {
            const effect = instruction.effect();
            const frame_count: usize = if (effect == .pow) 2 else 1;
            for (0..frame_count) |local_frame| {
                const purpose: program_contract.HashPurpose = if (effect == .draw or
                    (effect == .pow and local_frame == 1)) .draw else .mix;
                const word_count: usize = if (purpose == .draw)
                    program_contract.RATE + 2
                else if (effect == .pow)
                    program_contract.RATE + 4
                else
                    program_contract.RATE + try instruction.payloadWordCount();
                const count = try program.frameCallCount(word_count);
                try frame_list.append(allocator, .{
                    .instruction_index = instruction_index,
                    .local_frame = local_frame,
                    .first_call = call_count,
                    .call_count = count,
                    .word_count = word_count,
                    .purpose = purpose,
                });
                call_count += count;
            }
        }
        return .{
            .allocator = allocator,
            .vm_plan = vm_plan,
            .instructions = instructions,
            .frames = try frame_list.toOwnedSlice(allocator),
            .call_count = call_count,
            .lookup_activation = activation,
        };
    }

    fn deinit(self: *Shape) void {
        self.allocator.free(self.frames);
        self.allocator.free(self.instructions);
        self.vm_plan.deinit();
        self.* = undefined;
    }
};

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    row: usize,
    columns: [][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedTranscriptShape;
    const expected_count: usize = switch (row) {
        2 => binding.PREPROCESSED_COLUMN_COUNT,
        3 => state.PREPROCESSED_COLUMN_COUNT,
        4 => word_witness.PREPROCESSED_COLUMN_COUNT,
        5 => payload_witness.PREPROCESSED_COLUMN_COUNT,
        8 => relation.PREPROCESSED_COLUMN_COUNT,
        9 => randomness.PREPROCESSED_COLUMN_COUNT,
        else => return error.InvalidFixedTranscriptShape,
    };
    const placement = key.manifest.placements[row] orelse return error.InvalidFixedTranscriptShape;
    if (placement.geometry.preprocessed_columns != expected_count or
        columns.len != expected_count or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedTranscriptShape;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| {
        if (column.len != size) return error.InvalidFixedTranscriptShape;
        @memset(column, M31.zero());
    }
    var shape = try Shape.init(allocator, key);
    defer shape.deinit();
    const log_size = placement.geometry.log_size;

    switch (row) {
        2 => {
            if (shape.call_count > size) return error.InvalidFixedTranscriptShape;
            for (shape.frames, 0..) |frame, frame_index| {
                const instruction = shape.instructions[frame.instruction_index];
                const encoded = shape.vm_plan.steps[instruction.verifier_sequence].encode();
                const operation_first = frame.instruction_index == 0 or
                    shape.instructions[frame.instruction_index - 1].verifier_sequence != instruction.verifier_sequence;
                const pow_draw = instruction.effect() == .pow and frame.local_frame == 1;
                for (0..frame.call_count) |step| {
                    const logical = frame.first_call + step;
                    const fixed = binding.PreprocessedRow{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = source_contract.VERIFIER_ID,
                        .sequence = instruction.verifier_sequence,
                        .tag = encoded.tag,
                        .args = encoded.args,
                        .call_id = @intCast(logical),
                        .hash_id = @intCast(frame_index),
                        .hash_step = @intCast(step),
                        .is_first = @intFromBool(step == 0),
                        .is_last = @intFromBool(step + 1 == frame.call_count),
                        .is_draw = @intFromBool(frame.purpose == .draw),
                        .is_operation_first = @intFromBool(operation_first and frame.local_frame == 0 and step == 0),
                        .pow_final_mask = @intFromBool(pow_draw and step + 1 == frame.call_count),
                    };
                    put(columns, fixed.values(), logical, log_size);
                }
            }
        },
        3 => {
            if (shape.frames.len > size) return error.InvalidFixedTranscriptShape;
            var mix_ordinal: u32 = 0;
            for (shape.frames, 0..) |frame, frame_index| {
                const instruction = shape.instructions[frame.instruction_index];
                const encoded = shape.vm_plan.steps[instruction.verifier_sequence].encode();
                const is_mix = frame.purpose == .mix;
                const state_key = mix_ordinal + @intFromBool(is_mix);
                const pow_draw = instruction.effect() == .pow and frame.local_frame == 1;
                var consumers: u32 = 0;
                if (is_mix) for (shape.frames[frame_index + 1 ..]) |later| {
                    consumers += 1;
                    if (later.purpose == .mix) break;
                };
                const fixed = state.PreprocessedRow{
                    .row_mask = 1,
                    .segment_mask = 1,
                    .binary_mask = 0,
                    .verifier_id = source_contract.VERIFIER_ID,
                    .sequence = instruction.verifier_sequence,
                    .tag = encoded.tag,
                    .args = encoded.args,
                    .hash_id = @intCast(frame_index),
                    .input_state_key = if (is_mix) mix_ordinal else state_key,
                    .output_state_key = state_key,
                    .initial_mask = @intFromBool(is_mix and mix_ordinal == 0),
                    .state_consume_mask = @intFromBool(!is_mix or mix_ordinal > 0),
                    .state_produce_multiplicity = consumers,
                    .draw_output_mask = @intFromBool(!is_mix and !pow_draw),
                };
                put(columns, fixed.values(), frame_index, log_size);
                mix_ordinal += @intFromBool(is_mix);
            }
        },
        4, 5 => {
            var logical: usize = 0;
            var draw_count: u32 = 0;
            for (shape.frames, 0..) |frame, frame_index| {
                const instruction = shape.instructions[frame.instruction_index];
                const is_mix = frame.purpose == .mix;
                const padded_words = frame.call_count * program_contract.RATE;
                const tag = source_contract.typedTag(instruction.kind);
                var fixed_payload: [64]M31 = undefined;
                var has_fixed_payload = false;
                if (row == 5 and is_mix and frame.word_count - program_contract.RATE <= fixed_payload.len) {
                    const count = frame.word_count - program_contract.RATE;
                    has_fixed_payload = try program.writeFixedPayload(
                        fixed_payload[0..count],
                        key.profile.nativePcsConfig(),
                        shape.lookup_activation,
                        instruction,
                    );
                }
                for (program_contract.RATE..padded_words) |word_index| {
                    const is_payload = is_mix and word_index < frame.word_count;
                    if (row == 4) {
                        if (logical >= size) return error.InvalidFixedTranscriptShape;
                        const constant_value: u32 = if (is_payload)
                            0
                        else if (word_index < frame.word_count)
                            if (word_index == program_contract.RATE) draw_count else program_contract.channel.DRAW_TAG
                        else if (word_index == frame.word_count)
                            1
                        else
                            0;
                        const fixed = word_witness.Row{
                            .row_mask = 1,
                            .segment_mask = 1,
                            .binary_mask = 0,
                            .verifier_id = source_contract.VERIFIER_ID,
                            .sequence = @intCast(frame.instruction_index),
                            .tag = tag,
                            .args = instruction.args,
                            .hash_id = @intCast(frame_index),
                            .word_index = @intCast(word_index),
                            .is_payload = @intFromBool(is_payload),
                            .payload_index = if (is_payload) @intCast(word_index - program_contract.RATE) else 0,
                            .constant_value = constant_value,
                        };
                        put(columns, fixed.values(), logical, log_size);
                        logical += 1;
                    } else if (is_payload) {
                        if (logical >= size) return error.InvalidFixedTranscriptShape;
                        const payload_index = word_index - program_contract.RATE;
                        const metadata = source_rows.payloadMetadata(instruction, @intCast(payload_index));
                        const tree0 = instruction.kind == .trace_commitment and instruction.args[0] == 0;
                        const constant_value: u32 = if (tree0)
                            key.native_preprocessed_root[payload_index]
                        else if (metadata.constant_mask == 1)
                            if (has_fixed_payload) fixed_payload[payload_index].toU32() else return error.InvalidFixedTranscriptShape
                        else
                            0;
                        const fixed = [payload_witness.PREPROCESSED_COLUMN_COUNT]M31{
                            M31.one(),
                            M31.one(),
                            M31.zero(),
                            M31.fromCanonical(source_contract.VERIFIER_ID),
                            M31.fromCanonical(@intCast(frame.instruction_index)),
                            M31.fromCanonical(tag),
                            M31.fromCanonical(instruction.args[0]),
                            M31.fromCanonical(instruction.args[1]),
                            M31.fromCanonical(instruction.args[2]),
                            M31.fromCanonical(instruction.args[3]),
                            M31.fromCanonical(@intCast(payload_index)),
                            M31.fromCanonical(@intFromEnum(metadata.source_kind)),
                            M31.fromCanonical(metadata.item_index),
                            M31.fromCanonical(metadata.limb_index),
                            M31.fromCanonical(metadata.constant_mask),
                            M31.fromCanonical(metadata.input_use_count),
                            M31.fromCanonical(constant_value),
                        };
                        put(columns, fixed, logical, log_size);
                        logical += 1;
                    }
                }
                if (is_mix) {
                    draw_count = 0;
                } else if (instruction.effect() == .pow and frame.local_frame == 1) {
                    draw_count = 0;
                } else {
                    draw_count += 1;
                }
            }
        },
        8, 9 => {
            var logical: usize = 0;
            for (shape.instructions) |instruction| {
                const encoded = shape.vm_plan.steps[instruction.verifier_sequence].encode();
                if (row == 8 and instruction.kind == .relation_draw) {
                    if (logical >= size) return error.InvalidFixedTranscriptShape;
                    const fixed = relation.PreprocessedRow{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .public_logup_mask = @intFromBool(instruction.args[0] < 4),
                        .verifier_id = source_contract.VERIFIER_ID,
                        .sequence = instruction.verifier_sequence,
                        .tag = encoded.tag,
                        .args = encoded.args,
                        .challenge = instruction.args[0],
                    };
                    put(columns, fixed.values(), logical, log_size);
                    logical += 1;
                } else if (row == 9 and switch (instruction.kind) {
                    .composition_draw, .oods_draw, .deep_draw, .fri_alpha_draw, .query_draw => true,
                    else => false,
                }) {
                    if (logical >= size) return error.InvalidFixedTranscriptShape;
                    const descriptor = source_writer.randomnessDescriptor(instruction);
                    var multiplicities: [program_contract.RATE]u32 = .{0} ** program_contract.RATE;
                    for (0..descriptor.word_count) |word|
                        multiplicities[word] = descriptor.semantic_use_count;
                    const fixed = randomness.PreprocessedRow{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = source_contract.VERIFIER_ID,
                        .sequence = instruction.verifier_sequence,
                        .tag = encoded.tag,
                        .args = encoded.args,
                        .kind = descriptor.kind,
                        .item_base = descriptor.item_base,
                        .query_items = @intFromBool(descriptor.query_items),
                        .multiplicities = multiplicities,
                        .draw_index = @intCast(logical),
                    };
                    put(columns, fixed.values(), logical, log_size);
                    logical += 1;
                }
            }
        },
        else => unreachable,
    }
}

fn put(columns: [][]M31, values: anytype, logical: usize, log_size: u32) void {
    const committed = framework.committedRow(logical, log_size);
    for (columns, values) |column, value| column[committed] = value;
}
