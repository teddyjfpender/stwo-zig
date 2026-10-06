//! Shape-only physical preprocessing schedules for V2 transcript rows 2, 3,
//! 8 and 9. Dynamic sponge state, draw words, nonces and PoW checks remain main.
const std = @import("std");
const transcript = @import("transcript_program_v2.zig");
const transcript_program = @import("transcript_program_v2_program.zig");
const instruction_template = @import("transcript_instruction_template_v6.zig");
const schedule = @import("air/verifier_schedule.zig");
const statement = @import("../air/statement.zig");
const channel = @import("poseidon2_channel.zig");
const binding = @import("air/transcript_binding_witness.zig");
const state = @import("air/transcript_state_witness.zig");
const relation = @import("air/relation_challenge_witness.zig");
const randomness = @import("air/verifier_randomness_witness.zig");
const source_contract = @import("segment_transcript_outer_source_v2_contract.zig");
const source_writer = @import("segment_transcript_outer_source_v2_write_rows_assume_valid.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;

const Frame = struct {
    instruction_index: usize,
    hash_id: u32,
    first_call: u32,
    call_count: u32,
    is_mix: bool,
    pow_draw: bool,
    local_frame: u8,
};

pub const Fixed = struct {
    allocator: std.mem.Allocator,
    bindings: []binding.PreprocessedRow,
    states: []state.PreprocessedRow,
    relations: []relation.PreprocessedRow,
    randomness: []randomness.PreprocessedRow,
    call_count: u32,

    pub fn initFromAdmittedShape(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        wire_word_count: u32,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        lookup_enabled: bool,
    ) !Fixed {
        const instructions = try instruction_template.compileInstructions(
            allocator,
            plan,
            wire_word_count,
            component_descs,
            infra_descs,
            lookup_enabled,
        );
        defer allocator.free(instructions);
        return initFromInstructions(allocator, plan, instructions);
    }

    /// A test seam for the existing V2 source profile. Production uses the
    /// admitted-shape compiler above, never a proof-supplied ProgramV2 list.
    pub fn initFromInstructions(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        instructions: []const transcript.Instruction,
    ) !Fixed {
        try plan.validate();
        var frames: std.ArrayList(Frame) = .empty;
        defer frames.deinit(allocator);
        var call_count: u32 = 0;
        for (instructions, 0..) |instruction, instruction_index| {
            if (instruction.verifier_sequence >= plan.steps.len)
                return error.InvalidFixedTranscriptSchedule;
            switch (instruction.effect()) {
                .mix => try appendFrame(allocator, &frames, instruction_index, &call_count, true, false, 0, try instruction.payloadWordCount()),
                .draw => try appendFrame(allocator, &frames, instruction_index, &call_count, false, false, 0, 2),
                .pow => {
                    try appendFrame(allocator, &frames, instruction_index, &call_count, true, false, 0, try instruction.payloadWordCount());
                    try appendFrame(allocator, &frames, instruction_index, &call_count, false, true, 1, 2);
                },
            }
        }
        if (frames.items.len == 0) return error.InvalidFixedTranscriptSchedule;
        const bindings = try allocator.alloc(binding.PreprocessedRow, call_count);
        errdefer allocator.free(bindings);
        const states = try allocator.alloc(state.PreprocessedRow, frames.items.len);
        errdefer allocator.free(states);
        var relation_rows: std.ArrayList(relation.PreprocessedRow) = .empty;
        errdefer relation_rows.deinit(allocator);
        var randomness_rows: std.ArrayList(randomness.PreprocessedRow) = .empty;
        errdefer randomness_rows.deinit(allocator);
        var mix_ordinal: u32 = 0;
        for (frames.items, states) |item, *target| {
            const instruction = instructions[item.instruction_index];
            const encoded = plan.steps[instruction.verifier_sequence].encode();
            const state_key = mix_ordinal + @intFromBool(item.is_mix);
            target.* = .{
                .row_mask = 1,
                .segment_mask = 1,
                .binary_mask = 0,
                .verifier_id = 0,
                .sequence = instruction.verifier_sequence,
                .tag = encoded.tag,
                .args = encoded.args,
                .hash_id = item.hash_id,
                .input_state_key = if (item.is_mix) mix_ordinal else state_key,
                .output_state_key = state_key,
                .initial_mask = @intFromBool(item.is_mix and mix_ordinal == 0),
                .state_consume_mask = @intFromBool(!item.is_mix or mix_ordinal > 0),
                .state_produce_multiplicity = if (item.is_mix) consumers(frames.items, item.hash_id) else 0,
                .draw_output_mask = @intFromBool(!item.is_mix and !item.pow_draw),
            };
            mix_ordinal += @intFromBool(item.is_mix);
            const operation_first = item.instruction_index == 0 or
                instructions[item.instruction_index - 1].verifier_sequence != instruction.verifier_sequence;
            for (0..item.call_count) |step| {
                const is_last = step + 1 == item.call_count;
                bindings[item.first_call + step] = .{
                    .row_mask = 1,
                    .segment_mask = 1,
                    .binary_mask = 0,
                    .verifier_id = 0,
                    .sequence = instruction.verifier_sequence,
                    .tag = encoded.tag,
                    .args = encoded.args,
                    .call_id = @intCast(item.first_call + step),
                    .hash_id = item.hash_id,
                    .hash_step = @intCast(step),
                    .is_first = @intFromBool(step == 0),
                    .is_last = @intFromBool(is_last),
                    .is_draw = @intFromBool(!item.is_mix),
                    .is_operation_first = @intFromBool(operation_first and item.local_frame == 0 and step == 0),
                    .pow_final_mask = @intFromBool(item.pow_draw and is_last),
                };
            }
        }
        for (instructions) |instruction| {
            const encoded = plan.steps[instruction.verifier_sequence].encode();
            if (instruction.kind == .relation_draw) {
                try relation_rows.append(allocator, .{
                    .row_mask = 1,
                    .segment_mask = 1,
                    .binary_mask = 0,
                    .public_logup_mask = @intFromBool(instruction.args[0] < 4),
                    .verifier_id = 0,
                    .sequence = instruction.verifier_sequence,
                    .tag = encoded.tag,
                    .args = encoded.args,
                    .challenge = instruction.args[0],
                });
            } else switch (instruction.kind) {
                .composition_draw, .oods_draw, .deep_draw, .fri_alpha_draw, .query_draw => {
                    const descriptor = source_writer.randomnessDescriptor(instruction);
                    var multiplicities: [channel.RATE]u32 = .{0} ** channel.RATE;
                    if (descriptor.word_count > multiplicities.len)
                        return error.InvalidFixedTranscriptSchedule;
                    for (0..descriptor.word_count) |word| multiplicities[word] = descriptor.semantic_use_count;
                    try randomness_rows.append(allocator, .{
                        .row_mask = 1,
                        .segment_mask = 1,
                        .binary_mask = 0,
                        .verifier_id = 0,
                        .sequence = instruction.verifier_sequence,
                        .tag = encoded.tag,
                        .args = encoded.args,
                        .kind = descriptor.kind,
                        .item_base = descriptor.item_base,
                        .query_items = @intFromBool(descriptor.query_items),
                        .multiplicities = multiplicities,
                        .draw_index = @intCast(randomness_rows.items.len),
                    });
                },
                else => {},
            }
        }
        const relations = try relation_rows.toOwnedSlice(allocator);
        errdefer allocator.free(relations);
        const random_rows = try randomness_rows.toOwnedSlice(allocator);
        return .{
            .allocator = allocator,
            .bindings = bindings,
            .states = states,
            .relations = relations,
            .randomness = random_rows,
            .call_count = call_count,
        };
    }

    pub fn deinit(self: *Fixed) void {
        self.allocator.free(self.randomness);
        self.allocator.free(self.relations);
        self.allocator.free(self.states);
        self.allocator.free(self.bindings);
        self.* = undefined;
    }
};

fn appendFrame(
    allocator: std.mem.Allocator,
    frames: *std.ArrayList(Frame),
    instruction_index: usize,
    call_count: *u32,
    is_mix: bool,
    pow_draw: bool,
    local_frame: u8,
    payload_words: usize,
) !void {
    const words = try std.math.add(usize, channel.RATE, payload_words);
    const calls = try transcript_program.frameCallCount(words);
    if (calls > std.math.maxInt(u32) or frames.items.len >= std.math.maxInt(u32))
        return error.InvalidFixedTranscriptSchedule;
    const next = try std.math.add(u32, call_count.*, @intCast(calls));
    try frames.append(allocator, .{
        .instruction_index = instruction_index,
        .hash_id = @intCast(frames.items.len),
        .first_call = call_count.*,
        .call_count = @intCast(calls),
        .is_mix = is_mix,
        .pow_draw = pow_draw,
        .local_frame = local_frame,
    });
    call_count.* = next;
}

fn consumers(frames: []const Frame, mix_hash_id: u32) u32 {
    var result: u32 = 0;
    for (frames[mix_hash_id + 1 ..]) |item| {
        result += 1;
        if (item.is_mix) break;
    }
    return result;
}

test "V6 transcript fixed schedule matches executed V2 rows 2 3 8 9" {
    const allocator = std.testing.allocator;
    const support = @import("segment_transcript_outer_source_v2_test_support.zig");
    var fixture = try support.Fixture.init(allocator);
    defer fixture.deinit();
    var fixed = try Fixed.initFromInstructions(allocator, &fixture.plan, fixture.program.instructions);
    defer fixed.deinit();
    const counts = try source_contract.deriveCounts(&fixture.program, &fixture.execution, &fixture.plan);
    var destination = try support.OwnedDestinations.init(allocator, counts);
    defer destination.deinit();
    source_writer.writeRowsAssumeValid(destination.view(), &fixture.program, &fixture.execution, &fixture.plan);
    try std.testing.expectEqual(destination.transcript_binding.len, fixed.bindings.len);
    try std.testing.expectEqual(destination.transcript_state.len, fixed.states.len);
    try std.testing.expectEqual(destination.relation_challenge.len, fixed.relations.len);
    try std.testing.expectEqual(destination.verifier_randomness.len, fixed.randomness.len);
    for (destination.transcript_binding, fixed.bindings) |actual, expected|
        try std.testing.expectEqualDeep(actual.preprocessing, expected);
    for (destination.transcript_state, fixed.states) |actual, expected|
        try std.testing.expectEqualDeep(actual.preprocessing, expected);
    for (destination.relation_challenge, fixed.relations) |actual, expected|
        try std.testing.expectEqualDeep(actual.preprocessing, expected);
    for (destination.verifier_randomness, fixed.randomness) |actual, expected|
        try std.testing.expectEqualDeep(actual.preprocessing, expected);
    fixed.bindings[0].call_id += 1;
    try std.testing.expect(!std.meta.eql(destination.transcript_binding[0].preprocessing, fixed.bindings[0]));
}
