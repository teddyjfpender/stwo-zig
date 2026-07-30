//! Scalar scheduler row for the exact ten-round Blake AIR.

const std = @import("std");
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");

pub const RoundInput = struct {
    state: [constants.STATE_SIZE]u32,
    message: [constants.MESSAGE_SIZE]u32,
};

pub const Output = struct {
    row: [geometry.SCHEDULER_MAIN_COLUMNS]u32,
    round_inputs: [constants.N_ROUNDS]RoundInput,
    final_state: [constants.STATE_SIZE]u32,
};

pub fn inputForPackedLane(pack_index: usize, lane: usize) RoundInput {
    std.debug.assert(lane < 16);
    const base: u32 = @intCast(pack_index + 2 * lane);
    return .{
        .state = [_]u32{base} ** constants.STATE_SIZE,
        .message = [_]u32{base +% 1} ** constants.MESSAGE_SIZE,
    };
}

pub fn generate(input: RoundInput) Output {
    var row: [geometry.SCHEDULER_MAIN_COLUMNS]u32 = undefined;
    var round_inputs: [constants.N_ROUNDS]RoundInput = undefined;
    var index: usize = 0;
    appendWords(&row, &index, input.message);
    appendWords(&row, &index, input.state);

    var state = input.state;
    for (0..constants.N_ROUNDS) |round_index| {
        const schedule = constants.SIGMA[round_index];
        var round_message: [constants.MESSAGE_SIZE]u32 = undefined;
        for (&round_message, schedule) |*word, source_index| {
            word.* = input.message[source_index];
        }
        round_inputs[round_index] = .{
            .state = state,
            .message = round_message,
        };
        constants.round(&state, input.message, round_index);
        appendWords(&row, &index, state);
    }
    std.debug.assert(index == geometry.SCHEDULER_MAIN_COLUMNS);
    return .{
        .row = row,
        .round_inputs = round_inputs,
        .final_state = state,
    };
}

fn appendWords(
    row: *[geometry.SCHEDULER_MAIN_COLUMNS]u32,
    index: *usize,
    words: [constants.STATE_SIZE]u32,
) void {
    for (words) |word| {
        row[index.*] = word & 0xffff;
        row[index.* + 1] = word >> 16;
        index.* += 2;
    }
}

test "exact Blake scheduler row preserves upstream column order" {
    const input = RoundInput{
        .state = [_]u32{0x1234_5678} ** constants.STATE_SIZE,
        .message = [_]u32{0x9abc_def0} ** constants.MESSAGE_SIZE,
    };
    const output = generate(input);
    try std.testing.expectEqual(@as(u32, 0xdef0), output.row[0]);
    try std.testing.expectEqual(@as(u32, 0x9abc), output.row[1]);
    try std.testing.expectEqual(@as(u32, 0x5678), output.row[32]);
    try std.testing.expectEqual(@as(u32, 0x1234), output.row[33]);

    var expected = input.state;
    for (0..constants.N_ROUNDS) |round_index| {
        constants.round(&expected, input.message, round_index);
    }
    try std.testing.expectEqualSlices(u32, &expected, &output.final_state);
}

test "exact Blake scheduler emits the pinned packed-lane input sequence" {
    const first = inputForPackedLane(0, 0);
    const next_lane = inputForPackedLane(0, 1);
    const next_pack = inputForPackedLane(1, 0);
    try std.testing.expectEqual(@as(u32, 0), first.state[0]);
    try std.testing.expectEqual(@as(u32, 1), first.message[0]);
    try std.testing.expectEqual(@as(u32, 2), next_lane.state[0]);
    try std.testing.expectEqual(@as(u32, 1), next_pack.state[0]);
}

test "exact Blake scheduler applies sigma to every round relation tuple" {
    var message: [constants.MESSAGE_SIZE]u32 = undefined;
    for (&message, 0..) |*word, index| word.* = @intCast(index);
    const output = generate(.{
        .state = [_]u32{0} ** constants.STATE_SIZE,
        .message = message,
    });
    for (output.round_inputs, constants.SIGMA) |round_input, schedule| {
        for (round_input.message, schedule) |word, source_index| {
            try std.testing.expectEqual(@as(u32, source_index), word);
        }
    }
}
