//! Exact host implementation of Stwo-Cairo's generic partial EC-mul deduction.

const std = @import("std");
const felt252 = @import("felt252.zig");

pub const scalar_word_count: usize = 10;
pub const felt_word_count: usize = felt252.word_count;
pub const io_word_count: usize = 2 + scalar_word_count + 4 * felt_word_count + 1;

const Point = struct {
    x: u256,
    y: u256,
};

pub const Error = felt252.Error || error{
    InvalidWordCount,
    InvalidWidth27Word,
};

pub fn apply(args: []const u32, outputs: []u32) Error!void {
    if (args.len != io_word_count or outputs.len != io_word_count)
        return error.InvalidWordCount;

    const scalar_start = 2;
    const point_start = scalar_start + scalar_word_count;
    const accumulator_start = point_start + 2 * felt_word_count;
    const counter_index = accumulator_start + 2 * felt_word_count;

    const scalar = args[scalar_start..point_start];
    try validateScalar(scalar);
    const point = try decodePoint(args[point_start..accumulator_start]);
    const accumulator = try decodePoint(args[accumulator_start..counter_index]);

    outputs[0] = args[0];
    outputs[1] = incrementM31(args[1]);
    shiftScalar(scalar, args[counter_index], outputs[scalar_start..point_start]);

    const doubled = try doublePoint(point);
    encodePoint(doubled, outputs[point_start..accumulator_start]);
    const next_accumulator = if (scalar[0] & 1 == 1)
        try addPoints(accumulator, point)
    else
        accumulator;
    encodePoint(next_accumulator, outputs[accumulator_start..counter_index]);
    outputs[counter_index] = if (args[counter_index] == 0)
        26
    else
        args[counter_index] - 1;
}

fn validateScalar(words: []const u32) Error!void {
    for (words[0 .. scalar_word_count - 1]) |word| {
        if (word >= 1 << 27) return error.InvalidWidth27Word;
    }
    if (words[scalar_word_count - 1] >= 1 << 9)
        return error.InvalidWidth27Word;
}

fn shiftScalar(input: []const u32, counter: u32, output: []u32) void {
    std.debug.assert(input.len == scalar_word_count);
    std.debug.assert(output.len == scalar_word_count);
    if (counter == 0) {
        std.mem.copyForwards(u32, output[0 .. scalar_word_count - 1], input[1..]);
        output[scalar_word_count - 1] = 0;
        return;
    }
    output[0] = input[0] >> 1;
    @memcpy(output[1..], input[1..]);
}

fn decodePoint(words: []const u32) felt252.Error!Point {
    std.debug.assert(words.len == 2 * felt_word_count);
    return .{
        .x = try felt252.decode(words[0..felt_word_count]),
        .y = try felt252.decode(words[felt_word_count..]),
    };
}

fn encodePoint(point: Point, words: []u32) void {
    std.debug.assert(words.len == 2 * felt_word_count);
    felt252.encode(point.x, words[0..felt_word_count]);
    felt252.encode(point.y, words[felt_word_count..]);
}

fn addPoints(lhs: Point, rhs: Point) felt252.Error!Point {
    const slope = try felt252.div(
        felt252.sub(rhs.y, lhs.y),
        felt252.sub(rhs.x, lhs.x),
    );
    const x = felt252.sub(
        felt252.sub(felt252.mul(slope, slope), lhs.x),
        rhs.x,
    );
    return .{
        .x = x,
        .y = felt252.sub(felt252.mul(slope, felt252.sub(lhs.x, x)), lhs.y),
    };
}

fn doublePoint(point: Point) felt252.Error!Point {
    const three_x_squared = felt252.mul(3, felt252.mul(point.x, point.x));
    const slope = try felt252.div(
        felt252.add(three_x_squared, 1),
        felt252.add(point.y, point.y),
    );
    const x = felt252.sub(felt252.mul(slope, slope), felt252.add(point.x, point.x));
    return .{
        .x = x,
        .y = felt252.sub(felt252.mul(slope, felt252.sub(point.x, x)), point.y),
    };
}

fn incrementM31(value: u32) u32 {
    const modulus = (@as(u32, 1) << 31) - 1;
    return if (value == modulus - 1) 0 else value + 1;
}

test "generic partial EC-mul shifts the active width-27 word" {
    var args = [_]u32{0} ** io_word_count;
    var outputs: [io_word_count]u32 = undefined;
    args[1] = 7;
    args[2] = 0b10;
    args[3] = 91;
    args[12] = 1;
    args[40] = 1;
    args[68] = 2;
    args[96] = 3;
    args[124] = 8;

    try apply(&args, &outputs);

    try std.testing.expectEqual(@as(u32, 8), outputs[1]);
    try std.testing.expectEqual(@as(u32, 1), outputs[2]);
    try std.testing.expectEqual(@as(u32, 91), outputs[3]);
    try std.testing.expectEqual(@as(u32, 7), outputs[124]);
    try std.testing.expectEqualSlices(u32, args[68..124], outputs[68..124]);
}

test "generic partial EC-mul rotates width-27 words when counter reaches zero" {
    var input = [_]u32{0} ** scalar_word_count;
    var output: [scalar_word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = @intCast(index);
    shiftScalar(&input, 0, &output);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 },
        &output,
    );
}
