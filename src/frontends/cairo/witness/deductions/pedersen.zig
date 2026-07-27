//! Exact host implementation of Stwo-Cairo's windowed Pedersen deductions.

const std = @import("std");
const felt252 = @import("felt252.zig");
const stark_curve = @import("stark_curve.zig");

const default_window_bits: u5 = 18;
const default_window_count: u32 = 252 / default_window_bits;
const default_rows_per_window: u32 = 1 << default_window_bits;
const default_section_rows: u32 = default_window_count * default_rows_per_window;
const real_table_rows: u32 = 2 * default_section_rows;
const point_words: usize = 2 * felt252.word_count;

pub const p0 = stark_curve.AffinePoint{
    .x = 0x0234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b,
    .y = 0x03b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615,
};
pub const p1 = stark_curve.AffinePoint{
    .x = 0x04fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378,
    .y = 0x03fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54d,
};
pub const p2 = stark_curve.AffinePoint{
    .x = 0x04ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997,
    .y = 0x0040301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219c,
};
pub const p3 = stark_curve.AffinePoint{
    .x = 0x054302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202,
    .y = 0x01b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426,
};
pub const negative_shift = stark_curve.AffinePoint{
    .x = 0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804,
    .y = felt252.prime -
        0x03ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a,
};

pub const Error = felt252.Error || stark_curve.Error || error{
    InvalidRound,
    InvalidTableIndex,
    InvalidWindow,
    InvalidWordCount,
};

pub fn applyPointsTable(args: []const u32, outputs: []u32) Error!void {
    return applyPointsTableForWindow(args, outputs, default_window_bits);
}

pub fn applyPointsTableWindowBits9(args: []const u32, outputs: []u32) Error!void {
    return applyPointsTableForWindow(args, outputs, 9);
}

fn applyPointsTableForWindow(
    args: []const u32,
    outputs: []u32,
    comptime requested_window_bits: u5,
) Error!void {
    if (args.len != 1 or outputs.len != point_words)
        return error.InvalidWordCount;
    const point = try tablePointForWindow(args[0], requested_window_bits);
    felt252.encode(point.x, outputs[0..felt252.word_count]);
    felt252.encode(point.y, outputs[felt252.word_count..point_words]);
}

pub fn applyPartialEcMul(args: []const u32, outputs: []u32) Error!void {
    return applyPartialEcMulForWindow(args, outputs, default_window_bits);
}

pub fn applyPartialEcMulWindowBits9(args: []const u32, outputs: []u32) Error!void {
    return applyPartialEcMulForWindow(args, outputs, 9);
}

fn applyPartialEcMulForWindow(
    args: []const u32,
    outputs: []u32,
    comptime requested_window_bits: u5,
) Error!void {
    const requested_window_count: usize = 252 / @as(usize, requested_window_bits);
    const requested_rows_per_window: u32 = 1 << requested_window_bits;
    const requested_partial_words = 2 + requested_window_count + point_words;
    if (args.len != requested_partial_words or outputs.len != requested_partial_words)
        return error.InvalidWordCount;
    if (args[1] >= @as(u32, @intCast(2 * requested_window_count)))
        return error.InvalidRound;
    if (args[2] >= requested_rows_per_window) return error.InvalidWindow;

    const table_row = args[1] * requested_rows_per_window + args[2];
    const table_point = try tablePointForWindow(table_row, requested_window_bits);
    const accumulator = stark_curve.AffinePoint{
        .x = try felt252.decode(args[2 + requested_window_count ..][0..felt252.word_count]),
        .y = try felt252.decode(
            args[2 + requested_window_count + felt252.word_count ..][0..felt252.word_count],
        ),
    };
    const sum = try stark_curve.addAffine(accumulator, table_point);

    outputs[0] = args[0];
    outputs[1] = args[1] + 1;
    @memcpy(
        outputs[2 .. 2 + requested_window_count - 1],
        args[3 .. 2 + requested_window_count],
    );
    outputs[2 + requested_window_count - 1] = 0;
    felt252.encode(
        sum.x,
        outputs[2 + requested_window_count ..][0..felt252.word_count],
    );
    felt252.encode(
        sum.y,
        outputs[2 + requested_window_count + felt252.word_count ..][0..felt252.word_count],
    );
}

pub fn tablePoint(raw_index: u32) Error!stark_curve.AffinePoint {
    return tablePointForWindow(raw_index, default_window_bits);
}

pub fn tablePointForWindow(
    raw_index: u32,
    requested_window_bits: u5,
) Error!stark_curve.AffinePoint {
    if ((requested_window_bits != 9 and requested_window_bits != 18) or
        @as(u32, 252) % requested_window_bits != 0)
        return error.InvalidWindow;
    const requested_window_count = 252 / @as(u32, requested_window_bits);
    const requested_rows_per_window = @as(u32, 1) << requested_window_bits;
    const requested_low_window_count = requested_window_count - 1;
    const requested_high_rows_per_block =
        @as(u32, 1) << @intCast(requested_window_bits - 4);
    const requested_section_rows = requested_window_count * requested_rows_per_window;
    const requested_real_rows = 2 * requested_section_rows;
    const requested_padded_rows = std.math.ceilPowerOfTwo(
        u32,
        requested_real_rows,
    ) catch unreachable;
    if (raw_index >= requested_padded_rows) return error.InvalidTableIndex;
    if (raw_index >= requested_real_rows) return negative_shift;

    const second_value = raw_index >= requested_section_rows;
    const local_index = if (second_value)
        raw_index - requested_section_rows
    else
        raw_index;
    const low_point = if (second_value) p2 else p0;
    const high_point = if (second_value) p3 else p1;
    const low_section_rows = requested_low_window_count * requested_rows_per_window;
    if (local_index < low_section_rows) {
        const window = local_index / requested_rows_per_window;
        const scalar = @as(u256, local_index % requested_rows_per_window) <<
            @intCast(@as(u32, requested_window_bits) * window);
        return stark_curve.tableCombination(low_point, scalar, null, 0, negative_shift);
    }
    const high_index = local_index - low_section_rows;
    const high_scalar = high_index / requested_high_rows_per_block;
    const low_scalar = @as(u256, high_index % requested_high_rows_per_block) <<
        @intCast(@as(u32, requested_window_bits) * requested_low_window_count);
    return stark_curve.tableCombination(
        low_point,
        low_scalar,
        high_point,
        high_scalar,
        negative_shift,
    );
}

test "Pedersen table padding repeats the first official point" {
    const first = try tablePoint(0);
    const padded = try tablePoint(real_table_rows);
    try @import("std").testing.expectEqual(first, padded);
    try @import("std").testing.expect(stark_curve.isOnCurve(first));
}

test "window-9 Pedersen deduction preserves the official state layout" {
    const requested_window_count: usize = 28;
    const partial_words = 2 + requested_window_count + point_words;
    var args = [_]u32{0} ** partial_words;
    var outputs = [_]u32{0} ** partial_words;

    args[0] = 1234;
    args[1] = 0;
    args[2] = 56;
    args[3] = 99;
    felt252.encode(p1.x, args[2 + requested_window_count ..][0..felt252.word_count]);
    felt252.encode(
        p1.y,
        args[2 + requested_window_count + felt252.word_count ..][0..felt252.word_count],
    );

    try applyPartialEcMulWindowBits9(&args, &outputs);

    const expected = try stark_curve.addAffine(p1, try tablePointForWindow(56, 9));
    try std.testing.expectEqual(@as(u32, 1234), outputs[0]);
    try std.testing.expectEqual(@as(u32, 1), outputs[1]);
    try std.testing.expectEqual(@as(u32, 99), outputs[2]);
    try std.testing.expectEqualSlices(
        u32,
        &([_]u32{0} ** (requested_window_count - 1)),
        outputs[3 .. 2 + requested_window_count],
    );
    try std.testing.expectEqual(
        expected.x,
        try felt252.decode(outputs[2 + requested_window_count ..][0..felt252.word_count]),
    );
    try std.testing.expectEqual(
        expected.y,
        try felt252.decode(
            outputs[2 + requested_window_count + felt252.word_count ..][0..felt252.word_count],
        ),
    );
}

test "window-9 Pedersen points-table wrapper matches the generalized table" {
    var output = [_]u32{0} ** point_words;
    try applyPointsTableWindowBits9(&.{512}, &output);
    const expected = try tablePointForWindow(512, 9);
    try std.testing.expectEqual(
        expected.x,
        try felt252.decode(output[0..felt252.word_count]),
    );
    try std.testing.expectEqual(
        expected.y,
        try felt252.decode(output[felt252.word_count..point_words]),
    );
}
