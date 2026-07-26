//! Exact host implementation of Stwo-Cairo's window-18 Pedersen deductions.

const felt252 = @import("felt252.zig");
const stark_curve = @import("stark_curve.zig");

const window_bits: u32 = 18;
const window_count: u32 = 14;
const rows_per_window: u32 = 1 << window_bits;
const low_window_count: u32 = window_count - 1;
const high_rows_per_block: u32 = 1 << (window_bits - 4);
const section_rows: u32 = window_count * rows_per_window;
const real_table_rows: u32 = 2 * section_rows;
const padded_table_rows: u32 = 1 << 23;
const point_words: usize = 2 * felt252.word_count;
const partial_words: usize = 2 + window_count + point_words;

const p0 = stark_curve.AffinePoint{
    .x = 0x0234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b,
    .y = 0x03b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615,
};
const p1 = stark_curve.AffinePoint{
    .x = 0x04fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378,
    .y = 0x03fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54d,
};
const p2 = stark_curve.AffinePoint{
    .x = 0x04ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997,
    .y = 0x0040301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219c,
};
const p3 = stark_curve.AffinePoint{
    .x = 0x054302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202,
    .y = 0x01b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426,
};
const negative_shift = stark_curve.AffinePoint{
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
    if (args.len != 1 or outputs.len != point_words)
        return error.InvalidWordCount;
    const point = try tablePoint(args[0]);
    felt252.encode(point.x, outputs[0..felt252.word_count]);
    felt252.encode(point.y, outputs[felt252.word_count..point_words]);
}

pub fn applyPartialEcMul(args: []const u32, outputs: []u32) Error!void {
    if (args.len != partial_words or outputs.len != partial_words)
        return error.InvalidWordCount;
    if (args[1] >= 2 * window_count) return error.InvalidRound;
    if (args[2] >= rows_per_window) return error.InvalidWindow;

    const table_row = args[1] * rows_per_window + args[2];
    const table_point = try tablePoint(table_row);
    const accumulator = stark_curve.AffinePoint{
        .x = try felt252.decode(args[2 + window_count ..][0..felt252.word_count]),
        .y = try felt252.decode(args[2 + window_count + felt252.word_count ..][0..felt252.word_count]),
    };
    const sum = try stark_curve.addAffine(accumulator, table_point);

    outputs[0] = args[0];
    outputs[1] = args[1] + 1;
    @memcpy(outputs[2 .. 2 + window_count - 1], args[3 .. 2 + window_count]);
    outputs[2 + window_count - 1] = 0;
    felt252.encode(sum.x, outputs[2 + window_count ..][0..felt252.word_count]);
    felt252.encode(
        sum.y,
        outputs[2 + window_count + felt252.word_count ..][0..felt252.word_count],
    );
}

fn tablePoint(raw_index: u32) Error!stark_curve.AffinePoint {
    if (raw_index >= padded_table_rows) return error.InvalidTableIndex;
    if (raw_index >= real_table_rows) return negative_shift;

    const second_value = raw_index >= section_rows;
    const local_index = if (second_value) raw_index - section_rows else raw_index;
    const low_point = if (second_value) p2 else p0;
    const high_point = if (second_value) p3 else p1;
    const low_section_rows = low_window_count * rows_per_window;
    if (local_index < low_section_rows) {
        const window = local_index / rows_per_window;
        const scalar = @as(u256, local_index % rows_per_window) <<
            @intCast(window_bits * window);
        return stark_curve.tableCombination(low_point, scalar, null, 0, negative_shift);
    }
    const high_index = local_index - low_section_rows;
    const high_scalar = high_index / high_rows_per_block;
    const low_scalar = @as(u256, high_index % high_rows_per_block) <<
        @intCast(window_bits * low_window_count);
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
