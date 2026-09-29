//! Differential checks for bounded, strided production deduction batches.
const std = @import("std");
const program = @import("../program.zig");
const felt = @import("felt252.zig");
const curve = @import("stark_curve.zig");
const generic = @import("partial_ec_mul_generic.zig");
const pedersen = @import("pedersen.zig");
const deductions = @import("mod.zig");
const rows = 259; // Two complete chunks and a ragged tail.
const sentinel: u32 = 0xa5a5a5a5;

const Buffers = struct {
    args: []u32,
    outputs: []u32,
    expected: []u32,
    batch: program.DeduceBatch,
    fn init(args: usize, outputs: usize) !Buffers {
        const a = try std.testing.allocator.alloc(u32, rows * (args + 3));
        errdefer std.testing.allocator.free(a);
        const o = try std.testing.allocator.alloc(u32, rows * (outputs + 7));
        errdefer std.testing.allocator.free(o);
        const e = try std.testing.allocator.alloc(u32, o.len);
        @memset(a, 0);
        @memset(o, sentinel);
        @memset(e, sentinel);
        return .{ .args = a, .outputs = o, .expected = e, .batch = .{
            .rows = rows,
            .args = a,
            .arg_stride = args + 3,
            .arg_count = args,
            .outputs = o,
            .output_stride = outputs + 7,
            .output_count = outputs,
        } };
    }
    fn deinit(self: Buffers) void {
        std.testing.allocator.free(self.args);
        std.testing.allocator.free(self.outputs);
        std.testing.allocator.free(self.expected);
    }
    fn expectedRow(self: Buffers, row: usize) []u32 {
        return self.expected[row * self.batch.output_stride ..][0..self.batch.output_count];
    }
};
fn encodePoint(p: curve.AffinePoint, words: []u32) void {
    felt.encode(p.x, words[0..28]);
    felt.encode(p.y, words[28..56]);
}

test "batched felt division preserves strided rows and rejects zero and malformed inputs" {
    var b = try Buffers.init(56, 28);
    defer b.deinit();
    var rng = std.Random.DefaultPrng.init(0xa117b);
    for (0..rows) |row| {
        const a = b.args[row * b.batch.arg_stride ..][0..56];
        const numerator = rng.random().int(u256) % felt.prime;
        const denominator = 1 + rng.random().int(u256) % (felt.prime - 1);
        felt.encode(numerator, a[0..28]);
        felt.encode(denominator, a[28..56]);
        try felt.apply(.div, a, b.expectedRow(row));
    }
    try deductions.context().callBatch(@intFromEnum(deductions.Selector.felt_div), b.batch, .zero());
    try std.testing.expectEqualSlices(u32, b.expected, b.outputs);
    for (0..rows) |row| {
        const a = b.batch.rowArgs(row);
        const quotient = try felt.decode(b.batch.rowOutputs(row));
        // Independent wide reduction verifies the inverse and final result.
        try std.testing.expectEqual(try felt.decode(a[0..28]), @as(u256, @intCast((@as(u512, quotient) * try felt.decode(a[28..56])) % felt.prime)));
    }
    @memset(b.args[28..56], 0);
    try std.testing.expectError(error.DivisionByZero, felt.applyDivBatch(b.batch));
    b.args[0] = 512;
    try std.testing.expectError(error.InvalidFeltWord, felt.applyDivBatch(b.batch));
    var malformed = b.batch;
    malformed.arg_stride = 55;
    try std.testing.expectError(error.InvalidDeduceBatch, felt.applyDivBatch(malformed));
    malformed = b.batch;
    malformed.args = b.args[0..56];
    try std.testing.expectError(error.InvalidDeduceBatch, felt.applyDivBatch(malformed));
}

test "batched affine addition matches scalar projective doubling and infinity errors" {
    const n = 33;
    var a: [n]curve.AffinePoint = undefined;
    var rhs: [n]curve.AffinePoint = undefined;
    var actual: [n]curve.AffinePoint = undefined;
    var prefixes: [n]u256 = undefined;
    var nums: [n]u256 = undefined;
    var dens: [n]u256 = undefined;
    for (0..n) |i| {
        a[i] = .{ .x = i + 1, .y = i + 3 };
        rhs[i] = if (i % 2 == 0) a[i] else .{ .x = i + 10, .y = i + 12 };
    }
    try curve.batchAddAffine(&a, &rhs, &actual, &prefixes, &nums, &dens);
    for (0..n) |i| try std.testing.expectEqual(try curve.addAffine(a[i], rhs[i]), actual[i]);
    rhs[3] = .{ .x = a[3].x, .y = felt.sub(0, a[3].y) };
    try std.testing.expectError(error.PointAtInfinity, curve.batchAddAffine(&a, &rhs, &actual, &prefixes, &nums, &dens));
    a[3].y = 0;
    rhs[3] = a[3];
    try std.testing.expectError(error.PointAtInfinity, curve.batchAddAffine(&a, &rhs, &actual, &prefixes, &nums, &dens));
}

test "batched generic EC deduction matches odd even rotation and doubling across chunks" {
    var b = try Buffers.init(generic.io_word_count, generic.io_word_count);
    defer b.deinit();
    for (0..rows) |row| {
        const a = b.args[row * b.batch.arg_stride ..][0..generic.io_word_count];
        a[0] = @intCast(row);
        a[1] = if (row % 7 == 0) 0x7ffffffe else @intCast(row);
        a[2] = @intCast(row % 4);
        a[3] = 91;
        const p: curve.AffinePoint = .{ .x = row + 1, .y = row + 3 };
        encodePoint(p, a[12..68]);
        encodePoint(if (row % 3 == 0) p else .{ .x = row + 10, .y = row + 12 }, a[68..124]);
        a[124] = @intCast(row % 27);
        try generic.apply(a, b.expectedRow(row));
    }
    try generic.applyBatch(b.batch);
    try std.testing.expectEqualSlices(u32, b.expected, b.outputs);
    b.args[2] = 1 << 27;
    try std.testing.expectError(error.InvalidWidth27Word, generic.applyBatch(b.batch));
    b.args[2] = 0;
    @memset(b.args[40..68], 0);
    try std.testing.expectError(error.PointAtInfinity, generic.applyBatch(b.batch));
}

fn checkPedersen(comptime bits: u5) !void {
    const words = 2 + 252 / @as(usize, bits) + 56;
    var b = try Buffers.init(words, words);
    defer b.deinit();
    const points = [_]curve.AffinePoint{
        .{ .x = 1, .y = 3 }, .{ .x = 2, .y = 4 }, .{ .x = 3, .y = 5 }, .{ .x = 4, .y = 6 }, .{ .x = 5, .y = 7 },
    };
    for (0..rows) |row| {
        const a = b.args[row * b.batch.arg_stride ..][0..words];
        a[0] = @intCast(row);
        a[2] = @intCast(row % points.len);
        for (a[3 .. words - 56], 0..) |*word, index| word.* = @intCast(index + 13);
        const p = points[row % points.len];
        encodePoint(if (row % 2 == 0) p else .{ .x = row + 17, .y = row + 19 }, a[words - 56 ..]);
        try pedersen.applyPartialEcMulCached(a, b.expectedRow(row), bits, &points);
    }
    const cfg: deductions.Context = .{ .pedersen_table = .{ .window_bits = bits, .points = &points } };
    const selector = if (bits == 18) deductions.Selector.partial_ec_mul_w18 else deductions.Selector.partial_ec_mul_w9;
    try deductions.contextWithConfig(&cfg).callBatch(@intFromEnum(selector), b.batch, .zero());
    try std.testing.expectEqualSlices(u32, b.expected, b.outputs);
    b.args[1] = 2 * (252 / @as(u32, bits));
    try std.testing.expectError(error.InvalidRound, pedersen.applyPartialEcMulBatchCached(b.batch, bits, &points));
    b.args[1] = 0;
    b.args[2] = 1 << bits;
    try std.testing.expectError(error.InvalidWindow, pedersen.applyPartialEcMulBatchCached(b.batch, bits, &points));
    b.args[2] = 5;
    try std.testing.expectError(error.InvalidTableIndex, pedersen.applyPartialEcMulBatchCached(b.batch, bits, &points));
    const wrong: deductions.Context = .{ .pedersen_table = .{ .window_bits = if (bits == 18) 9 else 18, .points = &points } };
    try std.testing.expectError(error.InvalidPedersenTableWindow, deductions.contextWithConfig(&wrong).callBatch(@intFromEnum(selector), b.batch, .zero()));
}

test "batched cached Pedersen deductions preserve both window formats" {
    try checkPedersen(9);
    try checkPedersen(18);
}
