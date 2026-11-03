//! Immutable sampling geometry and typed device regions. Numerical sampling
//! is dispatched by resident.Commands, with its existing custody/poisoning.
const std = @import("std");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
pub const factor_stride: usize = 28;
/// Receiver-derived map from grouped sampling slots to transcript order.
pub const Order = struct { input: Slice, map: Slice, output: Slice, verdict: Slice, source_count: u32, count: u32 };
pub const Points = struct {
    parameter: Slice,
    recipes: Slice,
    points: Slice,
    factors: Slice,
    ready: Slice,
    verdict: Slice,
    count: u32,
};
pub const Evaluation = struct {
    trees: [4]?Slice,
    sources: Slice,
    terms: Slice,
    recipes: Slice,
    factors: Slice,
    point_ready: Slice,
    scratch_a: Slice,
    scratch_b: Slice,
    values: Slice,
    valid: Slice,
    verdict: Slice,
    source_count: u32,
    term_capacity: u32,
    group_count: u32,
    first: u32,
    count: u32,
    coefficient_log: u32,
};
pub const Plan = struct {
    blocks: u32,
    scratch_words: usize,
    scratch_bytes: usize,
    dispatches: u32,
    pub fn init(coefficient_log: u32, count: u32) !Plan {
        if (coefficient_log == 0 or coefficient_log > 28 or count == 0 or count > 65535) return error.InvalidGeometry;
        const n = @as(u32, 1) << @intCast(coefficient_log);
        const blocks = (n + 1023) / 1024;
        const words = try std.math.mul(usize, try std.math.mul(usize, blocks, count), 8);
        var remaining = blocks;
        var dispatches: u32 = 3;
        while (remaining > 1) : (dispatches += 1) remaining = (remaining + 255) / 256;
        return .{ .blocks = blocks, .scratch_words = words, .scratch_bytes = try std.math.mul(usize, words, 8), .dispatches = dispatches };
    }
};
test "sampling scratch covers compact reduction levels without source sized secure arrays" {
    const p = try Plan.init(22, 512);
    try std.testing.expectEqual(@as(u32, 4096), p.blocks);
    try std.testing.expectEqual(@as(usize, 134217728), p.scratch_bytes);
    try std.testing.expectEqual(@as(u32, 5), p.dispatches);
    try std.testing.expectEqual(@as(u32, 3), (try Plan.init(1, 1)).dispatches);
    try std.testing.expectEqual(@as(u32, 4), (try Plan.init(11, 1)).dispatches);
    try std.testing.expectError(error.InvalidGeometry, Plan.init(0, 1));
    try std.testing.expectError(error.InvalidGeometry, Plan.init(29, 1));
    try std.testing.expectError(error.InvalidGeometry, Plan.init(22, 65536));
}
