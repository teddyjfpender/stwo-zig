//! Involutive conversion between native and Rust SIMD circle coefficient order.
const std = @import("std");

pub fn transposeSimdBlocks(
    words: []u32,
    log_rows: u32,
) void {
    const log_lanes: u32 = 4;
    std.debug.assert(
        log_rows > 16 and
            words.len == @as(usize, 1) << @intCast(log_rows),
    );
    const log_vectors = log_rows - log_lanes;
    const half = log_vectors / 2;
    const outer = @as(usize, 1) << @intCast(half);
    const middle = @as(usize, 1) << @intCast(log_vectors & 1);
    for (0..outer) |a| {
        for (0..middle) |b| {
            for (0..outer) |c| {
                const i = (a << @intCast(log_vectors - half)) |
                    (b << @intCast(half)) | c;
                const j = (c << @intCast(log_vectors - half)) |
                    (b << @intCast(half)) | a;
                if (i >= j) continue;
                const lhs = words[i * 16 ..][0..16];
                const rhs = words[j * 16 ..][0..16];
                for (lhs, rhs) |*left, *right|
                    std.mem.swap(u32, left, right);
            }
        }
    }
}
