//! Host aggregate sizes and bounded device-local coefficient addressing.
const std = @import("std");

pub const streaming_threshold_words: usize = 64 * 1024 * 1024 / @sizeOf(u32);

pub fn usesStreaming(words: usize) bool {
    return words >= streaming_threshold_words;
}

/// Streamed tasks are rebased by their source-column identity for each native
/// run. A global offset is neither needed nor representable for large sources.
/// Direct tasks retain their checked offset into the small flattened buffer.
pub fn taskOffset(global_offset: usize, total_words: usize) !u32 {
    if (total_words == 0 or global_offset >= total_words) return error.InvalidSampledCoefficientShape;
    if (usesStreaming(total_words)) return 0;
    return std.math.cast(u32, global_offset) orelse error.InvalidSampledCoefficientShape;
}

pub fn addSourceWords(left: usize, right: usize) !usize {
    const result = try std.math.add(usize, left, right);
    _ = try std.math.mul(usize, result, @sizeOf(u32));
    return result;
}

test "streamed coefficient geometry accepts host totals beyond device offsets" {
    if (@bitSizeOf(usize) < 64) return error.SkipZigTest;
    const large = @as(usize, std.math.maxInt(u32)) + 4097;
    try std.testing.expectEqual(large, try addSourceWords(std.math.maxInt(u32), 4097));
    try std.testing.expectEqual(@as(u32, 0), try taskOffset(@as(usize, std.math.maxInt(u32)) + 1, large));
    try std.testing.expectEqual(@as(u32, 123), try taskOffset(123, streaming_threshold_words - 1));
    try std.testing.expectEqual(@as(u32, 0), try taskOffset(123, streaming_threshold_words));
    try std.testing.expectError(error.InvalidSampledCoefficientShape, taskOffset(large, large));
    try std.testing.expectError(error.Overflow, addSourceWords(std.math.maxInt(usize) / 4, 1));
}
