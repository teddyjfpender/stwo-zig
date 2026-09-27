//! Shared hash-provider admission cap; independent coefficient and PCS domain
//! checks still apply. This is a supported geometry bound, not a memory promise.
const std = @import("std");
pub const MAX_LOG_SIZE: u32 = 25;
pub fn logsForCounts(counts: anytype) ![@typeInfo(@TypeOf(counts)).array.len]u32 {
    var logs: [@typeInfo(@TypeOf(counts)).array.len]u32 = undefined;
    for (counts, &logs) |count, *log| {
        log.* = @max(1, std.math.log2_int_ceil(usize, @max(1, count)));
        if (log.* > MAX_LOG_SIZE) return error.CommitmentTraceTooLarge;
    }
    return logs;
}
test "hash geometry admits log25 and rejects overflow without allocating columns" {
    try std.testing.expectEqualDeep([_]u32{ 1, 1, 24, 25, 25 }, try logsForCounts([_]usize{ 0, 1, 1 << 24, (1 << 24) + 1, 1 << 25 }));
    try std.testing.expectError(error.CommitmentTraceTooLarge, logsForCounts([_]usize{(1 << 25) + 1}));
    try std.testing.expectError(error.CommitmentTraceTooLarge, logsForCounts([_]usize{std.math.maxInt(usize)}));
}
