//! Pure extent/alias parity for the actual Metal uniform commitment ABI.
const std = @import("std");
const geometry = @import("backends/metal/runtime/resident_budget_v1.zig");

test "resident budget: private Merkle extent matches every padded layer" {
    for ([_]u32{ 12, 13, 17, 22, 25 }) |log| {
        var expected_words: usize = 0;
        var count: usize = @as(usize, 1) << @intCast(log);
        for (0..log + 1) |_| {
            const padding = (64 - expected_words % 64) % 64;
            expected_words += padding + count * 8;
            count /= 2;
        }
        try std.testing.expectEqual(expected_words * 4, try geometry.merkleBytes(log));
        const no_copy = try geometry.commitment(log, 92, 0, 0, 0);
        try std.testing.expectEqual(expected_words * 4, no_copy.retained_bytes);
        try std.testing.expectEqual(expected_words * 4 + 92 * 12 + 64, no_copy.peak_bytes);
        const copied = try geometry.commitment(log, 92, 256, 512, 1024);
        try std.testing.expectEqual(no_copy.retained_bytes, copied.retained_bytes);
        try std.testing.expectEqual(no_copy.peak_bytes + 256 + 512 + 1024, copied.peak_bytes);
    }
    try std.testing.expectError(error.InvalidResidentBudgetGeometry, geometry.commitment(12, 0, 0, 0, 0));
    try std.testing.expectError(error.InvalidResidentBudgetGeometry, geometry.merkleBytes(31));
    try std.testing.expectError(error.Overflow, geometry.commitment(12, 92, std.math.maxInt(usize), 1, 0));
}

test "resident budget: no-copy aliases cost zero only for exact aligned extents" {
    try std.testing.expectEqual(@as(usize, 0), try geometry.copiedBytes(16384, 65536, 16384));
    try std.testing.expectEqual(@as(usize, 65536), try geometry.copiedBytes(16388, 65536, 16384));
    try std.testing.expectEqual(@as(usize, 65532), try geometry.copiedBytes(16384, 65532, 16384));
    try std.testing.expectError(error.InvalidResidentBudgetAlignment, geometry.copiedBytes(16384, 65536, 3));
}

test "resident budget: interaction envelopes retain only output after checked scan completion" {
    for ([_]usize{ 2, 17, 23 }) |planes| {
        for ([_]usize{ 2, 128, 4096, 65536 }) |rows| {
            const exact = try geometry.interaction(rows, planes, 78, 19);
            const output = planes * 4 * (rows + 1) * 4;
            const scratch = planes * 4 * ((rows + 255) / 256) * 4;
            const descriptors = 78 * 8 + 19 * 4 * 4 + 4 * 4 + 4;
            try std.testing.expectEqual(output, exact.retained_bytes);
            try std.testing.expectEqual(output + scratch + descriptors, exact.peak_bytes);
        }
    }
    const zero_profile = try geometry.interaction(4096, 23, 78, 0);
    try std.testing.expectEqual(@as(usize, 78 * 8 + 4 + 16 + 4 + 23 * 16 * 16), zero_profile.peak_bytes - zero_profile.retained_bytes);
    try std.testing.expectError(error.InvalidResidentBudgetGeometry, geometry.interaction(4096, 22, 78, 19));
    try std.testing.expectError(error.Overflow, geometry.interaction(4096, 23, 78, std.math.maxInt(usize)));
}
