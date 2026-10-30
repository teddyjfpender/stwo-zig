//! Explicit transport capacity override; semantic Cairo bounds stay unchanged.
const std = @import("std");

pub fn maximumFileBytes(allocator: std.mem.Allocator) !u64 {
    const text = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_MAX_INPUT_BYTES") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return 4 * 1024 * 1024 * 1024,
        else => return err,
    };
    defer allocator.free(text);
    return parse(text);
}

fn parse(text: []const u8) !u64 {
    const value = std.fmt.parseUnsigned(u64, text, 10) catch return error.InvalidInputCapacity;
    if (value < 4 * 1024 * 1024 * 1024 or value > 64 * 1024 * 1024 * 1024)
        return error.InvalidInputCapacity;
    return value;
}

test "capacity override is bounded and rejects malformed values" {
    for ([_][]const u8{ "", "-1", "0", "4294967295", "68719476737", "999999999999999999999999" }) |text|
        try std.testing.expectError(error.InvalidInputCapacity, parse(text));
    try std.testing.expectEqual(@as(u64, 4 * 1024 * 1024 * 1024), try parse("4294967296"));
    try std.testing.expectEqual(@as(u64, 64 * 1024 * 1024 * 1024), try parse("68719476736"));
}
