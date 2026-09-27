//! Lifetime process RSS peak for block-v4 CLI reports. The host-budget peak
//! remains a separate allocator metric; it does not include all process RSS.
const std = @import("std");
const builtin = @import("builtin");

pub fn peakBytes() !?u64 {
    return switch (builtin.os.tag) {
        .linux => linux: {
            const usage = std.posix.getrusage(std.posix.rusage.SELF);
            if (usage.maxrss < 0) return error.InvalidPeakRss;
            break :linux try std.math.mul(u64, @intCast(usage.maxrss), 1024);
        },
        .macos, .ios => darwin: {
            const usage = std.posix.getrusage(std.posix.rusage.SELF);
            if (usage.maxrss < 0) return error.InvalidPeakRss;
            break :darwin @as(u64, @intCast(usage.maxrss));
        },
        else => null,
    };
}

test "block-v4 CLI RSS sample uses normalized bytes" {
    const value = try peakBytes();
    if (builtin.os.tag == .linux or builtin.os.tag == .macos or builtin.os.tag == .ios)
        try std.testing.expect(value.? > 0);
}
