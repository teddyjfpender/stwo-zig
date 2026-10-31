//! RUSAGE_SELF interval counters, including every thread in this process.
//! Nested, adopted and overlapping stage intervals must never be summed.
const std = @import("std");
const builtin = @import("builtin");

pub const SCOPE = "whole process, all threads; nested, adopted and overlapping intervals are not additive";
pub const ProcessUsage = struct {
    scope: []const u8 = SCOPE,
    user_seconds: f64,
    system_seconds: f64,
    minor_faults: u64,
    major_faults: u64,
    voluntary_switches: u64,
    involuntary_switches: u64,
};
pub const Snapshot = struct {
    user_us: u64,
    system_us: u64,
    minor_faults: u64,
    major_faults: u64,
    voluntary_switches: u64,
    involuntary_switches: u64,
};

/// Unsupported hosts return unavailable. Callers must avoid this call entirely
/// when telemetry is disabled; no allocation or per-row sampling is performed.
pub fn read() ?Snapshot {
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .linux) {
        const r = std.posix.getrusage(std.posix.rusage.SELF);
        if (r.utime.sec < 0 or r.utime.usec < 0 or r.stime.sec < 0 or r.stime.usec < 0 or
            r.minflt < 0 or r.majflt < 0 or r.nvcsw < 0 or r.nivcsw < 0) return null;
        const user_us = std.math.mul(u64, @intCast(r.utime.sec), 1_000_000) catch return null;
        const system_us = std.math.mul(u64, @intCast(r.stime.sec), 1_000_000) catch return null;
        return .{
            .user_us = std.math.add(u64, user_us, @intCast(r.utime.usec)) catch return null,
            .system_us = std.math.add(u64, system_us, @intCast(r.stime.usec)) catch return null,
            .minor_faults = @intCast(r.minflt),
            .major_faults = @intCast(r.majflt),
            .voluntary_switches = @intCast(r.nvcsw),
            .involuntary_switches = @intCast(r.nivcsw),
        };
    }
    return null;
}

/// Reject a regressing counter instead of wrapping or reporting negative work.
pub fn delta(start: Snapshot, end: Snapshot) ?ProcessUsage {
    inline for (std.meta.fields(Snapshot)) |field| {
        if (@field(end, field.name) < @field(start, field.name)) return null;
    }
    return .{
        .user_seconds = @as(f64, @floatFromInt(end.user_us - start.user_us)) / 1_000_000,
        .system_seconds = @as(f64, @floatFromInt(end.system_us - start.system_us)) / 1_000_000,
        .minor_faults = end.minor_faults - start.minor_faults,
        .major_faults = end.major_faults - start.major_faults,
        .voluntary_switches = end.voluntary_switches - start.voluntary_switches,
        .involuntary_switches = end.involuntary_switches - start.involuntary_switches,
    };
}

test "stage process usage: deterministic deltas, zero and regressions" {
    const a: Snapshot = .{ .user_us = 10, .system_us = 20, .minor_faults = 30, .major_faults = 40, .voluntary_switches = 50, .involuntary_switches = 60 };
    const b: Snapshot = .{ .user_us = 1_500_010, .system_us = 250_020, .minor_faults = 33, .major_faults = 42, .voluntary_switches = 57, .involuntary_switches = 69 };
    const d = delta(a, b).?;
    try std.testing.expectEqual(@as(f64, 1.5), d.user_seconds);
    try std.testing.expectEqual(@as(f64, 0.25), d.system_seconds);
    try std.testing.expectEqual(@as(u64, 3), d.minor_faults);
    try std.testing.expectEqual(@as(u64, 2), d.major_faults);
    try std.testing.expectEqual(@as(u64, 7), d.voluntary_switches);
    try std.testing.expectEqual(@as(u64, 9), d.involuntary_switches);
    try std.testing.expectEqual(@as(f64, 0), delta(a, a).?.user_seconds);
    inline for (std.meta.fields(Snapshot)) |field| {
        var bad = b;
        @field(bad, field.name) = @field(a, field.name) - 1;
        try std.testing.expect(delta(a, bad) == null);
    }
}

test "stage process usage: host counters are monotonic without sleeping" {
    const a = read() orelse return error.SkipZigTest;
    const b = read() orelse return error.SkipZigTest;
    try std.testing.expect(delta(a, b) != null);
}
