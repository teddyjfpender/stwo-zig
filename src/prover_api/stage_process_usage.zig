//! RUSAGE_SELF interval counters, including every thread in this process.
//! Nested, adopted and overlapping stage intervals must never be summed.
//! Optional lane counters (Darwin only) sum the CPU time of exactly the
//! threads a scheduler bound to the calling thread, so concurrent lanes can be
//! attributed separately. All values are operational telemetry only.
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
    /// Process-lifetime high-water mark at interval end, not a stage-local peak
    /// or a delta. Darwin reports bytes; Linux reports KiB, normalized below.
    process_peak_resident_bytes_at_end: u64 = 0,
    /// Current (not peak) process resident bytes at interval end. Darwin only;
    /// zero where unavailable.
    process_resident_bytes_at_end: u64 = 0,
    /// Darwin physical footprint (the `time -l` "peak memory footprint"
    /// counter's current value) at interval end; zero where unavailable.
    process_footprint_bytes_at_end: u64 = 0,
    /// Darwin process-lifetime footprint high-water mark at interval end.
    process_footprint_peak_bytes_at_end: u64 = 0,
    /// Threads owned by the scheduler lane that began and ended the interval
    /// (lane thread plus its pool helpers); zero when no lane was bound.
    lane_threads: u32 = 0,
    /// CPU time of only those lane threads. Concurrent lanes are disjoint, so
    /// these are attributable per proof; nested intervals still overlap.
    lane_user_seconds: ?f64 = null,
    lane_system_seconds: ?f64 = null,
};
/// Threads whose CPU time a lane-scoped interval reports. The scheduler owns
/// the handle storage and keeps it alive while bound.
pub const LaneThreads = struct {
    handles: []const std.Thread.Handle,
};
threadlocal var bound_lane: ?*const LaneThreads = null;
/// Binds lane threads to the calling thread; returns the previous binding,
/// which the caller restores before the storage is released.
pub fn bindLane(lane: ?*const LaneThreads) ?*const LaneThreads {
    const previous = bound_lane;
    bound_lane = lane;
    return previous;
}
extern "c" fn pthread_mach_thread_np(thread: std.c.pthread_t) std.c.mach_port_t;
const LaneTimes = struct { user_us: u64 = 0, system_us: u64 = 0, threads: u32 = 0, identity: usize = 0 };
fn readLane() LaneTimes {
    if (comptime builtin.os.tag != .macos or !builtin.link_libc) return .{};
    const lane = bound_lane orelse return .{};
    var out = LaneTimes{ .identity = @intFromPtr(lane) };
    for (lane.handles) |handle| {
        var info: std.c.thread_basic_info = undefined;
        var count: std.c.mach_msg_type_number_t = std.c.THREAD_BASIC_INFO_COUNT;
        if (std.c.thread_info(pthread_mach_thread_np(handle), std.c.THREAD_BASIC_INFO, @ptrCast(&info), &count) != 0) return .{};
        if (info.user_time.seconds < 0 or info.user_time.microseconds < 0 or info.system_time.seconds < 0 or info.system_time.microseconds < 0) return .{};
        out.user_us += @as(u64, @intCast(info.user_time.seconds)) * 1_000_000 + @as(u64, @intCast(info.user_time.microseconds));
        out.system_us += @as(u64, @intCast(info.system_time.seconds)) * 1_000_000 + @as(u64, @intCast(info.system_time.microseconds));
        out.threads += 1;
    }
    return out;
}
const Memory = struct { resident: u64 = 0, footprint: u64 = 0, footprint_peak: u64 = 0 };
fn readMemory() Memory {
    if (comptime builtin.os.tag != .macos or !builtin.link_libc) return .{};
    var info: std.c.task_vm_info_data_t = undefined;
    var count: std.c.mach_msg_type_number_t = std.c.TASK_VM_INFO_COUNT;
    if (std.c.task_info(std.c.mach_task_self(), std.c.TASK_VM_INFO, @ptrCast(&info), &count) != 0) return .{};
    return .{ .resident = info.resident_size, .footprint = info.phys_footprint, .footprint_peak = if (info.ledger_phys_footprint_peak > 0) @intCast(info.ledger_phys_footprint_peak) else 0 };
}
pub const Snapshot = struct {
    user_us: u64,
    system_us: u64,
    minor_faults: u64,
    major_faults: u64,
    voluntary_switches: u64,
    involuntary_switches: u64,
    peak_resident_bytes: u64 = 0,
    // Gauges and lane counters below are never checked for monotonicity
    // against the process-wide counters above.
    resident_bytes: u64 = 0,
    footprint_bytes: u64 = 0,
    footprint_peak_bytes: u64 = 0,
    lane: LaneTimes = .{},
};
const MONOTONIC = [_][]const u8{ "user_us", "system_us", "minor_faults", "major_faults", "voluntary_switches", "involuntary_switches", "peak_resident_bytes" };

/// Unsupported hosts return unavailable. Callers must avoid this call entirely
/// when telemetry is disabled; no allocation or per-row sampling is performed.
pub fn read() ?Snapshot {
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .linux) {
        const r = std.posix.getrusage(std.posix.rusage.SELF);
        if (r.utime.sec < 0 or r.utime.usec < 0 or r.stime.sec < 0 or r.stime.usec < 0 or
            r.maxrss < 0 or r.minflt < 0 or r.majflt < 0 or r.nvcsw < 0 or r.nivcsw < 0) return null;
        const user_us = std.math.mul(u64, @intCast(r.utime.sec), 1_000_000) catch return null;
        const system_us = std.math.mul(u64, @intCast(r.stime.sec), 1_000_000) catch return null;
        const memory = readMemory();
        return .{
            .resident_bytes = memory.resident,
            .footprint_bytes = memory.footprint,
            .footprint_peak_bytes = memory.footprint_peak,
            .lane = readLane(),
            .user_us = std.math.add(u64, user_us, @intCast(r.utime.usec)) catch return null,
            .system_us = std.math.add(u64, system_us, @intCast(r.stime.usec)) catch return null,
            .minor_faults = @intCast(r.minflt),
            .major_faults = @intCast(r.majflt),
            .voluntary_switches = @intCast(r.nvcsw),
            .involuntary_switches = @intCast(r.nivcsw),
            .peak_resident_bytes = std.math.mul(u64, @intCast(r.maxrss), if (builtin.os.tag == .linux) 1024 else 1) catch return null,
        };
    }
    return null;
}

/// Reject a regressing counter instead of wrapping or reporting negative work.
pub fn delta(start: Snapshot, end: Snapshot) ?ProcessUsage {
    inline for (MONOTONIC) |name| {
        if (@field(end, name) < @field(start, name)) return null;
    }
    // Lane CPU is reported only when the same lane binding spans the interval.
    const same_lane = start.lane.threads != 0 and start.lane.identity == end.lane.identity and start.lane.threads == end.lane.threads and end.lane.user_us >= start.lane.user_us and end.lane.system_us >= start.lane.system_us;
    return .{
        .process_resident_bytes_at_end = end.resident_bytes,
        .process_footprint_bytes_at_end = end.footprint_bytes,
        .process_footprint_peak_bytes_at_end = end.footprint_peak_bytes,
        .lane_threads = if (same_lane) end.lane.threads else 0,
        .lane_user_seconds = if (same_lane) @as(f64, @floatFromInt(end.lane.user_us - start.lane.user_us)) / 1_000_000 else null,
        .lane_system_seconds = if (same_lane) @as(f64, @floatFromInt(end.lane.system_us - start.lane.system_us)) / 1_000_000 else null,
        .user_seconds = @as(f64, @floatFromInt(end.user_us - start.user_us)) / 1_000_000,
        .system_seconds = @as(f64, @floatFromInt(end.system_us - start.system_us)) / 1_000_000,
        .minor_faults = end.minor_faults - start.minor_faults,
        .major_faults = end.major_faults - start.major_faults,
        .voluntary_switches = end.voluntary_switches - start.voluntary_switches,
        .involuntary_switches = end.involuntary_switches - start.involuntary_switches,
        .process_peak_resident_bytes_at_end = end.peak_resident_bytes,
    };
}

test "stage process usage: deterministic deltas, zero and regressions" {
    const a: Snapshot = .{ .user_us = 10, .system_us = 20, .minor_faults = 30, .major_faults = 40, .voluntary_switches = 50, .involuntary_switches = 60, .peak_resident_bytes = 70 };
    const b: Snapshot = .{ .user_us = 1_500_010, .system_us = 250_020, .minor_faults = 33, .major_faults = 42, .voluntary_switches = 57, .involuntary_switches = 69, .peak_resident_bytes = 80 };
    const d = delta(a, b).?;
    try std.testing.expectEqual(@as(f64, 1.5), d.user_seconds);
    try std.testing.expectEqual(@as(f64, 0.25), d.system_seconds);
    try std.testing.expectEqual(@as(u64, 3), d.minor_faults);
    try std.testing.expectEqual(@as(u64, 2), d.major_faults);
    try std.testing.expectEqual(@as(u64, 7), d.voluntary_switches);
    try std.testing.expectEqual(@as(u64, 9), d.involuntary_switches);
    try std.testing.expectEqual(@as(u64, 80), d.process_peak_resident_bytes_at_end);
    try std.testing.expectEqual(@as(u64, 70), delta(a, a).?.process_peak_resident_bytes_at_end);
    try std.testing.expectEqual(@as(f64, 0), delta(a, a).?.user_seconds);
    inline for (MONOTONIC) |name| {
        var bad = b;
        @field(bad, name) = @field(a, name) - 1;
        try std.testing.expect(delta(a, bad) == null);
    }
}

test "stage process usage: host counters are monotonic without sleeping" {
    const a = read() orelse return error.SkipZigTest;
    const b = read() orelse return error.SkipZigTest;
    try std.testing.expect(delta(a, b) != null);
    try std.testing.expect(b.peak_resident_bytes != 0);
}

test "stage process usage: lane counters attribute only a stable binding" {
    const base: Snapshot = .{ .user_us = 0, .system_us = 0, .minor_faults = 0, .major_faults = 0, .voluntary_switches = 0, .involuntary_switches = 0, .resident_bytes = 9 };
    var start = base;
    start.lane = .{ .user_us = 100, .system_us = 10, .threads = 3, .identity = 1 };
    var end = base;
    end.resident_bytes = 5; // Gauges may fall without rejecting the interval.
    end.lane = .{ .user_us = 2_100, .system_us = 510, .threads = 3, .identity = 1 };
    const d = delta(start, end).?;
    try std.testing.expectEqual(@as(u32, 3), d.lane_threads);
    try std.testing.expectEqual(@as(?f64, 0.002), d.lane_user_seconds);
    try std.testing.expectEqual(@as(?f64, 0.0005), d.lane_system_seconds);
    try std.testing.expectEqual(@as(u64, 5), d.process_resident_bytes_at_end);
    end.lane.identity = 2;
    try std.testing.expectEqual(@as(?f64, null), delta(start, end).?.lane_user_seconds);
    try std.testing.expectEqual(@as(?f64, null), delta(base, base).?.lane_user_seconds);
}

test "stage process usage: bound lane threads report their own CPU time" {
    if (comptime builtin.os.tag != .macos or !builtin.link_libc) return error.SkipZigTest;
    const handles = [_]std.Thread.Handle{std.c.pthread_self()};
    const lane = LaneThreads{ .handles = &handles };
    const previous = bindLane(&lane);
    defer _ = bindLane(previous);
    const a = read() orelse return error.SkipZigTest;
    var sink: u64 = 0;
    for (0..20_000_000) |i| sink +%= i *% 2654435761;
    std.mem.doNotOptimizeAway(sink);
    const b = read() orelse return error.SkipZigTest;
    const d = delta(a, b).?;
    try std.testing.expectEqual(@as(u32, 1), d.lane_threads);
    try std.testing.expect(d.lane_user_seconds.? > 0);
    try std.testing.expect(d.process_resident_bytes_at_end != 0 and d.process_footprint_bytes_at_end != 0);
}
