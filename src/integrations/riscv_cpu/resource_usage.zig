//! RISC-V report projection over the shared process resource sampler.

const std = @import("std");
const builtin = @import("builtin");
const process_usage = @import("stwo_prover_engine").measurement.process_usage;

pub const SOURCE = "darwin.proc_pid_rusage.RUSAGE_INFO_V6";
pub const SCOPE = "self_process_lifetime";

pub const Snapshot = struct {
    lifetime_max_phys_footprint_bytes: u64,
    energy_nj: u64,
    instructions: u64,
    cycles: u64,
};

pub const IntervalDelta = struct {
    energy_nj: u64,
    instructions: u64,
    cycles: u64,
};

pub const UnavailableReason = enum {
    unsupported_platform,
    sampling_failed,
};

pub const Capture = union(enum) {
    available: Snapshot,
    unavailable: UnavailableReason,
};

pub const ReportUnavailableReason = enum {
    unsupported_platform,
    before_warmups_sampling_failed,
    after_verified_samples_sampling_failed,
    counter_regression,
};

pub const Report = struct {
    availability: enum { available, unavailable },
    source: []const u8 = SOURCE,
    scope: []const u8 = SCOPE,
    unavailable_reason: ?ReportUnavailableReason,
    before_warmups: ?Snapshot,
    after_verified_samples: ?Snapshot,
    interval_delta: ?IntervalDelta,
};

pub fn capture() Capture {
    const sampled = process_usage.sample() catch
        return .{ .unavailable = .sampling_failed };
    if (sampled.source == .unsupported)
        return .{ .unavailable = .unsupported_platform };
    return .{ .available = .{
        .lifetime_max_phys_footprint_bytes = sampled.lifetime_peak_physical_footprint_bytes orelse
            return .{ .unavailable = .sampling_failed },
        .energy_nj = sampled.energy_nj orelse
            return .{ .unavailable = .sampling_failed },
        .instructions = sampled.instructions orelse
            return .{ .unavailable = .sampling_failed },
        .cycles = sampled.cycles orelse
            return .{ .unavailable = .sampling_failed },
    } };
}

pub fn report(before: Capture, after: Capture) Report {
    const before_value = switch (before) {
        .available => |value| value,
        .unavailable => |reason| return unavailable(switch (reason) {
            .unsupported_platform => .unsupported_platform,
            .sampling_failed => .before_warmups_sampling_failed,
        }),
    };
    const after_value = switch (after) {
        .available => |value| value,
        .unavailable => |reason| return unavailable(switch (reason) {
            .unsupported_platform => .unsupported_platform,
            .sampling_failed => .after_verified_samples_sampling_failed,
        }),
    };
    if (after_value.lifetime_max_phys_footprint_bytes <
        before_value.lifetime_max_phys_footprint_bytes or
        after_value.energy_nj < before_value.energy_nj or
        after_value.instructions < before_value.instructions or
        after_value.cycles < before_value.cycles)
        return unavailable(.counter_regression);

    return .{
        .availability = .available,
        .unavailable_reason = null,
        .before_warmups = before_value,
        .after_verified_samples = after_value,
        .interval_delta = .{
            .energy_nj = after_value.energy_nj - before_value.energy_nj,
            .instructions = after_value.instructions - before_value.instructions,
            .cycles = after_value.cycles - before_value.cycles,
        },
    };
}

fn unavailable(reason: ReportUnavailableReason) Report {
    return .{
        .availability = .unavailable,
        .unavailable_reason = reason,
        .before_warmups = null,
        .after_verified_samples = null,
        .interval_delta = null,
    };
}

test "resource report computes the exact measured interval" {
    const before = Snapshot{
        .lifetime_max_phys_footprint_bytes = 100,
        .energy_nj = 20,
        .instructions = 30,
        .cycles = 40,
    };
    const after = Snapshot{
        .lifetime_max_phys_footprint_bytes = 150,
        .energy_nj = 27,
        .instructions = 41,
        .cycles = 53,
    };
    const value = report(.{ .available = before }, .{ .available = after });
    try std.testing.expectEqual(.available, value.availability);
    try std.testing.expectEqual(@as(u64, 150), value.after_verified_samples.?.lifetime_max_phys_footprint_bytes);
    try std.testing.expectEqual(@as(u64, 7), value.interval_delta.?.energy_nj);
    try std.testing.expectEqual(@as(u64, 11), value.interval_delta.?.instructions);
    try std.testing.expectEqual(@as(u64, 13), value.interval_delta.?.cycles);
}

test "resource report fails closed on incomplete or regressing counters" {
    const snapshot = Snapshot{
        .lifetime_max_phys_footprint_bytes = 100,
        .energy_nj = 20,
        .instructions = 30,
        .cycles = 40,
    };
    const missing = report(
        .{ .unavailable = .sampling_failed },
        .{ .available = snapshot },
    );
    try std.testing.expectEqual(
        ReportUnavailableReason.before_warmups_sampling_failed,
        missing.unavailable_reason.?,
    );
    var regressed = snapshot;
    regressed.energy_nj -= 1;
    const invalid = report(
        .{ .available = snapshot },
        .{ .available = regressed },
    );
    try std.testing.expectEqual(
        ReportUnavailableReason.counter_regression,
        invalid.unavailable_reason.?,
    );
}

test "resource sampler uses shared Darwin process counters" {
    const value = capture();
    if (comptime builtin.os.tag == .macos) {
        const snapshot = switch (value) {
            .available => |item| item,
            .unavailable => return error.TestUnexpectedResult,
        };
        try std.testing.expect(snapshot.lifetime_max_phys_footprint_bytes > 0);
    } else {
        try std.testing.expectEqual(
            UnavailableReason.unsupported_platform,
            value.unavailable,
        );
    }
}
