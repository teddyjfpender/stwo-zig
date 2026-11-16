//! Shared monotonic capture clock and atomic failure precedence.
const std = @import("std");

pub const ClockFailure = enum(u8) {
    none,
    unavailable,
    regression,
    counter_overflow,
};

/// Test-only/custom monotonic source. Values are arbitrary monotonic ticks in
/// nanoseconds; `Clock.start` subtracts the first value so receipts always use
/// offsets from the graph origin. The callback and its context must be safe for
/// concurrent use because coordinator and helper tasks sample the same source.
pub const ClockSource = struct {
    context: *anyopaque,
    now_fn: *const fn (context: *anyopaque) anyerror!u64,

    pub fn now(self: ClockSource) anyerror!u64 {
        return self.now_fn(self.context);
    }
};

const CustomClock = struct {
    source: ClockSource,
    origin_ns: u64,
};

/// One immutable origin shared by all graph workers. Unlike `std.time.Timer`,
/// this value has no mutable `previous` sample and is therefore safe to read
/// concurrently.
pub const Clock = union(enum) {
    system: std.time.Instant,
    custom: CustomClock,

    pub fn start(source: ?ClockSource) !Clock {
        if (source) |custom| {
            return .{ .custom = .{
                .source = custom,
                .origin_ns = custom.now() catch
                    return error.TaskProfileClockUnavailable,
            } };
        }
        return .{ .system = std.time.Instant.now() catch
            return error.TaskProfileClockUnavailable };
    }

    /// Returns an offset from this graph's origin. A sampling failure is
    /// retained in `failure`; workers continue to their structured join and
    /// the coordinator reports the profile error afterward.
    pub fn sample(
        self: *const Clock,
        failure: *std.atomic.Value(u8),
    ) ?u64 {
        return switch (self.*) {
            .system => |origin| system: {
                const now = std.time.Instant.now() catch {
                    recordClockFailure(failure, .unavailable);
                    break :system null;
                };
                if (now.order(origin) == .lt) {
                    recordClockFailure(failure, .regression);
                    break :system null;
                }
                break :system now.since(origin);
            },
            .custom => |custom| custom_block: {
                const now_ns = custom.source.now() catch {
                    recordClockFailure(failure, .unavailable);
                    break :custom_block null;
                };
                if (now_ns < custom.origin_ns) {
                    recordClockFailure(failure, .regression);
                    break :custom_block null;
                }
                break :custom_block now_ns - custom.origin_ns;
            },
        };
    }
};

pub fn clockError(failure: *const std.atomic.Value(u8)) ?anyerror {
    return switch (@as(ClockFailure, @enumFromInt(failure.load(.acquire)))) {
        .none => null,
        .unavailable => error.TaskProfileClockUnavailable,
        .regression => error.TaskProfileClockRegression,
        .counter_overflow => error.TaskProfileCounterOverflow,
    };
}

pub fn recordCounterOverflow(failure: *std.atomic.Value(u8)) void {
    recordClockFailure(failure, .counter_overflow);
}

pub fn recordClockFailure(
    failure: *std.atomic.Value(u8),
    value: ClockFailure,
) void {
    // Enum order is the fixed diagnostic precedence. This CAS-max makes the
    // reported profile failure independent of which concurrent sampler wins:
    // counter overflow > clock regression > clock unavailable.
    const candidate = @intFromEnum(value);
    var observed = failure.load(.acquire);
    while (candidate > observed) {
        if (failure.cmpxchgWeak(
            observed,
            candidate,
            .acq_rel,
            .acquire,
        )) |actual| {
            observed = actual;
        } else {
            return;
        }
    }
}
