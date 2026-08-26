//! Adversarial state-machine tests for exact witness-phase timing.

const std = @import("std");
const phase_meter = @import("proof_phase_meter.zig");

const Reading = union(enum) {
    value: u64,
    failure: anyerror,
};

const ScriptClock = struct {
    readings: []const Reading,
    next: std.atomic.Value(usize) = .init(0),

    fn now(raw: *anyopaque) anyerror!u64 {
        const self: *ScriptClock = @ptrCast(@alignCast(raw));
        const index = self.next.fetchAdd(1, .monotonic);
        if (index >= self.readings.len) return error.ClockScriptExhausted;
        return switch (self.readings[index]) {
            .value => |value| value,
            .failure => |failure| failure,
        };
    }

    fn source(self: *ScriptClock) phase_meter.ClockSource {
        return .{ .context = self, .now_fn = now };
    }

    fn calls(self: *const ScriptClock) usize {
        return self.next.load(.acquire);
    }
};

fn finishOne(meter: *phase_meter.Meter) !void {
    var region = try meter.begin();
    errdefer region.abort();
    try region.finish();
}

test "five witness regions sum exactly and exclude every gap" {
    const readings = [_]Reading{
        .{ .value = 10 },   .{ .value = 15 },
        .{ .value = 20 },   .{ .value = 22 },
        .{ .value = 100 },  .{ .value = 110 },
        .{ .value = 111 },  .{ .value = 111 },
        .{ .value = 1000 }, .{ .value = 1020 },
    };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());

    for (0..5) |_| try finishOne(&meter);

    try std.testing.expectEqual(@as(u64, 37), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, 1020), meter.last_boundary_ns);
    try std.testing.expectEqual(@as(usize, 10), clock.calls());
    try std.testing.expect(!meter.hasActiveRegion());
    try meter.requireComplete();

    try std.testing.expectError(
        error.ProofPhaseRegionCountExceeded,
        meter.begin(),
    );
    try std.testing.expectEqual(@as(usize, 10), clock.calls());
}

test "completion rejects missing open and aborted regions" {
    var meter = phase_meter.Meter.init(null);
    try std.testing.expectError(error.IncompleteProofPhasePartition, meter.requireComplete());

    var open = try meter.begin();
    try std.testing.expectError(error.IncompleteProofPhasePartition, meter.requireComplete());
    open.abort();

    for (1..phase_meter.REGION_COUNT) |_| try finishOne(&meter);
    try std.testing.expectError(error.IncompleteProofPhasePartition, meter.requireComplete());
}

test "nested begin rejects before sampling and leaves the first region open" {
    const readings = [_]Reading{.{ .value = 40 }};
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());
    var region = try meter.begin();
    defer region.abort();

    try std.testing.expectError(
        error.ProofPhaseRegionAlreadyActive,
        meter.begin(),
    );
    try std.testing.expectEqual(@as(usize, 1), clock.calls());
    try std.testing.expect(meter.hasActiveRegion());
}

test "begin and finish reject clock regression without partial publication" {
    const readings = [_]Reading{
        .{ .value = 10 }, .{ .value = 20 },
        .{ .value = 19 }, .{ .value = 30 },
        .{ .value = 29 },
    };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());
    try finishOne(&meter);

    try std.testing.expectError(error.ProofPhaseClockRegression, meter.begin());
    try std.testing.expect(!meter.hasActiveRegion());
    try std.testing.expectEqual(@as(u64, 10), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, 20), meter.last_boundary_ns);

    var region = try meter.begin();
    defer region.abort();
    try std.testing.expectError(error.ProofPhaseClockRegression, region.finish());
    try std.testing.expect(meter.hasActiveRegion());
    try std.testing.expectEqual(@as(u64, 10), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, 30), meter.last_boundary_ns);
}

test "finish overflow is checked and leaves the region abortable" {
    const readings = [_]Reading{ .{ .value = 50 }, .{ .value = 52 } };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());
    meter.witness_ns = std.math.maxInt(u64) - 1;
    var region = try meter.begin();

    try std.testing.expectError(error.ProofPhaseWitnessOverflow, region.finish());
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, 50), meter.last_boundary_ns);
    try std.testing.expect(meter.hasActiveRegion());
    region.abort();
    try std.testing.expect(!meter.hasActiveRegion());
}

test "generation overflow fails before clock sampling or state mutation" {
    var clock = ScriptClock{ .readings = &.{} };
    var meter = phase_meter.Meter.init(clock.source());
    meter.next_generation = std.math.maxInt(u64);

    try std.testing.expectError(error.ProofPhaseGenerationOverflow, meter.begin());
    try std.testing.expectEqual(@as(usize, 0), clock.calls());
    try std.testing.expectEqual(@as(u64, 0), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, null), meter.last_boundary_ns);
    try std.testing.expect(!meter.hasActiveRegion());
}

test "unclosed double and stale tokens preserve the active generation" {
    const readings = [_]Reading{
        .{ .value = 10 }, .{ .value = 20 }, .{ .value = 25 },
    };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());
    var first = try meter.begin();
    var stale = first;
    try std.testing.expectError(error.ProofPhaseRegionAlreadyActive, meter.begin());
    first.abort();
    first.abort();

    var current = try meter.begin();
    stale.abort();
    try std.testing.expect(meter.hasActiveRegion());
    try std.testing.expectEqual(@as(usize, 2), clock.calls());
    try current.finish();
    try std.testing.expectError(error.ProofPhaseRegionClosed, current.finish());
    current.abort();
    try std.testing.expectEqual(@as(u64, 5), meter.witness_ns);
    try std.testing.expect(!meter.hasActiveRegion());
}

test "a stale finish rejects without sampling or disturbing a newer region" {
    const readings = [_]Reading{
        .{ .value = 10 }, .{ .value = 20 }, .{ .value = 25 },
    };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());
    var original = try meter.begin();
    var stale = original;
    original.abort();
    var current = try meter.begin();
    defer current.abort();

    try std.testing.expectError(error.ProofPhaseRegionStale, stale.finish());
    try std.testing.expectEqual(@as(usize, 2), clock.calls());
    try std.testing.expect(meter.hasActiveRegion());
    stale.abort();
    try current.finish();
}

test "clock errors propagate and leave begin or finish state fail-atomic" {
    const readings = [_]Reading{
        .{ .failure = error.TestClockUnavailable },
        .{ .value = 70 },
        .{ .failure = error.TestClockUnavailable },
    };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());

    try std.testing.expectError(error.TestClockUnavailable, meter.begin());
    try std.testing.expect(!meter.hasActiveRegion());
    try std.testing.expectEqual(@as(?u64, null), meter.last_boundary_ns);

    var region = try meter.begin();
    try std.testing.expectError(error.TestClockUnavailable, region.finish());
    try std.testing.expect(meter.hasActiveRegion());
    try std.testing.expectEqual(@as(u64, 0), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, 70), meter.last_boundary_ns);
    region.abort();
    try std.testing.expectEqual(@as(usize, 3), clock.calls());
}

test "equal boundaries are deterministic and each operation samples once" {
    const readings = [_]Reading{
        .{ .value = 10 }, .{ .value = 10 },
        .{ .value = 10 }, .{ .value = 12 },
    };
    var clock = ScriptClock{ .readings = &readings };
    var meter = phase_meter.Meter.init(clock.source());

    try finishOne(&meter);
    try finishOne(&meter);
    try std.testing.expectEqual(@as(u64, 2), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, 12), meter.last_boundary_ns);
    try std.testing.expectEqual(@as(usize, 4), clock.calls());
}

test "disabled lifecycle performs zero clock calls and zero allocations" {
    var unused_clock = ScriptClock{ .readings = &.{} };
    var no_storage: [0]u8 = .{};
    const fixed = std.heap.FixedBufferAllocator.init(&no_storage);
    const allocation_cursor = fixed.end_index;
    var meter = phase_meter.Meter.init(null);

    var region = try meter.begin();
    try std.testing.expectError(error.ProofPhaseRegionAlreadyActive, meter.begin());
    try region.finish();
    try std.testing.expectError(error.ProofPhaseRegionClosed, region.finish());
    region.abort();
    var aborted = try meter.begin();
    aborted.abort();
    aborted.abort();

    try std.testing.expectEqual(@as(u64, 0), meter.witness_ns);
    try std.testing.expectEqual(@as(?u64, null), meter.last_boundary_ns);
    try std.testing.expect(!meter.hasActiveRegion());
    try std.testing.expectEqual(@as(u64, 1), meter.completed_regions);
    try std.testing.expectEqual(@as(usize, 0), unused_clock.calls());
    try std.testing.expectEqual(allocation_cursor, fixed.end_index);
}
