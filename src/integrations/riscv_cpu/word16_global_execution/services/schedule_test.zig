const std = @import("std");
const Schedule = @import("schedule.zig");
const Pool = @import("stwo_prover_engine").work_pool;
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;
const Probe = struct {
    arrivals: std.atomic.Value(u32) = .init(0),
    active: std.atomic.Value(u32) = .init(0),
    peak: std.atomic.Value(u32) = .init(0),
    done: [8]std.atomic.Value(u32) = @splat(.init(0)),
    both: std.Thread.ResetEvent = .{},
    failed: std.Thread.ResetEvent = .{},
    fail: bool = false,
    fn execute(self: *Probe, index: usize) !void {
        const pool = Pool.currentScopedPool() orelse return error.MissingWorkerPool;
        if (pool.workerCount() != 2) return error.WrongWorkerPool;
        const active = self.active.fetchAdd(1, .acq_rel) + 1;
        defer _ = self.active.fetchSub(1, .acq_rel);
        var peak = self.peak.load(.acquire);
        while (active > peak) peak = self.peak.cmpxchgWeak(peak, active, .acq_rel, .acquire) orelse break;
        if (self.arrivals.fetchAdd(1, .acq_rel) + 1 == 2) self.both.set();
        self.both.wait();
        if (self.fail and index == 1) {
            self.failed.set();
            return error.SyntheticWorkerFailure;
        }
        if (self.fail and index == 0) self.failed.wait();
        if (self.done[index].fetchAdd(1, .acq_rel) != 0) return error.DuplicateWorkerOrdinal;
    }
};
test "Two service lanes own disjoint pools and join callbacks on success failure and reuse" {
    const before = Pool.currentScopedPool();
    var success = Probe{};
    try Schedule.run(Probe, a, &success, 8, .{ .lanes = 2, .workers_per_lane = 2 }, Probe.execute);
    try std.testing.expectEqual(@as(u32, 2), success.peak.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), success.active.load(.acquire));
    for (&success.done) |*n| try std.testing.expectEqual(@as(u32, 1), n.load(.acquire));
    var failure = Probe{ .fail = true };
    try std.testing.expectError(error.SyntheticWorkerFailure, Schedule.run(Probe, a, &failure, 8, .{ .lanes = 2, .workers_per_lane = 2 }, Probe.execute));
    try std.testing.expectEqual(@as(u32, 0), failure.active.load(.acquire));
    try std.testing.expectEqual(before, Pool.currentScopedPool());
    var retry = Probe{};
    try Schedule.run(Probe, a, &retry, 8, .{ .lanes = 2, .workers_per_lane = 2 }, Probe.execute);
    try std.testing.expectEqual(@as(u32, 0), retry.active.load(.acquire));
}
test "Concurrent two-phase services preserve all proof bytes claims manifest and fresh verification" {
    var expected = try F.Case.init(a);
    defer expected.deinit();
    for ([_]u32{ 8, 64 }) |batch| {
        var captured = try F.Captured.init(a);
        defer captured.deinit();
        var candidate = try E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected.expected(), .{ .commit_batch_columns = batch, .schedule = .{ .lanes = 2, .workers_per_lane = 2 }, .consume_memory_events = true });
        defer candidate.deinit(a);
        try E.verify(a, &expected.keys(), &expected.truths(), expected.expected(), &candidate);
        try std.testing.expectEqualDeep(expected.bundle.manifest.digest, candidate.manifest.digest);
        for (expected.bundle.cpus, candidate.cpus) |x, y| {
            try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
            try std.testing.expectEqualDeep(x.claims, y.claims);
        }
        for (expected.bundle.truths, candidate.truths) |x, y| {
            try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
            try std.testing.expectEqualDeep(x.claims, y.claims);
        }
    }
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try @import("../retained_main_store.zig").Store.init(path, 1);
    defer store.deinit();
    try std.testing.expectError(error.RetainedMainBudgetExceeded, E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected.expected(), .{ .schedule = .{ .lanes = 2, .workers_per_lane = 2 }, .retained_main = &store }));
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
}
test "Consistently rekeyed declaration and resealed manifest still reject the old physical proof" {
    var c = try F.Case.init(a);
    defer c.deinit();
    var geometry = c.setups[0].materials.geometry;
    geometry.cpu_log += 1; // Valid capacity and mass; not an admission failure.
    var changed = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, c.setups[0].bridges);
    defer changed.deinit();
    const keys = [_]*const R.CpuSetup{ &changed, c.setups[1] };
    const truths = c.truths();
    const requests = [_]P.Request{ c.bundle.cpus[0].request, c.bundle.cpus[1].request };
    _ = try P.admit(a, &keys, &truths, &requests, c.expected());
    var specs = c.bundle.manifest.specs[0..5].*;
    var roots = c.bundle.manifest.roots[0..5].*;
    var channel = G.T.P.Channel{};
    try P.beginCpu(&channel, &changed, requests[0], c.expected(), 0, 0, try P.firstIds(&requests, 0));
    specs[0] = channel.digestBytes();
    roots[0].fixed.bytes = changed.key.root;
    var manifest = try G.Manifest.init(a, &specs, &roots);
    defer manifest.deinit();
    var candidate = c.bundle;
    candidate.manifest = manifest;
    try std.testing.expectError(error.CombinedStage1Mismatch, E.verify(a, &keys, &truths, c.expected(), &candidate));
}
const Wide = struct {
    active: std.atomic.Value(u32) = .init(0),
    peak: std.atomic.Value(u32) = .init(0),
    bytes: std.atomic.Value(u64) = .init(0),
    peak_bytes: std.atomic.Value(u64) = .init(0),
    done: [12]std.atomic.Value(u32) = @splat(.init(0)),
    workers: [12]std.atomic.Value(usize) = @splat(.init(0)),
    estimates: []const u64 = &.{},
    fn execute(self: *Wide, index: usize) !void {
        const pool = Pool.currentScopedPool() orelse return error.MissingWorkerPool;
        self.workers[index].store(pool.workerCount(), .release);
        const active = self.active.fetchAdd(1, .acq_rel) + 1;
        defer _ = self.active.fetchSub(1, .acq_rel);
        _ = self.peak.fetchMax(active, .acq_rel);
        const estimate = if (self.estimates.len == 0) 0 else self.estimates[index];
        const bytes = self.bytes.fetchAdd(estimate, .acq_rel) + estimate;
        defer _ = self.bytes.fetchSub(estimate, .acq_rel);
        _ = self.peak_bytes.fetchMax(bytes, .acq_rel);
        var spin: u64 = 0;
        for (0..2_000_000) |i| spin +%= i;
        std.mem.doNotOptimizeAway(spin);
        if (self.done[index].fetchAdd(1, .acq_rel) != 0) return error.DuplicateWorkerOrdinal;
    }
};
test "Four lanes honour per-lane worker counts and run every index exactly once" {
    var wide = Wide{};
    var trace: [12]Schedule.Trace = undefined;
    const policy = Schedule.Policy{ .lanes = 4, .workers_per_lane = 2, .lane_workers = .{ 3, 2, 2, 1 } };
    try Schedule.runWithOptions(Wide, a, &wide, 12, policy, .{ .trace = &trace }, Wide.execute);
    for (&wide.done) |*n| try std.testing.expectEqual(@as(u32, 1), n.load(.acquire));
    for (&wide.workers, trace) |*w, t| {
        try std.testing.expect(t.lane < 4);
        try std.testing.expectEqual(@as(usize, policy.workers(t.lane)), w.load(.acquire));
        try std.testing.expect(t.finished_ns >= t.started_ns and t.started_ns >= t.claimed_ns);
    }
    try std.testing.expectError(error.InvalidServiceSchedule, (Schedule.Policy{ .lanes = 5 }).validate());
    try std.testing.expectError(error.InvalidServiceSchedule, (Schedule.Policy{ .lanes = 4, .workers_per_lane = 9 }).validate());
    try std.testing.expectError(error.InvalidServiceSchedule, (Schedule.Policy{ .lanes = 2, .lane_workers = .{ 8, 8, 8, 0 } }).validate());
    try (Schedule.Policy{ .lanes = 2, .workers_per_lane = 8 }).validate();
}
test "Memory cap bounds summed in-flight estimates and admits an oversized index alone" {
    const estimates = [_]u64{ 6, 6, 6, 6, 1, 1, 1, 1, 20, 6, 1, 1 };
    var wide = Wide{ .estimates = &estimates };
    var trace: [12]Schedule.Trace = undefined;
    try Schedule.runWithOptions(Wide, a, &wide, 12, .{ .lanes = 4, .workers_per_lane = 2, .memory_cap_bytes = 13 }, .{ .estimates = &estimates, .trace = &trace }, Wide.execute);
    for (&wide.done) |*n| try std.testing.expectEqual(@as(u32, 1), n.load(.acquire));
    // The 20-byte index exceeds the cap and therefore ran with nothing else.
    try std.testing.expectEqual(@as(u64, 20), trace[8].in_flight_bytes_at_start);
    for (trace, 0..) |t, i| if (i != 8) try std.testing.expect(t.in_flight_bytes_at_start <= 13);
    try std.testing.expectError(error.MissingServiceMemoryEstimates, Schedule.runWithOptions(Wide, a, &wide, 12, .{ .lanes = 2, .memory_cap_bytes = 1 }, .{}, Wide.execute));
}
test "Four memory-capped lanes preserve all proof bytes claims manifest and fresh verification" {
    var expected = try F.Case.init(a);
    defer expected.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const policy = Schedule.Policy{ .lanes = 4, .workers_per_lane = 2, .lane_workers = .{ 3, 2, 2, 1 }, .memory_cap_bytes = 1 };
    var candidate = try E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected.expected(), .{ .schedule = policy, .consume_memory_events = true });
    defer candidate.deinit(a);
    try E.verify(a, &expected.keys(), &expected.truths(), expected.expected(), &candidate);
    try std.testing.expectEqualDeep(expected.bundle.manifest.digest, candidate.manifest.digest);
    for (expected.bundle.cpus, candidate.cpus) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    for (expected.bundle.truths, candidate.truths) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    var unbounded = try F.Captured.init(a);
    defer unbounded.deinit();
    var wide = try E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &unbounded.native[0], &unbounded.native[1] }, &unbounded.advice, expected.expected(), .{ .schedule = .{ .lanes = 4, .workers_per_lane = 2 }, .consume_memory_events = true });
    defer wide.deinit(a);
    for (expected.bundle.cpus, wide.cpus) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    for (expected.bundle.truths, wide.truths) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
}
test "Schedule policy reports resolved lane workers as numbers" {
    const json = try std.json.Stringify.valueAlloc(a, Schedule.Policy{ .lanes = 3, .workers_per_lane = 4, .lane_workers = .{ 6, 0, 2, 0 }, .memory_cap_bytes = 7 }, .{});
    defer a.free(json);
    try std.testing.expectEqualStrings("{\"lanes\":3,\"workers_per_lane\":4,\"lane_workers\":[6,4,2],\"memory_cap_bytes\":7}", json);
}
