const std = @import("std");
const Schedule = @import("schedule.zig");
const Pool = @import("stwo_prover_engine").work_pool;
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;
const Pipeline = @import("pipeline.zig");
const Recorder = struct {
    tickets: std.atomic.Value(usize) = .init(0),
    seen: [7]usize = @splat(std.math.maxInt(usize)),
    runs: [7]std.atomic.Value(u32) = @splat(.init(0)),
    fn execute(self: *Recorder, slot: usize) !void {
        const ticket = self.tickets.fetchAdd(1, .acq_rel);
        self.seen[ticket] = slot;
        if (self.runs[slot].fetchAdd(1, .acq_rel) != 0) return error.DuplicateWorkerOrdinal;
    }
};
test "Ordered dispatch runs every slot exactly once and rejects non-permutations" {
    const order = [_]usize{ 4, 6, 5, 0, 1, 2, 3 };
    var serial = Recorder{};
    try Schedule.runOrdered(Recorder, a, &serial, 7, &order, .{ .lanes = 1, .workers_per_lane = 1 }, Recorder.execute);
    try std.testing.expectEqualSlices(usize, &order, &serial.seen);
    for (0..4) |_| {
        var parallel = Recorder{};
        try Schedule.runOrdered(Recorder, a, &parallel, 7, &order, .{ .lanes = 2, .workers_per_lane = 2 }, Recorder.execute);
        for (&parallel.runs) |*n| try std.testing.expectEqual(@as(u32, 1), n.load(.acquire));
    }
    var unused = Recorder{};
    for ([_][]const usize{ &.{ 0, 1, 2, 3, 4, 5 }, &.{ 0, 1, 2, 3, 4, 5, 5 }, &.{ 0, 1, 2, 3, 4, 5, 7 } }) |bad| {
        try std.testing.expectError(error.InvalidServiceDispatchOrder, Schedule.runOrdered(Recorder, a, &unused, 7, bad, .{ .lanes = 2, .workers_per_lane = 2 }, Recorder.execute));
    }
    try std.testing.expectEqual(@as(usize, 0), unused.tickets.load(.acquire));
}
test "Truths-first dispatch is a permutation with truths by declared cells descending then CPUs" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const truths = c.truths();
    const manifest = try Pipeline.dispatchOrder(a, 2, &truths, .manifest);
    defer a.free(manifest);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2, 3, 4 }, manifest);
    const lpt = try Pipeline.dispatchOrder(a, 2, &truths, .truths_first);
    defer a.free(lpt);
    try Schedule.validateOrder(a, 5, lpt);
    for (lpt[0..3]) |slot| try std.testing.expect(slot >= 2);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1 }, lpt[3..]);
    try std.testing.expectEqual(@as(usize, 2), lpt[0]); // Keccak is the widest truth.
}
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
    // Fixture bundle is lane-1 truths-first; every dispatch order and lane
    // count must reproduce it byte for byte.
    for ([_]u32{ 8, 64, 64 }, [_]@import("profiling.zig").Dispatch{ .manifest, .truths_first, .manifest }, [_]u8{ 2, 2, 1 }) |batch, dispatch, lanes| {
        var captured = try F.Captured.init(a);
        defer captured.deinit();
        var candidate = try E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected.expected(), .{ .commit_batch_columns = batch, .schedule = .{ .lanes = lanes, .workers_per_lane = 2 }, .dispatch = dispatch, .consume_memory_events = true });
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
