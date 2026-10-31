//! Legacy mixed-component scheduling: exclusive row-pool phases are joined.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("accumulation.zig");
const scheduler = @import("component_parallel.zig");
const work = @import("../work_pool.zig");
const a = std.testing.allocator;
const Control = struct {
    first_started: std.Thread.ResetEvent = .{},
    leaf_done: std.atomic.Value(bool) = .init(false),
    live_exclusive: std.atomic.Value(usize) = .init(0),
    parallel_calls: [3]std.atomic.Value(usize) = .{ .init(0), .init(0), .init(0) },
    helper_calls: std.atomic.Value(usize) = .init(0),
    enforce_phases: bool = true,
    fail_at: ?usize = null,
    fn helper(self: *Control) void {
        _ = self.helper_calls.fetchAdd(1, .monotonic);
    }
};
const Mock = struct {
    index: usize,
    control: *Control,
    prepare_domain_evaluator: ?u8 = null,
    domain_parallel_evaluator: ?u8 = 0,
    pool_exclusive_domain: bool,
    pub fn nConstraints(self: Mock) usize {
        return if (self.index == 0) 2 else 1;
    }
    pub fn maxConstraintLogDegreeBound(_: Mock) u32 {
        return 2;
    }
    pub fn prepareConstraintQuotientsOnDomain(_: Mock, _: std.mem.Allocator, _: *const u8, _: *accumulation.DomainEvaluationAccumulator) anyerror!?@import("prepared_domain.zig").PreparedDomainEvaluation {
        return error.UnexpectedPreparedCompositionAdapter;
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: Mock, _: *const u8, out: *accumulation.DomainEvaluationAccumulator) !void {
        if (self.index == 1) {
            if (self.control.enforce_phases) try self.control.first_started.timedWait(5 * std.time.ns_per_s);
            self.control.leaf_done.store(true, .release);
        }
        if (self.control.fail_at == self.index) return error.InjectedExclusiveComponentFailure;
        for (0..self.nConstraints()) |_| try out.accumulateConstant(2, Q.fromU32Unchecked(@intCast(11 + self.index * 7), 3, 5, 9));
    }
    pub fn evaluateConstraintQuotientsOnDomainParallel(self: Mock, trace: *const u8, out: *accumulation.DomainEvaluationAccumulator, pool: *work.WorkPool) !void {
        const previous = self.control.live_exclusive.fetchAdd(1, .acq_rel);
        defer _ = self.control.live_exclusive.fetchSub(1, .acq_rel);
        if (previous != 0) return error.OverlappingExclusiveComponents;
        _ = self.control.parallel_calls[self.index].fetchAdd(1, .monotonic);
        if (self.index == 0) self.control.first_started.set();
        if (self.index == 2 and !self.control.leaf_done.load(.acquire)) return error.UndrainedOrdinaryComponent;
        var lease = try pool.acquire(try work.WorkerBudget.init(pool.workerCount()));
        defer lease.deinit();
        var group: std.Thread.WaitGroup = .{};
        {
            defer {
                group.wait();
                lease.completeWave();
            }
            if (pool.workerCount() > 1) try lease.spawnWg(&group, Control.helper, .{self.control});
            self.control.helper();
        }
        return self.evaluateConstraintQuotientsOnDomain(trace, out);
    }
};
fn components(control: *Control, exclusive: bool) [3]Mock {
    return .{
        .{ .index = 0, .control = control, .pool_exclusive_domain = exclusive },
        .{ .index = 1, .control = control, .pool_exclusive_domain = false, .domain_parallel_evaluator = null },
        .{ .index = 2, .control = control, .pool_exclusive_domain = exclusive },
    };
}
fn compute(allocator: std.mem.Allocator, values: []const Mock, pool: *work.WorkPool) !@import("../secure_column.zig").SecureColumnByCoords {
    const trace: u8 = 0;
    return scheduler.compute(allocator, values, 2, 4, Q.fromU32Unchecked(3, 1, 4, 1), &trace, pool);
}
test "exclusive domain components acquire full pool sequentially and preserve protocol coefficient ranges" {
    for ([_]usize{ 1, 3, 8 }) |workers| {
        var pool: work.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
        defer pool.deinit();
        var baseline = Control{ .enforce_phases = false };
        const plain = components(&baseline, false);
        var expected = try compute(a, &plain, &pool);
        defer expected.deinit(a);
        var control = Control{ .enforce_phases = workers > 1 };
        const flagged = components(&control, true);
        var actual = try compute(a, &flagged, &pool);
        defer actual.deinit(a);
        try std.testing.expectEqual(expected.len(), actual.len());
        for (0..actual.len()) |i| try std.testing.expect(actual.at(i).eql(expected.at(i)));
        try std.testing.expectEqual(@as(usize, 1), control.parallel_calls[0].load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), control.parallel_calls[1].load(.acquire));
        try std.testing.expectEqual(@as(usize, 1), control.parallel_calls[2].load(.acquire));
        try std.testing.expectEqual(@as(usize, if (workers == 1) 2 else 4), control.helper_calls.load(.acquire));
        try std.testing.expectEqual(workers, pool.availableWorkers());
    }
}
test "exclusive first/ordinary/later component errors drain every submission and release leases" {
    for (0..3) |failed| {
        var pool: work.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = a });
        defer pool.deinit();
        var control = Control{ .fail_at = failed };
        const flagged = components(&control, true);
        try std.testing.expectError(error.InjectedExclusiveComponentFailure, compute(a, &flagged, &pool));
        try std.testing.expect(control.leaf_done.load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), control.live_exclusive.load(.acquire));
        try std.testing.expectEqual(@as(usize, if (failed == 2) 1 else 0), control.parallel_calls[2].load(.acquire));
        var regained = try pool.acquire(try work.WorkerBudget.init(3));
        regained.deinit();
    }
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    // A serial pool makes injected allocation failures deterministic while
    // exercising the identical exclusive scheduling and accumulator custody.
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    var control = Control{ .enforce_phases = false };
    const flagged = components(&control, true);
    var result = try compute(allocator, &flagged, &pool);
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.availableWorkers());
}
test "exclusive domain allocation failure unwinds partial component outputs" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
