//! Cooperative composition queue: bit-identical to the established scheduler
//! on mixed component sets, for every worker count and admission budget.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Q = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("accumulation.zig");
const scheduler = @import("component_parallel.zig");
const work = @import("../work_pool.zig");
const SecureColumnByCoords = @import("../secure_column.zig").SecureColumnByCoords;
const a = std.testing.allocator;

const Shared = struct {
    live_exclusive: std.atomic.Value(usize) = .init(0),
    overlapped_exclusive: std.atomic.Value(bool) = .init(false),
    cooperative_splits: std.atomic.Value(usize) = .init(0),
};

const Mock = struct {
    index: usize,
    log_size: u32,
    constraints: usize,
    shared: *Shared,
    fail: bool = false,
    prepare_domain_evaluator: ?u8 = null,
    domain_parallel_evaluator: ?u8 = 0,
    pool_exclusive_domain: bool = false,
    cooperative_domain: bool = false,

    pub fn nConstraints(self: Mock) usize {
        return self.constraints;
    }
    pub fn maxConstraintLogDegreeBound(self: Mock) u32 {
        return self.log_size;
    }
    pub fn prepareConstraintQuotientsOnDomain(_: Mock, _: std.mem.Allocator, _: *const u8, _: *accumulation.DomainEvaluationAccumulator) anyerror!?@import("prepared_domain.zig").PreparedDomainEvaluation {
        return error.UnexpectedPreparedCompositionAdapter;
    }

    fn value(self: Mock, row: usize, constraint: usize) Q {
        const seed: u32 = @intCast((self.index * 7919 + row * 104729 + constraint * 1299709) % 2147483000);
        return Q.fromU32Unchecked(seed % 2147483647, (seed *% 3) % 2147483647, (seed *% 5) % 2147483647, (seed *% 7) % 2147483647);
    }

    fn rowValue(self: Mock, powers: []const Q, row: usize) Q {
        var sum = Q.zero();
        for (powers, 0..) |power, constraint| sum = sum.add(power.mul(self.value(row, constraint)));
        return sum;
    }

    const Split = struct {
        mock: Mock,
        output: *accumulation.ColumnAccumulator,
        rows: usize,
        chunks: usize,
        fn run(context: *anyopaque, index: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            var local = self.output.*;
            for (self.rows * index / self.chunks..self.rows * (index + 1) / self.chunks) |row|
                local.accumulate(row, self.mock.rowValue(local.random_coeff_powers, row));
        }
    };

    pub fn evaluateConstraintQuotientsOnDomain(self: Mock, _: *const u8, acc: *accumulation.DomainEvaluationAccumulator) !void {
        if (self.fail) return error.InjectedQueueComponentFailure;
        // One constant contribution, then one domain column for the rest.
        try acc.accumulateConstant(self.log_size, Q.fromU32Unchecked(@intCast(self.index + 1), 2, 3, 4));
        const columns = try acc.columns(acc.allocator, &.{.{ .log_size = self.log_size, .n_cols = self.constraints - 1 }});
        defer acc.allocator.free(columns);
        var output = columns[0];
        const rows = @as(usize, 1) << @intCast(self.log_size);
        if (work.cooperative.current()) |queue| {
            const chunks = queue.preferredChunks(rows / 4);
            if (chunks > 1) {
                _ = self.shared.cooperative_splits.fetchAdd(1, .monotonic);
                output.next_fresh_index = null;
                var split = Split{ .mock = self, .output = &output, .rows = rows, .chunks = chunks };
                var batch = work.cooperative.Batch{ .context = &split, .run = Split.run, .count = chunks };
                queue.split(&batch);
                return;
            }
        }
        for (0..rows) |row| output.accumulate(row, self.rowValue(output.random_coeff_powers, row));
    }

    pub fn evaluateConstraintQuotientsOnDomainParallel(self: Mock, trace: *const u8, acc: *accumulation.DomainEvaluationAccumulator, pool: *work.WorkPool) !void {
        if (self.pool_exclusive_domain) {
            if (self.shared.live_exclusive.fetchAdd(1, .acq_rel) != 0)
                self.shared.overlapped_exclusive.store(true, .release);
            defer _ = self.shared.live_exclusive.fetchSub(1, .acq_rel);
            // A non-cooperative exclusive evaluator owns the whole pool.
            var lease = try pool.acquire(try work.WorkerBudget.init(pool.workerCount()));
            defer lease.deinit();
        }
        return self.evaluateConstraintQuotientsOnDomain(trace, acc);
    }
};

const Kind = enum { ordinary, exclusive, exclusive_cooperative, ordinary_cooperative };

fn mock(shared: *Shared, index: usize, log_size: u32, constraints: usize, kind: Kind) Mock {
    return .{
        .index = index,
        .log_size = log_size,
        .constraints = constraints,
        .shared = shared,
        .pool_exclusive_domain = kind == .exclusive or kind == .exclusive_cooperative,
        .cooperative_domain = kind == .exclusive_cooperative or kind == .ordinary_cooperative,
        .domain_parallel_evaluator = if (kind == .ordinary) null else 0,
    };
}

fn totalConstraints(values: []const Mock) usize {
    var total: usize = 0;
    for (values) |value| total += value.constraints;
    return total;
}

fn maxLog(values: []const Mock) u32 {
    var result: u32 = 0;
    for (values) |value| result = @max(result, value.log_size);
    return result;
}

fn run(values: []const Mock, pool: *work.WorkPool, which: scheduler.Scheduler, options: scheduler.QueueOptions) !SecureColumnByCoords {
    const trace: u8 = 0;
    return scheduler.computeWithScheduler(a, values, maxLog(values), totalConstraints(values), Q.fromU32Unchecked(3, 1, 4, 1), &trace, pool, which, options);
}

fn expectSame(expected: *const SecureColumnByCoords, actual: *const SecureColumnByCoords) !void {
    try std.testing.expectEqual(expected.len(), actual.len());
    for (expected.columns, actual.columns) |lhs, rhs| try std.testing.expectEqualSlices(M, lhs, rhs);
}

fn mixedSets(shared: *Shared) [4][9]Mock {
    return .{
        // Dominant cooperative exclusive component plus ordinary large and
        // small components and one non-cooperative exclusive tail.
        .{
            mock(shared, 0, 12, 5, .exclusive_cooperative),
            mock(shared, 1, 9, 3, .exclusive_cooperative),
            mock(shared, 2, 4, 2, .ordinary),
            mock(shared, 3, 11, 4, .ordinary_cooperative),
            mock(shared, 4, 11, 6, .ordinary_cooperative),
            mock(shared, 5, 6, 3, .exclusive),
            mock(shared, 6, 10, 7, .exclusive),
            mock(shared, 7, 8, 2, .ordinary),
            mock(shared, 8, 12, 3, .ordinary_cooperative),
        },
        // Every component at the composition domain: the parallel finalizer
        // sees many buckets of one log.
        .{
            mock(shared, 0, 12, 2, .exclusive_cooperative),
            mock(shared, 1, 12, 2, .ordinary_cooperative),
            mock(shared, 2, 12, 2, .ordinary),
            mock(shared, 3, 12, 2, .exclusive),
            mock(shared, 4, 12, 2, .exclusive_cooperative),
            mock(shared, 5, 12, 2, .ordinary_cooperative),
            mock(shared, 6, 12, 2, .ordinary),
            mock(shared, 7, 12, 2, .exclusive_cooperative),
            mock(shared, 8, 12, 2, .ordinary_cooperative),
        },
        // Many distinct small logs below the composition domain (lifting).
        .{
            mock(shared, 0, 16, 3, .exclusive_cooperative),
            mock(shared, 1, 3, 2, .ordinary),
            mock(shared, 2, 5, 2, .ordinary_cooperative),
            mock(shared, 3, 7, 2, .exclusive_cooperative),
            mock(shared, 4, 9, 2, .exclusive),
            mock(shared, 5, 11, 2, .ordinary_cooperative),
            mock(shared, 6, 13, 2, .ordinary),
            mock(shared, 7, 14, 2, .exclusive_cooperative),
            mock(shared, 8, 15, 4, .ordinary_cooperative),
        },
        // Only cooperative components.
        .{
            mock(shared, 0, 13, 9, .exclusive_cooperative),
            mock(shared, 1, 13, 2, .exclusive_cooperative),
            mock(shared, 2, 10, 3, .exclusive_cooperative),
            mock(shared, 3, 8, 2, .ordinary_cooperative),
            mock(shared, 4, 6, 2, .ordinary_cooperative),
            mock(shared, 5, 13, 5, .exclusive_cooperative),
            mock(shared, 6, 4, 2, .ordinary_cooperative),
            mock(shared, 7, 9, 2, .exclusive_cooperative),
            mock(shared, 8, 11, 2, .ordinary_cooperative),
        },
    };
}

test "composition queue matches the established scheduler bit for bit on mixed component sets" {
    for ([_]usize{ 1, 2, 3, 8 }) |workers| {
        var pool: work.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
        defer pool.deinit();
        var shared = Shared{};
        const sets = mixedSets(&shared);
        for (&sets) |*set| {
            var expected = try run(set, &pool, .legacy, .{});
            defer expected.deinit(a);
            // Unbounded, default, and one-at-a-time admission.
            for ([_]?usize{ std.math.maxInt(usize), null, 1 }) |admission| {
                var actual = try run(set, &pool, .queue, .{ .admission_bytes = admission });
                defer actual.deinit(a);
                try expectSame(&expected, &actual);
                try std.testing.expectEqual(workers, pool.availableWorkers());
            }
            // Automatic selection takes the queue for these sets.
            var automatic = try run(set, &pool, .auto, .{});
            defer automatic.deinit(a);
            try expectSame(&expected, &automatic);
        }
        try std.testing.expect(!shared.overlapped_exclusive.load(.acquire));
        if (workers > 1) try std.testing.expect(shared.cooperative_splits.load(.monotonic) > 0);
    }
}

test "composition queue joins every component and returns leases after a failure" {
    for ([_]usize{ 1, 4 }) |workers| {
        for ([_]usize{ 0, 3, 5 }) |failed| {
            var pool: work.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
            defer pool.deinit();
            var shared = Shared{};
            var set = mixedSets(&shared)[0];
            set[failed].fail = true;
            try std.testing.expectError(error.InjectedQueueComponentFailure, run(&set, &pool, .queue, .{}));
            try std.testing.expectEqual(workers, pool.availableWorkers());
        }
    }
}

test "composition queue holds no partial outputs under allocation failure" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    var shared = Shared{};
    const set = [_]Mock{
        mock(&shared, 0, 6, 3, .exclusive_cooperative),
        mock(&shared, 1, 4, 2, .ordinary),
        mock(&shared, 2, 5, 2, .exclusive),
    };
    const trace: u8 = 0;
    var result = try scheduler.computeWithScheduler(allocator, &set, 6, totalConstraints(&set), Q.fromU32Unchecked(3, 1, 4, 1), &trace, &pool, .queue, .{});
    defer result.deinit(allocator);
}

test "parallel finalizer equals the serial finalizer over many lifted buckets" {
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var shared = Shared{};
    const set = mixedSets(&shared)[2];
    var expected = try run(&set, &pool, .legacy, .{});
    defer expected.deinit(a);
    var actual = try run(&set, &pool, .queue, .{});
    defer actual.deinit(a);
    try expectSame(&expected, &actual);
}
