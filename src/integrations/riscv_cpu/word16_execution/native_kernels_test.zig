const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const Fill = @import("stwo_riscv_frontend").rv64_air.providers.native_fill;
const Prefix = @import("stwo_riscv_frontend").rv64_air.providers.prefix_waves;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Rows = struct {
    pub const Context = struct { values: []usize, overflow: bool = false };
    pub const BINS = [_]usize{ 3, 2 };
    pub fn prepare(_: Context) void {}
    pub fn rows(context: Context, start: usize, end: usize, counts: []u64) void {
        for (start..end) |i| context.values[i] = i + 1;
        counts[0] = if (context.overflow and start == 0) std.math.maxInt(u64) else end - start;
        counts[3] = 2 * (end - start);
    }
};
test "shared physical fill covers nondivisible physical ranges and checked histograms at1 3 16workers" {
    const n = 65549;
    const values = try a.alloc(usize, n);
    defer a.free(values);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: work.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = Fill.MIN_STACK_BYTES, .backing_allocator = a });
        defer pool.deinit();
        @memset(values, 0);
        var h0: [3]u64 = @splat(0);
        var h1: [2]u64 = @splat(0);
        try Fill.fill(Rows, a, .{ .values = values }, n, .{ &h0, &h1 }, .{ n, 2 * n }, &pool);
        for (values, 0..) |value, i| try std.testing.expectEqual(i + 1, value);
        try std.testing.expectEqualSlices(u64, &.{ n, 0, 0 }, &h0);
        try std.testing.expectEqualSlices(u64, &.{ 2 * n, 0 }, &h1);
        @memset(&h0, 0);
        @memset(&h1, 0);
        try std.testing.expectError(error.InvalidNativeFillMass, Fill.fill(Rows, a, .{ .values = values, .overflow = true }, n, .{ &h0, &h1 }, .{ n, 2 * n }, &pool));
        try std.testing.expectEqualSlices(u64, &.{ 0, 0, 0 }, &h0);
        try std.testing.expectEqualSlices(u64, &.{ 0, 0 }, &h1);
    }
}
test "shared physical fill submission OOM and small-stack failures preserve outputs and drain leases" {
    const n = 16385;
    const values = try a.alloc(usize, n);
    defer a.free(values);
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = Fill.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    const available = pool.availableWorkers();
    for ([_]usize{ 0, 1 }) |after| {
        @memset(values, 91);
        var h0: [3]u64 = @splat(0);
        var h1: [2]u64 = @splat(0);
        try std.testing.expectError(error.InjectedNativeFillSubmissionFailure, Fill.testing.failSubmission(Rows, a, .{ .values = values }, n, .{ &h0, &h1 }, .{ n, 2 * n }, &pool, after));
        for (values) |value| try std.testing.expectEqual(@as(usize, 91), value);
        try std.testing.expectEqual(available, pool.availableWorkers());
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, Fill.fill(Rows, failing.allocator(), .{ .values = values }, n, .{ &h0, &h1 }, .{ n, 2 * n }, &pool));
        for (values) |value| try std.testing.expectEqual(@as(usize, 91), value);
        try Fill.fill(Rows, a, .{ .values = values }, n, .{ &h0, &h1 }, .{ n, 2 * n }, &pool);
    }
    var small: work.WorkPool = .{};
    try small.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = Fill.MIN_STACK_BYTES / 2, .backing_allocator = a });
    defer small.deinit();
    var h0: [3]u64 = @splat(0);
    var h1: [2]u64 = @splat(0);
    try std.testing.expectError(error.InvalidNativeFillStack, Fill.fill(Rows, a, .{ .values = values }, n, .{ &h0, &h1 }, .{ n, 2 * n }, &small));
    try std.testing.expectError(error.InvalidNativeFillShape, Fill.fill(Rows, a, .{ .values = values }, n, .{ &h0, h0[0..2] }, .{ n, 2 * n }, &pool));
}
const Job = struct {
    const CHUNK = 1000;
    output: []Q,
    summaries: [][2]Q,
    completed: *std.atomic.Value(usize),
    start: usize,
    end: usize,
    stride: usize,
    fail_correct: ?bool = null,
    correct: bool = false,
    failure: ?anyerror = null,
    pub fn validateTotals(_: *const Job, _: [2]Q) !void {}
    pub fn run(self: *Job) void {
        if (self.correct) {
            for (self.start..self.end) |p| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, 14), 14);
                const offset = self.summaries[logical / CHUNK];
                self.output[p] = self.output[p].add(offset[0].add(offset[1]));
            }
        } else {
            var chunk = self.start;
            while (chunk < self.end) : (chunk += self.stride) {
                var sums: [2]Q = @splat(Q.zero());
                for (chunk * CHUNK..@min(self.output.len, (chunk + 1) * CHUNK)) |i| {
                    sums[0] = sums[0].add(Q.fromBase(M.fromCanonical(@intCast(i + 1))));
                    sums[1] = sums[1].sub(Q.fromBase(M.fromCanonical(@intCast(2 * i + 3))));
                    self.output[core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(i, 14), 14)] = sums[0].add(sums[1]);
                }
                self.summaries[chunk] = sums;
            }
        }
        _ = self.completed.fetchAdd(1, .seq_cst);
        if (self.fail_correct == self.correct) self.failure = error.InjectedNativeKernelFailure;
    }
};
fn jobsFor(jobs: []Job, output: []Q, summaries: [][2]Q, completed: *std.atomic.Value(usize)) void {
    for (jobs, 0..) |*job, i| job.* = .{ .output = output, .summaries = summaries, .completed = completed, .start = i, .end = summaries.len, .stride = jobs.len };
}
test "shared prefix waves preserve exact prefixes with partial chunks shifted physical halos and1 3 16workers" {
    const n = 16384;
    const output = try a.alloc(Q, n);
    defer a.free(output);
    const summaries = try a.alloc([2]Q, 17);
    defer a.free(summaries);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: work.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = Fill.MIN_STACK_BYTES, .backing_allocator = a });
        defer pool.deinit();
        var jobs: [16]Job = undefined;
        var completed: std.atomic.Value(usize) = .init(0);
        jobsFor(jobs[0..workers], output, summaries, &completed);
        const totals = try Prefix.run(2, Job, jobs[0..workers], summaries, n, &pool);
        var sum = Q.zero();
        for (0..n) |logical| {
            sum = sum.add(Q.fromBase(M.fromCanonical(@intCast(logical + 1)))).sub(Q.fromBase(M.fromCanonical(@intCast(2 * logical + 3))));
            const p = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, 14), 14);
            try std.testing.expect(sum.sub(totals[0]).sub(totals[1]).eql(output[p]));
        }
        try std.testing.expectEqual(2 * workers, completed.load(.seq_cst));
    }
}
test "shared prefix both-wave partial submissions and callback failures drain leases before cleanup and reuse" {
    const output = try a.alloc(Q, 16384);
    defer a.free(output);
    var summaries: [17][2]Q = undefined;
    var jobs: [4]Job = undefined;
    var completed: std.atomic.Value(usize) = .init(0);
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = Fill.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    const available = pool.availableWorkers();
    for (0..2) |which| for (0..2) |after| {
        jobsFor(&jobs, output, &summaries, &completed);
        try std.testing.expectError(error.InjectedNativePrefixSubmissionFailure, Prefix.testing.failSubmission(2, Job, &jobs, &summaries, output.len, &pool, which, after));
        try std.testing.expectEqual(available, pool.availableWorkers());
        jobsFor(&jobs, output, &summaries, &completed);
        _ = try Prefix.run(2, Job, &jobs, &summaries, output.len, &pool);
    };
    for ([_]bool{ false, true }) |correct| {
        jobsFor(&jobs, output, &summaries, &completed);
        completed.store(0, .seq_cst);
        jobs[0].fail_correct = correct;
        try std.testing.expectError(error.InjectedNativeKernelFailure, Prefix.run(2, Job, &jobs, &summaries, output.len, &pool));
        try std.testing.expectEqual(@as(usize, if (correct) 8 else 4), completed.load(.seq_cst));
        try std.testing.expectEqual(available, pool.availableWorkers());
    }
}
