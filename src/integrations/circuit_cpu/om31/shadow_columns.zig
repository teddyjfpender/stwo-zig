//! Exact 2n coefficient views for the native OM31 circuit evaluator. Each
//! requested column keeps its minimal coefficient domain and lifting semantics.
//! Twiddles are immutable, shared only within this call, and released after all
//! bounded helper jobs join. There is no process-wide expansion cache.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const M = Core.fields.m31.M31;
const Trace = Engine.air.component_trace.Trace;
const Twiddles = Engine.poly.twiddles;
const Tree = Twiddles.TwiddleTree([]M);
const Pool = Engine.work_pool;
pub const Request = struct { tree: u8, column: usize };
pub const Shadow = struct {
    values: [3][]?[]M,
    pub fn deinit(self: *Shadow, a: std.mem.Allocator) void {
        for (self.values) |tree| {
            for (tree) |entry| if (entry) |values| a.free(values);
            a.free(tree);
        }
    }
};
const Job = struct {
    request: Request,
    coefficients: Engine.poly.circle.CircleCoefficients,
    log: u32,
    output: *?[]M,
    failure: ?anyerror = null,
};
const Work = struct {
    allocator: std.mem.Allocator,
    jobs: []Job,
    trees: *const [32]?Tree,
    next: *std.atomic.Value(usize),
    fn run(self: *const Work) void {
        while (true) {
            const index = self.next.fetchAdd(1, .monotonic);
            if (index >= self.jobs.len) return;
            const job = &self.jobs[index];
            self.evaluate(job) catch |err| {
                job.failure = err;
            };
        }
    }
    fn evaluate(self: *const Work, job: *Job) !void {
        const tree = self.trees[job.log].?;
        const domain = Core.poly.circle.canonic.CanonicCoset.new(job.log).circleDomain();
        const value = try job.coefficients.evaluateWithTwiddles(self.allocator, domain, .{ .root_coset = tree.root_coset, .twiddles = tree.twiddles, .itwiddles = tree.itwiddles });
        job.output.* = @constCast(value.values);
    }
};
pub fn prepare(a: std.mem.Allocator, trace: *const Trace, requests: []const Request, pool: ?*Pool.WorkPool) !Shadow {
    var shadow: Shadow = .{ .values = undefined };
    var made: usize = 0;
    errdefer for (shadow.values[0..made]) |tree| {
        for (tree) |entry| if (entry) |values| a.free(values);
        a.free(tree);
    };
    for (&shadow.values, 0..) |*tree, t| {
        tree.* = try a.alloc(?[]M, if (t < trace.polys.items.len) trace.polys.items[t].len else 0);
        @memset(tree.*, null);
        made += 1;
    }
    var jobs: std.ArrayList(Job) = .empty;
    defer jobs.deinit(a);
    for (requests) |request| {
        if (request.tree >= 3 or request.tree >= trace.polys.items.len or request.column >= trace.polys.items[request.tree].len) return error.MissingOm31Trace;
        const source = trace.polys.items[request.tree][request.column];
        try source.validate();
        if (source.device != null) return error.Om31CircuitRequiresHostLde;
        const coefficients = source.coefficients orelse return error.Om31CircuitRequiresHostLde;
        const log = coefficients.logSize() + 1;
        // Compact storage keeps the domain tag but releases its host LDE.
        // A matching tag alone does not make host values available.
        if (source.log_size == log and source.values.len != 0) continue;
        if (log >= 32) return error.InvalidLogSize;
        var duplicate = false;
        for (jobs.items) |job| if (std.meta.eql(job.request, request)) {
            duplicate = true;
            break;
        };
        if (duplicate) continue;
        try jobs.append(a, .{ .request = request, .coefficients = coefficients, .log = log, .output = &shadow.values[request.tree][request.column] });
    }
    var trees: [32]?Tree = @splat(null);
    defer for (&trees) |*maybe| if (maybe.*) |*tree| Twiddles.deinitM31(a, tree);
    for (jobs.items) |job| if (trees[job.log] == null) {
        const domain = Core.poly.circle.canonic.CanonicCoset.new(job.log).circleDomain();
        trees[job.log] = Twiddles.precomputeM31(a, domain.half_coset) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.SingularTwiddle => return error.SingularSystem,
        };
    };
    var next = std.atomic.Value(usize).init(0);
    const work = Work{ .allocator = a, .jobs = jobs.items, .trees = &trees, .next = &next };
    const workers = if (pool) |active| @min(active.workerCount(), jobs.items.len) else 1;
    if (workers < 2) {
        work.run();
    } else {
        var lease = try pool.?.acquire(try Pool.WorkerBudget.init(workers));
        defer lease.deinit();
        var group = std.Thread.WaitGroup{};
        var joined = false;
        defer {
            if (!joined) group.wait();
            lease.completeWave();
        }
        for (1..workers) |_| try lease.spawnWg(&group, Work.run, .{&work});
        work.run();
        group.wait();
        joined = true;
    }
    for (jobs.items) |job| if (job.failure) |err| return err;
    return shadow;
}

fn qualify(a: std.mem.Allocator, parallel: bool) !void {
    const Poly = Engine.air.component_trace.Poly;
    const Coeff = Engine.poly.circle.CircleCoefficients;
    var aa: [8]M = undefined;
    var bb: [16]M = undefined;
    for (&aa, 0..) |*v, i| v.* = M.fromCanonical(@intCast(7 + 11 * i));
    for (&bb, 0..) |*v, i| v.* = M.fromCanonical(@intCast(19 + 13 * i));
    const ac = try Coeff.initBorrowed(&aa);
    const bc = try Coeff.initBorrowed(&bb);
    const already = [_]M{M.one()} ** 16;
    const fixed = [_]Poly{
        .{ .log_size = 6, .values = &.{}, .coefficients = ac },
        .{ .log_size = 4, .values = &already, .coefficients = ac },
        .{ .log_size = 4, .values = &.{}, .coefficients = ac },
    };
    const main = [_]Poly{.{ .log_size = 6, .values = &.{}, .coefficients = bc }};
    var trees = [_][]const Poly{ &fixed, &main, &.{} };
    const trace = Trace{ .polys = .{ .items = &trees } };
    var pool: Pool.WorkPool = .{};
    if (parallel) try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer if (parallel) pool.deinit();
    const requests = [_]Request{ .{ .tree = 0, .column = 0 }, .{ .tree = 1, .column = 0 }, .{ .tree = 0, .column = 0 }, .{ .tree = 0, .column = 1 }, .{ .tree = 0, .column = 2 } };
    var shadow = try prepare(a, &trace, &requests, if (parallel) &pool else null);
    defer shadow.deinit(a);
    const ae = try ac.evaluate(a, Core.poly.circle.canonic.CanonicCoset.new(4).circleDomain());
    defer a.free(@constCast(ae.values));
    const be = try bc.evaluate(a, Core.poly.circle.canonic.CanonicCoset.new(5).circleDomain());
    defer a.free(@constCast(be.values));
    try std.testing.expectEqualSlices(M, ae.values, shadow.values[0][0].?);
    try std.testing.expectEqualSlices(M, be.values, shadow.values[1][0].?);
    try std.testing.expect(shadow.values[0][1] == null);
    try std.testing.expectEqualSlices(M, ae.values, shadow.values[0][2].?);
}
test "OM31 shadow column preparation preserves minimal domains and duplicate read custody" {
    try qualify(std.testing.allocator, false);
    try qualify(std.testing.allocator, true);
}
test "OM31 shadow column preparation is failure atomic through twiddles and evaluations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, qualify, .{false});
}

test "OM31 shadow column requests reject invalid trees and columns" {
    const Poly = Engine.air.component_trace.Poly;
    var trees = [_][]const Poly{ &.{}, &.{}, &.{} };
    const trace = Trace{ .polys = .{ .items = &trees } };
    try std.testing.expectError(error.MissingOm31Trace, prepare(std.testing.allocator, &trace, &.{.{ .tree = 3, .column = 0 }}, null));
    try std.testing.expectError(error.MissingOm31Trace, prepare(std.testing.allocator, &trace, &.{.{ .tree = 0, .column = 0 }}, null));
}
