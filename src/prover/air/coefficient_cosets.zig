//! Bounded coefficient expansion under the composition task's worker lease.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Poly = @import("component_trace.zig").Poly;
const circle = @import("../poly/circle/mod.zig");
const twiddles = @import("../poly/twiddles.zig");
const graph = @import("../task_graph.zig");
const pool = @import("../work_pool.zig");

pub fn fill(sources: []const Poly, buffers: []const []M31, domain: circle.CircleDomain, transform: twiddles.TwiddleTree([]const M31), context: *graph.TaskContext) !void {
    if (sources.len != buffers.len) return error.InvalidProofShape;
    if (sources.len == 0) return;
    const Worker = struct {
        sources: []const Poly,
        buffers: []const []M31,
        domain: circle.CircleDomain,
        transform: twiddles.TwiddleTree([]const M31),
        cancellation: *const graph.CancellationToken,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.evaluate() catch |err| {
                self.failure = err;
            };
        }
        fn evaluate(self: *@This()) !void {
            for (self.sources, self.buffers) |source, values| {
                if (self.cancellation.isCancelled()) return;
                const coefficients = (source.coefficients orelse return error.InvalidProofShape).coefficients();
                if (values.len != self.domain.size() or coefficients.len > values.len) return error.InvalidProofShape;
                @memcpy(values[0..coefficients.len], coefficients);
                @memset(values[coefficients.len..], M31.zero());
                try circle.poly.evaluateBuffersWithTwiddles(&.{values}, self.domain, self.transform);
            }
        }
    };
    var workers: [pool.MAX_WORKERS]Worker = undefined;
    const count = @min(sources.len, if (context.task_class == .pool_exclusive) context.worker_budget.count else 1);
    if (count == 0 or count > workers.len) return error.InvalidProofShape;
    defer context.joinChildren();
    for (workers[0..count], 0..) |*worker, i| {
        const start = sources.len * i / count;
        const end = sources.len * (i + 1) / count;
        worker.* = .{ .sources = sources[start..end], .buffers = buffers[start..end], .domain = domain, .transform = .{ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles }, .cancellation = context.cancellation };
    }
    for (workers[1..count]) |*worker| try context.spawnChild(Worker.run, .{worker});
    workers[0].run();
    if (count > 1) try context.waitForChildren();
    for (workers[0..count]) |worker| if (worker.failure) |failure| return failure;
}
