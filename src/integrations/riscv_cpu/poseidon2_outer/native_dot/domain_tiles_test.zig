//! Row scheduling parity on independently instantiated component equations.
//! The synthetic domain values intentionally need not be a satisfying witness;
//! no proof or verifier authority is inferred from this evaluator unit test.
const std = @import("std");
const Core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const K = @import("outer_authority.zig");
const W = @import("outer_witness.zig");
const A = @import("../authority.zig");
const Domain = E.air.accumulation.ForField(A.O);
const PC = E.air.component_prover.ForField(A.O);
fn evaluate(a: std.mem.Allocator, component: anytype, trace: *const PC.Trace, log: u32) !E.secure_column.SecureColumnByCoordsFor(A.O) {
    var acc = try Domain.DomainEvaluationAccumulator.init(a, A.O.fromBase(A.M.fromCanonical(37)), log, component.nConstraints());
    defer acc.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &acc);
    return acc.finalize();
}
fn same(a: std.mem.Allocator, left: anytype, right: anytype) !void {
    const x = try left.toVec(a);
    defer a.free(x);
    const y = try right.toVec(a);
    defer a.free(y);
    try std.testing.expectEqualDeep(x, y);
}
test "native dot packed domain disjoint tiles equal serial and saturated lease fallback" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    {
        const a = budget.allocator();
        var ctx = try @import("recursive_test.zig").source(a, 7, 3, false);
        defer ctx.deinit();
        var key = try K.Key.init(a, &ctx, .op_target_b4_q72_p0_fold4_v1);
        defer key.deinit();
        const log = @max(key.dot_log, key.input_log) + 1;
        const input_starts = [3]usize{ K.INPUT_FIXED_START, K.INPUT_MAIN_START, K.INPUT_INTER_START };
        var trees: [3][]const E.air.component_trace.Poly = undefined;
        var made: usize = 0;
        defer for (trees[0..made]) |columns| {
            for (columns) |poly| a.free(@constCast(poly.values));
            a.free(columns);
        };
        for (&trees, [_]usize{ K.FIXED_COUNT, K.MAIN_COUNT, K.INTER_COUNT }, 0..) |*tree, width, t| {
            const columns = try a.alloc(E.air.component_trace.Poly, width);
            var initialized: usize = 0;
            errdefer {
                for (columns[0..initialized]) |poly| a.free(@constCast(poly.values));
                a.free(columns);
            }
            for (columns, 0..) |*poly, c| {
                const column_log = (if (c >= input_starts[t]) key.input_log else key.dot_log) + 1;
                const values = try a.alloc(A.M, @as(usize, 1) << @intCast(column_log));
                for (values, 0..) |*v, r| v.* = A.M.fromCanonical(@intCast(1 + 97 * c + 49157 * r + 7919 * t));
                poly.* = .{ .log_size = column_log, .values = values };
                initialized += 1;
            }
            tree.* = columns;
            made += 1;
        }
        const trace = PC.Trace{ .polys = .{ .items = &trees } };
        const elements = W.Elements.init(A.O.fromBase(A.M.fromCanonical(1234567)), A.O.fromBase(A.M.fromCanonical(1741)));
        const dot = @import("outer_component.zig").Component{ .key = &key, .elements = elements, .claim = A.O.fromBase(A.M.fromCanonical(97)) };
        const input = @import("input_component.zig").Component{ .key = &key, .elements = elements, .claim = A.O.fromBase(A.M.fromCanonical(101)) };
        var serial_dot = try evaluate(a, &dot, &trace, log);
        defer serial_dot.deinit(a);
        var serial_input = try evaluate(a, &input, &trace, log);
        defer serial_input.deinit(a);
        var pool: E.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
        defer pool.deinit();
        var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var parallel_dot = try evaluate(a, &dot, &trace, log);
        defer parallel_dot.deinit(a);
        var parallel_input = try evaluate(a, &input, &trace, log);
        defer parallel_input.deinit(a);
        try same(a, serial_dot, parallel_dot);
        try same(a, serial_input, parallel_input);
        try std.testing.expectEqual(@as(usize, 4), pool.availableWorkers());
        var held = try pool.acquire(try E.work_pool.WorkerBudget.init(4));
        defer held.deinit();
        var fallback_dot = try evaluate(a, &dot, &trace, log);
        defer fallback_dot.deinit(a);
        var fallback_input = try evaluate(a, &input, &trace, log);
        defer fallback_input.deinit(a);
        try same(a, serial_dot, fallback_dot);
        try same(a, serial_input, fallback_input);
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
test "native dot packed domain tiles join failures and release worker admission" {
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var counts: [128]std.atomic.Value(u32) = undefined;
    for (&counts) |*v| v.* = .init(0);
    const Kernel = struct {
        counts: []std.atomic.Value(u32),
        pub fn runRange(self: *const @This(), first: usize, end: usize) !void {
            for (self.counts[first..end]) |*v| _ = v.fetchAdd(1, .monotonic);
            if (first == 0) return error.DeliberateRowFailure;
        }
    };
    const kernel = Kernel{ .counts = &counts };
    try std.testing.expectError(error.DeliberateRowFailure, @import("domain_tiles.zig").run(Kernel, &kernel, 128, 16));
    for (&counts) |*v| try std.testing.expectEqual(@as(u32, 1), v.load(.acquire));
    try std.testing.expectEqual(@as(usize, 4), pool.availableWorkers());
}
