//! Coefficient-only compact columns exercise the real serial FFT path, including
//! matching-domain descriptors whose host LDE has been discarded.
const std = @import("std");
const Core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const P = @import("polynomials.zig").Prepared;
const M = Core.fields.m31.M31;
const Poly = E.air.component_trace.Poly;
const Trace = E.air.component_prover.ForField(Core.fields.om31.OM31).Trace;
const Fixture = struct {
    a: std.mem.Allocator,
    columns: []Poly,
    coefficients: []M,
    borrowed: []M,
    trees: [3][]const Poly,
    log: u32,
    fn init(a: std.mem.Allocator, count: usize, log: u32) !Fixture {
        const half = @as(usize, 1) << @intCast(log - 1);
        const coefficients = try a.alloc(M, count * half);
        errdefer a.free(coefficients);
        for (coefficients, 0..) |*v, i| v.* = M.fromCanonical(@intCast(1 + (i * 4099) % 1_000_000_000));
        const borrowed = try a.alloc(M, 2 * half);
        errdefer a.free(borrowed);
        for (borrowed, 0..) |*v, i| v.* = M.fromCanonical(@intCast(17 + 97 * i));
        const columns = try a.alloc(Poly, count);
        errdefer a.free(columns);
        for (columns, 0..) |*poly, i| poly.* = .{ .log_size = log, .values = if (i == 0) borrowed else &.{}, .coefficients = try E.poly.circle.CircleCoefficients.initBorrowed(coefficients[i * half ..][0..half]) };
        return .{ .a = a, .columns = columns, .coefficients = coefficients, .borrowed = borrowed, .trees = .{ columns, &.{}, &.{} }, .log = log };
    }
    fn deinit(self: *Fixture) void {
        self.a.free(self.columns);
        self.a.free(self.coefficients);
        self.a.free(self.borrowed);
    }
    fn trace(self: *Fixture) Trace {
        return .{ .polys = .{ .items = &self.trees } };
    }
};
fn same(left: *const P, right: *const P) !void {
    try std.testing.expectEqualSlices(bool, left.owned, right.owned);
    for (left.polys, right.polys) |x, y| {
        try std.testing.expectEqual(x.log_size, y.log_size);
        try std.testing.expectEqualSlices(M, x.values, y.values);
    }
}
test "native dot packed domain preparation compact columns parity bounded FFT probe and OOM joins" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    {
        const a = budget.allocator();
        var fixture = try Fixture.init(a, 12, 16);
        defer fixture.deinit();
        const trace = fixture.trace();
        var pool: E.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
        defer pool.deinit();
        var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var timer = try std.time.Timer.start();
        var serial = try P.initSerialForTest(a, &trace, fixture.log, .{ fixture.columns.len, 0, 0 }, .{ 0, 0, 0 });
        defer serial.deinit();
        const serial_ns = timer.lap();
        var parallel = try P.init(a, &trace, fixture.log, .{ fixture.columns.len, 0, 0 }, .{ 0, 0, 0 });
        defer parallel.deinit();
        const parallel_ns = timer.lap();
        try same(&serial, &parallel);
        try std.testing.expect(!parallel.owned[0]);
        try std.testing.expect(parallel.polys[0].values.ptr == fixture.borrowed.ptr);
        for (parallel.owned[1..]) |owned| try std.testing.expect(owned);
        {
            var held = try pool.acquire(try E.work_pool.WorkerBudget.init(4));
            defer held.deinit();
            var fallback = try P.init(a, &trace, fixture.log, .{ fixture.columns.len, 0, 0 }, .{ 0, 0, 0 });
            defer fallback.deinit();
            try same(&serial, &fallback);
        }
        const small = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 1 << 20);
        defer small.destroy();
        try std.testing.expectError(error.OutOfMemory, P.init(small.allocator(), &trace, fixture.log, .{ fixture.columns.len, 0, 0 }, .{ 0, 0, 0 }));
        try std.testing.expectEqual(@as(usize, 0), small.snapshot().live_bytes);
        try std.testing.expectEqual(@as(usize, 4), pool.availableWorkers());
        std.debug.print("OP_R7_PREPARE_FFT_PROBE columns={} target_log={} serial_ns={} parallel_ns={} workers=4 exact=true bounded_microprobe_not_block_benchmark=true\n", .{ fixture.columns.len, fixture.log, serial_ns, parallel_ns });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
fn allocationGraph(a: std.mem.Allocator, trace: *const Trace) !void {
    var prepared = try P.init(a, trace, 5, .{ 3, 0, 0 }, .{ 0, 0, 0 });
    defer prepared.deinit();
}
test "native dot packed domain preparation failure atomic borrowed custody and degree refusal" {
    var fixture = try Fixture.init(std.testing.allocator, 3, 5);
    defer fixture.deinit();
    const trace = fixture.trace();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationGraph, .{&trace});
    try std.testing.expectError(error.NativeDotPhysicalDegree, P.init(std.testing.allocator, &trace, 3, .{ 3, 0, 0 }, .{ 0, 0, 0 }));
    try std.testing.expectError(error.NativeDotPhysicalTrace, P.init(std.testing.allocator, &trace, 5, .{ std.math.maxInt(usize), 1, 0 }, .{ 0, 0, 0 }));
}
