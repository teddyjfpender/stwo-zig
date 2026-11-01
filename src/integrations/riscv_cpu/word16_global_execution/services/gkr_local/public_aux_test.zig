const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const MP = @import("../../../logup_gkr/mle_point.zig");
const Aux = @import("public_aux.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Poly = engine.poly.circle.CircleCoefficients;
const Point = MP.MleEvalPointFor(O);
const a = std.testing.allocator;
fn pointFor(log: u32) !Point {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    var values: [MP.MAX_VARIABLES]O = undefined;
    for (values[0..log]) |*v| v.* = channel.drawSecureFelt();
    return Point.init(values[0..log]);
}
fn release(allocator: std.mem.Allocator, polys: *[10]Poly) void {
    for (polys) |*p| p.deinit(allocator);
}
/// Untouched previous construction, intentionally independent of optimized
/// physical indexing and coefficient ownership/interpolation scheduling.
fn original(allocator: std.mem.Allocator, point: *const Point, log: u32) ![10]Poly {
    const rows = @as(usize, 1) << @intCast(log);
    var out: [10]Poly = undefined;
    var done: usize = 0;
    errdefer for (out[0..done]) |*p| p.deinit(allocator);
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    for (&out, 0..) |*coefficient, column| {
        const values = try allocator.alloc(M, rows);
        defer allocator.free(values);
        @memset(values, M.zero());
        if (column < 8) {
            for (0..rows) |logical| {
                const t: usize = @ctz(~(logical / 2));
                const q = if (logical % 2 == 0) point.hc0[t] else point.hc1[t];
                values[A.witness.physical(logical, log)] = q.toM31Array()[column];
            }
        } else values[A.witness.physical(column - 8, log)] = M.one();
        coefficient.* = try engine.poly.circle.poly.interpolateFromEvaluation(allocator, try engine.poly.circle.evaluation.CircleEvaluation.init(domain, values));
        done += 1;
    }
    return out;
}
fn same(expected: *const [10]Poly, actual: *const [10]Poly) !void {
    for (expected, actual, 0..) |e, v, i| {
        try std.testing.expectEqual(e.log_size, v.log_size);
        try std.testing.expectEqualSlices(M, e.coeffs, v.coeffs);
        try std.testing.expect(v.owns_coeffs);
        for (actual[i + 1 ..]) |other| {
            const start = @intFromPtr(v.coeffs.ptr);
            const end = start + v.coeffs.len * @sizeOf(M);
            const second = @intFromPtr(other.coeffs.ptr);
            try std.testing.expect(end <= second or second + other.coeffs.len * @sizeOf(M) <= start);
        }
    }
}
test "one-pass public auxiliaries match every untouched scalar coefficient" {
    for (1..15) |log_value| {
        const log: u32 = @intCast(log_value);
        const point = try pointFor(log);
        const before = point;
        var expected = try original(a, &point, log);
        defer release(a, &expected);
        var actual = try Aux.init(a, &point, log, null);
        defer release(a, &actual);
        try same(&expected, &actual);
        try std.testing.expectEqualDeep(before.p, point.p);
        try std.testing.expectEqualSlices(O, before.hc0[0..log], point.hc0[0..log]);
        try std.testing.expectEqualSlices(O, before.hc1[0..log], point.hc1[0..log]);
        try std.testing.expect(before.eq0.eql(point.eq0) and before.eq1.eql(point.eq1));
    }
}
test "public auxiliary pooled transforms and held lease preserve coefficients" {
    const point = try pointFor(18);
    var expected = try original(a, &point, 18);
    defer release(a, &expected);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1 << 20 });
    defer pool.deinit();
    var pooled = try Aux.init(a, &point, 18, &pool);
    defer release(a, &pooled);
    try same(&expected, &pooled);
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    defer lease.deinit();
    var held = try Aux.init(a, &point, 18, &pool);
    defer release(a, &held);
    try same(&expected, &held);
}
fn lifecycle(allocator: std.mem.Allocator, point: Point) !void {
    var polys = try Aux.init(allocator, &point, 6, null);
    defer release(allocator, &polys);
}
test "public auxiliary admission and allocation cleanup never mutate point or alias owners" {
    const point = try pointFor(6);
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{point});
    const p = try Aux.plan(6);
    var budget = engine.host_budget_allocator.HostBudgetAllocator.init(a, p.peak_requested_heap_bytes);
    var polys = try Aux.init(budget.allocator(), &point, 6, null);
    release(budget.allocator(), &polys);
    try std.testing.expectEqual(@as(usize, 0), budget.live_bytes);
    try std.testing.expect(budget.peak_live_bytes <= p.peak_requested_heap_bytes);
    var none = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidPublicAuxGeometry, Aux.init(none.allocator(), &point, 5, null));
    try std.testing.expectEqual(@as(usize, 0), none.alloc_index);
    try std.testing.expectError(error.InvalidPublicAuxGeometry, Aux.plan(0));
    try std.testing.expectError(error.InvalidPublicAuxGeometry, Aux.plan(23));
    var degenerate: [6]O = @splat(O.one());
    try std.testing.expectError(error.DegenerateEvalPoint, Point.init(&degenerate));
    degenerate[0] = O.zero();
    try std.testing.expectError(error.DegenerateEvalPoint, Point.init(&degenerate));
}
