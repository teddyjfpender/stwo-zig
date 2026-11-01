const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Columns = @import("commitment_tree.zig");
const Sampling = @import("sampled_values_field.zig");
const API = Sampling.ForField(O);
const Wide = @import("../poly/circle/point_evaluation_wide.zig");
const Poly = @import("../poly/circle/poly.zig");
const Factors = @import("../poly/circle/point_evaluation_family.zig").ForField(O);
const Pools = @import("../work_pool.zig");
const a = std.testing.allocator;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const B = Columns.HostMerkleBackend;
const Tree = Columns.CommitmentTreeProverForBackend(B, H);
fn dense(i: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, j| v.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return O.fromM31Array(c);
}
fn reference(c: []const M, p: Point) O {
    var buffer: [core.circle.M31_CIRCLE_LOG_ORDER]O = undefined;
    const factors = Factors.fillEvalFactorsForPoint(p, std.math.log2_int(usize, c.len), &buffer);
    var result = O.zero();
    for (c, 0..) |coefficient, i| {
        var weight = O.one();
        for (factors, 0..) |factor, bit| if (i & (@as(usize, 1) << @intCast(bit)) != 0) {
            weight = weight.mul(factor);
        };
        result = result.add(weight.mulM31(coefficient));
    }
    return result;
}
fn fixture(allocator: std.mem.Allocator, comptime log: u32, options: Sampling.Options) !void {
    const n = 1 << log;
    const coefficients = try allocator.alloc(M, n);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*v, i| v.* = if (i % 3 == 0) M.one().neg() else M.fromCanonical(@intCast(i * 7 + 3));
    // Retained polynomial degree can be lower than the committed column log.
    // The fold normalizes by the COLUMN log, not coefficient log.
    var columns = [_]Columns.ColumnEvaluation{
        .{ .log_size = log + 2, .values = &.{}, .coefficient_values = coefficients },
        .{ .log_size = log + 1, .values = &.{}, .coefficient_values = coefficients },
        .{ .log_size = log + 2, .values = &.{}, .coefficient_values = coefficients },
    };
    // Sampling only touches descriptor/coefficients; no Merkle payload is read.
    var trees = [_]Tree{
        .{ .columns = &columns, .coefficients = null, .commitment = undefined, .compact_polynomials = true },
        .{ .columns = columns[0..1], .coefficients = null, .commitment = undefined, .compact_polynomials = true },
    };
    const p = Point{ .x = dense(3), .y = dense(5) };
    const q = Point{ .x = dense(7).neg(), .y = dense(11) };
    var p0 = [_]Point{ p, p, q };
    var p1 = [_]Point{p};
    var p2 = [_]Point{ p, q };
    var p3 = [_]Point{ p, q };
    var points0 = [_][]Point{ &p0, &p1, &p2 };
    var points1 = [_][]Point{&p3};
    var point_trees = [_][][]Point{ &points0, &points1 };
    // Use mutable local lists only because TreeVec models borrowed input lists.
    var result = try API.evaluateWithOptions(B, H, allocator, &trees, core.pcs.TreeVec([][]Point).initOwned(&point_trees), log + 4, options);
    defer result.deinitDeep(allocator);
    for (trees, point_trees, result.items) |tree, pss, values| for (tree.columns, pss, values) |column, ps, vs| {
        for (ps, vs) |point, v| try std.testing.expectEqualDeep(reference(coefficients, point.repeatedDouble(log + 4 - column.log_size)), v);
    };
    for (trees) |tree| try std.testing.expect(tree.columns[0].coefficient_values != null);
}
test "wide sampling groups across trees preserve exact folded points and cap fallback" {
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try fixture(a, 10, .{});
    try fixture(a, 5, .{ .allow_parallel = false });
    try fixture(a, 5, .{ .scratch_limit = 1 });
    var lease = try pool.acquire(try Pools.WorkerBudget.init(4));
    defer lease.deinit();
    try fixture(a, 5, .{});
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    try fixture(allocator, 3, .{});
}
test "wide sampled grouping allocation failures retain input coefficients and clean all temporary owners" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
test "wide split basis has sqrt geometry and matches independent coefficient products" {
    const p = Point{ .x = dense(13), .y = dense(17).neg() };
    for ([_]u32{ 0, 1, 2, 3, 7, 8, 9, 12 }) |log| {
        const coefficients = try a.alloc(M, @as(usize, 1) << @intCast(log));
        defer a.free(coefficients);
        for (coefficients, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 23 + 7));
        var basis = try Wide.Basis.init(a, p, log);
        defer basis.deinit(a);
        try std.testing.expect(basis.storage.len <= 2 * (@as(usize, 1) << @intCast((log + 1) / 2)));
        try std.testing.expectEqualDeep(reference(coefficients, p), basis.evaluate(coefficients));
        const poly = try Poly.CircleCoefficients.initBorrowed(coefficients);
        try std.testing.expectEqualDeep(poly.evalAtPointFor(O, p), basis.evaluate(coefficients));
    }
}
test "optional wide sampled scalar vs shared split basis kernel benchmark" {
    if (!std.process.hasEnvVarConstant("STWO_ZIG_BENCH_WIDE_SAMPLING")) return;
    const log: u32 = 16;
    const rows = 1 << log;
    const columns = 16;
    const c = try a.alloc(M, rows * columns);
    defer a.free(c);
    for (c, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i % 1048573));
    const p = Point{ .x = dense(19), .y = dense(23) };
    var timer = try std.time.Timer.start();
    var sum = O.zero();
    for (0..columns) |ci| {
        const poly = try Poly.CircleCoefficients.initBorrowed(c[ci * rows ..][0..rows]);
        sum = sum.add(poly.evalAtPointFor(O, p));
    }
    const scalar_ns = timer.read();
    std.mem.doNotOptimizeAway(sum);
    timer.reset();
    var basis = try Wide.Basis.init(a, p, log);
    defer basis.deinit(a);
    var actual = O.zero();
    for (0..columns) |ci| actual = actual.add(basis.evaluate(c[ci * rows ..][0..rows]));
    const split_ns = timer.read();
    std.mem.doNotOptimizeAway(actual);
    try std.testing.expectEqualDeep(sum, actual);
    std.debug.print("WIDE_SAMPLE_KERNEL columns={d} log={d} scalar_ns={d} split_including_basis_ns={d} basis_bytes={d} speedup={d:.3}\n", .{ columns, log, scalar_ns, split_ns, basis.storage.len * @sizeOf(O), @as(f64, @floatFromInt(scalar_ns)) / @as(f64, @floatFromInt(split_ns)) });
}
