const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = core.fri.ForField(O);
const Native = @import("fri_om_cpu.zig");
const Pools = @import("work_pool.zig");
const a = std.testing.allocator;
fn value(seed: usize) O {
    var coords: [8]M = undefined;
    for (&coords, 0..) |*c, i| c.* = M.fromCanonical(@intCast((seed * 7919 + i * 983 + 17) % 1048573));
    return O.fromM31Array(coords);
}
fn parity(workers: ?usize, held: bool) !void {
    var pool: Pools.WorkPool = undefined;
    if (workers) |n| try pool.initInPlaceWithOptions(.{ .worker_count = n, .stack_size = 1 << 20 });
    defer if (workers != null) pool.deinit();
    var binding = if (workers != null) try Pools.ScopedPoolBinding.init(&pool) else null;
    defer if (binding) |*b| b.deinit();
    var lease = if (held and workers != null) try pool.acquire(try Pools.WorkerBudget.init(workers.?)) else null;
    defer if (lease) |*l| l.deinit();
    for ([_]u32{ 2, 5, 15 }) |log| {
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const rows = domain.size();
        var columns: [8][]M = undefined;
        var done: usize = 0;
        defer for (columns[0..done]) |c| a.free(c);
        for (&columns, 0..) |*c, k| {
            c.* = try a.alloc(M, rows);
            done += 1;
            for (c.*, 0..) |*v, i| v.* = value(i + 31).toM31Array()[k];
        }
        const expected = try a.alloc(O, rows / 2);
        defer a.free(expected);
        const actual = try a.alloc(O, rows / 2);
        defer a.free(actual);
        @memset(expected, O.zero());
        @memset(actual, value(999)); // Fresh hook must overwrite, never accumulate.
        var workspace = try F.FoldCircleWorkspace.init(a, 0);
        defer workspace.deinit(a);
        var refs: [8][]const M = undefined;
        for (columns, &refs) |c, *v| v.* = c;
        try F.foldCircleColumnsIntoLineWithWorkspace(a, expected, refs, domain, value(61), &workspace);
        try Native.foldCircleFreshIntoLine(a, actual, refs, domain, value(61), &workspace);
        try std.testing.expectEqualDeep(expected, actual);
        const line = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(log - 1));
        for ([_]u32{ 0, 1, @min(4, log - 1) }) |folds| {
            var x = try a.dupe(O, expected);
            var y = try a.dupe(O, expected);
            var x_owner = true;
            var y_owner = true;
            defer if (x_owner) a.free(x);
            defer if (y_owner) a.free(y);
            var w0 = try F.FoldLineWorkspace.init(a, 0);
            defer w0.deinit(a);
            var w1 = try F.FoldLineWorkspace.init(a, 0);
            defer w1.deinit(a);
            x = (try F.foldLineInPlaceNWithWorkspace(a, x, line, value(71), &w0, folds)).values;
            y = (try Native.foldLineN(a, y, line, value(71), &w1, folds)).values;
            try std.testing.expectEqualDeep(x, y);
            a.free(x);
            x_owner = false;
            a.free(y);
            y_owner = false;
        }
    }
}
test "packed pooled OM FRI exact circle and multi-line folds across short tails and real parallel ranges" {
    try parity(null, false);
    try parity(3, false);
    try parity(3, true);
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    const rows = 256;
    var values = try allocator.alloc(O, rows);
    defer allocator.free(values);
    for (values, 0..) |*v, i| v.* = value(i);
    var workspace = try F.FoldLineWorkspace.init(allocator, 0);
    defer workspace.deinit(allocator);
    const domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(8));
    const folded = try Native.foldLineN(allocator, values, domain, value(9), &workspace, 4);
    values = folded.values;
}
test "packed OM FRI keeps original ownership on every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
test "packed OM FRI explicit scratch refusal preserves scalar proof law" {
    var values = try a.alloc(O, 64);
    defer a.free(values);
    for (values, 0..) |*v, i| v.* = value(i);
    var expected = try a.dupe(O, values);
    defer a.free(expected);
    var w0 = try F.FoldLineWorkspace.init(a, 0);
    defer w0.deinit(a);
    var w1 = try F.FoldLineWorkspace.init(a, 0);
    defer w1.deinit(a);
    const domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(6));
    expected = (try F.foldLineInPlaceNWithWorkspace(a, expected, domain, value(5), &w0, 3)).values;
    values = (try Native.foldLineNWithLimit(a, values, domain, value(5), &w1, 3, 0)).values;
    try std.testing.expectEqualDeep(expected, values);
    try std.testing.expectError(error.InvalidEvaluationLength, Native.foldLineN(a, values, domain, value(5), &w1, 9));
}

test "OM fresh circle rejects wrong domain and non-power-two destination before writes" {
    const data = try a.alloc(M, 64);
    defer a.free(data);
    @memset(data, M.one());
    const dst = try a.alloc(O, 32);
    defer a.free(dst);
    @memset(dst, value(99));
    const src: [8][]const M = @splat(data);
    var workspace = try F.FoldCircleWorkspace.init(a, 0);
    defer workspace.deinit(a);
    try std.testing.expectError(error.ShapeMismatch, Native.foldCircleFreshIntoLine(a, dst, src, core.poly.circle.canonic.CanonicCoset.new(5).circleDomain(), value(3), &workspace));
    const short: [8][]const M = @splat(data[0..60]);
    try std.testing.expectError(error.ShapeMismatch, Native.foldCircleFreshIntoLine(a, dst[0..30], short, core.poly.circle.canonic.CanonicCoset.new(6).circleDomain(), value(3), &workspace));
    for (dst) |v| try std.testing.expectEqualDeep(value(99), v);
}
