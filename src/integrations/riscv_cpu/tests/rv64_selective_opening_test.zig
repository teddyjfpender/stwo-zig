const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circle = engine.poly.circle;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn check(log: u32, extra: u32, positions: []const usize) !void {
    const n = @as(usize, 1) << @intCast(log);
    const coefficients = try a.alloc(M, n >> @intCast(extra));
    defer a.free(coefficients);
    for (coefficients, 0..) |*v, i| v.* = M.fromU64(17 + i * i * 19);
    const p = try circle.CircleCoefficients.initBorrowed(coefficients);
    const domain = circle.CanonicCoset.new(log).circleDomain();
    const reference = try p.evaluate(a, domain);
    defer a.free(reference.values);
    var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &tw);
    const view = engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles);
    const scratch = try a.alloc(M, if (extra == 1 and log > 5) n / 2 else n);
    defer a.free(scratch);
    const out = try a.alloc(M, positions.len);
    defer a.free(out);
    try circle.poly.evaluateSelectedCoefficientsWithTwiddles(coefficients, scratch, domain, view, positions, out);
    for (positions, out) |position, value| {
        try std.testing.expectEqual(reference.values[position], value);
        if (log <= 7) {
            const point = domain.at(core.utils.bitReverseIndex(position, log));
            try std.testing.expectEqual(Q.fromBase(value), p.evalAtPoint(.{ .x = Q.fromBase(point.x), .y = Q.fromBase(point.y) }));
        }
    }
}
test "sparse half windows match full packed FFT and scalar circle-basis evaluation across small logs" {
    for (1..13) |l| {
        const log: u32 = @intCast(l);
        const n = @as(usize, 1) << @intCast(log);
        const positions = try a.alloc(usize, n);
        defer a.free(positions);
        for (positions, 0..) |*p, i| p.* = i;
        for (0..@min(l, 3)) |extra| try check(log, @intCast(extra), positions);
        try check(log, 1, &.{});
    }
}
test "pruned half windows preserve repeated targets either half and sparse radix frontiers" {
    for (6..19) |l| {
        const log: u32 = @intCast(l);
        const n = @as(usize, 1) << @intCast(log);
        var positions: [73]usize = undefined;
        for (&positions, 0..) |*p, i| p.* = (i * 7919 + i * i * 17) % n;
        positions[1] = positions[0];
        std.sort.heap(usize, &positions, {}, std.sort.asc(usize));
        try check(log, 1, &positions);
        try check(log, 1, &.{ 0, 0, n / 2 - 1 });
        try check(log, 1, &.{ n / 2, n / 2, n - 1 });
        try check(log, 2, &positions);
    }
}
test "invalid sparse geometry refuses before publishing or touching coefficient inputs" {
    const coefficients = [_]M{M.one()} ** 32;
    var scratch = [_]M{M.fromCanonical(91)} ** 32;
    var out = [_]M{M.fromCanonical(77)} ** 2;
    const domain = circle.CanonicCoset.new(6).circleDomain();
    var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &tw);
    const view = engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles);
    for ([_][2]usize{ .{ 63, 0 }, .{ 0, 64 } }) |positions| {
        try std.testing.expectError(error.InvalidLength, circle.poly.evaluateSelectedCoefficientsWithTwiddles(&coefficients, &scratch, domain, view, &positions, &out));
        for (out) |v| try std.testing.expectEqual(M.fromCanonical(77), v);
        for (scratch) |v| try std.testing.expectEqual(M.fromCanonical(91), v);
    }
    try std.testing.expectError(error.InvalidLength, circle.poly.evaluateSelectedCoefficientsWithTwiddles(&coefficients, &scratch, domain, view, &.{ 0, 2 }, scratch[0..2]));
    const malformed = engine.poly.twiddles.TwiddleTree([]const M).init(view.root_coset, &.{}, &.{});
    try std.testing.expectError(error.InvalidLength, circle.poly.evaluateSelectedCoefficientsWithTwiddles(&coefficients, &scratch, domain, malformed, &.{ 0, 2 }, &out));
    for (out) |v| try std.testing.expectEqual(M.fromCanonical(77), v);
    for (scratch) |v| try std.testing.expectEqual(M.fromCanonical(91), v);
}

const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const Tree = engine.pcs.CommitmentTreeProver(H);
fn makeTree(allocator: std.mem.Allocator) !Tree {
    return makeTreeFor(allocator, &.{ 9, 7, 9, 6 });
}
fn makeTreeFor(allocator: std.mem.Allocator, logs: []const u32) !Tree {
    var transferred = false;
    const columns = try allocator.alloc(engine.pcs.ColumnEvaluation, logs.len);
    errdefer if (!transferred) allocator.free(columns);
    const coefficients = try allocator.alloc(circle.CircleCoefficients, logs.len);
    var count: usize = 0;
    defer if (!transferred) {
        for (columns[0..count], coefficients[0..count]) |column, *coefficient| {
            allocator.free(column.values);
            coefficient.deinit(allocator);
        }
        allocator.free(coefficients);
    };
    for (logs, columns, coefficients, 0..) |log, *column, *coefficient, i| {
        const values = try allocator.alloc(M, @as(usize, 1) << @intCast(log - 1));
        errdefer allocator.free(values);
        for (values, 0..) |*value, row| value.* = M.fromU64(13 + i * 7 + row * row);
        const poly = try circle.CircleCoefficients.initOwned(values);
        const eval = try poly.evaluate(allocator, circle.CanonicCoset.new(log).circleDomain());
        coefficient.* = poly;
        column.* = .{ .log_size = log, .values = eval.values };
        count += 1;
    }
    // Constructor consumes ownership only after successful return.
    var tree = try Tree.initOwnedWithCoefficients(allocator, columns, coefficients);
    transferred = true;
    errdefer tree.deinit(allocator);
    try tree.compactPolynomialStorage(allocator, 8);
    return tree;
}
fn openingCase(allocator: std.mem.Allocator) !void {
    var tree = try makeTree(allocator);
    defer tree.deinit(allocator);
    const queries = [_]usize{ 0, 7, 7, 31, 128, 271, 511 };
    var expected = try engine.pcs.coefficient_opening.testing.decommitFull(H, allocator, tree, &queries);
    defer expected.deinit(allocator);
    var actual = try engine.pcs.coefficient_opening.testing.decommitHalf(H, allocator, tree, &queries);
    defer actual.deinit(allocator);
    try std.testing.expectEqualDeep(expected, actual);
    var half_waves = try engine.pcs.coefficient_opening.testing.decommitHalfWaves(H, allocator, tree, &queries);
    defer half_waves.deinit(allocator);
    try std.testing.expectEqualDeep(expected, half_waves);
    var full_queued = try engine.pcs.coefficient_opening.testing.decommitFullQueued(H, allocator, tree, &queries);
    defer full_queued.deinit(allocator);
    try std.testing.expectEqualDeep(expected, full_queued);
}
test "mixed compact and materialized pruned Merkle openings preserve all bytes and drain OOM" {
    try openingCase(a);
    try std.testing.checkAllAllocationFailures(a, openingCase, .{});
}

test "public tree openings restore unsorted repeated request order" {
    var tree = try makeTree(a);
    defer tree.deinit(a);
    const queries = [_]usize{ 511, 7, 0, 7, 128 };
    var opened = try tree.decommit(a, &queries);
    defer opened.deinit(a);
    for (tree.columns, tree.coefficients.?, opened.queried_values) |column, coefficient, values| {
        const expected = try coefficient.evaluate(a, circle.CanonicCoset.new(column.log_size).circleDomain());
        defer a.free(expected.values);
        const shift: std.math.Log2Int(usize) = @intCast(9 - column.log_size + 1);
        for (queries, values) |query, value| try std.testing.expectEqual(expected.values[((query >> shift) << 1) + (query & 1)], value);
    }
}
test "half-scratch native17 openings match serial and sixteen workers on256KiB stacks" {
    const logs = [_]u32{18} ** 16;
    var tree = try makeTreeFor(a, &logs);
    defer tree.deinit(a);
    var queries: [70]usize = undefined;
    for (&queries, 0..) |*q, i| q.* = (7919 * i + 17 * i * i) % (1 << 18);
    std.sort.heap(usize, &queries, {}, std.sort.asc(usize));
    var serial: engine.work_pool.WorkPool = undefined;
    try serial.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = 256 * 1024 });
    defer serial.deinit();
    var parallel: engine.work_pool.WorkPool = undefined;
    try parallel.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 256 * 1024 });
    defer parallel.deinit();
    var expected = blk: {
        var binding = try engine.work_pool.ScopedPoolBinding.init(&serial);
        defer binding.deinit();
        break :blk try engine.pcs.coefficient_opening.testing.decommitFull(H, a, tree, &queries);
    };
    defer expected.deinit(a);
    var actual = blk: {
        var binding = try engine.work_pool.ScopedPoolBinding.init(&parallel);
        defer binding.deinit();
        break :blk try engine.pcs.coefficient_opening.testing.decommitHalf(H, a, tree, &queries);
    };
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
    var full_queued = blk: {
        var binding = try engine.work_pool.ScopedPoolBinding.init(&parallel);
        defer binding.deinit();
        break :blk try engine.pcs.coefficient_opening.testing.decommitFullQueued(H, a, tree, &queries);
    };
    defer full_queued.deinit(a);
    try std.testing.expectEqualDeep(expected, full_queued);
}

test "queued openings over mixed heights match full-scratch waves under sixteen workers" {
    const logs = [_]u32{ 18, 7, 12, 18, 9, 15, 6, 16, 18, 11, 14, 17, 8, 13, 10, 16, 18, 12 };
    var tree = try makeTreeFor(a, &logs);
    defer tree.deinit(a);
    var queries: [70]usize = undefined;
    for (&queries, 0..) |*q, i| q.* = (104729 * i + 31 * i * i) % (1 << 18);
    std.sort.heap(usize, &queries, {}, std.sort.asc(usize));
    var parallel: engine.work_pool.WorkPool = undefined;
    try parallel.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 256 * 1024 });
    defer parallel.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&parallel);
    defer binding.deinit();
    var expected = try engine.pcs.coefficient_opening.testing.decommitFull(H, a, tree, &queries);
    defer expected.deinit(a);
    var actual = try engine.pcs.coefficient_opening.testing.decommitHalf(H, a, tree, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
    var full_queued = try engine.pcs.coefficient_opening.testing.decommitFullQueued(H, a, tree, &queries);
    defer full_queued.deinit(a);
    try std.testing.expectEqualDeep(expected, full_queued);
}
