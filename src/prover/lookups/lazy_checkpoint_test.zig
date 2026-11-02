const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Circuit = @import("gkr_circuit.zig");
const ML = @import("mle.zig");
const Pools = @import("../work_pool.zig");
const a = std.testing.allocator;
fn dense(comptime S: type, seed: usize) S {
    var c: [S.zero().toM31Array().len]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 7919 + i * 977 + 3) % 1048573));
    return S.fromM31Array(c);
}
fn check(comptime S: type) !void {
    const C = Circuit.ForField(S);
    for ([_]u5{ 2, 3, 4, 6, 17 }) |log| {
        const n = @as(usize, 1) << log;
        const ns = try a.alloc(S, n);
        defer a.free(ns);
        const ms = try a.alloc(M, n);
        defer a.free(ms);
        const ds = try a.alloc(S, n);
        defer a.free(ds);
        for (ns, ms, ds, 0..) |*num, *weight, *den, i| {
            weight.* = if (i % 3 == 0) M.zero() else M.fromCanonical(@intCast(i % 19)).neg();
            num.* = if (i % 17 == 0) S.zero() else dense(S, i + 211);
            den.* = if (i % 17 == 0) S.one() else if (i % 41 == 0) S.zero() else dense(S, i);
        }
        const inputs = [_]C.Layer{
            .{ .GrandProduct = try ML.MleFor(S, S).initBorrowed(ds) },
            .{ .LogUpGeneric = .{ .numerators = try ML.MleFor(S, S).initBorrowed(ns), .denominators = try ML.MleFor(S, S).initBorrowed(ds) } },
            .{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(S, M).initBorrowed(ms), .denominators = try ML.MleFor(S, S).initBorrowed(ds) } },
            .{ .LogUpSingles = .{ .denominators = try ML.MleFor(S, S).initBorrowed(ds) } },
        };
        const ys = try a.alloc(S, log - 2);
        defer a.free(ys);
        for (ys, 0..) |*y, i| y.* = dense(S, i + 901);
        var eq = try C.EqEvals.generate(a, ys);
        defer eq.deinit(a);
        for (inputs) |input| {
            const original = (try input.nextLayer(a)).?;
            var expected = original.intoMultivariatePolyOwned(dense(S, 111), &eq);
            defer expected.deinit(a);
            var lazy = try input.intoReducedMultivariatePoly(dense(S, 111), &eq);
            defer lazy.deinit(a);
            while (!expected.isConstant()) {
                const claim = dense(S, 317);
                var p = try expected.sumAsPolyInFirstVariable(a, claim);
                defer p.deinit(a);
                var q = try lazy.sumAsPolyInFirstVariable(a, claim);
                defer q.deinit(a);
                try std.testing.expectEqualDeep(p.coeffsSlice(), q.coeffsSlice());
                const challenge = dense(S, 431 + expected.nVariables());
                try expected.fixFirstVariableInPlace(a, challenge);
                try lazy.fixFirstVariableInPlace(a, challenge);
                try std.testing.expect(!lazy.reduce_input);
                try std.testing.expectEqualDeep(expected.input_layer, lazy.input_layer);
            }
            var expected_mask = try expected.tryIntoMask(a);
            defer expected_mask.deinit(a);
            var lazy_mask = try lazy.tryIntoMask(a);
            defer lazy_mask.deinit(a);
            try std.testing.expectEqualDeep(expected_mask, lazy_mask);
        }
        for (ns, ms, ds, 0..) |num, weight, den, i| {
            try std.testing.expectEqualDeep(if (i % 17 == 0) S.zero() else dense(S, i + 211), num);
            try std.testing.expectEqualDeep(if (i % 3 == 0) M.zero() else M.fromCanonical(@intCast(i % 19)).neg(), weight);
            try std.testing.expectEqualDeep(if (i % 17 == 0) S.one() else if (i % 41 == 0) S.zero() else dense(S, i), den);
        }
    }
}
test "lazy checkpoint Q OM all kinds match original sums folds masks signed padding and zero denominators" {
    try check(core.fields.qm31.QM31);
    try check(core.fields.om31.OM31);
}
test "lazy checkpoint first sums and folds preserve three worker and held lease execution" {
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try check(core.fields.om31.OM31);
    var lease = try pool.acquire(try Pools.WorkerBudget.init(3));
    defer lease.deinit();
    try check(core.fields.om31.OM31);
}
test "lazy checkpoint rejects malformed source shapes and preserves exceptional challenge errors" {
    const S = core.fields.om31.OM31;
    const C = Circuit.ForField(S);
    var values: [8]S = undefined;
    @memset(&values, S.one());
    var eq = try C.EqEvals.generate(a, &.{S.one()});
    defer eq.deinit(a);
    const short = C.Layer{ .GrandProduct = try ML.MleFor(S, S).initBorrowed(values[0..2]) };
    try std.testing.expectError(error.InvalidLayerStructure, short.intoReducedMultivariatePoly(S.one(), &eq));
    const malformed = C.Layer{ .LogUpGeneric = .{ .numerators = try ML.MleFor(S, S).initBorrowed(values[0..4]), .denominators = try ML.MleFor(S, S).initBorrowed(&values) } };
    try std.testing.expectError(error.InvalidLayerStructure, malformed.intoReducedMultivariatePoly(S.one(), &eq));
    const input = C.Layer{ .GrandProduct = try ML.MleFor(S, S).initBorrowed(&values) };
    var expected = ((try input.nextLayer(a)).?).intoMultivariatePolyOwned(S.one(), &eq);
    defer expected.deinit(a);
    var lazy = try input.intoReducedMultivariatePoly(S.one(), &eq);
    defer lazy.deinit(a);
    try std.testing.expectError(error.DivisionByZero, expected.sumAsPolyInFirstVariable(a, S.one()));
    try std.testing.expectError(error.DivisionByZero, lazy.sumAsPolyInFirstVariable(a, S.one()));
    var clone = try lazy.cloneOwned(a);
    defer clone.deinit(a);
    try std.testing.expect(clone.reduce_input and clone.input_layer.GrandProduct.owns_evals);
    @memset(&values, S.zero());
    try clone.fixFirstVariableInPlace(a, dense(S, 97));
    try std.testing.expect(!clone.reduce_input);
    for (clone.input_layer.GrandProduct.evals) |v| try std.testing.expectEqualDeep(S.one(), v);
}
