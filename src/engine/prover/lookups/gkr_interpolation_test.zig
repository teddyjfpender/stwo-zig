const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Circuit = @import("gkr_circuit_field.zig");
const Utils = @import("utils.zig");
const a = std.testing.allocator;
fn dense(comptime S: type, i: usize) S {
    var cs: [S.zero().toM31Array().len]M = undefined;
    for (&cs, 0..) |*v, j| v.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return S.fromM31Array(cs);
}
fn check(comptime S: type) !void {
    const G = Circuit.ForField(S);
    const P = Utils.UnivariatePoly(S);
    const two = S.one().add(S.one());
    for (0..32) |i| {
        const b = dense(S, i + 197);
        const values: [3]S = if (i == 0) @splat(S.zero()) else if (i == 1) .{ b.neg(), S.one().sub(b), two.sub(b) } else if (i == 2) .{ b.neg().mul(two), S.one().sub(b).mul(two.add(S.one())), two.sub(b).mul(two.add(two)) } else .{ dense(S, i), dense(S, i + 31), dense(S, i + 97) };
        var generic = try P.interpolateLagrange(a, &.{ S.zero(), S.one(), two, b }, &.{ values[0], values[1], values[2], S.zero() });
        defer generic.deinit(a);
        var fixed = try G.interpolate012WithRoot(a, values, b);
        defer fixed.deinit(a);
        try std.testing.expectEqualDeep(generic.coeffsSlice(), fixed.coeffsSlice());
        try std.testing.expectEqualDeep(S.zero(), fixed.evalAtPoint(b));
    }
    for ([_]S{ S.zero(), S.one(), two }) |b| {
        try std.testing.expectError(error.DivisionByZero, G.interpolate012WithRoot(a, @splat(S.zero()), b));
        try std.testing.expectError(error.DivisionByZero, P.interpolateLagrange(a, &.{ S.zero(), S.one(), two, b }, &.{ S.zero(), S.zero(), S.zero(), S.zero() }));
    }
    const third = try S.one().div(S.fromBase(M.fromCanonical(3)));
    const half = S.fromBase(M.fromCanonical(1073741824));
    for ([_]S{ S.zero(), S.one(), third, half }) |y| {
        try std.testing.expectError(error.DivisionByZero, G.correctSumAsPolyInFirstVariable(a, S.zero(), S.zero(), S.zero(), &.{y}, 1));
    }
}
test "GKR corrected cubic Q matches generic Lagrange exact coefficients and poles" {
    try check(core.fields.qm31.QM31);
}
test "GKR corrected cubic OM matches generic Lagrange exact coefficients and poles" {
    try check(core.fields.om31.OM31);
}
fn lifecycle(a_: std.mem.Allocator) !void {
    const O = core.fields.om31.OM31;
    var p = try Circuit.ForField(O).interpolate012WithRoot(a_, .{ dense(O, 1), dense(O, 3), dense(O, 7) }, dense(O, 9));
    defer p.deinit(a_);
}
test "GKR fixed cubic allocation failure preserves ownership" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
fn bench(comptime S: type) !void {
    const G = Circuit.ForField(S);
    const P = Utils.UnivariatePoly(S);
    const two = S.one().add(S.one());
    const b = dense(S, 197);
    const values = [_]S{ dense(S, 1), dense(S, 31), dense(S, 97) };
    var timer = try std.time.Timer.start();
    var generic_ns: u64 = 0;
    var fixed_ns: u64 = 0;
    for (0..100) |_| {
        timer.reset();
        var old = try P.interpolateLagrange(a, &.{ S.zero(), S.one(), two, b }, &.{ values[0], values[1], values[2], S.zero() });
        generic_ns += timer.read();
        defer old.deinit(a);
        timer.reset();
        var new = try G.interpolate012WithRoot(a, values, b);
        fixed_ns += timer.read();
        defer new.deinit(a);
        try std.testing.expectEqualDeep(old.coeffsSlice(), new.coeffsSlice());
    }
    std.debug.print("GKR_CUBIC field={s} rounds=100 generic_ns={d} fixed_ns={d} speedup={d:.3}\n", .{ @typeName(S), generic_ns, fixed_ns, @as(f64, @floatFromInt(generic_ns)) / @as(f64, @floatFromInt(fixed_ns)) });
}
test "optional GKR corrected cubic numerical microbenchmark" {
    if (!std.process.hasEnvVarConstant("STWO_ZIG_BENCH_GKR_PACKED")) return;
    try bench(core.fields.qm31.QM31);
    try bench(core.fields.om31.OM31);
}
