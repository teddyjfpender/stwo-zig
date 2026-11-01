const std = @import("std");
const core = @import("stwo_core");
const lane = @import("om31_circuit_lane.zig");
const F = lane.Lane;
const O = lane.O;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
test "OM31 wire tower arithmetic matches native with all eight guessed coordinates" {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const x = O.fromM31Array(.{ M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(5), M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17), M.fromCanonical(19) });
    const y = x.square().add(O.one());
    const u = try F.guess(&ctx, x);
    const v = try F.guess(&ctx, y);
    try std.testing.expect(u.add(v).value().eql(x.add(y)));
    try std.testing.expect(u.sub(v).value().eql(x.sub(y)));
    try std.testing.expect(u.mul(v).value().eql(x.mul(y)));
    try std.testing.expect(u.square().value().eql(x.square()));
    try std.testing.expect(u.quadraticConjugate().value().eql(x.quadraticConjugate()));
    try std.testing.expect(u.mulM31(M.fromCanonical(23)).value().eql(x.mulM31(M.fromCanonical(23))));
    try std.testing.expect(u.mulInner(v.c0).value().eql(x.mulInner(y.c0)));
    try std.testing.expect(u.inv().mul(u).value().eql(O.one()));
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
fn inverseGraph(value: O) !struct { valid: bool, gates: @import("stwo_circuit_frontend").builder.context.GateCounts, vars: u32 } {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const input = try F.guess(&ctx, value);
    const inverse = input.inv();
    try ctx.markAsMaybeUnused(inverse.c0.v);
    try ctx.markAsMaybeUnused(inverse.c1.v);
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    return .{ .valid = try ctx.isCircuitValid(), .gates = ctx.gate_counts, .vars = ctx.circuit.n_vars };
}
test "OM31 guessed zero inverse is unsatisfied with identical nonzero topology" {
    const good = try inverseGraph(O.one().add(O.basis()));
    const bad = try inverseGraph(O.zero());
    try std.testing.expect(good.valid);
    try std.testing.expect(!bad.valid);
    try std.testing.expectEqualDeep(good.gates, bad.gates);
    try std.testing.expectEqual(good.vars, bad.vars);
}

fn allocationEmission(allocator: std.mem.Allocator) !void {
    var ctx = try lane.Context.init(allocator, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const x = try F.guess(&ctx, O.one().add(O.basis()));
    const y = x.square().mul(x).inv();
    try lane.check();
    try ctx.markAsMaybeUnused(y.c0.v);
    try ctx.markAsMaybeUnused(y.c1.v);
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "OM31 lane latches allocation failures and clears emission ownership" {
    try std.testing.checkAllAllocationFailures(a, allocationEmission, .{});
}
