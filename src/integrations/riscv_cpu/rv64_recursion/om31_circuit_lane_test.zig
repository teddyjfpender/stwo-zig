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
    const y = F.fromPartialEvals(@splat(x)).square().mul(x).inv();
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

const RemixMetrics = struct { gates: @import("stwo_circuit_frontend").builder.context.GateCounts, variables: u32, emission_qm31_ops: u64 };
fn remixGraph(comptime reference: bool, mutate_all: bool) !RemixMetrics {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var random = core.channel.raw_mod_m31.Om31Channel.init();
    var native: [8]O = undefined;
    var input: [8]F = undefined;
    for (&native, &input) |*v, *w| {
        v.* = random.drawSecureFelt();
        w.* = try F.guess(&ctx, v.*);
    }
    var result = F.zero();
    if (reference) {
        // Deliberately retained slow mathematical oracle: exactly the former
        // sum-of-eight-basis-products circuit, not a second optimized formula.
        for (input, 0..) |v, i| {
            var basis = [_]M{M.zero()} ** 8;
            basis[i] = M.one();
            result = result.add(v.mul(F.fromOm31(O.fromM31Array(basis))));
        }
    } else result = F.fromPartialEvals(input);
    const expected = F.fromOm31(O.fromPartialEvals(native));
    try ctx.eq(result.c0.v, expected.c0.v);
    try ctx.eq(result.c1.v, expected.c1.v);
    const emission_qm31_ops = ctx.gate_counts.qm31_ops;
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    if (mutate_all) for (input) |v| for (0..8) |coordinate| {
        const half = if (coordinate < 4) v.c0.v else v.c1.v;
        const old = ctx.value_table.items[half.idx];
        var changed = old.toM31Array();
        changed[coordinate % 4] = changed[coordinate % 4].add(M.one());
        ctx.value_table.items[half.idx] = core.fields.qm31.QM31.fromM31Array(changed);
        try std.testing.expect(!try ctx.isCircuitValid());
        ctx.value_table.items[half.idx] = old;
    };
    return .{ .gates = ctx.gate_counts, .variables = ctx.circuit.n_vars, .emission_qm31_ops = @intCast(emission_qm31_ops) };
}
test "OM31 shared quartic basis remixes reduce actual gates and bind all64 input coordinates" {
    const before = try remixGraph(true, false);
    const after = try remixGraph(false, true);
    try std.testing.expect(after.gates.qm31_ops < before.gates.qm31_ops);
    try std.testing.expect(after.variables < before.variables);
    std.debug.print("OM31_BASIS_REMIX reference={f} shared={f}\n", .{ std.json.fmt(before, .{}), std.json.fmt(after, .{}) });
}
