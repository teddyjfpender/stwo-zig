const std = @import("std");
const a = std.testing.allocator;
test "structural circuit arithmetic is symbolic and scope restores legacy topology" {
    const Lane = @import("om31_circuit_lane.zig");
    const QLane = @import("circuit_lane.zig");
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    const Q = core.fields.qm31.QM31;
    try std.testing.expect(!QLane.structuralIdentitiesEnabled());
    var rng = core.channel.raw_mod_m31.Om31Channel.init();
    for (0..16) |_| {
        var ctx = try Lane.Context.init(a, 0);
        defer ctx.deinit();
        Lane.begin(&ctx);
        var active = true;
        defer if (active) Lane.finish() catch {};
        var scope = Lane.StructuralScope.init();
        var scoped = true;
        defer if (scoped) scope.deinit();
        const vx = rng.drawSecureFelt();
        const vy = rng.drawSecureFelt().c0;
        const x = try Lane.Lane.guess(&ctx, vx);
        const y = Lane.Lane.fromInner(QLane.Lane.wire(try ctx.guess(vy)));
        const before = ctx.circuit.nQm31OpsRows();
        const xy = x.mul(y);
        try std.testing.expectEqual(before + 2, ctx.circuit.nQm31OpsRows());
        try std.testing.expect(xy.value().eql(vx.mul(O.fromInner(vy))));
        try std.testing.expect(y.mul(x).value().eql(O.fromInner(vy).mul(vx)));
        try std.testing.expect(y.square().value().eql(O.fromInner(vy).square()));
        try std.testing.expectEqual(@as(u32, 0), x.sub(x).c0.v.idx);
        try std.testing.expectEqual(@as(u32, 0), x.sub(x).c1.v.idx);
        try std.testing.expectEqual(x.c0.v.idx, x.sub(Lane.Lane.zero()).c0.v.idx);
        // A guessed zero is not the immutable zero wire. The full product
        // must retain constraints for that coordinate, independent of values.
        const guessed_zero = try Lane.Lane.guess(&ctx, O.fromInner(vy));
        const start = ctx.circuit.nQm31OpsRows();
        const product = guessed_zero.mul(x);
        const full_cost = ctx.circuit.nQm31OpsRows() - start;
        try std.testing.expectEqual(@as(usize, 7), full_cost);
        try std.testing.expect(product.value().eql(O.fromInner(vy).mul(vx)));
        const vz = rng.drawSecureFelt();
        const z = try Lane.Lane.guess(&ctx, vz);
        const xz = x.mul(z);
        try std.testing.expect(xz.value().eql(vx.mul(vz)));
        for (0..8) |coordinate| {
            const var_id = if (coordinate < 4) z.c0.v else z.c1.v;
            const saved = ctx.value_table.items[var_id.idx];
            var words = saved.toM31Array();
            words[coordinate % 4] = words[coordinate % 4].add(core.fields.m31.M31.one());
            ctx.value_table.items[var_id.idx] = Q.fromM31Array(words);
            try std.testing.expect(!try ctx.isCircuitValid());
            ctx.value_table.items[var_id.idx] = saved;
        }
        scope.deinit();
        scoped = false;
        try std.testing.expect(!QLane.structuralIdentitiesEnabled());
        const legacy_start = ctx.circuit.nQm31OpsRows();
        _ = y.sub(y);
        try std.testing.expectEqual(legacy_start + 2, ctx.circuit.nQm31OpsRows());
        try Lane.finish();
        active = false;
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        const old = ctx.value_table.items[guessed_zero.c1.v.idx];
        ctx.value_table.items[guessed_zero.c1.v.idx] = Q.one();
        try std.testing.expect(!try ctx.isCircuitValid());
        ctx.value_table.items[guessed_zero.c1.v.idx] = old;
    }
}

test "structural circuit arithmetic basis products and inverse equations retain the field" {
    const Lane = @import("om31_circuit_lane.zig");
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    const M = core.fields.m31.M31;
    var ctx = try Lane.Context.init(a, 0);
    defer ctx.deinit();
    var scope = Lane.StructuralScope.init();
    defer scope.deinit();
    Lane.begin(&ctx);
    var active = true;
    defer if (active) Lane.finish() catch {};
    for (0..8) |i| for (0..8) |j| {
        var x: [8]M = @splat(M.zero());
        var y: [8]M = @splat(M.zero());
        x[i] = M.one();
        y[j] = M.one();
        const vx = O.fromM31Array(x);
        const vy = O.fromM31Array(y);
        const actual = Lane.Lane.fromOm31(vx).mul(Lane.Lane.fromOm31(vy));
        try std.testing.expect(actual.value().eql(vx.mul(vy)));
    };
    var random = core.channel.raw_mod_m31.Om31Channel.init();
    for (0..16) |_| {
        const value = random.drawSecureFelt();
        const x = try Lane.Lane.guess(&ctx, value);
        try std.testing.expect(x.inv().value().eql(try value.inv()));
    }
    try Lane.finish();
    active = false;
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

fn failureEmission(allocator: std.mem.Allocator) !void {
    const Lane = @import("om31_circuit_lane.zig");
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    var ctx = try Lane.Context.init(allocator, 0);
    defer ctx.deinit();
    var scope = Lane.StructuralScope.init();
    defer scope.deinit();
    Lane.begin(&ctx);
    var active = true;
    defer if (active) Lane.finish() catch {};
    const x = try Lane.Lane.guess(&ctx, O.one().add(O.basis()));
    const y = x.mul(Lane.Lane.fromInner(x.c0)).square().sub(x).inv();
    try Lane.check();
    try ctx.markAsMaybeUnused(y.c0.v);
    try ctx.markAsMaybeUnused(y.c1.v);
    try Lane.finish();
    active = false;
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "structural circuit arithmetic allocation failures release emission and policy ownership" {
    try std.testing.checkAllAllocationFailures(a, failureEmission, .{});
    try std.testing.expect(!@import("circuit_lane.zig").structuralIdentitiesEnabled());
}
