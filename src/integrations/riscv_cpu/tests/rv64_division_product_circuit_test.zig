//! Tests the actual external-wire point evaluator, not a native-value wrapper.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const D = front.rv64_air.arithmetic.division.word16_product;
const E = front.rv64_air.evaluation;
const LaneModule = @import("../rv64_recursion/circuit_lane.zig");
const F = LaneModule.Lane;
const Context = LaneModule.Context;
const Q = E.Q;
const L = D.layout;
fn wire(ctx: *Context, q: Q) !F {
    return F.wire(try ctx.guess(q));
}
const Masks = struct {
    data: [3][2][L.MAIN]Q,
    pub fn count(_: @This(), tree: usize, global: usize) !usize {
        if (tree >= 3) return error.BadMask;
        const offsets = [_]usize{ 2, 3, 4 };
        const widths = [_]usize{ L.FIXED, L.MAIN, L.INTERACTION };
        if (global < offsets[tree] or global - offsets[tree] >= widths[tree]) return error.BadMask;
        const c = global - offsets[tree];
        return if ((tree == 1 and c == L.COUNT) or (tree == 2 and c >= L.PREFIX)) 2 else 1;
    }
    pub fn at(self: @This(), tree: usize, global: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, global)) return error.BadMask;
        return self.data[tree][sample][global - ([_]usize{ 2, 3, 4 })[tree]];
    }
};
const CircuitMasks = struct {
    ctx: *Context,
    native: Masks,
    pub fn count(self: @This(), tree: usize, c: usize) !usize {
        return self.native.count(tree, c);
    }
    pub fn at(self: @This(), tree: usize, c: usize, sample: usize) !F {
        return wire(self.ctx, try self.native.at(tree, c, sample));
    }
};
test "narrow DIV circuit point binds dynamic count claim challenges point and exact offset masks" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: D.lookup.Challenges = undefined;
    ch.function.offset = channel.drawSecureFelt();
    for (&ch.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    const claim = channel.drawSecureFelt();
    var masks: Masks = undefined;
    for (&masks.data) |*tree| for (tree) |*row| for (row) |*v| {
        v.* = channel.drawSecureFelt();
    };
    const point = core.circle.secureFieldPointFromRandomSeed(channel.drawSecureFelt());
    const native = D.component.Component{ .log_size = 6, .count = 7, .fixed_offset = 2, .main_offset = 3, .interaction_offset = 4, .claim = claim, .challenges = ch };
    var expected: [L.CONSTRAINTS]Q = undefined;
    var out = E.Sink{ .values = &expected };
    try native.evaluateQuotientsAtPointFor(Q, point, 7, masks, &out);
    for (0..5) |mutation| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var wc: D.lookup.ChallengesFor(F) = undefined;
        wc.function.offset = try wire(&ctx, ch.function.offset);
        for (&wc.function.coefficients, ch.function.coefficients) |*v, q| v.* = try wire(&ctx, q);
        wc.range16 = .{ .offset = try wire(&ctx, ch.range16.offset.add(if (mutation == 3) Q.one() else Q.zero())), .coefficient = try wire(&ctx, ch.range16.coefficient) };
        const c = D.component.ComponentFor(F){ .log_size = 6, .count = try wire(&ctx, E.q(if (mutation == 1) 8 else 7)), .fixed_offset = 2, .main_offset = 3, .interaction_offset = 4, .claim = try wire(&ctx, claim.add(if (mutation == 2) Q.one() else Q.zero())), .challenges = wc };
        const p = front.rv64_air.geometry.PointFor(F){ .x = try wire(&ctx, point.x.add(if (mutation == 4) Q.one() else Q.zero())), .y = try wire(&ctx, point.y) };
        var values: [L.CONSTRAINTS]F = undefined;
        var sink = E.SinkFor(F){ .values = &values };
        LaneModule.begin(&ctx);
        var bound = true;
        defer if (bound) {
            LaneModule.finish() catch {};
        };
        try c.evaluateQuotientsAtPointFor(F, p, 7, CircuitMasks{ .ctx = &ctx, .native = masks }, &sink);
        try LaneModule.finish();
        bound = false;
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
        for (values, expected) |got, wanted| try ctx.eq(got.v, try ctx.constant(wanted));
        try ctx.eq(sink.scale.?.v, try ctx.constant(out.scale.?));
        try ctx.finalize(false);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
