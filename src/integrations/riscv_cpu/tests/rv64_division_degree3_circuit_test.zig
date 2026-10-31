//! Real CircuitLane point adapter; no QM31 challenges captured as host constants.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const E = rv.evaluation;
const L = @import("../rv64_recursion/circuit_lane.zig");
const F = L.Lane;
const Q = E.Q;
fn wire(ctx: *L.Context, value: Q) !F {
    return F.wire(try ctx.guess(value));
}
const Masks = struct {
    fixed: [3]Q,
    main: [2][D.layout.MAIN]Q,
    inter: [2][D.layout.INTERACTION]Q,
    pub fn count(_: @This(), tree: usize, c: usize) !usize {
        const widths = [_]usize{ 3, D.layout.MAIN, D.layout.INTERACTION };
        if (tree > 2 or c >= widths[tree]) return error.InvalidMask;
        return if ((tree == 1 and c == D.layout.COUNT) or (tree == 2 and c >= 4)) 2 else 1;
    }
    pub fn at(self: @This(), tree: usize, c: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, c)) return error.InvalidMask;
        return switch (tree) {
            0 => self.fixed[c],
            1 => self.main[sample][c],
            2 => self.inter[sample][c],
            else => unreachable,
        };
    }
};
const CircuitMasks = struct {
    ctx: *L.Context,
    native: Masks,
    pub fn count(self: @This(), t: usize, c: usize) !usize {
        return self.native.count(t, c);
    }
    pub fn at(self: @This(), t: usize, c: usize, s: usize) !F {
        return wire(self.ctx, try self.native.at(t, c, s));
    }
};
test "degree3 DIV point circuit binds count challenges claims and all1567 residuals" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const challenges = D.provider.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    const point = core.circle.secureFieldPointFromRandomSeed(channel.drawSecureFelt());
    var masks: Masks = undefined;
    for (&masks.fixed) |*v| v.* = channel.drawSecureFelt();
    for (&masks.main) |*row| for (row) |*v| {
        v.* = channel.drawSecureFelt();
    };
    for (&masks.inter) |*row| for (row) |*v| {
        v.* = channel.drawSecureFelt();
    };
    const native = D.degree3_component.Component{ .base = .{ .log_size = 6, .count = 17, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .claim = claim } };
    var expected: [D.layout.CONSTRAINTS]Q = undefined;
    var ns = E.Sink{ .values = &expected };
    try native.evaluateQuotientsAtPointFor(Q, point, 7, masks, &ns);
    for (0..4) |mutation| {
        var ctx = try L.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var ch: D.provider.ChallengesFor(F) = undefined;
        ch.offset = try wire(&ctx, challenges.offset.add(if (mutation == 1) Q.one() else Q.zero()));
        for (&ch.coefficients, challenges.coefficients) |*v, q| v.* = try wire(&ctx, q);
        const candidate = D.degree3_component.ComponentFor(F){ .base = .{ .log_size = 6, .count = try wire(&ctx, E.q(if (mutation == 2) 18 else 17)), .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = ch, .claim = try wire(&ctx, claim.add(if (mutation == 3) Q.one() else Q.zero())) } };
        const p = rv.geometry.PointFor(F){ .x = try wire(&ctx, point.x), .y = try wire(&ctx, point.y) };
        var actual: [D.layout.CONSTRAINTS]F = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        L.begin(&ctx);
        try candidate.evaluateQuotientsAtPointFor(F, p, 7, CircuitMasks{ .ctx = &ctx, .native = masks }, &sink);
        try L.finish();
        try std.testing.expectEqual(D.layout.CONSTRAINTS, sink.count);
        for (actual, expected) |v, q| try ctx.eq(v.v, try ctx.constant(q));
        try ctx.finalize(false);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
