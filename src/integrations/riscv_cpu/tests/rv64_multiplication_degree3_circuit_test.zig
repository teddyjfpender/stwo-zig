//! Real circuit wires for new MUL strict-pair authority and unchanged BYTE math.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const M = rv.arithmetic.multiplication;
const L = M.degree3_layout;
const E = rv.evaluation;
const Q = E.Q;
const Lane = @import("../rv64_recursion/circuit_lane.zig");
const F = Lane.Lane;
fn wire(ctx: *Lane.Context, q: Q) !F {
    return F.wire(try ctx.guess(q));
}
const Masks = struct {
    byte: bool,
    values: [5][L.INTERACTION]Q,
    pub fn count(self: @This(), tree: usize, c: usize) !usize {
        const widths: [3]usize = if (self.byte) .{ 3, 1, 8 } else .{ 3, L.MAIN, L.INTERACTION };
        if (tree > 2 or c >= widths[tree]) return error.InvalidMask;
        return if ((!self.byte and tree == 1 and c == L.COUNT) or (tree == 2 and c >= (if (self.byte) @as(usize, 4) else L.PREFIX))) 2 else 1;
    }
    pub fn at(self: @This(), tree: usize, c: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, c)) return error.InvalidMask;
        return self.values[if (tree == 0) 0 else if (tree == 1) (if (sample == 0) @as(usize, 1) else 2) else (if (sample == 0) @as(usize, 3) else 4)][c];
    }
};
const CircuitMasks = struct {
    context: *Lane.Context,
    native: Masks,
    pub fn count(self: @This(), t: usize, c: usize) !usize {
        return self.native.count(t, c);
    }
    pub fn at(self: @This(), t: usize, c: usize, s: usize) !F {
        return wire(self.context, try self.native.at(t, c, s));
    }
};
test "MUL2n and BYTE2n CircuitLane points bind every alpha challenge count and claim" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = M.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    const claim = channel.drawSecureFelt();
    const point = core.circle.secureFieldPointFromRandomSeed(channel.drawSecureFelt());
    inline for (.{ false, true }) |is_byte| {
        const n = if (is_byte) 4 else L.CONSTRAINTS;
        var masks = Masks{ .byte = is_byte, .values = undefined };
        for (&masks.values) |*row| for (row) |*v| {
            v.* = channel.drawSecureFelt();
        };
        var expected: [n]Q = undefined;
        var native_sink = E.Sink{ .values = &expected };
        if (is_byte) {
            const c = rv.providers.byte_degree3.Component{ .base = .{ .log_size = 8, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .alpha = alpha, .claim = claim } };
            try c.evaluateQuotientsAtPointFor(Q, point, 9, masks, &native_sink);
        } else {
            const c = M.degree3_component.Component{ .log_size = 6, .count = 15, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = ch, .byte_alpha = alpha, .claim = claim };
            try c.evaluateQuotientsAtPointFor(Q, point, 9, masks, &native_sink);
        }
        for (0..4) |mutation| {
            var ctx = try Lane.Context.init(std.testing.allocator, 0);
            defer ctx.deinit();
            const aw = try wire(&ctx, alpha.add(if (mutation == 1) Q.one() else Q.zero()));
            const cw = try wire(&ctx, claim.add(if (mutation == 2) Q.one() else Q.zero()));
            var chw: M.provider.ChallengesFor(F) = undefined;
            chw.offset = try wire(&ctx, ch.offset.add(if (mutation == 3) Q.one() else Q.zero()));
            for (&chw.coefficients, ch.coefficients) |*v, q| v.* = try wire(&ctx, q);
            const count = try wire(&ctx, E.q(if (mutation == 3) 16 else 15));
            const pw = rv.geometry.PointFor(F){ .x = try wire(&ctx, point.x), .y = try wire(&ctx, point.y) };
            var actual: [n]F = undefined;
            var sink = E.SinkFor(F){ .values = &actual };
            Lane.begin(&ctx);
            if (is_byte) {
                const c = rv.providers.byte_degree3.ComponentFor(F){ .base = .{ .log_size = 8, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .alpha = aw, .claim = cw } };
                try c.evaluateQuotientsAtPointFor(F, pw, 9, CircuitMasks{ .context = &ctx, .native = masks }, &sink);
            } else {
                const c = M.degree3_component.ComponentFor(F){ .log_size = 6, .count = count, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = chw, .byte_alpha = aw, .claim = cw };
                try c.evaluateQuotientsAtPointFor(F, pw, 9, CircuitMasks{ .context = &ctx, .native = masks }, &sink);
            }
            try Lane.finish();
            for (actual, expected) |v, q| try ctx.eq(v.v, try ctx.constant(q));
            try ctx.finalize(false);
            // BYTE has neither a public count nor a FUNCTION challenge.
            try std.testing.expectEqual(mutation == 0 or (is_byte and mutation == 3), try ctx.isCircuitValid());
        }
    }
}
