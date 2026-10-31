const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const D = K.pair2n;
const V = A.evaluation;
const Q = V.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn randomQ(r: std.Random) Q {
    return Q.fromM31(M.fromU64(r.int(u32)), M.fromU64(r.int(u32)), M.fromU64(r.int(u32)), M.fromU64(r.int(u32)));
}
const Circuit = @import("../rv64_recursion/circuit_lane.zig");
const F = Circuit.Lane;
const Masks = struct {
    fixed: [D.layout.FIXED]Q,
    main: [5][D.layout.MAIN]Q,
    inter: [2][D.layout.INTERACTION]Q,
    pub fn count(_: *const @This(), tree: usize, c: usize) !usize {
        const widths = [_]usize{ D.layout.FIXED, D.layout.MAIN, D.layout.INTERACTION };
        if (tree > 2 or c >= widths[tree]) return error.InvalidMask;
        return if (tree == 1 and c < K.layout.STATE) 5 else if ((tree == 1 and c >= K.layout.ACTIVE_A and c < K.layout.MAIN) or (tree == 2 and c >= D.layout.PREFIX)) 2 else 1;
    }
    pub fn at(self: *const @This(), tree: usize, c: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, c)) return error.InvalidMask;
        return switch (tree) {
            0 => self.fixed[c],
            1 => self.main[sample][c],
            2 => self.inter[sample][c],
            else => unreachable,
        };
    }
};
fn wire(ctx: *Circuit.Context, q: Q) !F {
    return F.wire(try ctx.guess(q));
}
const CircuitMasks = struct {
    context: *Circuit.Context,
    native: *const Masks,
    pub fn count(self: @This(), t: usize, c: usize) !usize {
        return self.native.count(t, c);
    }
    pub fn at(self: @This(), t: usize, c: usize, s: usize) !F {
        return wire(self.context, try self.native.at(t, c, s));
    }
};
test "pair2n Circuit point adapter shares every scaled OODS residual and binds challenge claim and enable wires" {
    var prng = std.Random.DefaultPrng.init(0x44454733);
    const random = prng.random();
    const masks = try a.create(Masks);
    defer a.destroy(masks);
    for (&masks.fixed) |*q| q.* = randomQ(random);
    for (&masks.main) |*row| for (row) |*q| {
        q.* = randomQ(random);
    };
    for (&masks.inter) |*row| for (row) |*q| {
        q.* = randomQ(random);
    };
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = K.equations.Challenges.draw(&channel);
    const claim = randomQ(random);
    const point = core.circle.secureFieldPointFromRandomSeed(randomQ(random));
    const component = D.component.Component{ .kind = .permutation, .log_size = 7, .calls = 5, .first_call_id = 19, .challenges = ch, .claim = claim };
    const expected = try a.alloc(Q, D.layout.CONSTRAINTS);
    defer a.free(expected);
    var ns = V.Sink{ .values = expected };
    try component.evaluatePointFor(Q, point, 9, masks, ch, .{ .calls = 5, .first_id = 19 }, claim, &ns);
    for (0..4) |mutation| {
        var context = try Circuit.Context.init(a, 0);
        defer context.deinit();
        var challenges: K.equations.ChallengesFor(F) = undefined;
        inline for (.{ "chi", "xor5", "io" }) |name| {
            @field(challenges, name).offset = try wire(&context, @field(ch, name).offset.add(if (mutation == 1 and std.mem.eql(u8, name, "chi")) Q.one() else Q.zero()));
            for (&@field(challenges, name).coefficients, @field(ch, name).coefficients) |*v, q| v.* = try wire(&context, q);
        }
        const circuit_point = A.geometry.PointFor(F){ .x = try wire(&context, point.x), .y = try wire(&context, point.y) };
        const cclaim = try wire(&context, claim.add(if (mutation == 2) Q.one() else Q.zero()));
        const public = V.CallSpanFor(F){ .calls = try wire(&context, V.q(5)), .first_id = try wire(&context, V.q(19)), .nonempty = try wire(&context, V.q(if (mutation == 3) 0 else 1)) };
        const actual = try a.alloc(F, D.layout.CONSTRAINTS);
        defer a.free(actual);
        var sink = V.SinkFor(F){ .values = actual };
        Circuit.begin(&context);
        try component.evaluatePointFor(F, circuit_point, 9, CircuitMasks{ .context = &context, .native = masks }, challenges, public, cclaim, &sink);
        try Circuit.finish();
        try std.testing.expectEqual(D.layout.CONSTRAINTS, sink.count);
        for (actual, expected) |v, q| try context.eq(v.v, try context.constant(q));
        try context.finalize(false);
        try std.testing.expectEqual(mutation == 0, try context.isCircuitValid());
    }
}
