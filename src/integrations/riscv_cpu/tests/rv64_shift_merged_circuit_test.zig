//! Direct circuit wires for the complete SHIFT38 polynomial, including claims.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const P = rv.word16_v1.shift_word_packed_experiment.lookup;
const E = rv.evaluation;
const Q = E.Q;
const Lane = @import("../rv64_recursion/circuit_lane.zig");
const F = Lane.Lane;
fn wire(ctx: *Lane.Context, q: Q) !F {
    return F.wire(try ctx.guess(q));
}
test "SHIFT36 complete CircuitLane binds function range and total claim without independent ledger certificates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch = P.Challenges{ .shift = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined }, .range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() }, .function = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined } };
    for (&ch.shift.coefficients) |*v| v.* = channel.drawSecureFelt();
    for (&ch.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    const claims = P.Claims{ .shift = channel.drawSecureFelt(), .range16 = channel.drawSecureFelt(), .function = channel.drawSecureFelt() };
    var main: [P.MAIN]Q = undefined;
    var current: [P.INTERACTION]Q = undefined;
    var previous: [P.INTERACTION]Q = undefined;
    for (&main) |*v| v.* = channel.drawSecureFelt();
    for (&current) |*v| v.* = channel.drawSecureFelt();
    for (&previous) |*v| v.* = channel.drawSecureFelt();
    const first = channel.drawSecureFelt();
    const last = channel.drawSecureFelt();
    var expected: [P.CONSTRAINTS]Q = undefined;
    var native = E.Sink{ .values = &expected };
    P.emitFor(Q, &main, &current, &previous, first, last, claims, ch, &native);
    for (0..5) |mutation| {
        var ctx = try Lane.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var mw: [P.MAIN]F = undefined;
        var cw: [P.INTERACTION]F = undefined;
        var pw: [P.INTERACTION]F = undefined;
        for (&mw, main) |*v, q| v.* = try wire(&ctx, q);
        for (&cw, current) |*v, q| v.* = try wire(&ctx, q);
        for (&pw, previous) |*v, q| v.* = try wire(&ctx, q);
        const fc = try wire(&ctx, first);
        const lc = try wire(&ctx, last);
        var chw: P.ChallengesFor(F) = undefined;
        chw.shift.offset = try wire(&ctx, ch.shift.offset);
        for (&chw.shift.coefficients, ch.shift.coefficients) |*v, q| v.* = try wire(&ctx, q);
        chw.range16.offset = try wire(&ctx, ch.range16.offset);
        chw.range16.coefficient = try wire(&ctx, ch.range16.coefficient.add(if (mutation == 2) Q.one() else Q.zero()));
        chw.function.offset = try wire(&ctx, ch.function.offset.add(if (mutation == 1) Q.one() else Q.zero()));
        for (&chw.function.coefficients, ch.function.coefficients) |*v, q| v.* = try wire(&ctx, q);
        const claimw = P.ClaimsFor(F){ .shift = try wire(&ctx, claims.shift), .range16 = try wire(&ctx, claims.range16.add(if (mutation == 3 or mutation == 4) Q.one() else Q.zero())), .function = try wire(&ctx, claims.function.sub(if (mutation == 4) Q.one() else Q.zero())) };
        var actual: [P.CONSTRAINTS]F = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        Lane.begin(&ctx);
        P.emitFor(F, &mw, &cw, &pw, fc, lc, claimw, chw, &sink);
        try Lane.finish();
        try std.testing.expectEqual(P.CONSTRAINTS, sink.count);
        for (actual, expected) |value, q| try ctx.eq(value.v, try ctx.constant(q));
        try ctx.finalize(false);
        try std.testing.expectEqual(mutation == 0 or mutation == 4, try ctx.isCircuitValid());
    }
}
