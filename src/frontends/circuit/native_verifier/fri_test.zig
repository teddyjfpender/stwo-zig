//! Value-mode parity of `fri.zig` with `core/fri.zig`: the commit
//! transcript on a prover-built FRI proof, query positions as circle
//! domain points, and the last-layer line polynomial. Decommitment is
//! exercised end to end by `e2e_test.zig`.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const channel_mod = @import("channel.zig");
const fixture_mod = @import("test_fixture.zig");
const fri = @import("fri.zig");
const proof_mod = @import("proof.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const Simd = builder.simd.Simd;
const Blake2sChannel = core.channel.blake2s.Blake2sChannel;

test "native fri: friCommit mixes roots, draws alphas and mixes the last layer like FriVerifier.commit" {
    const gpa = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(gpa, fixture_mod.default_config, fixture_mod.default_statement);
    defer fixture.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const value_proof = try proof_mod.fromNative(arena.allocator(), fixture_mod.Hasher, &fixture.proof, &fixture.capture, &fixture.shape);

    // Both channels start from the same arbitrary state.
    var native = Blake2sChannel{};
    native.mixU64(0xABCD);
    const config = fixture.config.fri_config;
    const bound = core.fri.CirclePolyDegreeBound.init(fixture.shape.logDegreeBound());
    var native_fri = try core.fri.FriVerifier(fixture_mod.Hasher, fixture_mod.MerkleChannel).commit(gpa, &native, config, fixture.proof.commitment_scheme_proof.fri_proof, bound);
    defer native_fri.deinit(gpa);

    var ctx = try Context.init(gpa, 0);
    defer ctx.deinit();
    var channel = try channel_mod.NativeChannel.init(QM31, &ctx);
    const lo = try builder.wrappers.guessU32(QM31, &ctx, builder.wrappers.u32Value(QM31, 0xABCD));
    const hi = try builder.wrappers.guessU32(QM31, &ctx, builder.wrappers.u32Value(QM31, 0));
    try channel.mixU64(QM31, &ctx, lo, hi);
    const wires = try proof_mod.guess(QM31, &ctx, &value_proof);
    const alphas = try fri.friCommit(QM31, &ctx, &channel, &wires.fri);

    try std.testing.expectEqual(1 + native_fri.inner_layers.len, alphas.len);
    try std.testing.expect(ctx.get(alphas[0]).eql(native_fri.first_layer.folding_alpha));
    for (alphas[1..], native_fri.inner_layers) |alpha, layer| try std.testing.expect(ctx.get(alpha).eql(layer.folding_alpha));
    try std.testing.expectEqualSlices(u8, &native.digestBytes(), &channel.debugDigest(&ctx));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

fn bitSimd(ctx: *Context, positions: []const usize, bit: usize) !Simd {
    const lanes = try ctx.scratch().alloc(builder.wrappers.M31Wrapper(Var), positions.len);
    for (lanes, positions) |*lane, position| {
        lane.* = .newUnsafe(try ctx.guess(builder.ivalue.qm31FromU32s(@intCast((position >> @intCast(bit)) & 1), 0, 0, 0)));
    }
    return builder.simd.pack(QM31, ctx, lanes);
}

test "native fri: query points are the canonic domain at the bit-reversed position" {
    const log_domain: u32 = 4;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log_domain).circleDomain();
    var positions: [16]usize = undefined;
    for (&positions, 0..) |*position, i| position.* = i;
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const bits = try ctx.scratch().alloc(Simd, log_domain);
    for (bits, 0..) |*bit, i| bit.* = try bitSimd(&ctx, &positions, i);
    const points = try fri.queryPoints(QM31, &ctx, bits, log_domain);
    for (positions) |position| {
        const expected = domain.at(core.utils.bitReverseIndex(position, log_domain));
        const x = ctx.get(points.x.data[position / 4]).toM31Array()[position % 4];
        const y = ctx.get(points.y.data[position / 4]).toM31Array()[position % 4];
        try std.testing.expect(x.eql(expected.x));
        try std.testing.expect(y.eql(expected.y));
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "native fri: evalLinePoly matches LinePoly.evalAtPoint" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    for ([_]usize{ 1, 2, 4, 8 }) |n| {
        const coeffs = try std.testing.allocator.alloc(QM31, n);
        defer std.testing.allocator.free(coeffs);
        for (coeffs, 0..) |*coeff, i| coeff.* = QM31.fromU32Unchecked(@intCast(11 * i + 3), @intCast(i), @intCast(5 * i), 1);
        const poly = core.poly.line.LinePoly.initOwned(coeffs);
        const x = QM31.fromU32Unchecked(77_777, 3, 9, 123);
        const expected = try poly.evalAtPoint(std.testing.allocator, x);
        const wires = try ctx.scratch().alloc(Var, n);
        for (wires, coeffs) |*wire, coeff| wire.* = try ctx.guess(coeff);
        const actual = try fri.evalLinePoly(QM31, &ctx, wires, try ctx.guess(x));
        try std.testing.expect(ctx.get(actual).eql(expected));
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "native fri: fold step schedule follows allFoldSteps" {
    var buffer: [16]u32 = undefined;
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1 }, core.fri.allFoldSteps(4, 1, &buffer));
    try std.testing.expectEqualSlices(u32, &.{ 3, 1 }, core.fri.allFoldSteps(4, 3, &buffer));
    _ = M31.one();
}
