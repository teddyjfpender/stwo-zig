const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const V = @import("vectors.zig");
fn input(v: V.Vector) W.Input {
    return .{ .z = v.z, .seed = v.seed, .c = v.c[0..6].*, .inverse2 = v.inverse2 };
}
test "BN254 residue fixed exponent source DAG and Fp6 literal alias authority" {
    const p = &W.ROM;
    try std.testing.expectEqual(@as(usize, 109), p.operation_count);
    try std.testing.expectEqual(@as(usize, 768), p.square_count);
    try std.testing.expectEqual(@as(usize, 504), p.multiply_count);
    try std.testing.expectEqual(@as(usize, 36), p.frobenius_count);
    try std.testing.expectEqual(@as(u1024, 0), S.LAMBDA % S.R);
    for (p.scale[6..]) |id| try std.testing.expectEqual(S.ZERO, id);
    var writers: [S.VALUES]bool = @splat(false);
    @memset(writers[0 .. S.INITIAL + S.PRIVATE_HINTS], true);
    inline for (.{ S.Kind.square, S.Kind.multiply, S.Kind.frobenius }) |kind| {
        const nodes = switch (kind) {
            .square => p.squares[0..],
            .multiply => p.multiplies[0..],
            .frobenius => p.frobenius[0..],
        };
        for (nodes) |node| {
            try std.testing.expect(!writers[node.writer]);
            writers[node.writer] = true;
            for (node.input[0..S.inputs(kind)]) |id| try std.testing.expect(id < node.writer);
        }
    }
    for (writers) |yes| try std.testing.expect(yes);
    const fanout = S.fanout(p);
    var mass: u32 = 0;
    for (fanout) |n| mass += n;
    try std.testing.expectEqual(@as(u32, 21456), mass);
    try std.testing.expect(mass < S.B.M31);
}
test "BN254 residue efficient source certificate matches real four-pair oracle and generic Frobenius powers" {
    var witness = try W.Witness.init(std.testing.allocator, input(V.POSITIVE));
    defer witness.deinit();
    try std.testing.expect(witness.satisfied());
    try std.testing.expectEqual(V.EXPECTED_FROBENIUS[0], witness.output(W.ROM.seed1));
    try std.testing.expectEqual(V.EXPECTED_FROBENIUS[1], witness.output(W.ROM.seed2));
    try std.testing.expectEqual(V.EXPECTED_FROBENIUS[2], witness.output(W.ROM.seed3));
    inline for (.{ S.Kind.square, S.Kind.multiply, S.Kind.frobenius }) |kind| std.debug.print("RESIDUE_SOURCE kind={s} main={d} byte_queries={d} carry_bits={d} q_bytes={d}\n", .{ @tagName(kind), W.Layout(kind).MAIN, W.Layout(kind).BYTE_QUERIES, W.Layout(kind).G.carry_bits, W.Layout(kind).G.q_bytes });
}
test "BN254 residue unrestricted negative-z inverse scale reaches ONE but immutable Fp6 binding rejects" {
    var witness = try W.Witness.init(std.testing.allocator, input(V.OFF_SUBFIELD));
    defer witness.deinit();
    var nonzero = false;
    for (V.OFF_SUBFIELD.c[6..]) |v| nonzero = nonzero or v != 0;
    try std.testing.expect(nonzero);
    witness.injectOffSubfieldForTesting(&V.OFF_SUBFIELD.c);
    try std.testing.expect(witness.hintsCanonical());
    try std.testing.expect(witness.arithmeticValid());
    try std.testing.expect(witness.endpointsOne());
    try std.testing.expect(!witness.sourceReadsConsistent());
    try std.testing.expect(!witness.satisfied());
}
test "BN254 residue zero seed and altered inverse cannot bypass full ONE predicates" {
    var bad = input(V.POSITIVE);
    bad.seed = @splat(0);
    var zero = try W.Witness.init(std.testing.allocator, bad);
    defer zero.deinit();
    try std.testing.expect(!zero.endpointsOne());
    bad = input(V.POSITIVE);
    bad.inverse2[7] = (bad.inverse2[7] + 1) % S.B.BN254_P;
    var inverse = try W.Witness.init(std.testing.allocator, bad);
    defer inverse.deinit();
    try std.testing.expect(!W.Witness.one(inverse.output(W.ROM.inverse_check)));
}

test "BN254 residue identity and zero-scale cases plus carried-output mutations" {
    var args = W.Input{ .z = @splat(0), .seed = @splat(0), .c = @splat(0), .inverse2 = @splat(0) };
    args.z[0] = 1;
    args.seed[0] = 1;
    args.c[0] = 1;
    args.inverse2[0] = 1;
    var identity = try W.Witness.init(std.testing.allocator, args);
    defer identity.deinit();
    try std.testing.expect(identity.satisfied());
    args.c = @splat(0);
    var zero = try W.Witness.init(std.testing.allocator, args);
    defer zero.deinit();
    try std.testing.expect(!zero.endpointsOne());
    var positive = try W.Witness.init(std.testing.allocator, input(V.POSITIVE));
    defer positive.deinit();
    inline for (.{ S.Kind.square, S.Kind.multiply, S.Kind.frobenius }) |kind| {
        const L = W.Layout(kind);
        try std.testing.expectEqual(@as(usize, 1), L.G.group);
        const nodes = switch (kind) {
            .square => W.ROM.squares[0..],
            .multiply => W.ROM.multiplies[0..],
            .frobenius => W.ROM.frobenius[0..],
        };
        const row = positive.rowAt(kind, 0);
        var bad = row;
        bad[L.OUTPUT] ^= 1;
        try std.testing.expect(!L.valid(0, &bad));
        bad = row;
        bad[L.QUOTIENT] ^= 1;
        try std.testing.expect(!L.valid(0, &bad));
        bad = row;
        bad[L.CARRY] ^= 1;
        try std.testing.expect(!L.valid(0, &bad));
        var operands: [S.inputs(kind)]u256 = undefined;
        for (nodes[0].input[0..S.inputs(kind)], &operands) |id, *value| value.* = positive.values[id];
        const forged = L.congruentForgeryForTesting(0, &operands);
        try std.testing.expect(L.rangeValid(&forged));
        try std.testing.expect(L.carriedValid(0, &forged));
        try std.testing.expect(!L.valid(0, &forged));
    }
}
