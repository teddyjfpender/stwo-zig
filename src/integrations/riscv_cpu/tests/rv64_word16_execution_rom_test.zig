const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const E = front.rv64_air.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const R = X.rom_component;
fn challenge() X.types.RomChallenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: X.types.RomChallenges = undefined;
    ch.offset = channel.drawSecureFelt();
    for (&ch.coefficients) |*v| v.* = channel.drawSecureFelt();
    return ch;
}
fn q(comptime N: usize, values: [N]M) [N]Q {
    var out: [N]Q = undefined;
    for (values, &out) |v, *o| o.* = Q.fromBase(v);
    return out;
}
test "ROM30 negative physical prefix closes and rejects invalid counts wrong claims and unused poles" {
    const ch = challenge();
    const entry = X.Entry.fromDecoded(0x001080b3, 0x1000);
    var fixed: [32][32]M = @splat(@splat(M.zero()));
    @memcpy(fixed[0][0..30], &entry.romTuple(false));
    fixed[0][30] = M.one();
    fixed[31][31] = M.one();
    var inter: [32][8]M = undefined;
    const claim = (try ch.denominatorFor(Q, q(32, fixed[0])[0..30].*).inv()).mulM31(M.fromCanonical(3)).neg();
    var sum = claim.neg();
    for (0..32) |row| {
        const inverse = try ch.denominatorFor(Q, q(32, fixed[row])[0..30].*).inv();
        @memcpy(inter[row][0..4], &inverse.toM31Array());
        if (row == 0) sum = sum.sub(inverse.mulM31(M.fromCanonical(3)));
        @memcpy(inter[row][4..8], &sum.toM31Array());
    }
    const c = R.Component{ .log_size = 5, .offsets = .{ 0, 0, 0 }, .claim = claim, .challenges = ch };
    _ = c.asProverComponent();
    _ = c.asVerifierComponent();
    for (0..32) |row| {
        var values: [4]Q = undefined;
        var sink = E.Sink{ .values = &values };
        c.emitFor(Q, &q(32, fixed[row]), &.{E.q(if (row == 0) 3 else 0)}, &.{Q.zero()}, &q(8, inter[row]), &q(8, inter[(row + 31) % 32]), &sink);
        for (values) |v| try std.testing.expect(v.isZero());
    }
    var values: [4]Q = undefined;
    var sink = E.Sink{ .values = &values };
    c.emitFor(Q, &q(32, fixed[1]), &.{Q.one()}, &.{Q.zero()}, &q(8, inter[1]), &q(8, inter[0]), &sink);
    try std.testing.expect(values[1].eql(Q.one()));
    var bad = c;
    bad.claim = claim.add(Q.one());
    sink = .{ .values = &values };
    bad.emitFor(Q, &q(32, fixed[0]), &.{E.q(3)}, &.{Q.zero()}, &q(8, inter[0]), &q(8, inter[31]), &sink);
    try std.testing.expect(values[2].eql(Q.one()));
    bad = c;
    bad.challenges = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    sink = .{ .values = &values };
    bad.emitFor(Q, &q(32, fixed[1]), &.{Q.zero()}, &.{Q.zero()}, &q(8, inter[1]), &q(8, inter[0]), &sink);
    try std.testing.expect(values[0].eql(Q.one().neg()));
}
test "ROM30 every scalar and secure lookup polynomial is quadratic and all base lanes match" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const c = R.Component{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .claim = channel.drawSecureFelt(), .challenges = challenge() };
    var constants: [3][32]Q = undefined;
    var slopes: [3][32]Q = undefined;
    for (&constants, &slopes) |*a, *b| for (a, b) |*x, *y| {
        x.* = channel.drawSecureFelt();
        y.* = channel.drawSecureFelt();
    };
    var residuals: [4][4]Q = undefined;
    for (0..4) |point| {
        var data: [3][32]Q = undefined;
        for (&data, constants, slopes) |*row, a, b| {
            for (row, a, b) |*v, x, y| v.* = x.add(y.mulM31(M.fromCanonical(@intCast(point))));
        }
        var sink = E.Sink{ .values = &residuals[point] };
        c.emitFor(Q, &data[0], data[1][0..1], &.{Q.zero()}, data[2][0..8], data[2][8..16], &sink);
        try std.testing.expectEqual(@as(usize, 4), sink.count);
    }
    for (0..4) |i| try std.testing.expect(residuals[3][i].sub(residuals[2][i].mulM31(M.fromCanonical(3))).add(residuals[1][i].mulM31(M.fromCanonical(3))).sub(residuals[0][i]).isZero());
    var native: [3][32][16]M = undefined;
    var simd: [3][32]E.PackedBase = undefined;
    for (&native, &simd) |*a, *b| for (a, b) |*lanes, *v| {
        for (lanes) |*lane| lane.* = channel.drawSecureFelt().toM31Array()[0];
        v.* = E.PackedBase.fromLanes(lanes.*);
    };
    var got: [4]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &got };
    c.emitFor(E.PackedBase, &simd[0], simd[1][0..1], &.{E.PackedBase.zero()}, simd[2][0..8], simd[2][8..16], &sink);
    for (0..16) |lane| {
        var values: [3][32]Q = undefined;
        for (&values, native) |*a, b| {
            for (a, b) |*v, lanes| v.* = Q.fromBase(lanes[lane]);
        }
        var expected: [4]Q = undefined;
        var out = E.Sink{ .values = &expected };
        c.emitFor(Q, &values[0], values[1][0..1], &.{Q.zero()}, values[2][0..8], values[2][8..16], &out);
        for (expected, got) |x, y| try std.testing.expect(x.eql(y.lane(lane)));
    }
}
test "ROM30 packed weighted domain kernel matches scalar previous masks and additive tails" {
    const c = R.Component{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .claim = Q.one(), .challenges = challenge() };
    const n = 128;
    var data: [R.COLUMNS][n]M = undefined;
    var columns: [R.COLUMNS][]const M = undefined;
    for (&data, &columns, 0..) |*row, *view, c_| {
        for (row, 0..) |*v, i| v.* = M.fromCanonical(@intCast(c_ * n + i + 1));
        view.* = row;
    }
    const powers = [_]Q{ Q.one(), E.q(3), E.q(7), E.q(11) };
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    var expected: [4][n]M = @splat(@splat(M.zero()));
    var actual: [4][n]M = @splat(@splat(M.zero()));
    var refcol = engine.secure_column.SecureColumnByCoords{ .columns = .{ &expected[0], &expected[1], &expected[2], &expected[3] }, .owns_columns = false };
    var gotcol = engine.secure_column.SecureColumnByCoords{ .columns = .{ &actual[0], &actual[1], &actual[2], &actual[3] }, .owns_columns = false };
    var refout = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &refcol, .next_fresh_index = 0 };
    var gotout = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &gotcol, .next_fresh_index = 0 };
    for (0..2) |pass| {
        for (0..n) |row| {
            var fixed: [32]Q = undefined;
            for (&fixed, 0..) |*v, i| v.* = Q.fromBase(columns[i][row]);
            var current: [8]Q = undefined;
            var prior: [8]Q = @splat(Q.zero());
            const previous = core.utils.previousBitReversedCircleDomainIndex(row, 6, 7);
            for (&current, 0..) |*v, i| {
                v.* = Q.fromBase(columns[33 + i][row]);
                if (i >= 4) prior[i] = Q.fromBase(columns[33 + i][previous]);
            }
            var acc = E.WeightedAccumulator{ .powers = &powers };
            var sink = E.Sink{ .values = null, .weighted_accumulator = &acc };
            c.emitFor(Q, &fixed, &.{Q.fromBase(columns[32][row])}, &.{Q.zero()}, &current, &prior, &sink);
            refout.accumulate(row, acc.accumulation.mulM31(inverses[row >> 6]));
        }
        if (pass == 0) try R.testing.packedRows.evaluate(&c, &columns, 0, n, &inverses, &gotout) else for ([_][2]usize{ .{ 0, 7 }, .{ 7, 65 }, .{ 65, n } }) |range| try R.testing.packedRows.evaluate(&c, &columns, range[0], range[1], &inverses, &gotout);
        for (expected, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
    }
}
