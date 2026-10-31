const std = @import("std");
const core = @import("stwo_core");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const L = X.layout;
const Eq = X.equations;
fn challenges(channel: *core.channel.blake2s.Blake2sChannel) X.types.Challenges {
    var out: X.types.Challenges = undefined;
    inline for (.{ "register", "function", "rom", "owner" }) |field| {
        @field(out, field).offset = channel.drawSecureFelt();
        for (&@field(out, field).coefficients) |*value| value.* = channel.drawSecureFelt();
    }
    inline for (.{ "range16", "range8" }) |field| @field(out, field) = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return out;
}
fn inputs() X.types.Inputs {
    return .{ .steps = 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 }, .epoch = 1 };
}
fn toQ(comptime N: usize, values: [N]M) [N]Q {
    var out: [N]Q = undefined;
    for (values, &out) |v, *o| o.* = Q.fromBase(v);
    return out;
}
test "full CPU55 residuals are cubic over dense full-extension coordinates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const claim = channel.drawSecureFelt();
    var constants: [5][53]Q = undefined;
    var slopes: [5][53]Q = undefined;
    for (&constants, &slopes) |*a, *b| for (a, b) |*x, *y| {
        x.* = channel.drawSecureFelt();
        y.* = channel.drawSecureFelt();
    };
    var result: [5][55]Q = undefined;
    for (0..5) |point| {
        var data: [5][53]Q = undefined;
        for (&data, constants, slopes) |*row, a, b| {
            for (row, a, b) |*v, c, s| v.* = c.add(s.mulM31(M.fromCanonical(@intCast(point))));
        }
        var sink = E.Sink{ .values = &result[point] };
        Eq.emitFor(Q, data[0][0..3], &data[1], &data[2], data[3][0..40], data[4][0..40], inputs(), claim, ch, &sink);
        try std.testing.expectEqual(@as(usize, 55), sink.count);
    }
    var cubic = false;
    for (0..55) |i| {
        const fourth = result[0][i].sub(result[1][i].mulM31(M.fromCanonical(4))).add(result[2][i].mulM31(M.fromCanonical(6))).sub(result[3][i].mulM31(M.fromCanonical(4))).add(result[4][i]);
        try std.testing.expect(fourth.isZero());
        const third = result[3][i].sub(result[2][i].mulM31(M.fromCanonical(3))).add(result[1][i].mulM31(M.fromCanonical(3))).sub(result[0][i]);
        cubic = cubic or !third.isZero();
    }
    try std.testing.expect(cubic);
}
test "full CPU mixed packed lanes and native denominator/contribution projections equal QM31" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const claim = channel.drawSecureFelt();
    const B = E.PackedBase;
    var data: [5][53][16]M = undefined;
    var simd: [5][53]B = undefined;
    for (&data, &simd) |*a, *b| for (a, b) |*lanes, *v| {
        for (lanes) |*lane| lane.* = channel.drawSecureFelt().toM31Array()[0];
        v.* = B.fromLanes(lanes.*);
    };
    var packed_result: [55]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &packed_result };
    Eq.emitFor(B, simd[0][0..3], &simd[1], &simd[2], simd[3][0..40], simd[4][0..40], inputs(), claim, ch, &sink);
    try std.testing.expectEqual(@as(usize, 55), sink.count);
    for (0..16) |lane| {
        var native: [5][53]M = undefined;
        for (&native, data) |*a, b| {
            for (a, b) |*v, lanes| v.* = lanes[lane];
        }
        var q: [5][53]Q = undefined;
        for (native, &q) |a, *b| b.* = toQ(53, a);
        var residuals: [55]Q = undefined;
        var out = E.Sink{ .values = &residuals };
        Eq.emitFor(Q, q[0][0..3], &q[1], &q[2], q[3][0..40], q[4][0..40], inputs(), claim, ch, &out);
        for (residuals, packed_result) |wanted, got| try std.testing.expect(wanted.eql(got.lane(lane)));
        const a = Eq.denominatorsFor(Q, q[0][0..3], &q[1], inputs(), ch);
        const b = Eq.nativeDenominators(native[0][0..3], &native[1], inputs(), ch);
        const aa = Eq.inverseDenominatorsFor(Q, a);
        const bb = Eq.inverseDenominatorsFor(Q, b);
        for (aa, bb) |x, y| try std.testing.expect(x.eql(y));
        try std.testing.expect(Eq.nativeContribution(b, &native[1], aa).eql(Eq.contributionFor(Q, a, Eq.weightsFor(Q, &q[1]), aa)));
    }
}
test "full CPU native witness satisfies all55 equations and rejects ghosts wrapped clocks and unused poles" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    var main: [32][53]M = undefined;
    var fixed: [32][3]M = undefined;
    var inter: [32][40]M = undefined;
    var contributions: [32]Q = undefined;
    var claim = Q.zero();
    const entry = X.Entry.fromDecoded(0x001080b3, 0x1000); // add x1,x1,x1.
    for (0..32) |row| {
        fixed[row] = .{ M.fromCanonical(@intCast(row)), M.fromCanonical(@intFromBool(row == 0)), M.fromCanonical(@intFromBool(row == 31)) };
        main[row] = if (row == 0) try X.row.active(entry, 0, 0x1004, .{ .a = 7, .b = 7, .c = 14, .previous_rd = 7 }, .{ 0, 1, 2 }) else try X.row.padding(@intCast(row), 0x1004);
        const ds = Eq.nativeDenominators(&fixed[row], &main[row], inputs(), ch);
        var inverse: [9]Q = undefined;
        for (Eq.inverseDenominatorsFor(Q, ds), &inverse) |d, *value| value.* = try d.inv();
        for (inverse, 0..) |value, i| @memcpy(inter[row][4 * i ..][0..4], &value.toM31Array());
        contributions[row] = Eq.nativeContribution(ds, &main[row], inverse);
        claim = claim.add(contributions[row]);
    }
    var sum = claim.neg();
    for (0..32) |row| {
        sum = sum.add(contributions[row]);
        @memcpy(inter[row][36..40], &sum.toM31Array());
    }
    try std.testing.expect(sum.isZero());
    for (0..32) |row| {
        const prior = (row + 31) % 32;
        var residuals: [55]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        Eq.emitFor(Q, &toQ(3, fixed[row]), &toQ(53, main[row]), &toQ(53, main[prior]), &toQ(40, inter[row]), &toQ(40, inter[prior]), inputs(), claim, ch, &sink);
        for (residuals) |value| try std.testing.expect(value.isZero());
    }
    var ghost = toQ(53, main[1]);
    ghost[L.main.function] = Q.one();
    var residuals: [55]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    Eq.emitFor(Q, &toQ(3, fixed[1]), &ghost, &toQ(53, main[0]), &toQ(40, inter[1]), &toQ(40, inter[0]), inputs(), claim, ch, &sink);
    try std.testing.expect(!residuals[43].isZero());
    var pole = ch;
    pole.function.offset = Q.zero();
    pole.function.coefficients = @splat(Q.zero());
    sink = .{ .values = &residuals };
    Eq.emitFor(Q, &toQ(3, fixed[1]), &toQ(53, main[1]), &toQ(53, main[0]), &toQ(40, inter[1]), &toQ(40, inter[0]), inputs(), claim, pole, &sink);
    try std.testing.expect(residuals[47].eql(Q.one().neg()));
    var bad = inputs();
    bad.epoch = 0;
    try std.testing.expectError(error.InvalidExecutionInputs, X.types.validateInputs(bad, 5));
    bad = inputs();
    bad.initial_pc[0] = 65536;
    try std.testing.expectError(error.InvalidExecutionInputs, X.types.validateInputs(bad, 5));
}
