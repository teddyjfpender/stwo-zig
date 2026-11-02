//! Opt-in fused-tail CPU interaction (36 columns, 51 residuals): degree,
//! lane parity, exact per-row LogUp increment and forged-witness rejection.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const L = X.layout;
const Eq = X.equations;
const W = L.fused.COUNT;
const N = Eq.FUSED_CONSTRAINTS;
// Residual indices of the fused interaction block.
const REG = Eq.MAIN_CONSTRAINTS;
const FUNCTION = REG + 3;
const ROM = REG + 4;
const OWNER = REG + 5;
const U16 = REG + 6;
const U8 = REG + 7;
const FUSED = REG + 8;
const LAST = REG + 9;
comptime {
    std.debug.assert(W == 36 and N == 51 and LAST == N - 1);
}
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
fn toQ(comptime K: usize, values: [K]M) [K]Q {
    var out: [K]Q = undefined;
    for (values, &out) |v, *o| o.* = Q.fromBase(v);
    return out;
}
fn put(row: *[W]M, column: usize, value: Q) void {
    @memcpy(row[column..][0..4], &value.toM31Array());
}
fn get(row: [W]M, column: usize) Q {
    return Q.fromM31Array(row[column..][0..4].*);
}

test "fused CPU residuals are cubic over dense full-extension coordinates (all51)" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const claim = channel.drawSecureFelt();
    var constants: [5][L.main.COUNT]Q = undefined;
    var slopes: [5][L.main.COUNT]Q = undefined;
    for (&constants, &slopes) |*a, *b| for (a, b) |*x, *y| {
        x.* = channel.drawSecureFelt();
        y.* = channel.drawSecureFelt();
    };
    var result: [5][N]Q = undefined;
    for (0..5) |point| {
        var data: [5][L.main.COUNT]Q = undefined;
        for (&data, constants, slopes) |*row, a, b| {
            for (row, a, b) |*v, c, s| v.* = c.add(s.mulM31(M.fromCanonical(@intCast(point))));
        }
        var sink = E.Sink{ .values = &result[point] };
        Eq.emitFusedFor(Q, data[0][0..3], &data[1], &data[2], data[3][0..W], data[4][0..W], inputs(), claim, ch, &sink);
        try std.testing.expectEqual(@as(usize, N), sink.count);
    }
    var cubic_fused = false;
    for (0..N) |i| {
        const fourth = result[0][i].sub(result[1][i].mulM31(M.fromCanonical(4))).add(result[2][i].mulM31(M.fromCanonical(6))).sub(result[3][i].mulM31(M.fromCanonical(4))).add(result[4][i]);
        try std.testing.expect(fourth.isZero());
        const third = result[3][i].sub(result[2][i].mulM31(M.fromCanonical(3))).add(result[1][i].mulM31(M.fromCanonical(3))).sub(result[0][i]);
        if (i == FUSED) cubic_fused = !third.isZero();
    }
    // The fused prefix residual genuinely uses the degree-3 budget.
    try std.testing.expect(cubic_fused);
}

test "fused CPU packed lanes equal QM31 and fused contribution equals the legacy increment" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const claim = channel.drawSecureFelt();
    const B = E.PackedBase;
    var data: [5][L.main.COUNT][16]M = undefined;
    var simd: [5][L.main.COUNT]B = undefined;
    for (&data, &simd) |*a, *b| for (a, b) |*lanes, *v| {
        for (lanes) |*lane| lane.* = channel.drawSecureFelt().toM31Array()[0];
        v.* = B.fromLanes(lanes.*);
    };
    var packed_result: [N]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &packed_result };
    Eq.emitFusedFor(B, simd[0][0..3], &simd[1], &simd[2], simd[3][0..W], simd[4][0..W], inputs(), claim, ch, &sink);
    try std.testing.expectEqual(@as(usize, N), sink.count);
    for (0..16) |lane| {
        var native: [5][L.main.COUNT]M = undefined;
        for (&native, data) |*a, b| {
            for (a, b) |*v, lanes| v.* = lanes[lane];
        }
        var q: [5][L.main.COUNT]Q = undefined;
        for (native, &q) |a, *b| b.* = toQ(L.main.COUNT, a);
        var residuals: [N]Q = undefined;
        var out = E.Sink{ .values = &residuals };
        Eq.emitFusedFor(Q, q[0][0..3], &q[1], &q[2], q[3][0..W], q[4][0..W], inputs(), claim, ch, &out);
        for (residuals, packed_result) |wanted, got| try std.testing.expect(wanted.eql(got.lane(lane)));
        // Same LogUp statement: identical per-row increment on random rows.
        const ds = Eq.nativeDenominators(native[0][0..3], &native[1], inputs(), ch);
        var inverse: [9]Q = undefined;
        for (Eq.inverseDenominatorsFor(Q, ds), &inverse) |d, *value| value.* = try d.inv();
        const witnesses = try Eq.nativeFusedWitnesses(ds, &native[1]);
        try std.testing.expect((try Eq.nativeFusedContribution(ds, &native[1], witnesses)).eql(Eq.nativeContribution(ds, &native[1], inverse)));
    }
}

const Trace = struct {
    fixed: [32][3]M,
    main: [32][L.main.COUNT]M,
    inter: [32][W]M,
    claim: Q,
    ch: X.types.Challenges,
    fn init() !Trace {
        var channel = core.channel.blake2s.Blake2sChannel{};
        var self: Trace = undefined;
        self.ch = challenges(&channel);
        var contributions: [32]Q = undefined;
        self.claim = Q.zero();
        const entry = X.Entry.fromDecoded(0x001080b3, 0x1000); // add x1,x1,x1.
        for (0..32) |row| {
            self.fixed[row] = .{ M.fromCanonical(@intCast(row)), M.fromCanonical(@intFromBool(row == 0)), M.fromCanonical(@intFromBool(row == 31)) };
            self.main[row] = if (row == 0) try X.row.active(entry, 0, 0x1004, .{ .a = 7, .b = 7, .c = 14, .previous_rd = 7 }, .{ 0, 1, 2 }) else try X.row.padding(@intCast(row), 0x1004);
            const ds = Eq.nativeDenominators(&self.fixed[row], &self.main[row], inputs(), self.ch);
            const witnesses = try Eq.nativeFusedWitnesses(ds, &self.main[row]);
            for (witnesses, 0..) |value, i| put(&self.inter[row], 4 * i, value);
            contributions[row] = try Eq.nativeFusedContribution(ds, &self.main[row], witnesses);
            self.claim = self.claim.add(contributions[row]);
        }
        var sum = self.claim.neg();
        for (0..32) |row| {
            sum = sum.add(contributions[row]);
            put(&self.inter[row], L.fused.sum, sum);
        }
        try std.testing.expect(sum.isZero());
        return self;
    }
    fn residuals(self: *const Trace, row: usize, current: [W]M, previous: [W]M, ch: X.types.Challenges) [N]Q {
        const prior = (row + 31) % 32;
        var out: [N]Q = undefined;
        var sink = E.Sink{ .values = &out };
        Eq.emitFusedFor(Q, &toQ(3, self.fixed[row]), &toQ(L.main.COUNT, self.main[row]), &toQ(L.main.COUNT, self.main[prior]), &toQ(W, current), &toQ(W, previous), inputs(), self.claim, ch, &sink);
        return out;
    }
    fn at(self: *const Trace, row: usize) [N]Q {
        return self.residuals(row, self.inter[row], self.inter[(row + 31) % 32], self.ch);
    }
};
fn onlyNonzero(values: [N]Q, wanted: []const usize) !void {
    for (values, 0..) |value, i| {
        const expected = std.mem.indexOfScalar(usize, wanted, i) != null;
        try std.testing.expectEqual(expected, !value.isZero());
    }
}

test "fused CPU native witness satisfies all51 and every forged witness is rejected" {
    const t = try Trace.init();
    for (0..32) |row| try onlyNonzero(t.at(row), &.{});
    const delta = Q.fromU32Unchecked(3, 1, 4, 1);
    // Row 0 is `add x1,x1,x1`: all three register slots are enabled.
    try std.testing.expectEqual(M.one(), t.main[0][L.main.enabled + 2]);
    for (0..3) |slot| {
        var forged = t.inter[0];
        put(&forged, 4 * slot, get(forged, 4 * slot).add(delta));
        // R_s perturbed: the fraction AND the prefix both fail.
        try onlyNonzero(t.residuals(0, forged, t.inter[31], t.ch), &.{ REG + slot, FUSED });
        // Prefix repaired by the same delta: the fraction residual alone still rejects.
        put(&forged, L.fused.sum, get(forged, L.fused.sum).add(delta));
        try onlyNonzero(t.residuals(0, forged, t.inter[31], t.ch), &.{REG + slot});
        // R_s replaced by the bare (legacy) inverse 1/(before*after).
        const ds = Eq.nativeDenominators(&t.fixed[0], &t.main[0], inputs(), t.ch);
        forged = t.inter[0];
        put(&forged, 4 * slot, try ds.before[slot].mul(ds.after[slot]).inv());
        try std.testing.expect(!t.residuals(0, forged, t.inter[31], t.ch)[REG + slot].isZero());
    }
    // Disabled slot (padding row): a nonzero fraction cannot inject mass.
    try std.testing.expectEqual(M.zero(), t.main[5][L.main.enabled]);
    var forged = t.inter[5];
    put(&forged, 0, delta);
    put(&forged, L.fused.sum, get(forged, L.fused.sum).add(delta));
    try onlyNonzero(t.residuals(5, forged, t.inter[4], t.ch), &.{REG});
    // OWNER+U16 pair fraction perturbed, prefix repaired.
    forged = t.inter[0];
    put(&forged, 20, get(forged, 20).add(delta));
    put(&forged, L.fused.sum, get(forged, L.fused.sum).add(delta));
    try onlyNonzero(t.residuals(0, forged, t.inter[31], t.ch), &.{OWNER});
    // Strict inverse slots keep rejecting perturbations.
    for ([_]usize{ 3, 4, 6, 7 }, [_]usize{ FUNCTION, ROM, U16, U8 }) |slot, residual| {
        forged = t.inter[3];
        put(&forged, 4 * slot, get(forged, 4 * slot).add(delta));
        try std.testing.expect(!t.residuals(3, forged, t.inter[2], t.ch)[residual].isZero());
    }
    // S+delta on one row: that row and its successor reject.
    forged = t.inter[7];
    put(&forged, L.fused.sum, get(forged, L.fused.sum).add(delta));
    try onlyNonzero(t.residuals(7, forged, t.inter[6], t.ch), &.{FUSED});
    try onlyNonzero(t.residuals(8, t.inter[8], forged, t.ch), &.{FUSED});
    // Zeroed fused-tail fraction compensated in S at another row: every
    // witness and the global claim are honest, only the prefix path moves.
    const d6 = Eq.nativeDenominators(&t.fixed[9], &t.main[9], inputs(), t.ch).affine[6];
    const tail = try d6.inv();
    var shifted = t.inter;
    for (9..12) |row| put(&shifted[row], L.fused.sum, get(shifted[row], L.fused.sum).sub(tail));
    try std.testing.expect(!t.residuals(9, shifted[9], shifted[8], t.ch)[FUSED].isZero());
    try std.testing.expect(!t.residuals(12, shifted[12], shifted[11], t.ch)[FUSED].isZero());
    // Last row must carry a zero prefix.
    forged = t.inter[31];
    put(&forged, L.fused.sum, delta);
    try std.testing.expect(!t.residuals(31, forged, t.inter[30], t.ch)[LAST].isZero());
}

test "fused tail is strict at a U8 pole and strict inverse slots keep their poles" {
    const t = try Trace.init();
    // Choose the U8 challenge so that row 3's tail denominator vanishes.
    var pole = t.ch;
    pole.range8.offset = pole.range8.coefficient.mulM31(t.main[3][L.main.gap8 + 2]);
    const residuals = t.residuals(3, t.inter[3], t.inter[2], pole);
    try std.testing.expect(residuals[FUSED].eql(Q.one().neg()));
    var fn_pole = t.ch;
    fn_pole.function.offset = Q.zero();
    fn_pole.function.coefficients = @splat(Q.zero());
    try std.testing.expect(t.residuals(1, t.inter[1], t.inter[0], fn_pole)[FUNCTION].eql(Q.one().neg()));
}

fn component(fused: bool) X.component.Component {
    var channel = core.channel.blake2s.Blake2sChannel{};
    return .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .public = .{ .steps = 1, .epoch = 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 } }, .claim = Q.fromU32Unchecked(3, 5, 7, 11), .challenges = challenges(&channel), .fused = fused };
}
test "fused CPU component binds 36 columns, 51 degree-3 residuals and prefix-only previous masks" {
    const legacy = component(false);
    const c = component(true);
    try std.testing.expectEqual([3]usize{ 3, 47, 40 }, legacy.widths());
    try std.testing.expectEqual(@as(usize, 52), legacy.nConstraints());
    try std.testing.expectEqual([3]usize{ 3, 47, 36 }, c.widths());
    try std.testing.expectEqual(@as(usize, 51), c.nConstraints());
    for (0..51) |index| try std.testing.expectEqual(@as(u8, 3), try c.constraintDegreeBound(index));
    try std.testing.expectError(error.InvalidConstraintIndex, c.constraintDegreeBound(51));
    for (0..36) |column| try std.testing.expectEqual(column >= 32, c.needsPrevious(2, column));
    const point = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
    var masks = try c.maskPoints(std.testing.allocator, point, 7);
    defer masks.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 36), masks.items[2].len);
    for (c.widths(), 0..) |width, tree| for (0..width) |column| try std.testing.expectEqual(@as(usize, if (c.needsPrevious(tree, column)) 2 else 1), masks.items[tree][column].len);
}
fn scalar(c: *const X.component.Component, columns: []const []const M, inverses: []const M, out: *engine.air.accumulation.ColumnAccumulator) void {
    const n = columns[0].len;
    for (0..n) |row| {
        var values: [3 + L.main.COUNT + W]Q = undefined;
        var pm: [L.main.COUNT]Q = @splat(Q.zero());
        var pi: [W]Q = @splat(Q.zero());
        for (columns, 0..) |column, i| values[i] = Q.fromBase(column[row]);
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, c.log_size, c.log_size + 1);
        for (0..L.main.COUNT) |i| if (L.previousMain(i)) {
            pm[i] = Q.fromBase(columns[3 + i][prior]);
        };
        for (0..W) |i| if (L.previousInterFor(true, i)) {
            pi[i] = Q.fromBase(columns[3 + L.main.COUNT + i][prior]);
        };
        var acc = E.WeightedAccumulator{ .powers = out.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &acc };
        c.emitFor(Q, values[0..3], values[3..][0..L.main.COUNT], &pm, values[3 + L.main.COUNT ..][0..W], &pi, &sink);
        out.accumulate(row, acc.accumulation.mulM31(inverses[row >> @intCast(c.log_size)]));
    }
}
test "fused CPU packed weighted domain kernel equals scalar" {
    const c = component(true);
    const n = 128;
    const COLS = 3 + L.main.COUNT + W;
    var data: [COLS][n]M = undefined;
    var columns: [COLS][]const M = undefined;
    for (&data, &columns, 0..) |*column, *view, i| {
        for (column, 0..) |*v, row| v.* = M.fromCanonical(@intCast(1 + i * n + row));
        view.* = column;
    }
    var powers: [N]Q = undefined;
    for (&powers, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(i + 3), 7, 11, 13);
    const inv = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    var expected: [4][n]M = @splat(@splat(M.zero()));
    var actual: [4][n]M = @splat(@splat(M.zero()));
    var refcol = engine.secure_column.SecureColumnByCoords{ .columns = .{ &expected[0], &expected[1], &expected[2], &expected[3] }, .owns_columns = false };
    var gotcol = engine.secure_column.SecureColumnByCoords{ .columns = .{ &actual[0], &actual[1], &actual[2], &actual[3] }, .owns_columns = false };
    var refout = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &refcol, .next_fresh_index = 0 };
    var gotout = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &gotcol, .next_fresh_index = 0 };
    scalar(&c, &columns, &inv, &refout);
    for ([_][2]usize{ .{ 0, 7 }, .{ 7, 65 }, .{ 65, 113 }, .{ 113, n } }) |range| try X.component.testing.packedRows.evaluate(&c, &columns, range[0], range[1], &inv, &gotout);
    for (expected, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
    // A legacy-width column set is rejected by the fused kernel.
    var wide: [3 + L.main.COUNT + 40][]const M = undefined;
    for (&wide, 0..) |*view, i| view.* = columns[@min(i, COLS - 1)];
    try std.testing.expectError(error.InvalidExecutionDomain, X.component.testing.packedRows.evaluate(&c, &wide, 0, n, &inv, &gotout));
}
