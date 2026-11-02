//! Opt-in byte-pair CPU interaction (Geometry.cpu_u8_pairs, 32 columns, 50
//! residuals) and the AND table that serves the tagged byte pairs: degree,
//! lane parity, exact per-row LogUp increment and forged-witness rejection.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const X = air.word16_execution;
const E = air.evaluation;
const Tables = air.providers.tables;
const Q = E.Q;
const M = core.fields.m31.M31;
const L = X.layout;
const Eq = X.equations;
const W = L.pairs.COUNT;
const N = Eq.PAIR_CONSTRAINTS;
// Residual indices of the pair interaction block.
const REG = Eq.MAIN_CONSTRAINTS;
const FUNCTION = REG + 3;
const ROM = REG + 4;
const OWNER = REG + 5;
const U16 = REG + 6;
const FUSED = REG + 7;
const LAST = REG + 8;
comptime {
    std.debug.assert(W == 32 and N == 50 and LAST == N - 1);
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

test "pair CPU residuals are cubic over dense full-extension coordinates (all50)" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const pc = Tables.Challenges.draw(&channel);
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
        Eq.emitPairsFor(Q, data[0][0..3], &data[1], &data[2], data[3][0..W], data[4][0..W], inputs(), claim, ch, pc, &sink);
        try std.testing.expectEqual(@as(usize, N), sink.count);
    }
    var cubic_fused = false;
    for (0..N) |i| {
        const fourth = result[0][i].sub(result[1][i].mulM31(M.fromCanonical(4))).add(result[2][i].mulM31(M.fromCanonical(6))).sub(result[3][i].mulM31(M.fromCanonical(4))).add(result[4][i]);
        try std.testing.expect(fourth.isZero());
        const third = result[3][i].sub(result[2][i].mulM31(M.fromCanonical(3))).add(result[1][i].mulM31(M.fromCanonical(3))).sub(result[0][i]);
        if (i == FUSED) cubic_fused = !third.isZero();
    }
    try std.testing.expect(cubic_fused);
}

test "pair CPU packed lanes equal QM31 and the pair increment equals the legacy increment with U8 replaced by pairs" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const pc = Tables.Challenges.draw(&channel);
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
    Eq.emitPairsFor(B, simd[0][0..3], &simd[1], &simd[2], simd[3][0..W], simd[4][0..W], inputs(), claim, ch, pc, &sink);
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
        Eq.emitPairsFor(Q, q[0][0..3], &q[1], &q[2], q[3][0..W], q[4][0..W], inputs(), claim, ch, pc, &out);
        for (residuals, packed_result) |wanted, got| try std.testing.expect(wanted.eql(got.lane(lane)));
        // Same statement on every relation but U8: legacy increment minus the
        // three U8 fractions plus the two byte-pair fractions.
        const row = &native[1];
        const ds = Eq.nativeDenominators(native[0][0..3], row, inputs(), ch);
        var inverse: [9]Q = undefined;
        for (Eq.inverseDenominatorsFor(Q, ds), &inverse) |d, *value| value.* = try d.inv();
        var wanted = Eq.nativeContribution(ds, row, inverse);
        for (4..7) |k| wanted = wanted.sub(try ds.affine[k].inv());
        const p = Eq.nativePairDenominators(row, pc);
        wanted = wanted.add(try p[0].inv()).add(try p[1].inv());
        const witnesses = try Eq.nativePairWitnesses(ds, row);
        try std.testing.expect((try Eq.nativePairContribution(row, pc, witnesses)).eql(wanted));
    }
}

const Trace = struct {
    fixed: [32][3]M,
    main: [32][L.main.COUNT]M,
    inter: [32][W]M,
    claim: Q,
    ch: X.types.Challenges,
    pc: Tables.Challenges,
    fn init() !Trace {
        var channel = core.channel.blake2s.Blake2sChannel{};
        var self: Trace = undefined;
        self.ch = challenges(&channel);
        self.pc = Tables.Challenges.draw(&channel);
        var contributions: [32]Q = undefined;
        self.claim = Q.zero();
        const entry = X.Entry.fromDecoded(0x001080b3, 0x1000); // add x1,x1,x1.
        for (0..32) |row| {
            self.fixed[row] = .{ M.fromCanonical(@intCast(row)), M.fromCanonical(@intFromBool(row == 0)), M.fromCanonical(@intFromBool(row == 31)) };
            self.main[row] = if (row == 0) try X.row.active(entry, 0, 0x1004, .{ .a = 7, .b = 7, .c = 14, .previous_rd = 7 }, .{ 0, 1, 2 }) else try X.row.padding(@intCast(row), 0x1004);
            const ds = Eq.nativeDenominators(&self.fixed[row], &self.main[row], inputs(), self.ch);
            const witnesses = try Eq.nativePairWitnesses(ds, &self.main[row]);
            for (witnesses, 0..) |value, i| put(&self.inter[row], 4 * i, value);
            contributions[row] = try Eq.nativePairContribution(&self.main[row], self.pc, witnesses);
            self.claim = self.claim.add(contributions[row]);
        }
        var sum = self.claim.neg();
        for (0..32) |row| {
            sum = sum.add(contributions[row]);
            put(&self.inter[row], L.pairs.sum, sum);
        }
        try std.testing.expect(sum.isZero());
        return self;
    }
    fn residualsWith(self: *const Trace, row: usize, main: [L.main.COUNT]M, current: [W]M, previous: [W]M, ch: X.types.Challenges, pc: Tables.Challenges) [N]Q {
        const prior = (row + 31) % 32;
        var out: [N]Q = undefined;
        var sink = E.Sink{ .values = &out };
        Eq.emitPairsFor(Q, &toQ(3, self.fixed[row]), &toQ(L.main.COUNT, main), &toQ(L.main.COUNT, self.main[prior]), &toQ(W, current), &toQ(W, previous), inputs(), self.claim, ch, pc, &sink);
        return out;
    }
    fn residuals(self: *const Trace, row: usize, current: [W]M, previous: [W]M) [N]Q {
        return self.residualsWith(row, self.main[row], current, previous, self.ch, self.pc);
    }
    fn at(self: *const Trace, row: usize) [N]Q {
        return self.residuals(row, self.inter[row], self.inter[(row + 31) % 32]);
    }
};
fn onlyNonzero(values: [N]Q, wanted: []const usize) !void {
    for (values, 0..) |value, i| {
        const expected = std.mem.indexOfScalar(usize, wanted, i) != null;
        try std.testing.expectEqual(expected, !value.isZero());
    }
}

test "pair CPU native witness satisfies all50 and every forged witness is rejected" {
    const t = try Trace.init();
    for (0..32) |row| try onlyNonzero(t.at(row), &.{});
    const delta = Q.fromU32Unchecked(3, 1, 4, 1);
    // Every committed slot is a fraction: perturbing it breaks its own residual
    // and the prefix; repairing the prefix leaves its own residual failing.
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 6 }, [_]usize{ REG, REG + 1, REG + 2, FUNCTION, ROM, OWNER, U16 }) |slot, residual| {
        var forged = t.inter[0];
        put(&forged, 4 * slot, get(forged, 4 * slot).add(delta));
        try onlyNonzero(t.residuals(0, forged, t.inter[31]), &.{ residual, FUSED });
        put(&forged, L.pairs.sum, get(forged, L.pairs.sum).add(delta));
        try onlyNonzero(t.residuals(0, forged, t.inter[31]), &.{residual});
    }
    // FUNCTION/ROM with the legacy bare inverse 1/d instead of w/d on a padding
    // row (w = 0): rejected (the fraction must be zero there).
    const ds5 = Eq.nativeDenominators(&t.fixed[5], &t.main[5], inputs(), t.ch);
    var forged = t.inter[5];
    put(&forged, 4 * 3, try ds5.function.inv());
    try std.testing.expect(!t.residuals(5, forged, t.inter[4])[FUNCTION].isZero());
    forged = t.inter[5];
    put(&forged, 4 * 4, try ds5.rom.inv());
    try std.testing.expect(!t.residuals(5, forged, t.inter[4])[ROM].isZero());
    // S+delta on one row: that row and its successor reject.
    forged = t.inter[7];
    put(&forged, L.pairs.sum, get(forged, L.pairs.sum).add(delta));
    try onlyNonzero(t.residuals(7, forged, t.inter[6]), &.{FUSED});
    try onlyNonzero(t.residuals(8, t.inter[8], forged), &.{FUSED});
    // Drop row 9's two pair fractions and compensate in S at row 12: every
    // witness and the claim are honest, only the prefix path moves.
    const p = Eq.nativePairDenominators(&t.main[9], t.pc);
    const tail = (try p[0].inv()).add(try p[1].inv());
    var shifted = t.inter;
    for (9..12) |row| put(&shifted[row], L.pairs.sum, get(shifted[row], L.pairs.sum).sub(tail));
    try std.testing.expect(!t.residuals(9, shifted[9], shifted[8])[FUSED].isZero());
    try std.testing.expect(!t.residuals(12, shifted[12], shifted[11])[FUSED].isZero());
    // Only one of the two pairs dropped: still rejected.
    shifted = t.inter;
    const half = try p[1].inv();
    for (9..12) |row| put(&shifted[row], L.pairs.sum, get(shifted[row], L.pairs.sum).sub(half));
    try std.testing.expect(!t.residuals(9, shifted[9], shifted[8])[FUSED].isZero());
    // Last row must carry a zero prefix.
    forged = t.inter[31];
    put(&forged, L.pairs.sum, delta);
    try std.testing.expect(!t.residuals(31, forged, t.inter[30])[LAST].isZero());
    // A changed gap8 limb changes the pair query, so the unchanged prefix rejects.
    var main = t.main[3];
    main[L.main.gap8 + 2] = M.fromCanonical(1);
    try std.testing.expect(!t.residualsWith(3, main, t.inter[3], t.inter[2], t.ch, t.pc)[FUSED].isZero());
}

test "fused byte pairs: a one-sided pole is unsatisfiable" {
    const t = try Trace.init();
    // Distinct pairs on one row (padding rows query (0,0) twice), with the pair
    // challenge chosen so that the first denominator vanishes: the fused
    // residual then reads -p1 != 0 whatever the prefix holds.
    var main = t.main[3];
    for (0..3, [_]u32{ 5, 7, 9 }) |slot, value| main[L.main.gap8 + slot] = M.fromCanonical(value);
    var pole = t.pc;
    pole.offset = pole.offset.sub(Eq.nativePairDenominators(&main, t.pc)[0]);
    const q = Eq.nativePairDenominators(&main, pole);
    try std.testing.expect(q[0].isZero() and !q[1].isZero());
    const residuals = t.residualsWith(3, main, t.inter[3], t.inter[2], t.ch, pole);
    try std.testing.expect(residuals[FUSED].eql(q[1].neg()));
}

test "tagged byte pairs never alias AND tuples or out-of-range pairs" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const pc = Tables.Challenges.draw(&channel);
    // (x, y, 0, 1) vs the AND tuple (x, y, x&y): distinct linear forms.
    for ([_][2]u32{ .{ 0, 0 }, .{ 3, 5 }, .{ 255, 255 } }) |xy| {
        const x = Q.fromBase(M.fromCanonical(xy[0]));
        const y = Q.fromBase(M.fromCanonical(xy[1]));
        const and_d = pc.denominator(&.{ x, y, Q.fromBase(M.fromCanonical(xy[0] & xy[1])) });
        try std.testing.expect(!Tables.pairDenominatorFor(Q, pc, x, y).eql(and_d));
    }
    // A packed alias (256, 0) is not the table pair (0, 1), and no table row
    // holds a coordinate >= 256; the LogUp sum of the forged query against the
    // honest supplier is nonzero.
    const forged = Tables.pairDenominatorFor(Q, pc, Q.fromBase(M.fromCanonical(256)), Q.zero());
    const honest = Tables.pairDenominatorFor(Q, pc, Q.zero(), Q.one());
    try std.testing.expect(!(try forged.inv()).sub(try honest.inv()).isZero());
    try std.testing.expectError(error.InvalidLookupTuple, Tables.Kind.byte_and.rowIndex(.{ 256, 0, 0, 0, 0, 0 }));
}

test "AND pair table residuals: honest fill satisfies them and forged multiplicities, inverses and prefixes reject" {
    const a = std.testing.allocator;
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = Tables.Challenges.draw(&channel);
    var setup = try Tables.Setup.init(a, .byte_and);
    defer setup.deinit();
    const size = Tables.Kind.byte_and.size();
    const counts = try a.alloc(u64, size);
    defer a.free(counts);
    const pairs = try a.alloc(u64, size);
    defer a.free(pairs);
    @memset(counts, 0);
    @memset(pairs, 0);
    counts[17] = 4;
    counts[size - 1] = 1;
    pairs[0] = 9;
    pairs[3 * 256 + 5] = 2;
    pairs[200 * 256] = 7;
    var request = try Tables.Request.initWithPairs(a, &setup, counts, pairs);
    defer request.deinit();
    const claim = try request.generateInteraction(ch);
    // Claim equals -(sum m/d + sum m_pair/p) over the tagged relation.
    var expected = Q.zero();
    for (0..size) |i| {
        const tuple = Tables.Kind.byte_and.tupleAt(i);
        const t = [3]Q{ Q.fromBase(M.fromCanonical(tuple[0])), Q.fromBase(M.fromCanonical(tuple[1])), Q.fromBase(M.fromCanonical(tuple[2])) };
        const p = Tables.pairDenominatorFor(Q, ch, t[0], t[1]);
        if (counts[i] != 0) expected = expected.sub((try ch.denominator(&t).inv()).mulM31(M.fromCanonical(@intCast(counts[i]))));
        if (pairs[i] != 0) expected = expected.sub((try p.inv()).mulM31(M.fromCanonical(@intCast(pairs[i]))));
        try std.testing.expect(request.pair_dictionary[i].mul(p).eql(Q.one()));
    }
    try std.testing.expect(claim.eql(expected));
    const physical = @import("stwo_riscv_frontend").rv64_air.witness.physical;
    for (0..size) |i| {
        const row = physical(i, 16);
        const prior = physical((i + size - 1) % size, 16);
        var tuple: [3]Q = undefined;
        for (&tuple, 0..) |*value, c| value.* = Q.fromBase(setup.fixed[c * size + row]);
        const first = Q.fromBase(setup.fixed[3 * size + row]);
        const last = Q.fromBase(setup.fixed[4 * size + row]);
        const m = Q.fromBase(request.main[row]);
        const mp = Q.fromBase(request.main[size + row]);
        const inverse = sec(request.interaction, size, row, 0);
        const sum = sec(request.interaction, size, row, 4);
        const previous = sec(request.interaction, size, prior, 4);
        for (Tables.evaluatePairFor(Q, &tuple, first, last, m, mp, inverse, sum, previous, claim, ch)) |r| try std.testing.expect(r.isZero());
        if (i == 3 * 256 + 5 or i == 0) {
            try std.testing.expect(!Tables.evaluatePairFor(Q, &tuple, first, last, m, mp.add(Q.one()), inverse, sum, previous, claim, ch)[1].isZero());
            try std.testing.expect(!Tables.evaluatePairFor(Q, &tuple, first, last, m, mp, inverse.add(Q.one()), sum, previous, claim, ch)[0].isZero());
        }
    }
    // The pair table is AND-only.
    var shift = try Tables.Setup.init(a, .byte_shift);
    defer shift.deinit();
    try std.testing.expectError(error.InvalidLookupMultiplicity, Tables.Request.initWithPairs(a, &shift, counts[0..shift.kind.size()], pairs[0..shift.kind.size()]));
    // One relation: AND + pair mass is admitted together below M31.
    counts[1] = core.fields.m31.Modulus - 10;
    try std.testing.expectError(error.InvalidLookupMultiplicity, Tables.Request.initWithPairs(a, &setup, counts, pairs));
}
fn sec(data: []const M, size: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * size + row], data[(column + 1) * size + row], data[(column + 2) * size + row], data[(column + 3) * size + row]);
}

fn component() X.component.Component {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    return .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .public = .{ .steps = 1, .epoch = 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 } }, .claim = Q.fromU32Unchecked(3, 5, 7, 11), .challenges = ch, .fused = true, .pairs = Tables.Challenges.draw(&channel) };
}
test "pair CPU component binds 32 columns, 50 degree-3 residuals and prefix-only previous masks" {
    const c = component();
    try std.testing.expectEqual([3]usize{ 3, 47, 32 }, c.widths());
    try std.testing.expectEqual(@as(usize, 50), c.nConstraints());
    for (0..50) |index| try std.testing.expectEqual(@as(u8, 3), try c.constraintDegreeBound(index));
    try std.testing.expectError(error.InvalidConstraintIndex, c.constraintDegreeBound(50));
    for (0..32) |column| try std.testing.expectEqual(column >= 28, c.needsPrevious(2, column));
    const point = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
    var masks = try c.maskPoints(std.testing.allocator, point, 7);
    defer masks.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 32), masks.items[2].len);
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
        for (0..W) |i| if (L.previousInterMode(true, true, i)) {
            pi[i] = Q.fromBase(columns[3 + L.main.COUNT + i][prior]);
        };
        var acc = E.WeightedAccumulator{ .powers = out.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &acc };
        c.emitFor(Q, values[0..3], values[3..][0..L.main.COUNT], &pm, values[3 + L.main.COUNT ..][0..W], &pi, &sink);
        out.accumulate(row, acc.accumulation.mulM31(inverses[row >> @intCast(c.log_size)]));
    }
}
test "pair CPU packed weighted domain kernel equals scalar" {
    const c = component();
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
    // A fused-width (36) column set is rejected by the pair kernel.
    var wide: [3 + L.main.COUNT + 36][]const M = undefined;
    for (&wide, 0..) |*view, i| view.* = columns[@min(i, COLS - 1)];
    try std.testing.expectError(error.InvalidExecutionDomain, X.component.testing.packedRows.evaluate(&c, &wide, 0, n, &inv, &gotout));
}
